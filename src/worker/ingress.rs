//! Ingress I/O Loop
//!
//! This module implements the high-performance ingress path for receiving multicast packets.
//! It uses the validated helper socket pattern from Experiment #1 and io_uring for batched
//! receive operations.
//!
//! ## Architecture
//!
//! The ingress loop consists of:
//! - **AF_PACKET socket** for raw packet capture (filters IPv4 via ETH_P_IP)
//! - **Helper AF_INET socket** for IGMP joins (stays open, not read from)
//! - **io_uring** for batched recv operations (32-64 packets per batch)
//! - **Buffer pool** for zero-copy packet allocation
//! - **Packet parser** for header extraction and validation
//! - **Rule table** for userspace demultiplexing by (dest_ip, dest_port)
//!
//! ## Performance Target
//!
//! - Throughput: 312k pps/core (for 1:5 amplification, 1.56M egress target)
//! - Latency: <100µs p99
//! - Buffer pool exhaustion: graceful packet drops (no crashes)

use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket as StdUdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::{mpsc, Arc};

use crate::worker::{parse_packet, BufferPool, EgressPacket};
use crate::ForwardingRule;

/// Statistics for the ingress loop
#[derive(Debug, Clone, Default)]
pub struct IngressStats {
    /// Total packets received from the AF_PACKET socket
    pub packets_received: u64,
    /// Packets successfully parsed and matched
    pub packets_matched: u64,
    /// Packets dropped due to parse errors
    pub parse_errors: u64,
    /// Packets dropped due to no matching rule
    pub no_rule_match: u64,
    /// Packets dropped due to buffer pool exhaustion
    pub buffer_exhaustion: u64,
    /// Packets dropped due to egress channel errors (full or closed)
    pub egress_channel_errors: u64,
    /// Total bytes received
    pub bytes_received: u64,
}

/// Configuration for the ingress loop
#[derive(Debug, Clone)]
pub struct IngressConfig {
    /// Queue depth for io_uring (recommended: 64-128)
    pub queue_depth: u32,
    /// Batch size for recv operations (recommended: 32-64)
    pub batch_size: usize,
    /// Enable statistics tracking (0.12% overhead)
    pub track_stats: bool,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            queue_depth: 64,
            batch_size: 32,
            track_stats: true,
        }
    }
}

/// Ingress loop for receiving multicast packets
pub struct IngressLoop {
    /// AF_PACKET socket for raw packet capture
    af_packet_socket: OwnedFd,

    /// Helper sockets for IGMP joins (one per multicast group)
    /// Key: (interface_name, multicast_group)
    helper_sockets: HashMap<(String, Ipv4Addr), StdUdpSocket>,

    /// io_uring instance for batched recv
    ring: IoUring,

    /// Buffer pool for packet allocations
    buffer_pool: BufferPool,

    /// Local rule table for packet demultiplexing
    /// Key: (dest_ip, dest_port)
    rules: HashMap<(Ipv4Addr, u16), Arc<ForwardingRule>>,

    /// Configuration
    config: IngressConfig,

    /// Statistics
    stats: IngressStats,

    /// Channel for sending packets to egress
    /// If None, packets are dropped after processing (for testing)
    egress_tx: Option<mpsc::Sender<EgressPacket>>,
}

impl IngressLoop {
    /// Create a new ingress loop
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Network interface to capture packets from (e.g., "eth0")
    /// * `config` - Ingress configuration
    /// * `egress_tx` - Optional channel for sending packets to egress
    ///
    /// # Returns
    ///
    /// A new `IngressLoop` instance ready to receive packets
    pub fn new(
        interface_name: &str,
        config: IngressConfig,
        egress_tx: Option<mpsc::Sender<EgressPacket>>,
    ) -> Result<Self> {
        let af_packet_socket = setup_af_packet_socket(interface_name)?;
        let ring = IoUring::new(config.queue_depth)?;
        let buffer_pool = BufferPool::new(config.track_stats);

        Ok(Self {
            af_packet_socket,
            helper_sockets: HashMap::new(),
            ring,
            buffer_pool,
            rules: HashMap::new(),
            config,
            stats: IngressStats::default(),
            egress_tx,
        })
    }

    /// Add a forwarding rule and join the multicast group
    ///
    /// This creates a helper socket for IGMP join if one doesn't already exist
    /// for this (interface, group) pair.
    pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
        let key = (rule.input_group, rule.input_port);
        self.rules.insert(key, rule.clone());

        // Ensure a helper socket exists for this rule's multicast group to maintain IGMP membership.
        // This is idempotent; if a socket for this group already exists, this does nothing.
        let helper_key = (rule.input_interface.clone(), rule.input_group);
        if let std::collections::hash_map::Entry::Vacant(e) = self.helper_sockets.entry(helper_key)
        {
            let helper_socket = setup_helper_socket(&rule.input_interface, rule.input_group)?;
            e.insert(helper_socket);
        }

        Ok(())
    }

    /// Remove a forwarding rule
    ///
    /// This removes the rule from the table but keeps the helper socket open
    /// (other rules might be using the same multicast group).
    pub fn remove_rule(&mut self, rule_id: &str) -> Result<()> {
        // Find and remove the rule
        self.rules.retain(|_key, rule| rule.rule_id != rule_id);
        Ok(())
    }

    /// Get current statistics
    pub fn stats(&self) -> IngressStats {
        self.stats.clone()
    }

    /// Main ingress loop - receives and processes packets
    ///
    /// This function runs indefinitely, receiving packets in batches via io_uring,
    /// parsing them, matching against rules, and queuing them for egress.
    ///
    /// # Packet Processing Flow
    ///
    /// 1. Submit batch of recv operations to io_uring
    /// 2. Wait for completions
    /// 3. For each received packet:
    ///    a. Parse Ethernet/IPv4/UDP headers
    ///    b. Match (dest_ip, dest_port) against rule table
    ///    c. If match: allocate buffer, copy payload, queue for egress
    ///    d. If no match: drop packet (increment stats)
    /// 4. Repeat
    ///
    /// # Error Handling
    ///
    /// - Parse errors: Log and drop packet (increment `parse_errors`)
    /// - Buffer exhaustion: Drop packet (increment `buffer_exhaustion`)
    /// - No rule match: Drop packet (increment `no_rule_match`)
    /// - io_uring errors: Return error and exit loop
    pub fn run(&mut self) -> Result<()> {
        // Allocate receive buffers (reused across iterations)
        let mut recv_buffers: Vec<Vec<u8>> = (0..self.config.batch_size)
            .map(|_| vec![0u8; 9000]) // Max jumbo frame size
            .collect();

        loop {
            // Submit batch of recv operations
            for buf in recv_buffers.iter_mut() {
                let recv_op = opcode::Recv::new(
                    types::Fd(self.af_packet_socket.as_raw_fd()),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                );

                unsafe {
                    self.ring
                        .submission()
                        .push(&recv_op.build())
                        .context("Failed to push recv operation to io_uring")?;
                }
            }

            // Submit all operations
            self.ring
                .submit_and_wait(1)
                .context("Failed to submit recv operations")?;

            // Collect completion results before processing
            // (This avoids holding a mutable borrow of self.ring while calling self.process_packet)
            let mut completions = Vec::with_capacity(self.config.batch_size);
            {
                let cq = self.ring.completion();
                for cqe in cq {
                    completions.push(cqe.result());
                }
            }

            // Process each completion
            for (idx, bytes_received) in completions.iter().enumerate() {
                let bytes_received = *bytes_received;

                if bytes_received < 0 {
                    // Error receiving packet - log and continue
                    eprintln!("Error receiving packet: {}", bytes_received);
                    continue;
                }

                if bytes_received == 0 {
                    // Connection closed (shouldn't happen with AF_PACKET)
                    continue;
                }

                let bytes_received = bytes_received as usize;

                // Update stats
                if self.config.track_stats {
                    self.stats.packets_received += 1;
                    self.stats.bytes_received += bytes_received as u64;
                }

                // Process the packet from the corresponding buffer
                if let Some(buf) = recv_buffers.get(idx) {
                    self.process_packet(&buf[..bytes_received])?;
                }
            }
        }
    }

    /// Process a single received packet
    fn process_packet(&mut self, packet_data: &[u8]) -> Result<()> {
        // Parse packet headers
        let headers = match parse_packet(packet_data, false) {
            Ok(h) => h,
            Err(_e) => {
                if self.config.track_stats {
                    self.stats.parse_errors += 1;
                }
                // Drop packet with parse error
                return Ok(());
            }
        };

        // Match against rules (userspace demux by dest_ip, dest_port)
        let key = (headers.ipv4.dst_ip, headers.udp.dst_port);
        let rule = match self.rules.get(&key) {
            Some(r) => r.clone(),
            None => {
                if self.config.track_stats {
                    self.stats.no_rule_match += 1;
                }
                // Drop packet with no matching rule
                return Ok(());
            }
        };

        // Allocate buffer for payload
        let payload_len = headers.payload_len;
        let mut buffer = match self.buffer_pool.allocate(payload_len) {
            Some(b) => b,
            None => {
                if self.config.track_stats {
                    self.stats.buffer_exhaustion += 1;
                }
                // Drop packet due to buffer exhaustion
                return Ok(());
            }
        };

        // Copy payload to buffer
        let payload_start = headers.payload_offset;
        let payload_end = payload_start + payload_len;
        buffer.as_mut_slice()[..payload_len]
            .copy_from_slice(&packet_data[payload_start..payload_end]);

        // Update stats
        if self.config.track_stats {
            self.stats.packets_matched += 1;
        }

        // Forward to egress (if channel is available)
        if let Some(ref tx) = self.egress_tx {
            // Create egress packets for each output destination
            for output in &rule.outputs {
                let dest_addr =
                    std::net::SocketAddr::new(std::net::IpAddr::V4(output.group), output.port);

                let egress_packet = EgressPacket {
                    buffer: buffer.clone_data(), // Clone buffer data for each output
                    interface_name: output.interface.clone(),
                    dest_addr,
                };

                if tx.send(egress_packet).is_err() {
                    // This can happen if the egress channel is full or closed.
                    // In a real-world scenario, we might want to log this or increment a counter.
                    // For now, we just drop the packet.
                    if self.config.track_stats {
                        self.stats.egress_channel_errors += 1;
                    }
                }
            }
        }

        // Deallocate buffer back to pool
        self.buffer_pool.deallocate(buffer);

        Ok(())
    }
}

/// Setup AF_PACKET socket for raw packet capture
///
/// This creates a raw socket with ETH_P_IP filter to capture only IPv4 packets
/// on the specified interface.
///
/// # Arguments
///
/// * `interface_name` - Network interface to bind to (e.g., "eth0")
///
/// # Returns
///
/// An `OwnedFd` for the AF_PACKET socket
pub fn setup_af_packet_socket(interface_name: &str) -> Result<OwnedFd> {
    // Create AF_PACKET socket with ETH_P_IP filter (0x0800)
    let socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0x0800)))
        .context("Failed to create AF_PACKET socket")?;

    // Get interface index
    let iface_index = get_interface_index(interface_name)
        .with_context(|| format!("Failed to get interface index for {}", interface_name))?;

    // Bind to the specific interface
    let mut addr_storage: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr_storage.sll_family = libc::AF_PACKET as u16;
    addr_storage.sll_protocol = (libc::ETH_P_IP as u16).to_be(); // Network byte order
    addr_storage.sll_ifindex = iface_index;

    unsafe {
        let addr_ptr = &addr_storage as *const libc::sockaddr_ll as *const libc::sockaddr;
        let addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        if libc::bind(socket.as_raw_fd(), addr_ptr, addr_len) < 0 {
            return Err(anyhow::anyhow!(
                "Failed to bind AF_PACKET socket to interface {}",
                interface_name
            ));
        }
    }

    // Convert Socket to OwnedFd
    // Socket::into_raw_fd() consumes the socket and returns RawFd
    let raw_fd = socket.into_raw_fd();
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    Ok(owned_fd)
}

/// Setup helper AF_INET socket for IGMP join
///
/// This creates a UDP socket and joins the specified multicast group.
/// The socket is kept open but never read from (validated pattern from Exp #1).
///
/// # Arguments
///
/// * `interface_name` - Network interface to join on
/// * `multicast_group` - Multicast group address to join
///
/// # Returns
///
/// A `UdpSocket` that maintains the IGMP membership
pub fn setup_helper_socket(
    interface_name: &str,
    multicast_group: Ipv4Addr,
) -> Result<StdUdpSocket> {
    // Create UDP socket
    let socket = StdUdpSocket::bind("0.0.0.0:0").context("Failed to create helper socket")?;

    // Get interface IP address
    let interface_ip = get_interface_ip(interface_name)
        .with_context(|| format!("Failed to get IP address for interface {}", interface_name))?;

    // Join multicast group
    socket
        .join_multicast_v4(&multicast_group, &interface_ip)
        .with_context(|| {
            format!(
                "Failed to join multicast group {} on interface {}",
                multicast_group, interface_name
            )
        })?;

    Ok(socket)
}

/// Get the interface index for a given interface name
fn get_interface_index(interface_name: &str) -> Result<i32> {
    use std::ffi::CString;

    let c_name = CString::new(interface_name)
        .with_context(|| format!("Invalid interface name: {}", interface_name))?;

    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

    if index == 0 {
        return Err(anyhow::anyhow!("Interface not found: {}", interface_name));
    }

    Ok(index as i32)
}

/// Get the IP address for a given interface name
fn get_interface_ip(interface_name: &str) -> Result<Ipv4Addr> {
    use pnet::datalink;

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| anyhow::anyhow!("Interface not found: {}", interface_name))?;

    // Find the first IPv4 address
    for ip_network in &interface.ips {
        if let std::net::IpAddr::V4(ipv4) = ip_network.ip() {
            return Ok(ipv4);
        }
    }

    Err(anyhow::anyhow!(
        "No IPv4 address found for interface {}",
        interface_name
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ingress_config_default() {
        let config = IngressConfig::default();
        assert_eq!(config.queue_depth, 64);
        assert_eq!(config.batch_size, 32);
        assert!(config.track_stats);
    }

    #[test]
    fn test_ingress_stats_default() {
        let stats = IngressStats::default();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_matched, 0);
        assert_eq!(stats.parse_errors, 0);
        assert_eq!(stats.no_rule_match, 0);
        assert_eq!(stats.buffer_exhaustion, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_get_interface_index() {
        // Test with loopback interface (should always exist)
        let result = get_interface_index("lo");
        assert!(result.is_ok(), "Should find loopback interface");
        assert!(result.unwrap() > 0, "Interface index should be positive");
    }

    #[test]
    fn test_get_interface_index_invalid() {
        // Test with non-existent interface
        let result = get_interface_index("nonexistent9999");
        assert!(result.is_err(), "Should fail for non-existent interface");
    }

    #[test]
    fn test_get_interface_ip() {
        // Test with loopback interface
        let result = get_interface_ip("lo");
        assert!(result.is_ok(), "Should find loopback interface IP");

        let ip = result.unwrap();
        assert_eq!(
            ip,
            Ipv4Addr::new(127, 0, 0, 1),
            "Loopback should be 127.0.0.1"
        );
    }

    #[test]
    fn test_get_interface_ip_invalid() {
        // Test with non-existent interface
        let result = get_interface_ip("nonexistent9999");
        assert!(result.is_err(), "Should fail for non-existent interface");
    }

    // Note: setup_af_packet_socket and setup_helper_socket require root privileges,
    // so we'll test them in integration tests rather than unit tests.

    // Note: IngressLoop::run() is an infinite loop, so we'll test it in integration
    // tests with a timeout and controlled shutdown mechanism.
}
