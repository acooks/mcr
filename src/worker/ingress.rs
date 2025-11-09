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
use nix::sys::eventfd::{EfdFlags, EventFd};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket as StdUdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::{mpsc, Arc, Mutex};

use crate::worker::buffer_pool::BufferSize;
use crate::worker::{buffer_pool::BufferPool, egress::EgressPacket, packet_parser::parse_packet};
use crate::{ForwardingRule, RelayCommand};

// Userdata constants for io_uring
const COMMAND_NOTIFY: u64 = 0;
const PACKET_RECV_BASE: u64 = 1;  // Buffer indices start at 1, allowing up to u64::MAX-1 buffers

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
    /// Wrapped in Arc<Mutex<>> for safe shared access with egress
    buffer_pool: Arc<Mutex<BufferPool>>,

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

    /// Channel for receiving commands from the supervisor
    command_rx: mpsc::Receiver<RelayCommand>,

    /// EventFD for command notifications
    command_event_fd: OwnedFd,
}

impl IngressLoop {
    /// Create a new ingress loop
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Network interface to capture packets from (e.g., "eth0")
    /// * `config` - Ingress configuration
    /// * `buffer_pool` - Shared buffer pool (must be the same pool used by egress)
    /// * `egress_tx` - Optional channel for sending packets to egress
    /// * `command_rx` - Channel for receiving commands from the supervisor
    /// * `command_event_fd` - EventFD for command notifications (signaled when commands arrive)
    ///
    /// # Returns
    ///
    /// A new `IngressLoop` instance ready to receive packets
    pub fn new(
        interface_name: &str,
        config: IngressConfig,
        buffer_pool: Arc<Mutex<BufferPool>>,
        egress_tx: Option<mpsc::Sender<EgressPacket>>,
        command_rx: mpsc::Receiver<RelayCommand>,
        command_event_fd: EventFd,
    ) -> Result<Self> {
        let af_packet_socket = setup_af_packet_socket(interface_name)?;
        let ring = IoUring::new(config.queue_depth)?;

        Ok(Self {
            af_packet_socket,
            helper_sockets: HashMap::new(),
            ring,
            buffer_pool,
            rules: HashMap::new(),
            config,
            stats: IngressStats::default(),
            egress_tx,
            command_rx,
            command_event_fd: command_event_fd.into(),
        })
    }

    /// Add a forwarding rule and join the multicast group
    ///
    /// This creates a helper socket for IGMP join if one doesn't already exist
    /// for this (interface, group) pair.
    pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
        let key = (rule.input_group, rule.input_port);
        println!("[Ingress] Adding rule: {:?}", key);
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
        println!("[Ingress] Removing rule: {}", rule_id);
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
    /// 2. Wait for completions with a timeout
    /// 3. Process any received packets
    /// 4. Check for and process any commands from the supervisor
    /// 5. Repeat
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

        // Buffer for reading from the eventfd
        let mut command_notify_buf = [0u8; 8];

        // Submit the initial command notification read
        self.submit_command_read(&mut command_notify_buf)?;

        loop {
            // 1. Submit a batch of recv operations for all available buffers
            let available_buffers = self.config.batch_size - self.ring.submission().len();
            for (i, buf) in recv_buffers.iter_mut().enumerate().take(available_buffers) {
                let recv_op = opcode::Recv::new(
                    types::Fd(self.af_packet_socket.as_raw_fd()),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                )
                .build()
                .user_data(PACKET_RECV_BASE + i as u64); // Encode buffer index in user_data

                unsafe {
                    self.ring
                        .submission()
                        .push(&recv_op)
                        .context("Failed to push recv operation to io_uring")?;
                }
            }

            // 2. Submit and wait for completions (both packets and commands)
            self.ring.submit_and_wait(1)?;

            // 3. Process all available completions
            let completions: Vec<_> = self.ring.completion().collect();
            for cqe in completions {
                let user_data = cqe.user_data();
                match user_data {
                    COMMAND_NOTIFY => {
                        // Command notification received, process all pending commands
                        self.process_commands()?;
                        // Re-submit the command notification read
                        self.submit_command_read(&mut command_notify_buf)?;
                    }
                    ud if ud >= PACKET_RECV_BASE && ud < PACKET_RECV_BASE + self.config.batch_size as u64 => {
                        // Decode buffer index from user_data
                        let buffer_idx = (ud - PACKET_RECV_BASE) as usize;
                        let bytes_received = cqe.result();

                        if bytes_received < 0 {
                            log::error!("Error receiving packet: {}", bytes_received);
                            continue;
                        }
                        let bytes_received = bytes_received as usize;
                        if bytes_received > 0 {
                            if self.config.track_stats {
                                self.stats.packets_received += 1;
                                self.stats.bytes_received += bytes_received as u64;
                            }
                            // Process the correct buffer based on decoded index
                            self.process_packet(&recv_buffers[buffer_idx][..bytes_received])?;
                        }
                    }
                    _ => {
                        log::warn!("Unknown io_uring user_data: {}", user_data);
                    }
                }
            }
        }
    }

    /// Process all pending commands from the supervisor
    fn process_commands(&mut self) -> Result<()> {
        while let Ok(command) = self.command_rx.try_recv() {
            match command {
                RelayCommand::AddRule(rule) => {
                    self.add_rule(Arc::new(rule))?;
                }
                RelayCommand::RemoveRule { rule_id } => {
                    self.remove_rule(&rule_id)?;
                }
            }
        }
        Ok(())
    }

    /// Submit a read operation to io_uring for the command eventfd
    fn submit_command_read(&mut self, buf: &mut [u8; 8]) -> Result<()> {
        let read_op = opcode::Read::new(
            types::Fd(self.command_event_fd.as_raw_fd()),
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
        .build()
        .user_data(COMMAND_NOTIFY);

        unsafe {
            self.ring
                .submission()
                .push(&read_op)
                .context("Failed to push command read to io_uring")?;
        }
        Ok(())
    }

    /// Process a single received packet
    fn process_packet(&mut self, packet_data: &[u8]) -> Result<()> {
        println!("\n--- process_packet start ---");
        println!("Packet data len: {}", packet_data.len());

        // Parse packet headers
        let headers = match parse_packet(packet_data, false) {
            Ok(h) => {
                println!("Parse successful: {:?}", h);
                h
            }
            Err(_e) => {
                println!("Parse failed");
                if self.config.track_stats {
                    self.stats.parse_errors += 1;
                }
                // Drop packet with parse error
                return Ok(());
            }
        };

        // Match against rules (userspace demux by dest_ip, dest_port)
        let key = (headers.ipv4.dst_ip, headers.udp.dst_port);
        println!("Matching rule for key: {:?}", key);
        let rule = match self.rules.get(&key) {
            Some(r) => {
                println!("Rule matched: {}", r.rule_id);
                r.clone()
            }
            None => {
                println!("No rule matched");
                if self.config.track_stats {
                    self.stats.no_rule_match += 1;
                }
                // Drop packet with no matching rule
                return Ok(());
            }
        };

        // If there are no outputs, we are done with this packet.
        if rule.outputs.is_empty() {
            println!("Rule has no outputs, returning.");
            return Ok(());
        }

        // Forward to egress (if channel is available)
        if let Some(ref tx) = self.egress_tx {
            let payload_len = headers.payload_len;
            println!("Payload len: {}", payload_len);
            let payload_start = headers.payload_offset;
            let payload_end = payload_start + payload_len;

            // A packet is considered "matched" once we successfully allocate a buffer
            // for its first destination. We only increment the counter once per packet.
            let mut matched_stat_incremented = false;

            // Iterate through the outputs.
            for output in &rule.outputs {
                println!("Processing output: {:?}", output);
                {
                    let pool = self.buffer_pool.lock().expect("BufferPool mutex poisoned");
                    println!(
                        "Buffer pool state before alloc: small={}, standard={}, jumbo={}",
                        pool.pool(BufferSize::Small).available(),
                        pool.pool(BufferSize::Standard).available(),
                        pool.pool(BufferSize::Jumbo).available()
                    );
                }

                // Allocate a buffer for each output destination.
                let mut buffer = match self
                    .buffer_pool
                    .lock()
                    .expect("BufferPool mutex poisoned")
                    .allocate(payload_len)
                {
                    Some(b) => {
                        println!("Buffer allocation successful");
                        b
                    }
                    None => {
                        println!("Buffer allocation failed (pool exhausted)");
                        // Pool is exhausted, increment stat and stop processing this packet.
                        if self.config.track_stats {
                            println!(
                                "Incrementing buffer_exhaustion. Old value: {}",
                                self.stats.buffer_exhaustion
                            );
                            self.stats.buffer_exhaustion += 1;
                        }
                        return Ok(());
                    }
                };

                // If this is the first successful allocation, increment the matched stat.
                if !matched_stat_incremented {
                    if self.config.track_stats {
                        println!(
                            "Incrementing packets_matched. Old value: {}",
                            self.stats.packets_matched
                        );
                        self.stats.packets_matched += 1;
                    }
                    matched_stat_incremented = true;
                }

                // Copy payload into the newly allocated buffer.
                buffer.as_mut_slice()[..payload_len]
                    .copy_from_slice(&packet_data[payload_start..payload_end]);

                let dest_addr =
                    std::net::SocketAddr::new(std::net::IpAddr::V4(output.group), output.port);

                let egress_packet = EgressPacket {
                    buffer, // Move ownership of the buffer to the egress packet
                    interface_name: output.interface.clone(),
                    dest_addr,
                };

                if tx.send(egress_packet).is_err() && self.config.track_stats {
                    println!(
                        "Egress send failed, incrementing egress_channel_errors. Old value: {}",
                        self.stats.egress_channel_errors
                    );
                    self.stats.egress_channel_errors += 1;
                }
            }
        }

        println!("--- process_packet end ---");
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
    println!("[Ingress] Setting up AF_PACKET socket for interface {}", interface_name);

    // Create AF_PACKET socket with ETH_P_IP filter (0x0800)
    // This requires CAP_NET_RAW capability
    let socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0x0800)))
        .map_err(|e| {
            eprintln!("[Ingress] FATAL: Failed to create AF_PACKET socket: {}", e);
            eprintln!("[Ingress] This likely means CAP_NET_RAW capability is missing");
            eprintln!("[Ingress] Error details: {:?}", e);
            e
        })
        .context("Failed to create AF_PACKET socket")?;

    // Increase the receive buffer size
    let rcvbuf_size = 32 * 1024 * 1024; // 32MB
    socket.set_recv_buffer_size(rcvbuf_size)?;
    println!("[Ingress] Set SO_RCVBUF to {}", rcvbuf_size);

    // Get interface index
    let iface_index = get_interface_index(interface_name)
        .with_context(|| format!("Failed to get interface index for {}", interface_name))?;
    println!("[Ingress] Interface index for {}: {}", interface_name, iface_index);

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
    println!("[Ingress] AF_PACKET socket bound to interface {}", interface_name);

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

#[cfg(test)]
mod tests_unit {
    use super::*;
    use crate::worker::egress::EgressPacket;
    use crate::ForwardingRule;
    use std::net::SocketAddr;
    use std::os::unix::io::{IntoRawFd, OwnedFd};
    use std::sync::{mpsc, Arc};

    // Helper to create a test IngressLoop with mock components
    fn setup_test_ingress_loop(
        buffer_pool: Arc<Mutex<BufferPool>>,
    ) -> (
        IngressLoop,
        mpsc::Receiver<EgressPacket>,
        mpsc::Sender<EgressPacket>,
    ) {
        let (egress_tx, egress_rx) = mpsc::channel();
        let (_command_tx, command_rx) = mpsc::channel();
        let config = IngressConfig {
            track_stats: true,
            ..Default::default()
        };

        // Create dummy FDs and an empty ring for the test instance.
        // These are not used by process_packet, which is what we're testing.
        // Use /dev/null to create a safe dummy FD that won't interfere with stdin/stdout/stderr
        let dummy_file = std::fs::File::open("/dev/null").expect("Failed to open /dev/null");
        let dummy_fd = unsafe { OwnedFd::from_raw_fd(dummy_file.into_raw_fd()) };
        let ring = IoUring::new(1).unwrap();
        let command_event_fd = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK)
            .expect("Failed to create eventfd for test");

        let ingress_loop = IngressLoop {
            af_packet_socket: dummy_fd,
            helper_sockets: HashMap::new(),
            ring,
            buffer_pool,
            rules: HashMap::new(),
            config,
            stats: IngressStats::default(),
            egress_tx: Some(egress_tx.clone()),
            command_rx,
            command_event_fd: command_event_fd.into(),
        };

        (ingress_loop, egress_rx, egress_tx)
    }

    // Helper to create a simple test packet (Ethernet/IPv4/UDP)
    fn create_test_packet(dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        // Ethernet header (dummy, but with correct EtherType for IPv4)
        packet.extend_from_slice(&[0u8; 12]);
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (dummy, with correct destination IP and length)
        let total_len = (20 + 8 + payload.len()) as u16;
        packet.extend_from_slice(&[
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0,
            0,
            0,
            0,
            64,
            17,
            0,
            0,
        ]);
        packet.extend_from_slice(&[127, 0, 0, 1]); // Src IP
        packet.extend_from_slice(&dst_ip.octets()); // Dst IP

        // UDP header (dummy, with correct destination port and length)
        let udp_len = (8 + payload.len()) as u16;
        packet.extend_from_slice(&[
            0, // Src port (dummy)
            0,
            (dst_port >> 8) as u8,
            dst_port as u8,
            (udp_len >> 8) as u8,
            udp_len as u8,
            0,
            0, // Checksum (dummy)
        ]);
        // Payload
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn test_process_packet_matching_rule() {
        let buffer_pool = Arc::new(Mutex::new(BufferPool::new(true)));
        let (mut ingress_loop, egress_rx, _) = setup_test_ingress_loop(buffer_pool);

        // Add a rule
        let rule = Arc::new(ForwardingRule {
            rule_id: "test-rule".to_string(),
            input_interface: "lo".to_string(),
            input_group: Ipv4Addr::new(239, 1, 1, 1),
            input_port: 1234,
            outputs: vec![crate::OutputDestination {
                interface: "lo".to_string(),
                group: Ipv4Addr::new(239, 10, 10, 10),
                port: 5678,
                dtls_enabled: false,
            }],
            dtls_enabled: false,
        });
        ingress_loop
            .rules
            .insert((rule.input_group, rule.input_port), rule.clone());

        // Create a matching packet
        let payload = b"hello";
        let packet = create_test_packet(rule.input_group, rule.input_port, payload);

        // Process the packet
        ingress_loop.process_packet(&packet).unwrap();

        // Check stats
        assert_eq!(ingress_loop.stats.packets_matched, 1);
        assert_eq!(ingress_loop.stats.no_rule_match, 0);
        assert_eq!(ingress_loop.stats.parse_errors, 0);

        // Check that the packet was sent to egress
        let egress_packet = egress_rx.try_recv().unwrap();
        assert_eq!(&egress_packet.buffer.as_slice()[..payload.len()], payload);
        assert_eq!(
            egress_packet.dest_addr,
            SocketAddr::new(rule.outputs[0].group.into(), rule.outputs[0].port)
        );
    }

    #[test]
    fn test_process_packet_no_matching_rule() {
        let buffer_pool = Arc::new(Mutex::new(BufferPool::new(true)));
        let (mut ingress_loop, egress_rx, _) = setup_test_ingress_loop(buffer_pool);

        // No rules added

        // Create a packet
        let packet = create_test_packet(Ipv4Addr::new(239, 1, 1, 1), 1234, b"hello");

        // Process the packet
        ingress_loop.process_packet(&packet).unwrap();

        // Check stats
        assert_eq!(ingress_loop.stats.packets_matched, 0);
        assert_eq!(ingress_loop.stats.no_rule_match, 1);
        assert_eq!(ingress_loop.stats.parse_errors, 0);

        // Check that no packet was sent to egress
        assert!(egress_rx.try_recv().is_err());
    }

    #[test]
    fn test_process_packet_parse_error() {
        let buffer_pool = Arc::new(Mutex::new(BufferPool::new(true)));
        let (mut ingress_loop, egress_rx, _) = setup_test_ingress_loop(buffer_pool);

        // Create a truncated packet (too short to be valid)
        let packet = &[0u8; 10];

        // Process the packet
        ingress_loop.process_packet(packet).unwrap();

        // Check stats
        assert_eq!(ingress_loop.stats.packets_matched, 0);
        assert_eq!(ingress_loop.stats.no_rule_match, 0);
        assert_eq!(ingress_loop.stats.parse_errors, 1);

        // Check that no packet was sent to egress
        assert!(egress_rx.try_recv().is_err());
    }

    #[test]
    fn test_process_packet_buffer_exhaustion() {
        // Create a pool with stat tracking enabled.
        let buffer_pool = Arc::new(Mutex::new(BufferPool::new(true)));
        // Manually exhaust the pool by taking all available buffers.
        let mut allocated = Vec::new();
        {
            let mut pool = buffer_pool.lock().unwrap();
            while let Some(buffer) = pool.allocate(100) {
                allocated.push(buffer);
            }
        }

        let (mut ingress_loop, egress_rx, _) = setup_test_ingress_loop(buffer_pool);

        // Add a rule
        let rule = Arc::new(ForwardingRule {
            rule_id: "test-rule".to_string(),
            input_interface: "lo".to_string(),
            input_group: Ipv4Addr::new(239, 1, 1, 1),
            input_port: 1234,
            outputs: vec![crate::OutputDestination {
                interface: "lo".to_string(),
                group: Ipv4Addr::new(239, 10, 10, 10),
                port: 5678,
                dtls_enabled: false,
            }],
            dtls_enabled: false,
        });
        ingress_loop
            .rules
            .insert((rule.input_group, rule.input_port), rule.clone());

        // Create a matching packet
        let packet = create_test_packet(rule.input_group, rule.input_port, b"hello");

        // Process the packet
        ingress_loop.process_packet(&packet).unwrap();

        // Check stats
        assert_eq!(ingress_loop.stats.buffer_exhaustion, 1);
        assert_eq!(ingress_loop.stats.packets_matched, 0); // Not matched because no buffer

        // Check that no packet was sent to egress
        assert!(egress_rx.try_recv().is_err());
    }

    #[test]
    fn test_add_and_remove_rule() {
        let buffer_pool = Arc::new(Mutex::new(BufferPool::new(false)));
        let (mut ingress_loop, _, _) = setup_test_ingress_loop(buffer_pool);

        let rule = Arc::new(ForwardingRule {
            rule_id: "rule-to-remove".to_string(),
            input_interface: "lo".to_string(),
            input_group: Ipv4Addr::new(239, 2, 2, 2),
            input_port: 5555,
            outputs: vec![],
            dtls_enabled: false,
        });

        // Add the rule and verify it's there
        // Note: We are not testing the helper socket side-effect here.
        ingress_loop.add_rule(rule.clone()).unwrap();
        assert_eq!(ingress_loop.rules.len(), 1);
        assert!(ingress_loop
            .rules
            .contains_key(&(rule.input_group, rule.input_port)));

        // Remove the rule and verify it's gone
        ingress_loop.remove_rule("rule-to-remove").unwrap();
        assert_eq!(ingress_loop.rules.len(), 0);
    }
}
