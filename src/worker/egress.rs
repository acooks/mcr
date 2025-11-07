//! Egress I/O Loop
//!
//! This module implements the high-performance egress path for sending multicast packets.
//! It uses io_uring for batched send operations based on the validated patterns from
//! Experiment #5.
//!
//! ## Architecture
//!
//! The egress loop consists of:
//! - **io_uring** for batched send operations (32-64 packets per batch)
//! - **Per-interface UDP sockets** bound to specific source IPs
//! - **Egress queue** for accumulating packets before batch submission
//! - **Buffer pool** for deallocating buffers after successful transmission
//!
//! ## Performance Target (from Exp #5)
//!
//! - Throughput: 1.85M pps (adequate for 1:5 amplification, 1.56M target)
//! - Latency: 34.6 µs per 64-packet batch
//! - Syscall reduction: 32x (batch of 64 reduces 1.85M → 57k syscalls/sec)
//! - Queue depth: 64-128 (no measurable difference)
//! - Batch size: 32-64 packets (optimal throughput plateau)

use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;

use crate::worker::{Buffer, BufferPool};

/// Statistics for the egress loop
#[derive(Debug, Clone, Default)]
pub struct EgressStats {
    /// Total packets submitted to io_uring
    pub packets_submitted: u64,
    /// Packets successfully sent
    pub packets_sent: u64,
    /// Send errors from io_uring completion queue
    pub send_errors: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
}

/// Configuration for the egress loop
#[derive(Debug, Clone)]
pub struct EgressConfig {
    /// Queue depth for io_uring (recommended: 64-128)
    pub queue_depth: u32,
    /// Batch size for send operations (recommended: 32-64)
    pub batch_size: usize,
    /// Enable statistics tracking (0.12% overhead)
    pub track_stats: bool,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            queue_depth: 64,
            batch_size: 32,
            track_stats: true,
        }
    }
}

/// A packet ready for egress
pub struct EgressPacket {
    /// Buffer containing packet payload
    pub buffer: Buffer,
    /// Destination address (multicast group:port)
    pub dest_addr: SocketAddr,
    /// Source interface name for socket selection
    pub interface_name: String,
}

/// Egress loop for sending multicast packets
pub struct EgressLoop {
    /// io_uring instance for batched send
    ring: IoUring,

    /// Connected UDP sockets per (interface, dest_group, dest_port)
    /// Key: (interface_name, dest_addr)
    /// Value: (socket_fd, source_ip)
    /// Using connected sockets allows us to use opcode::Send instead of sendto
    sockets: HashMap<(String, SocketAddr), (OwnedFd, Ipv4Addr)>,

    /// Egress queue (packets ready to send)
    egress_queue: Vec<EgressPacket>,

    /// Buffer pool (for deallocation after send)
    buffer_pool: Arc<BufferPool>,

    /// Configuration
    config: EgressConfig,

    /// Statistics
    stats: EgressStats,

    /// In-flight buffers (indexed by user_data from io_uring)
    /// This allows us to deallocate buffers after send completes
    in_flight: HashMap<u64, Buffer>,

    /// Next user_data value for tracking in-flight buffers
    next_user_data: u64,
}

impl EgressLoop {
    /// Create a new egress loop
    ///
    /// # Arguments
    ///
    /// * `config` - Egress configuration
    /// * `buffer_pool` - Shared buffer pool for deallocation
    ///
    /// # Returns
    ///
    /// A new `EgressLoop` instance ready to send packets
    pub fn new(config: EgressConfig, buffer_pool: Arc<BufferPool>) -> Result<Self> {
        let ring = IoUring::new(config.queue_depth)?;

        Ok(Self {
            ring,
            sockets: HashMap::new(),
            egress_queue: Vec::with_capacity(config.batch_size),
            buffer_pool,
            config,
            stats: EgressStats::default(),
            in_flight: HashMap::new(),
            next_user_data: 0,
        })
    }

    /// Add a socket for a specific (interface, destination) pair
    ///
    /// Creates a connected UDP socket bound to the source IP of the specified interface
    /// and connected to the destination address. This allows using opcode::Send instead
    /// of sendto, which was validated in Experiment #5.
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Network interface name (e.g., "eth0")
    /// * `dest_addr` - Destination multicast address (group:port)
    ///
    /// # Returns
    ///
    /// The source IP address that the socket is bound to
    pub fn add_destination(
        &mut self,
        interface_name: &str,
        dest_addr: SocketAddr,
    ) -> Result<Ipv4Addr> {
        let key = (interface_name.to_string(), dest_addr);

        if self.sockets.contains_key(&key) {
            // Socket already exists
            return Ok(self.sockets.get(&key).unwrap().1);
        }

        // Get interface IP address
        let source_ip = get_interface_ip(interface_name).with_context(|| {
            format!("Failed to get IP address for interface {}", interface_name)
        })?;

        // Create connected UDP socket
        let socket = create_connected_udp_socket(source_ip, dest_addr).with_context(|| {
            format!(
                "Failed to create connected UDP socket for {} -> {}",
                interface_name, dest_addr
            )
        })?;

        self.sockets.insert(key, (socket, source_ip));

        Ok(source_ip)
    }

    /// Queue a packet for egress
    ///
    /// The packet will be added to the egress queue and sent in the next batch.
    pub fn queue_packet(&mut self, packet: EgressPacket) {
        self.egress_queue.push(packet);
    }

    /// Send all queued packets in a batch
    ///
    /// This submits all packets in the egress queue to io_uring, waits for completions,
    /// and deallocates buffers.
    ///
    /// # Returns
    ///
    /// The number of packets successfully sent
    pub fn send_batch(&mut self) -> Result<usize> {
        if self.egress_queue.is_empty() {
            return Ok(0);
        }

        let batch_size = self.egress_queue.len().min(self.config.batch_size);

        // Submit send operations for each packet in the batch
        for _ in 0..batch_size {
            let packet = self.egress_queue.remove(0);
            self.submit_send(packet)?;
        }

        // Submit all operations to io_uring
        self.ring
            .submit()
            .context("Failed to submit send operations")?;

        // Reap completions
        let sent_count = self.reap_completions(batch_size)?;

        Ok(sent_count)
    }

    /// Submit a single send operation to io_uring
    fn submit_send(&mut self, packet: EgressPacket) -> Result<()> {
        // Get the connected socket for this (interface, destination) pair
        let key = (packet.interface_name.clone(), packet.dest_addr);
        let (socket_fd, _source_ip) = self.sockets.get(&key).ok_or_else(|| {
            anyhow::anyhow!(
                "No socket for interface {} -> {}. Call add_destination() first.",
                packet.interface_name,
                packet.dest_addr
            )
        })?;

        // Allocate user_data for tracking this buffer
        let user_data = self.next_user_data;
        self.next_user_data += 1;

        // Get buffer data pointer and length
        let data_ptr = packet.buffer.as_slice().as_ptr();
        let data_len = packet.buffer.len() as u32;

        // Create Send operation (validated pattern from Experiment #5)
        // Using connected socket, so we don't need to specify destination
        let send_op = opcode::Send::new(types::Fd(socket_fd.as_raw_fd()), data_ptr, data_len)
            .build()
            .user_data(user_data);

        // Submit to io_uring
        unsafe {
            self.ring
                .submission()
                .push(&send_op)
                .context("Failed to push send operation to io_uring")?;
        }

        // Track the buffer for later deallocation
        self.in_flight.insert(user_data, packet.buffer);

        // Update stats
        if self.config.track_stats {
            self.stats.packets_submitted += 1;
        }

        Ok(())
    }

    /// Reap completions from io_uring
    ///
    /// Processes completion queue entries, deallocates buffers, and updates statistics.
    fn reap_completions(&mut self, expected_count: usize) -> Result<usize> {
        let mut sent_count = 0;

        // Wait for at least one completion
        self.ring.submit_and_wait(1)?;

        // Process all available completions
        let cq = self.ring.completion();
        for cqe in cq {
            let user_data = cqe.user_data();
            let result = cqe.result();

            // Remove buffer from in-flight tracking
            let buffer = self
                .in_flight
                .remove(&user_data)
                .ok_or_else(|| anyhow::anyhow!("Unknown user_data in completion: {}", user_data))?;

            if result < 0 {
                // Send error
                if self.config.track_stats {
                    self.stats.send_errors += 1;
                }
                eprintln!("Error sending packet: {} (user_data={})", result, user_data);
            } else {
                // Success
                sent_count += 1;
                if self.config.track_stats {
                    self.stats.packets_sent += 1;
                    self.stats.bytes_sent += result as u64;
                }
            }

            // Deallocate buffer back to pool
            // SAFETY: buffer_pool is Arc, so we can safely get a mutable reference
            // through interior mutability (BufferPool uses RefCell internally)
            let pool_ptr = Arc::as_ptr(&self.buffer_pool) as *mut BufferPool;
            unsafe {
                (*pool_ptr).deallocate(buffer);
            }
        }

        // If we didn't process all expected completions, keep waiting
        while sent_count < expected_count {
            self.ring.submit_and_wait(1)?;
            let cq = self.ring.completion();
            for cqe in cq {
                let user_data = cqe.user_data();
                let result = cqe.result();

                let buffer = self
                    .in_flight
                    .remove(&user_data)
                    .ok_or_else(|| anyhow::anyhow!("Unknown user_data: {}", user_data))?;

                if result < 0 {
                    if self.config.track_stats {
                        self.stats.send_errors += 1;
                    }
                    eprintln!("Error sending packet: {}", result);
                } else {
                    sent_count += 1;
                    if self.config.track_stats {
                        self.stats.packets_sent += 1;
                        self.stats.bytes_sent += result as u64;
                    }
                }

                let pool_ptr = Arc::as_ptr(&self.buffer_pool) as *mut BufferPool;
                unsafe {
                    (*pool_ptr).deallocate(buffer);
                }
            }
        }

        Ok(sent_count)
    }

    /// Get current statistics
    pub fn stats(&self) -> EgressStats {
        self.stats.clone()
    }

    /// Get the number of packets in the egress queue
    pub fn queue_len(&self) -> usize {
        self.egress_queue.len()
    }

    /// Check if the egress queue is empty
    pub fn is_queue_empty(&self) -> bool {
        self.egress_queue.is_empty()
    }
}

/// Create a connected UDP socket bound to a specific source IP
///
/// This creates a UDP socket bound to the source IP and connected to the destination.
/// Connected sockets allow using opcode::Send instead of sendto, which was validated
/// in Experiment #5 to achieve 1.85M pps throughput.
fn create_connected_udp_socket(source_ip: Ipv4Addr, dest_addr: SocketAddr) -> Result<OwnedFd> {
    // Create UDP socket
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create UDP socket")?;

    // Set SO_REUSEADDR to allow multiple sockets on the same port
    socket
        .set_reuse_address(true)
        .context("Failed to set SO_REUSEADDR")?;

    // Bind to source IP (port 0 = any available port)
    let bind_addr = SocketAddr::new(std::net::IpAddr::V4(source_ip), 0);
    socket
        .bind(&bind_addr.into())
        .context("Failed to bind socket to source IP")?;

    // Connect to destination (validated pattern from Experiment #5)
    socket
        .connect(&dest_addr.into())
        .context("Failed to connect socket to destination")?;

    // Convert Socket to OwnedFd
    let raw_fd = socket.into_raw_fd();
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    Ok(owned_fd)
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

    #[test]
    fn test_egress_config_default() {
        let config = EgressConfig::default();
        assert_eq!(config.queue_depth, 64);
        assert_eq!(config.batch_size, 32);
        assert!(config.track_stats);
    }

    #[test]
    fn test_egress_stats_default() {
        let stats = EgressStats::default();
        assert_eq!(stats.packets_submitted, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.send_errors, 0);
        assert_eq!(stats.bytes_sent, 0);
    }

    #[test]
    fn test_get_interface_ip_loopback() {
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

    #[test]
    fn test_create_connected_udp_socket() {
        // Test creating a connected socket on loopback
        let source_ip = Ipv4Addr::new(127, 0, 0, 1);
        let dest_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);

        let result = create_connected_udp_socket(source_ip, dest_addr);
        assert!(
            result.is_ok(),
            "Should create connected UDP socket on loopback"
        );

        // Verify it's a valid file descriptor
        let fd = result.unwrap();
        assert!(fd.as_raw_fd() >= 0, "Should have valid file descriptor");
    }

    // Note: Full end-to-end egress tests (with io_uring) require
    // integration tests with actual network interfaces and receivers.
    // These are tested in the integration test suite.
}
