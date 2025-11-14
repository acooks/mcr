//! Egress I/O Loop
use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::logging::{Facility, Logger};
use crate::RelayCommand;
use nix::sys::eventfd::EventFd;
use std::sync::mpsc;

// Conditional imports and type definitions
#[cfg(feature = "lock_free_buffer_pool")]
use crate::worker::buffer_pool::{BufferPool as LockFreeBufferPool, ManagedBuffer};
#[cfg(feature = "lock_free_buffer_pool")]
use std::sync::Arc;

#[cfg(not(feature = "lock_free_buffer_pool"))]
use crate::worker::buffer_pool::{Buffer, BufferPool as MutexBufferPool};
#[cfg(not(feature = "lock_free_buffer_pool"))]
use std::sync::{Arc, Mutex};

use crate::worker::ingress::BufferPoolTrait;

// --- Structs for Egress Payloads ---

/// A packet ready for egress (Mutex backend)
#[cfg(not(feature = "lock_free_buffer_pool"))]
pub struct EgressPacket {
    pub buffer: Buffer,
    pub payload_len: usize,
    pub dest_addr: SocketAddr,
    pub interface_name: String,
}

/// A work item for the egress queue (Lock-Free backend)
#[cfg(feature = "lock_free_buffer_pool")]
pub struct EgressWorkItem {
    pub buffer: ManagedBuffer,
    pub payload_len: usize,
    pub dest_addr: SocketAddr,
    pub interface_name: String,
}

// --- Traits for abstracting over backend implementations ---

/// Trait to abstract over the different buffer types used in egress.
pub trait EgressBuffer: Deref<Target = [u8]> {
    fn payload_len(&self) -> usize;
    fn dest_addr(&self) -> SocketAddr;
    fn interface_name(&self) -> &str;
}

#[cfg(not(feature = "lock_free_buffer_pool"))]
impl EgressBuffer for EgressPacket {
    fn payload_len(&self) -> usize {
        self.payload_len
    }
    fn dest_addr(&self) -> SocketAddr {
        self.dest_addr
    }
    fn interface_name(&self) -> &str {
        &self.interface_name
    }
}
#[cfg(not(feature = "lock_free_buffer_pool"))]
impl Deref for EgressPacket {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buffer.as_slice()[..self.payload_len]
    }
}

#[cfg(feature = "lock_free_buffer_pool")]
impl EgressBuffer for EgressWorkItem {
    fn payload_len(&self) -> usize {
        self.payload_len
    }
    fn dest_addr(&self) -> SocketAddr {
        self.dest_addr
    }
    fn interface_name(&self) -> &str {
        &self.interface_name
    }
}
#[cfg(feature = "lock_free_buffer_pool")]
impl Deref for EgressWorkItem {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buffer[..self.payload_len]
    }
}

// --- Generic EgressLoop and its implementation ---

pub struct EgressLoop<B, P> {
    ring: IoUring,
    sockets: HashMap<(String, SocketAddr), (OwnedFd, Ipv4Addr)>,
    egress_queue: Vec<B>,
    buffer_pool: P,
    config: EgressConfig,
    stats: EgressStats,
    in_flight: HashMap<u64, B>,
    next_user_data: u64,
    command_rx: mpsc::Receiver<RelayCommand>,
    shutdown_event_fd: EventFd,
    shutdown_buffer: [u8; 8], // Buffer for eventfd read
    shutdown_requested: bool,
    logger: Logger,
    first_packet_logged: bool,
}

// Special user_data value to identify shutdown eventfd completions
const SHUTDOWN_USER_DATA: u64 = u64::MAX;

// Common implementation for both backends
impl<B, P> EgressLoop<B, P>
where
    B: EgressBuffer,
    P: BufferPoolTrait,
{
    pub fn add_destination(
        &mut self,
        interface_name: &str,
        dest_addr: SocketAddr,
    ) -> Result<Ipv4Addr> {
        let key = (interface_name.to_string(), dest_addr);
        if self.sockets.contains_key(&key) {
            return Ok(self.sockets.get(&key).unwrap().1);
        }
        let source_ip = get_interface_ip(interface_name)?;
        let socket = create_connected_udp_socket(source_ip, dest_addr)?;
        self.sockets.insert(key, (socket, source_ip));

        self.logger.debug(
            Facility::Egress,
            &format!(
                "New destination added: {} -> {} (total sockets: {})",
                source_ip, dest_addr, self.sockets.len()
            ),
        );

        Ok(source_ip)
    }

    pub fn queue_packet(&mut self, packet: B) {
        self.egress_queue.push(packet);
    }

    pub fn send_batch(&mut self) -> Result<usize> {
        if self.egress_queue.is_empty() {
            return Ok(0);
        }
        let batch_size = self.egress_queue.len().min(self.config.batch_size);
        for _ in 0..batch_size {
            let packet = self.egress_queue.remove(0);
            self.submit_send(packet)?;
        }
        self.ring.submit().context("Failed to submit send ops")?;
        self.reap_completions(batch_size)
    }

    fn submit_send(&mut self, packet: B) -> Result<()> {
        // Log first packet
        if !self.first_packet_logged {
            self.logger.debug(Facility::Egress, "First packet submitted");
            self.first_packet_logged = true;
        }

        // Extract packet metadata before moving
        let key = (packet.interface_name().to_string(), packet.dest_addr());
        let payload_len = packet.payload_len();

        let (socket_fd, _) = self
            .sockets
            .get(&key)
            .context("No socket for destination")?;
        let user_data = self.next_user_data;
        self.next_user_data += 1;
        let send_op = opcode::Send::new(
            types::Fd(socket_fd.as_raw_fd()),
            packet.deref().as_ptr(),
            payload_len as u32,
        )
        .build()
        .user_data(user_data);
        unsafe {
            self.ring
                .submission()
                .push(&send_op)
                .context("Failed to push send op")?;
        }
        self.in_flight.insert(user_data, packet);
        if self.config.track_stats {
            self.stats.packets_submitted += 1;
        }

        // Trace-level per-packet logging
        self.logger.trace(
            Facility::Egress,
            &format!(
                "Packet submitted: {} -> {} len={}",
                key.0,
                key.1,
                payload_len
            ),
        );

        Ok(())
    }

    pub fn reap_available_completions(&mut self) -> Result<usize> {
        self.process_cqe_batch()
    }

    fn reap_completions(&mut self, expected: usize) -> Result<usize> {
        let mut processed = self.process_cqe_batch()?;
        while processed < expected {
            self.ring.submit_and_wait(1)?;
            processed += self.process_cqe_batch()?;
        }
        Ok(processed)
    }

    fn process_cqe_batch(&mut self) -> Result<usize> {
        let mut count = 0;
        for cqe in self.ring.completion() {
            count += 1;
            let user_data = cqe.user_data();
            let result = cqe.result();

            // Check if this is the shutdown eventfd completion
            if user_data == SHUTDOWN_USER_DATA {
                if result >= 0 {
                    self.logger.info(Facility::Egress, "Shutdown signal received via io_uring");
                    self.shutdown_requested = true;
                    // Don't resubmit the shutdown read - we're shutting down
                } else if result != -(nix::errno::Errno::ECANCELED as i32) {
                    // Log error unless it's a cancellation (expected during shutdown)
                    self.logger.error(
                        Facility::Egress,
                        &format!("Error reading shutdown eventfd: errno={}", -result),
                    );
                }
                continue;
            }

            // Handle packet send completions
            let _buffer_item = self
                .in_flight
                .remove(&user_data)
                .context("Unknown user_data")?;
            if result < 0 {
                if self.config.track_stats {
                    self.stats.send_errors += 1;
                }
                // Log send errors (sample every 100th error to avoid spam)
                if self.stats.send_errors % 100 == 1 {
                    self.logger.error(
                        Facility::Egress,
                        &format!("Send error: errno={} (total errors: {})", -result, self.stats.send_errors),
                    );
                }
            } else {
                if self.config.track_stats {
                    self.stats.packets_sent += 1;
                    self.stats.bytes_sent += result as u64;
                }

                // Periodic stats logging (every 10,000 packets)
                if self.stats.packets_sent % 10000 == 0 {
                    self.logger.debug(
                        Facility::Egress,
                        &format!(
                            "Stats: sent={} submitted={} errors={} bytes={}",
                            self.stats.packets_sent,
                            self.stats.packets_submitted,
                            self.stats.send_errors,
                            self.stats.bytes_sent
                        ),
                    );
                }
            }
        }
        Ok(count)
    }

    pub fn stats(&self) -> EgressStats {
        self.stats.clone()
    }
    pub fn queue_len(&self) -> usize {
        self.egress_queue.len()
    }
    pub fn is_queue_empty(&self) -> bool {
        self.egress_queue.is_empty()
    }

    /// Submit a read operation on the shutdown eventfd to io_uring
    /// This allows submit_and_wait to wake up when shutdown is signaled
    fn submit_shutdown_read(&mut self) -> Result<()> {
        use std::os::fd::AsRawFd;

        let read_op = opcode::Read::new(
            types::Fd(self.shutdown_event_fd.as_raw_fd()),
            self.shutdown_buffer.as_mut_ptr(),
            self.shutdown_buffer.len() as u32,
        )
        .build()
        .user_data(SHUTDOWN_USER_DATA);

        unsafe {
            self.ring
                .submission()
                .push(&read_op)
                .context("Failed to push shutdown read op")?;
        }

        self.logger.trace(Facility::Egress, "Submitted shutdown eventfd read to io_uring");
        Ok(())
    }

    /// Check if shutdown has been requested
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Process commands from the command channel (non-blocking)
    pub fn process_commands(&mut self) {
        loop {
            match self.command_rx.try_recv() {
                Ok(RelayCommand::Shutdown) => {
                    self.logger.info(Facility::Egress, "Shutdown command received");
                    self.shutdown_requested = true;
                    return;
                }
                Ok(cmd) => {
                    self.logger.debug(
                        Facility::Egress,
                        &format!("Ignoring unhandled command: {:?}", cmd),
                    );
                }
                Err(mpsc::TryRecvError::Empty) => {
                    // No more commands to process
                    return;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.logger.error(Facility::Egress, "Command channel disconnected");
                    self.shutdown_requested = true;
                    return;
                }
            }
        }
    }

    pub fn print_final_stats(&self) {
        // Print final stats in the format expected by integration tests
        let msg = format!(
            "[STATS:Egress FINAL] submitted={} sent={} errors={} bytes={}",
            self.stats.packets_submitted,
            self.stats.packets_sent,
            self.stats.send_errors,
            self.stats.bytes_sent
        );
        self.logger.info(Facility::Egress, &msg);
    }
}

// --- Backend-specific `new` implementations ---

#[cfg(not(feature = "lock_free_buffer_pool"))]
impl EgressLoop<EgressPacket, Arc<Mutex<MutexBufferPool>>> {
    pub fn new(
        config: EgressConfig,
        buffer_pool: Arc<Mutex<MutexBufferPool>>,
        command_rx: mpsc::Receiver<RelayCommand>,
        shutdown_event_fd: EventFd,
        logger: Logger,
    ) -> Result<Self> {
        logger.info(Facility::Egress, "Egress loop starting");

        let egress_loop = Self {
            ring: IoUring::new(config.queue_depth)?,
            sockets: HashMap::new(),
            egress_queue: Vec::with_capacity(config.batch_size),
            buffer_pool,
            config,
            stats: EgressStats::default(),
            in_flight: HashMap::new(),
            next_user_data: 0,
            command_rx,
            shutdown_event_fd,
            shutdown_buffer: [0u8; 8],
            shutdown_requested: false,
            logger,
            first_packet_logged: false,
        };

        // Note: We don't submit the shutdown eventfd to io_uring for egress
        // because the egress loop polls the command channel directly.
        // The eventfd is kept for API consistency but not actively used.

        Ok(egress_loop)
    }
}

#[cfg(feature = "lock_free_buffer_pool")]
impl EgressLoop<EgressWorkItem, Arc<LockFreeBufferPool>> {
    pub fn new(
        config: EgressConfig,
        buffer_pool: Arc<LockFreeBufferPool>,
        command_rx: mpsc::Receiver<RelayCommand>,
        shutdown_event_fd: EventFd,
        logger: Logger,
    ) -> Result<Self> {
        logger.info(Facility::Egress, "Egress loop starting (lock-free)");

        let egress_loop = Self {
            ring: IoUring::new(config.queue_depth)?,
            sockets: HashMap::new(),
            egress_queue: Vec::with_capacity(config.batch_size),
            buffer_pool,
            config,
            stats: EgressStats::default(),
            in_flight: HashMap::new(),
            next_user_data: 0,
            command_rx,
            shutdown_event_fd,
            shutdown_buffer: [0u8; 8],
            shutdown_requested: false,
            logger,
            first_packet_logged: false,
        };

        // Note: We don't submit the shutdown eventfd to io_uring for egress
        // because the egress loop polls the command channel directly.
        // The eventfd is kept for API consistency but not actively used.

        Ok(egress_loop)
    }
}

// --- Unchanged structs and helper functions ---

#[derive(Debug, Clone, Default)]
pub struct EgressStats {
    pub packets_submitted: u64,
    pub packets_sent: u64,
    pub send_errors: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone)]
pub struct EgressConfig {
    pub queue_depth: u32,
    pub batch_size: usize,
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

fn create_connected_udp_socket(source_ip: Ipv4Addr, dest_addr: SocketAddr) -> Result<OwnedFd> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(source_ip.into(), 0).into())?;
    socket.connect(&dest_addr.into())?;
    Ok(socket.into())
}

fn get_interface_ip(interface_name: &str) -> Result<Ipv4Addr> {
    for iface in pnet::datalink::interfaces() {
        if iface.name == interface_name {
            for ip_net in iface.ips {
                if let std::net::IpAddr::V4(ip) = ip_net.ip() {
                    return Ok(ip);
                }
            }
        }
    }
    Err(anyhow::anyhow!(
        "No IPv4 address found for {}",
        interface_name
    ))
}
