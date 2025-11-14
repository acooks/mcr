//! Egress I/O Loop
use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use crate::logging::{Facility, Logger};
use crate::RelayCommand;
use std::sync::mpsc;

const SHUTDOWN_USER_DATA: u64 = u64::MAX;

use crate::worker::buffer_pool::{BufferPool, ManagedBuffer};
use crate::worker::ingress::BufferPoolTrait;

// --- Structs for Egress Payloads ---

/// A work item for the egress queue
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
    shutdown_requested: bool,
    logger: Logger,
    first_packet_logged: bool,
    shutdown_event_fd: OwnedFd,
    shutdown_buffer: [u8; 8],
}

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
        // NOTE: We do NOT call ring.submit() or reap_completions() here.
        // The main event loop is the ONLY place that calls submit_and_wait().
        // This keeps the event loop non-blocking and ensures we continuously drain packet_rx.
        Ok(batch_size)
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
        // Collect completion events to avoid borrow checker issues
        let mut completions = Vec::new();
        for cqe in self.ring.completion() {
            completions.push((cqe.user_data(), cqe.result()));
        }

        let mut count = 0;
        let mut need_shutdown_resubmit = false;

        for (user_data, result) in completions {
            count += 1;

            // Handle shutdown event completions
            if user_data == SHUTDOWN_USER_DATA {
                if result < 0 {
                    self.logger.error(
                        Facility::Egress,
                        &format!("Shutdown event read error: errno={}", -result),
                    );
                }
                // Process commands to check for shutdown
                let shutdown = self.process_commands();
                if !shutdown {
                    need_shutdown_resubmit = true;
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
                    self.logger.info(
                        Facility::Egress,
                        &format!(
                            "[STATS:Egress] sent={} submitted={} errors={} bytes={}",
                            self.stats.packets_sent,
                            self.stats.packets_submitted,
                            self.stats.send_errors,
                            self.stats.bytes_sent
                        ),
                    );
                }
            }
        }

        if need_shutdown_resubmit {
            self.handle_shutdown_resubmit()?;
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


    /// Check if shutdown has been requested
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Process commands from the command channel (non-blocking)
    /// Returns true if shutdown was requested
    pub fn process_commands(&mut self) -> bool {
        loop {
            match self.command_rx.try_recv() {
                Ok(RelayCommand::Shutdown) => {
                    self.logger.info(Facility::Egress, "Shutdown command received");
                    self.shutdown_requested = true;
                    return true;
                }
                Ok(cmd) => {
                    self.logger.debug(
                        Facility::Egress,
                        &format!("Ignoring unhandled command: {:?}", cmd),
                    );
                }
                Err(mpsc::TryRecvError::Empty) => {
                    // No more commands to process
                    return false;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.logger.error(Facility::Egress, "Command channel disconnected");
                    self.shutdown_requested = true;
                    return true;
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

    fn handle_shutdown_resubmit(&mut self) -> Result<()> {
        let read_op = opcode::Read::new(
            types::Fd(self.shutdown_event_fd.as_raw_fd()),
            self.shutdown_buffer.as_mut_ptr(),
            8,
        )
        .build()
        .user_data(SHUTDOWN_USER_DATA);

        unsafe {
            self.ring.submission().push(&read_op)?;
        }
        Ok(())
    }
}

// --- Backend-specific `new` implementation ---

impl EgressLoop<EgressWorkItem, Arc<BufferPool>> {
    pub fn new(
        config: EgressConfig,
        buffer_pool: Arc<BufferPool>,
        egress_channels: crate::worker::EgressChannelSet,
        logger: Logger,
    ) -> Result<Self> {
        logger.info(Facility::Egress, "Egress loop starting");

        // Extract command_rx and event_fd from the channel set
        let command_rx = egress_channels.command_rx;
        let event_fd = egress_channels.event_fd;

        // Convert EventFd to OwnedFd using Into trait (consumes EventFd)
        let shutdown_event_fd: OwnedFd = event_fd.into();

        let mut egress_loop = Self {
            ring: IoUring::new(config.queue_depth)?,
            sockets: HashMap::new(),
            egress_queue: Vec::with_capacity(config.batch_size),
            buffer_pool,
            config,
            stats: EgressStats::default(),
            in_flight: HashMap::new(),
            next_user_data: 0,
            command_rx,
            shutdown_requested: false,
            logger,
            first_packet_logged: false,
            shutdown_event_fd,
            shutdown_buffer: [0u8; 8],
        };

        // Submit initial shutdown read operation
        egress_loop.submit_shutdown_read()?;
        egress_loop.ring.submit()?;

        Ok(egress_loop)
    }

    fn submit_shutdown_read(&mut self) -> Result<()> {
        let read_op = opcode::Read::new(
            types::Fd(self.shutdown_event_fd.as_raw_fd()),
            self.shutdown_buffer.as_mut_ptr(),
            8,
        )
        .build()
        .user_data(SHUTDOWN_USER_DATA);

        unsafe {
            self.ring.submission().push(&read_op)?;
        }
        Ok(())
    }

    pub fn run(&mut self, packet_rx: &crossbeam_queue::SegQueue<EgressWorkItem>) -> Result<()> {
        loop {
            // Single blocking point
            self.ring.submit_and_wait(1)?;

            // Process completions
            self.process_cqe_batch()?;

            // Check shutdown
            if self.shutdown_requested() {
                // Drain remaining packets
                while let Some(packet) = packet_rx.pop() {
                    self.add_destination(&packet.interface_name, packet.dest_addr)?;
                    self.queue_packet(packet);
                }
                if !self.is_queue_empty() {
                    self.send_batch()?;
                }
                break;
            }

            // Drain packet queue
            while let Some(packet) = packet_rx.pop() {
                self.add_destination(&packet.interface_name, packet.dest_addr)?;
                self.queue_packet(packet);
            }

            // Send if we have packets
            if !self.is_queue_empty() {
                self.send_batch()?;
            }
        }

        self.print_final_stats();
        Ok(())
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
