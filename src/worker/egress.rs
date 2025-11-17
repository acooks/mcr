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

const SHUTDOWN_USER_DATA: u64 = u64::MAX;
const COMMAND_USER_DATA: u64 = u64::MAX - 1;
const PACKET_ARRIVAL_USER_DATA: u64 = u64::MAX - 2;

use crate::worker::adaptive_wakeup::WakeupStrategy;
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
    #[allow(dead_code)]
    buffer_pool: P,
    config: EgressConfig,
    stats: EgressStats,
    in_flight: HashMap<u64, B>,
    next_user_data: u64,
    cmd_stream_fd: OwnedFd,
    cmd_reader: crate::worker::command_reader::CommandReader,
    cmd_buffer: Vec<u8>,
    shutdown_requested: bool,
    logger: Logger,
    first_packet_logged: bool,
    shutdown_event_fd: OwnedFd,
    shutdown_buffer: [u8; 8],
    wakeup_strategy: Arc<dyn WakeupStrategy>,
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
                source_ip,
                dest_addr,
                self.sockets.len()
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

        // Submit send operations for each packet in the batch
        for _ in 0..batch_size {
            let packet = self.egress_queue.remove(0);
            self.submit_send(packet)?;
        }

        // Submit all operations to io_uring
        self.ring
            .submit()
            .context("Failed to submit send operations")?;

        // Reap completions - this is CRITICAL for performance!
        // It returns buffers to the pool immediately, preventing exhaustion.
        let sent_count = self.reap_completions_blocking(batch_size)?;

        Ok(sent_count)
    }

    /// Send queued packets without blocking on completions (for event-driven mode)
    fn send_batch_nonblocking(&mut self) -> Result<usize> {
        if self.egress_queue.is_empty() {
            return Ok(0);
        }

        let batch_size = self.egress_queue.len().min(self.config.batch_size);

        // Submit send operations for each packet in the batch
        for _ in 0..batch_size {
            let packet = self.egress_queue.remove(0);
            self.submit_send(packet)?;
        }

        // Submit to io_uring but DON'T wait for completions
        // Completions will be processed in the main event loop
        self.ring
            .submit()
            .context("Failed to submit send operations")?;

        Ok(batch_size)
    }

    fn submit_send(&mut self, packet: B) -> Result<()> {
        // Log first packet
        if !self.first_packet_logged {
            self.logger
                .debug(Facility::Egress, "First packet submitted");
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

        Ok(())
    }

    pub fn reap_available_completions(&mut self) -> Result<usize> {
        self.process_cqe_batch()
    }

    fn reap_completions_blocking(&mut self, expected: usize) -> Result<usize> {
        let mut processed = self.process_cqe_batch()?;

        // If we haven't processed all expected completions, wait for more
        while processed < expected {
            // Block until at least one completion is ready
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

            // Handle shutdown event completions (data path wakeup from ingress)
            if user_data == SHUTDOWN_USER_DATA {
                if result < 0 {
                    self.logger.error(
                        Facility::Egress,
                        &format!("Shutdown event read error: errno={}", -result),
                    );
                }
                // Just resubmit - no command processing here
                need_shutdown_resubmit = true;
                continue;
            }

            // Handle command stream completions
            if user_data == COMMAND_USER_DATA {
                if result > 0 {
                    // Process commands from buffer
                    if self.process_commands_from_buffer(result as usize)? {
                        // Shutdown requested, don't resubmit
                        continue;
                    }
                    // Resubmit command read for next command
                    self.submit_command_read()?;
                } else if result == 0 {
                    // Stream closed - supervisor disconnected
                    self.logger.info(Facility::Egress, "Command stream closed");
                    self.shutdown_requested = true;
                } else {
                    // Error
                    self.logger.error(
                        Facility::Egress,
                        &format!(
                            "Command read error: {}",
                            std::io::Error::from_raw_os_error(-result)
                        ),
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
                        &format!(
                            "Send error: errno={} (total errors: {})",
                            -result, self.stats.send_errors
                        ),
                    );
                }
            } else {
                if self.config.track_stats {
                    self.stats.packets_sent += 1;
                    self.stats.bytes_sent += result as u64;
                }

                // Periodic stats logging (every 10,000 packets)
                if self.stats.packets_sent.is_multiple_of(10000) {
                    self.logger.info(
                        Facility::Egress,
                        &format!(
                            "[STATS:Egress] total: sent={} submitted={} ch_recv={} errors={} bytes={}",
                            self.stats.packets_sent,
                            self.stats.packets_submitted,
                            self.stats.packets_received,
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

    /// Process completions in event-driven mode (handles eventfd + send completions)
    fn process_completions_event_driven(
        &mut self,
        packet_rx: &crossbeam_queue::SegQueue<B>,
    ) -> Result<()> {
        // Collect all completion events
        let mut completions = Vec::new();
        for cqe in self.ring.completion() {
            completions.push((cqe.user_data(), cqe.result()));
        }

        let mut need_shutdown_resubmit = false;
        let mut need_eventfd_rearm = false;

        for (user_data, result) in completions {
            match user_data {
                PACKET_ARRIVAL_USER_DATA => {
                    // Eventfd fired - new packets available
                    if result < 0 {
                        self.logger.error(
                            Facility::Egress,
                            &format!("Eventfd poll error: errno={}", -result),
                        );
                        need_eventfd_rearm = true;
                        continue;
                    }

                    // 1. Consume eventfd value to reset it
                    if let Some(eventfd_raw_fd) = self.wakeup_strategy.eventfd_raw_fd() {
                        let mut buf = [0u8; 8];
                        unsafe {
                            libc::read(eventfd_raw_fd, buf.as_mut_ptr() as *mut libc::c_void, 8);
                        }
                    }

                    // 2. Drain all packets from queue
                    while let Some(packet) = packet_rx.pop() {
                        if self.config.track_stats {
                            self.stats.packets_received += 1;
                        }
                        self.add_destination(packet.interface_name(), packet.dest_addr())?;
                        self.queue_packet(packet);
                    }

                    // 3. Send queued packets (non-blocking)
                    if !self.is_queue_empty() {
                        self.send_batch_nonblocking()?;
                    }

                    // 4. Re-arm eventfd poll for next notification
                    need_eventfd_rearm = true;
                }

                SHUTDOWN_USER_DATA => {
                    // Shutdown event
                    if result < 0 {
                        self.logger.error(
                            Facility::Egress,
                            &format!("Shutdown event read error: errno={}", -result),
                        );
                    }
                    need_shutdown_resubmit = true;
                }

                COMMAND_USER_DATA => {
                    // Command stream completion
                    if result > 0 {
                        if self.process_commands_from_buffer(result as usize)? {
                            continue;
                        }
                        self.submit_command_read()?;
                    } else if result == 0 {
                        self.logger.info(Facility::Egress, "Command stream closed");
                        self.shutdown_requested = true;
                    } else {
                        self.logger.error(
                            Facility::Egress,
                            &format!(
                                "Command read error: {}",
                                std::io::Error::from_raw_os_error(-result)
                            ),
                        );
                    }
                }

                _ => {
                    // Send completion - free buffer immediately
                    let _buffer_item = self
                        .in_flight
                        .remove(&user_data)
                        .context("Unknown user_data")?;

                    if result < 0 {
                        if self.config.track_stats {
                            self.stats.send_errors += 1;
                        }
                        if self.stats.send_errors % 100 == 1 {
                            self.logger.error(
                                Facility::Egress,
                                &format!(
                                    "Send error: errno={} (total: {})",
                                    -result, self.stats.send_errors
                                ),
                            );
                        }
                    } else {
                        if self.config.track_stats {
                            self.stats.packets_sent += 1;
                            self.stats.bytes_sent += result as u64;
                        }

                        // Periodic stats logging
                        if self.stats.packets_sent.is_multiple_of(10000) {
                            self.logger.info(
                                Facility::Egress,
                                &format!(
                                    "[STATS:Egress] total: sent={} submitted={} ch_recv={} errors={} bytes={}",
                                    self.stats.packets_sent,
                                    self.stats.packets_submitted,
                                    self.stats.packets_received,
                                    self.stats.send_errors,
                                    self.stats.bytes_sent
                                ),
                            );
                        }
                    }

                    // Buffer automatically freed by Drop (ManagedBuffer RAII)
                }
            }
        }

        // Re-arm eventfd poll if needed
        if need_eventfd_rearm {
            if let Some(eventfd_raw_fd) = self.wakeup_strategy.eventfd_raw_fd() {
                let poll_op = opcode::PollAdd::new(types::Fd(eventfd_raw_fd), libc::POLLIN as u32)
                    .build()
                    .user_data(PACKET_ARRIVAL_USER_DATA);

                unsafe {
                    self.ring
                        .submission()
                        .push(&poll_op)
                        .context("Failed to re-arm eventfd poll")?;
                }
            }
        }

        // Re-submit shutdown read if needed
        if need_shutdown_resubmit {
            self.handle_shutdown_resubmit()?;
        }

        Ok(())
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

    /// Process commands from command reader buffer
    /// Returns true if shutdown was requested
    fn process_commands_from_buffer(&mut self, bytes_read: usize) -> anyhow::Result<bool> {
        let commands = self
            .cmd_reader
            .process_bytes(&self.cmd_buffer[..bytes_read])
            .context("Failed to parse commands")?;

        for command in commands {
            match command {
                RelayCommand::Shutdown => {
                    self.logger
                        .info(Facility::Egress, "Shutdown command received");
                    self.shutdown_requested = true;
                    return Ok(true);
                }
                cmd => {
                    self.logger.debug(
                        Facility::Egress,
                        &format!("Ignoring unhandled command: {:?}", cmd),
                    );
                }
            }
        }
        Ok(false)
    }

    pub fn print_final_stats(&self) {
        // Print final stats in the format expected by integration tests
        let msg = format!(
            "[STATS:Egress FINAL] total: sent={} submitted={} ch_recv={} errors={} bytes={}",
            self.stats.packets_sent,
            self.stats.packets_submitted,
            self.stats.packets_received,
            self.stats.send_errors,
            self.stats.bytes_sent
        );
        self.logger.info(Facility::Egress, &msg);
    }

    fn submit_command_read(&mut self) -> Result<()> {
        let read_op = opcode::Read::new(
            types::Fd(self.cmd_stream_fd.as_raw_fd()),
            self.cmd_buffer.as_mut_ptr(),
            self.cmd_buffer.len() as u32,
        )
        .build()
        .user_data(COMMAND_USER_DATA);

        unsafe {
            self.ring.submission().push(&read_op)?;
        }
        Ok(())
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
        shutdown_event_fd: OwnedFd,
        cmd_stream_fd: OwnedFd,
        wakeup_strategy: Arc<dyn WakeupStrategy>,
        logger: Logger,
    ) -> Result<Self> {
        logger.info(Facility::Egress, "Egress loop starting");

        let mut egress_loop = Self {
            ring: IoUring::new(config.queue_depth)?,
            sockets: HashMap::new(),
            egress_queue: Vec::with_capacity(config.batch_size),
            buffer_pool,
            config,
            stats: EgressStats::default(),
            in_flight: HashMap::new(),
            next_user_data: 0,
            cmd_stream_fd,
            cmd_reader: crate::worker::command_reader::CommandReader::new(),
            cmd_buffer: vec![0u8; 4096],
            shutdown_requested: false,
            logger,
            first_packet_logged: false,
            shutdown_event_fd,
            shutdown_buffer: [0u8; 8],
            wakeup_strategy,
        };

        // Submit initial reads for both shutdown and command streams
        egress_loop.submit_shutdown_read()?;
        egress_loop.submit_command_read()?;
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
        // If we have an eventfd, set up persistent polling for packet arrivals
        if let Some(eventfd_raw_fd) = self.wakeup_strategy.eventfd_raw_fd() {
            let poll_op = opcode::PollAdd::new(types::Fd(eventfd_raw_fd), libc::POLLIN as u32)
                .build()
                .user_data(PACKET_ARRIVAL_USER_DATA);

            unsafe {
                self.ring
                    .submission()
                    .push(&poll_op)
                    .context("Failed to add eventfd poll")?;
            }
            self.ring.submit()?;

            self.logger.debug(
                Facility::Egress,
                "Set up eventfd polling for packet arrivals",
            );
        }

        // Determine mode: event-driven only if strategy says to use io_uring blocking
        // This respects HybridWakeup's dynamic switching between eventfd and spin
        let use_event_driven = false; // DISABLED: Option 2 event-driven mode has deadlock issues

        loop {
            // Check shutdown first
            if self.shutdown_requested() {
                // Drain remaining packets
                while let Some(packet) = packet_rx.pop() {
                    if self.config.track_stats {
                        self.stats.packets_received += 1;
                    }
                    self.add_destination(&packet.interface_name, packet.dest_addr)?;
                    self.queue_packet(packet);
                }

                // Send all queued packets
                while !self.is_queue_empty() {
                    self.send_batch()?;
                }

                break;
            }

            if use_event_driven {
                // EVENT-DRIVEN MODE: Process completions, check for packets, then wait if idle

                // 1. First, process any available completions (non-blocking)
                if !self.ring.completion().is_empty() {
                    self.process_completions_event_driven(packet_rx)?;
                }

                // 2. Check for new packets and queue them
                while let Some(packet) = packet_rx.pop() {
                    if self.config.track_stats {
                        self.stats.packets_received += 1;
                    }
                    self.add_destination(&packet.interface_name, packet.dest_addr)?;
                    self.queue_packet(packet);
                }

                // 3. Send any queued packets
                if !self.is_queue_empty() {
                    self.send_batch_nonblocking()?;
                }

                // 4. If we have no work, wait for events
                if packet_rx.is_empty() && self.egress_queue.is_empty() && self.in_flight.is_empty()
                {
                    // Wait for ANY event (packet arrival OR send completion OR shutdown)
                    self.ring.submit_and_wait(1)?;
                    // Process the completions we just woke up for
                    self.process_completions_event_driven(packet_rx)?;
                }
            } else {
                // SPIN MODE: Original behavior for SpinWakeup
                // Drain packet queue
                while let Some(packet) = packet_rx.pop() {
                    if self.config.track_stats {
                        self.stats.packets_received += 1;
                    }
                    self.add_destination(&packet.interface_name, packet.dest_addr)?;
                    self.queue_packet(packet);
                }

                // Send if we have packets
                if !self.is_queue_empty() {
                    self.send_batch()?;
                }
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
    pub packets_received: u64, // Received from ingress→egress channel
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
