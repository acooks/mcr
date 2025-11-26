// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Unified Single-Threaded Data Plane Loop
//!
//! This module implements a single-threaded event loop that handles both
//! ingress (AF_PACKET receive) and egress (UDP send) in one io_uring instance.
//!
//! ## Architecture
//!
//! ```text
//! Single Thread, One io_uring
//! ┌─────────────────────────────────────────────────┐
//! │  io_uring with unified event queue:             │
//! │                                                  │
//! │  ┌──────────────┐  ┌──────────────┐            │
//! │  │ RecvMsg ops  │  │   Send ops   │            │
//! │  │ (AF_PACKET)  │  │  (UDP/INET)  │            │
//! │  └──────┬───────┘  └──────┬───────┘            │
//! │         │                  │                     │
//! │         v                  v                     │
//! │  ┌────────────────────────────────┐             │
//! │  │   Completion Queue (CQ)        │             │
//! │  │   - Packet received            │             │
//! │  │   - Packet sent                │             │
//! │  │   - Shutdown signal            │             │
//! │  └────────────────────────────────┘             │
//! └─────────────────────────────────────────────────┘
//!          │
//!          v
//!    Event Loop:
//!    1. Process available completions
//!    2. Submit new operations
//!    3. Wait for next event
//! ```
//!
//! ## Benefits
//!
//! - **No cross-thread communication**: Eliminates SegQueue/mpsc overhead
//! - **No eventfd**: No cross-thread wakeup mechanism needed
//! - **Unified buffer pool**: No Arc<Mutex> synchronization
//! - **Natural batching**: Process multiple receives, submit multiple sends
//! - **Simple event loop**: Just process completions and submit new work

use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use crate::logging::{Facility, Logger};
use crate::worker::buffer_pool::{BufferPool, BufferSize, ManagedBuffer};
use crate::worker::packet_parser::parse_packet;
use crate::ForwardingRule;

// User data ranges for different operation types
const SHUTDOWN_USER_DATA: u64 = u64::MAX;
const COMMAND_USER_DATA: u64 = u64::MAX - 1;
const RECV_BASE: u64 = 0;
const RECV_MAX: u64 = 1_000_000;
const SEND_BASE: u64 = 1_000_001;
const SEND_MAX: u64 = 2_000_000;

/// Work item for a pending send operation
struct SendWorkItem {
    payload: Arc<[u8]>, // Shared payload for zero-copy fan-out
    dest_addr: SocketAddr,
    interface_name: String,
}

/// Metadata about where to forward a packet
struct ForwardingTarget {
    payload_offset: usize,
    payload_len: usize,
    dest_addr: SocketAddr,
    interface_name: String,
}

/// Configuration for the unified data plane
#[derive(Debug, Clone)]
pub struct UnifiedConfig {
    /// io_uring queue depth
    pub queue_depth: u32,
    /// Number of receive buffers to pre-post
    pub num_recv_buffers: usize,
    /// Batch size for send operations
    pub send_batch_size: usize,
    /// Track statistics
    pub track_stats: bool,
}

impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            queue_depth: 1024,    // Increased from 128 for high throughput (300k+ pps)
            num_recv_buffers: 32, // Reduced from 64 to avoid buffer pool exhaustion
            send_batch_size: 64,  // Increased from 32 to reduce syscall overhead
            track_stats: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UnifiedStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub recv_errors: u64,
    pub send_errors: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub rules_matched: u64,
    pub rules_not_matched: u64,
    pub packets_filtered: u64, // Non-UDP packets (ARP, IPv6, TCP, etc.)
    pub buffer_pool_exhaustion: u64, // Buffer pool exhaustion events
}

/// Unified single-threaded data plane loop
pub struct UnifiedDataPlane {
    ring: IoUring,

    // Ingress
    recv_socket: Socket,
    recv_buffers: Vec<ManagedBuffer>,
    in_flight_recvs: HashMap<u64, ManagedBuffer>,
    next_recv_user_data: u64,

    // Forwarding rules (keyed by input_group, input_port)
    rules: HashMap<(Ipv4Addr, u16), ForwardingRule>,

    // Egress
    egress_sockets: HashMap<(String, SocketAddr), (OwnedFd, Ipv4Addr)>,
    send_queue: Vec<SendWorkItem>,
    in_flight_sends: HashMap<u64, Arc<[u8]>>,
    next_send_user_data: u64,

    // Buffer pool
    buffer_pool: std::sync::Arc<BufferPool>,

    // Control
    shutdown_requested: bool,
    cmd_stream_fd: OwnedFd,
    cmd_buffer: Vec<u8>,
    cmd_reader: crate::worker::command_reader::CommandReader,

    // Stats and config
    config: UnifiedConfig,
    stats: UnifiedStats,
    logger: Logger,
}

impl UnifiedDataPlane {
    pub fn new(
        interface_name: &str,
        config: UnifiedConfig,
        buffer_pool: std::sync::Arc<BufferPool>,
        cmd_stream_fd: OwnedFd,
        fanout_group_id: u16,
        logger: Logger,
    ) -> Result<Self> {
        logger.info(Facility::DataPlane, "Creating unified data plane loop");

        // Create AF_PACKET socket for receiving
        let recv_socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0x0003)))
            .context("Failed to create AF_PACKET socket")?;

        // Get interface index
        let iface_index = get_interface_index(interface_name)?;

        // Bind to interface using raw libc bind
        unsafe {
            let sockaddr_ll = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                sll_ifindex: iface_index,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            let ret = libc::bind(
                recv_socket.as_raw_fd(),
                &sockaddr_ll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(anyhow::anyhow!("Failed to bind AF_PACKET socket"));
            }
        }

        // Configure PACKET_FANOUT if fanout_group_id is non-zero
        if fanout_group_id > 0 {
            let fanout_arg: u32 = (fanout_group_id as u32) | (libc::PACKET_FANOUT_CPU << 16);

            unsafe {
                if libc::setsockopt(
                    recv_socket.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_FANOUT,
                    &fanout_arg as *const _ as *const _,
                    std::mem::size_of::<u32>() as _,
                ) < 0
                {
                    return Err(anyhow::anyhow!("PACKET_FANOUT failed"));
                }
            }
        }

        // Set non-blocking
        recv_socket.set_nonblocking(true)?;

        let mut unified = Self {
            ring: IoUring::new(config.queue_depth)?,
            recv_socket,
            recv_buffers: Vec::new(),
            in_flight_recvs: HashMap::new(),
            next_recv_user_data: RECV_BASE,
            rules: HashMap::new(),
            egress_sockets: HashMap::new(),
            send_queue: Vec::with_capacity(config.send_batch_size),
            in_flight_sends: HashMap::new(),
            next_send_user_data: SEND_BASE,
            buffer_pool,
            shutdown_requested: false,
            cmd_stream_fd,
            cmd_buffer: vec![0u8; 4096],
            cmd_reader: crate::worker::command_reader::CommandReader::new(),
            config,
            stats: UnifiedStats::default(),
            logger,
        };

        // Submit initial command read
        unified.submit_command_read()?;
        unified.ring.submit()?;

        Ok(unified)
    }

    /// Add a forwarding rule
    pub fn add_rule(&mut self, rule: ForwardingRule) -> Result<()> {
        let key = (rule.input_group, rule.input_port);
        self.rules.insert(key, rule);
        Ok(())
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> Result<()> {
        // Find the rule by rule_id
        let key_to_remove = self
            .rules
            .iter()
            .find(|(_, rule)| rule.rule_id == rule_id)
            .map(|(key, _)| *key);

        match key_to_remove {
            Some(key) => {
                self.rules.remove(&key);
                Ok(())
            }
            None => Err(anyhow::anyhow!("Rule not found: {}", rule_id)),
        }
    }

    /// Main event loop
    pub fn run(&mut self) -> Result<()> {
        self.logger
            .info(Facility::DataPlane, "Starting unified event loop");

        // Pre-post receive buffers
        let initial_recv_count = self.submit_recv_buffers()?;
        self.logger.info(
            Facility::DataPlane,
            &format!("Pre-posted {} recv buffers", initial_recv_count),
        );
        self.ring.submit()?;

        loop {
            // Check shutdown
            if self.shutdown_requested {
                self.logger
                    .info(Facility::DataPlane, "Shutdown requested, draining");

                // Drain send queue
                while !self.send_queue.is_empty() {
                    self.submit_send_batch()?;
                }

                // Wait for all in-flight sends to complete
                self.ring.submit()?;
                while !self.in_flight_sends.is_empty() {
                    self.ring.submit_and_wait(1)?;
                    self.process_completions()?;
                }

                break;
            }

            // Process all available completions (non-blocking, drains CQ)
            self.process_completions()?;

            // Check shutdown again after processing completions
            // This ensures we don't block in submit_and_wait() after shutdown is requested
            if self.shutdown_requested {
                continue; // Go back to top of loop to execute shutdown logic
            }

            // Replenish receive buffers after processing completions
            self.submit_recv_buffers()?;

            // Submit any pending sends
            if !self.send_queue.is_empty() {
                self.submit_send_batch()?;
            }

            // CRITICAL: Submit all queued work AND wait for at least one completion
            // This is the ONLY place the loop blocks, preventing busy-spinning
            // The submit_and_wait(1) atomically submits SQ and waits for 1 CQE
            match self.ring.submit_and_wait(1) {
                Ok(_) => (),                                                 // At least one event ready
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue, // Interrupted
                Err(e) => return Err(e.into()),                              // Real error
            }
        }

        self.print_final_stats();
        Ok(())
    }

    /// Process all available completions
    fn process_completions(&mut self) -> Result<()> {
        let mut completions = Vec::new();
        {
            let mut cq = self.ring.completion();
            for cqe in &mut cq {
                completions.push((cqe.user_data(), cqe.result()));
            }
            // Sync to mark completions as consumed
            cq.sync();
        }

        if !completions.is_empty() && self.stats.packets_received < 5 {
            self.logger.info(
                Facility::DataPlane,
                &format!("Processing {} completions", completions.len()),
            );
        }

        for (user_data, result) in completions {
            match user_data {
                COMMAND_USER_DATA => self.handle_command_completion(result)?,
                SHUTDOWN_USER_DATA => self.handle_shutdown_completion(result)?,
                RECV_BASE..=RECV_MAX => self.handle_recv_completion(user_data, result)?,
                SEND_BASE..=SEND_MAX => self.handle_send_completion(user_data, result)?,
                _ => {
                    self.logger.error(
                        Facility::DataPlane,
                        &format!("Unknown user_data: {}", user_data),
                    );
                }
            }
        }

        Ok(())
    }

    /// Handle command stream completion
    fn handle_command_completion(&mut self, result: i32) -> Result<()> {
        if result > 0 {
            let commands = self
                .cmd_reader
                .process_bytes(&self.cmd_buffer[..result as usize])
                .context("Failed to parse commands")?;

            for command in commands {
                match command {
                    crate::RelayCommand::Shutdown => {
                        self.logger
                            .info(Facility::DataPlane, "Shutdown command received");
                        self.shutdown_requested = true;
                        return Ok(());
                    }
                    crate::RelayCommand::AddRule(rule) => {
                        self.logger.info(
                            Facility::DataPlane,
                            &format!(
                                "Adding rule: input={}:{} outputs={}",
                                rule.input_group,
                                rule.input_port,
                                rule.outputs.len()
                            ),
                        );
                        self.add_rule(rule)?;

                        // Log ruleset hash for drift detection
                        let ruleset_hash = crate::compute_ruleset_hash(self.rules.values());
                        self.logger.info(
                            Facility::DataPlane,
                            &format!(
                                "Ruleset updated: hash={:016x} rule_count={}",
                                ruleset_hash,
                                self.rules.len()
                            ),
                        );
                    }
                    crate::RelayCommand::RemoveRule { rule_id } => {
                        self.logger.info(
                            Facility::DataPlane,
                            &format!("Removing rule: {}", rule_id),
                        );

                        match self.remove_rule(&rule_id) {
                            Ok(()) => {
                                self.logger.info(
                                    Facility::DataPlane,
                                    &format!("Rule removed successfully: {}", rule_id),
                                );

                                // Log ruleset hash for drift detection
                                let ruleset_hash = crate::compute_ruleset_hash(self.rules.values());
                                self.logger.info(
                                    Facility::DataPlane,
                                    &format!(
                                        "Ruleset updated: hash={:016x} rule_count={}",
                                        ruleset_hash,
                                        self.rules.len()
                                    ),
                                );
                            }
                            Err(e) => {
                                self.logger.error(
                                    Facility::DataPlane,
                                    &format!("Failed to remove rule {}: {}", rule_id, e),
                                );
                            }
                        }
                    }
                    _ => {
                        self.logger.debug(
                            Facility::DataPlane,
                            &format!("Ignoring command: {:?}", command),
                        );
                    }
                }
            }

            // Resubmit command read
            self.submit_command_read()?;
        } else if result == 0 {
            self.logger
                .info(Facility::DataPlane, "Command stream closed");
            self.shutdown_requested = true;
        } else {
            self.logger.error(
                Facility::DataPlane,
                &format!("Command read error: errno={}", -result),
            );
        }

        Ok(())
    }

    /// Handle shutdown signal completion
    fn handle_shutdown_completion(&mut self, result: i32) -> Result<()> {
        if result < 0 {
            self.logger.error(
                Facility::DataPlane,
                &format!("Shutdown event error: errno={}", -result),
            );
        }
        self.shutdown_requested = true;
        Ok(())
    }

    /// Handle packet receive completion
    fn handle_recv_completion(&mut self, user_data: u64, result: i32) -> Result<()> {
        let buffer = self
            .in_flight_recvs
            .remove(&user_data)
            .context("Unknown recv user_data")?;

        if result < 0 {
            if self.config.track_stats {
                self.stats.recv_errors += 1;
            }
            // Return buffer to pool (will be resubmitted in main loop) - don't leak the buffer!
            self.recv_buffers.push(buffer);
            return Ok(());
        }

        let bytes_received = result as usize;

        if self.config.track_stats {
            self.stats.packets_received += 1;
            self.stats.bytes_received += bytes_received as u64;
        }

        // Parse packet and lookup rule(s) - returns Vec for fan-out support
        let targets = self.process_received_packet(&buffer[..bytes_received])?;

        if !targets.is_empty() {
            // Extract payload once and wrap in Arc for zero-copy sharing across outputs
            // All targets have the same payload offset/len (from same received packet)
            let payload_start = targets[0].payload_offset;
            let payload_len = targets[0].payload_len;
            let payload: Arc<[u8]> = Arc::from(&buffer[payload_start..payload_start + payload_len]);

            // Increment rules_matched once per matched packet (not per output)
            if self.config.track_stats {
                self.stats.rules_matched += 1;
            }

            // Queue send operation for each target (Arc clone is cheap - just refcount increment)
            for target in targets {
                self.send_queue.push(SendWorkItem {
                    payload: Arc::clone(&payload),
                    dest_addr: target.dest_addr,
                    interface_name: target.interface_name,
                });
            }
        }

        // Return buffer to pool (will be resubmitted in main loop)
        self.recv_buffers.push(buffer);

        Ok(())
    }

    /// Handle packet send completion
    fn handle_send_completion(&mut self, user_data: u64, result: i32) -> Result<()> {
        let _buffer = self
            .in_flight_sends
            .remove(&user_data)
            .context("Unknown send user_data")?;

        if result < 0 {
            if self.config.track_stats {
                self.stats.send_errors += 1;
            }
            if self.stats.send_errors % 100 == 1 {
                self.logger.error(
                    Facility::DataPlane,
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

            // Periodic stats
            if self.stats.packets_sent.is_multiple_of(10000) {
                self.logger.info(
                    Facility::DataPlane,
                    &format!(
                        "[STATS] rx={} tx={} matched={} not_matched={} rx_err={} tx_err={}",
                        self.stats.packets_received,
                        self.stats.packets_sent,
                        self.stats.rules_matched,
                        self.stats.rules_not_matched,
                        self.stats.recv_errors,
                        self.stats.send_errors
                    ),
                );
            }
        }

        // Buffer automatically returned to pool by Drop
        Ok(())
    }

    /// Process a received packet and determine where to forward it
    /// Returns a vector of forwarding targets (supports fan-out to multiple destinations)
    fn process_received_packet(&mut self, packet_data: &[u8]) -> Result<Vec<ForwardingTarget>> {
        // Parse packet headers (Ethernet → IPv4 → UDP)
        let headers = match parse_packet(packet_data, false) {
            Ok(h) => h,
            Err(_) => {
                // Not a valid UDP packet (could be ARP, IPv6, TCP, etc.)
                if self.config.track_stats {
                    self.stats.packets_filtered += 1;
                }
                return Ok(Vec::new());
            }
        };

        // Lookup forwarding rule based on (multicast_group, port)
        let key = (headers.ipv4.dst_ip, headers.udp.dst_port);
        let rule = match self.rules.get(&key) {
            Some(r) => r,
            None => {
                // No matching rule
                if self.config.track_stats {
                    self.stats.rules_not_matched += 1;
                }
                return Ok(Vec::new());
            }
        };

        // Check if rule has any outputs
        if rule.outputs.is_empty() {
            return Ok(Vec::new());
        }

        // Create forwarding targets for ALL outputs (fan-out support)
        let targets: Vec<ForwardingTarget> = rule
            .outputs
            .iter()
            .map(|output| ForwardingTarget {
                payload_offset: headers.payload_offset,
                payload_len: headers.payload_len,
                dest_addr: SocketAddr::new(output.group.into(), output.port),
                interface_name: output.interface.clone(),
            })
            .collect();

        Ok(targets)
    }

    /// Submit receive buffers to io_uring
    fn submit_recv_buffers(&mut self) -> Result<usize> {
        // Acquire buffers to reach target, accounting for what's already available to submit
        while self.recv_buffers.len() < self.config.num_recv_buffers - self.in_flight_recvs.len() {
            match self.buffer_pool.acquire(BufferSize::Small) {
                Some(buffer) => {
                    self.recv_buffers.push(buffer);
                }
                None => {
                    // Buffer pool exhausted - log it and continue with what we have
                    self.stats.buffer_pool_exhaustion += 1;
                    let pool_available = self.buffer_pool.available(BufferSize::Small);
                    self.logger.warning(
                        Facility::DataPlane,
                        &format!(
                            "Buffer pool exhausted: have {} recv buffers, wanted {}, pool_avail={}, in_flight_recvs={}, in_flight_sends={}",
                            self.recv_buffers.len(),
                            self.config.num_recv_buffers,
                            pool_available,
                            self.in_flight_recvs.len(),
                            self.in_flight_sends.len()
                        ),
                    );
                    break;
                }
            }
        }

        // Check available space in submission queue
        let sq = self.ring.submission();
        let sq_available = sq.capacity() - sq.len();
        drop(sq); // Release borrow before loop

        // Only submit as many as we have space for
        let to_submit = self.recv_buffers.len().min(sq_available);

        for _ in 0..to_submit {
            let mut buffer = match self.recv_buffers.pop() {
                Some(b) => b,
                None => break,
            };

            let user_data = self.next_recv_user_data;
            self.next_recv_user_data += 1;
            if self.next_recv_user_data > RECV_MAX {
                self.next_recv_user_data = RECV_BASE;
            }

            let recv_op = opcode::Recv::new(
                types::Fd(self.recv_socket.as_raw_fd()),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
            .build()
            .user_data(user_data);

            unsafe {
                self.ring.submission().push(&recv_op)?;
            }

            self.in_flight_recvs.insert(user_data, buffer);
        }

        Ok(to_submit)
    }

    /// Submit a batch of send operations
    fn submit_send_batch(&mut self) -> Result<()> {
        // Check available space in submission queue
        let sq = self.ring.submission();
        let sq_available = sq.capacity() - sq.len();
        drop(sq); // Release borrow before loop

        // Limit batch size to available space
        let batch_size = self
            .send_queue
            .len()
            .min(self.config.send_batch_size)
            .min(sq_available);

        for _ in 0..batch_size {
            let item = self.send_queue.remove(0);

            // Get or create egress socket
            let key = (item.interface_name.clone(), item.dest_addr);
            if !self.egress_sockets.contains_key(&key) {
                let source_ip = get_interface_ip(&item.interface_name)?;
                let socket = create_connected_udp_socket(source_ip, item.dest_addr)?;
                self.egress_sockets.insert(key.clone(), (socket, source_ip));
            }

            let (socket_fd, _) = self.egress_sockets.get(&key).unwrap();

            let user_data = self.next_send_user_data;
            self.next_send_user_data += 1;
            if self.next_send_user_data > SEND_MAX {
                self.next_send_user_data = SEND_BASE;
            }

            let send_op = opcode::Send::new(
                types::Fd(socket_fd.as_raw_fd()),
                item.payload.as_ptr(),
                item.payload.len() as u32,
            )
            .build()
            .user_data(user_data);

            unsafe {
                self.ring.submission().push(&send_op)?;
            }

            self.in_flight_sends.insert(user_data, item.payload);
        }

        self.ring.submit()?;
        Ok(())
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

    fn print_final_stats(&self) {
        // Log in format expected by test framework:
        // [STATS:Ingress FINAL] total: recv=X matched=X egr_sent=X filtered=X no_match=X buf_exhaust=X
        self.logger.info(
            Facility::DataPlane,
            &format!(
                "[STATS:Ingress FINAL] total: recv={} matched={} egr_sent={} filtered={} no_match={} buf_exhaust={}",
                self.stats.packets_received,
                self.stats.rules_matched,
                self.stats.packets_sent,  // egr_sent = what was queued to egress
                self.stats.packets_filtered,
                self.stats.rules_not_matched,
                self.stats.buffer_pool_exhaustion
            ),
        );
        // Log egress stats (in unified mode, egr_sent == ch_recv since there's no channel)
        // [STATS:Egress FINAL] total: sent=X submitted=X ch_recv=X errors=X bytes=X
        self.logger.info(
            Facility::DataPlane,
            &format!(
                "[STATS:Egress FINAL] total: sent={} submitted={} ch_recv={} errors={} bytes={}",
                self.stats.packets_sent, // Actual sends completed
                self.stats.packets_sent, // Same as sent (all submissions succeeded)
                self.stats.packets_sent, // In unified mode, egr_sent == ch_recv
                self.stats.send_errors,
                self.stats.bytes_sent
            ),
        );
    }
}

// Helper functions

fn get_interface_index(interface_name: &str) -> Result<i32> {
    for iface in pnet::datalink::interfaces() {
        if iface.name == interface_name {
            return Ok(iface.index as i32);
        }
    }
    Err(anyhow::anyhow!("Interface not found: {}", interface_name))
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

fn create_connected_udp_socket(source_ip: Ipv4Addr, dest_addr: SocketAddr) -> Result<OwnedFd> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    // Tune socket send buffer for high throughput (300k+ pps)
    // Default kernel buffer (~208 KB) is too small for sustained high-rate transmission
    // Set to 4 MB to buffer ~9ms worth of packets at 430 MB/s (307k pps × 1400 bytes)
    let send_buffer_size = std::env::var("MCR_SOCKET_SNDBUF")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4 * 1024 * 1024); // Default 4 MB

    socket
        .set_send_buffer_size(send_buffer_size)
        .context("Failed to set SO_SNDBUF")?;

    socket.bind(&SocketAddr::new(source_ip.into(), 0).into())?;
    socket.connect(&dest_addr.into())?;
    Ok(socket.into())
}
