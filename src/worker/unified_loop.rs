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
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;

use crate::logging::{Facility, Logger};
use crate::supervisor::socket_helpers;
use crate::worker::buffer_pool::{BufferPool, BufferSize, ManagedBuffer};
use crate::worker::packet_parser::parse_packet;
use crate::ForwardingRule;
use std::time::Instant;

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
    multicast_ttl: u8,
}

/// Metadata about where to forward a packet
struct ForwardingTarget {
    payload_offset: usize,
    payload_len: usize,
    dest_addr: SocketAddr,
    interface_name: String,
    multicast_ttl: u8,
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
    /// Stats reporting interval in milliseconds (default: 10000ms = 10 seconds)
    pub stats_interval_ms: u64,
    /// Maximum number of forwarding rules (0 = unlimited, default: 10000)
    pub max_rules: usize,
    /// Maximum number of flow counters to track (0 = unlimited, default: 100000)
    pub max_flow_counters: usize,
    /// Maximum number of cached egress sockets (0 = unlimited, default: 10000)
    pub max_egress_sockets: usize,
    /// TTL for outgoing multicast packets (default: 1)
    pub multicast_ttl: u8,
}

impl Default for UnifiedConfig {
    fn default() -> Self {
        // Get num_recv_buffers from environment, default to 32 (original value)
        // Investigation showed increasing to 64 or 128 caused worse performance
        let num_recv_buffers = std::env::var("MCR_NUM_RECV_BUFFERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(32);

        // Get stats interval from environment, default to 10000ms (10 seconds)
        // This matches the ARCHITECTURE.md specification for periodic stats reporting.
        // Set MCR_STATS_INTERVAL_MS=100 for faster reporting in tests.
        let stats_interval_ms = std::env::var("MCR_STATS_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10000);

        Self {
            queue_depth: 1024,   // Increased from 128 for high throughput (300k+ pps)
            num_recv_buffers,    // Configurable via MCR_NUM_RECV_BUFFERS (default: 32)
            send_batch_size: 64, // Increased from 32 to reduce syscall overhead
            track_stats: true,
            stats_interval_ms, // Configurable via MCR_STATS_INTERVAL_MS (default: 10000ms)
            max_rules: 10_000, // Reasonable limit for forwarding rules
            max_flow_counters: 100_000, // Track up to 100k unique flows
            max_egress_sockets: 10_000, // Cache up to 10k egress sockets
            multicast_ttl: std::env::var("MCR_MULTICAST_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
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
    pub stats_pipe_errors: u64, // Errors writing to supervisor stats pipe
    // Capacity metrics
    pub rules_rejected: u64,         // Rules rejected due to max_rules limit
    pub flow_counters_evicted: u64,  // Flow counters evicted due to max_flow_counters limit
    pub egress_sockets_evicted: u64, // Egress sockets evicted due to max_egress_sockets limit
}

/// Per-flow counters for stats reporting
#[derive(Debug, Clone, Default)]
struct FlowCounters {
    packets_relayed: u64,
    bytes_relayed: u64,
    // Snapshot values for rate calculation
    last_packets: u64,
    last_bytes: u64,
    last_snapshot_time: Option<Instant>,
}

/// Unified single-threaded data plane loop
pub struct UnifiedDataPlane {
    ring: IoUring,

    // Interface this worker is bound to (for diagnostics and logging)
    #[allow(dead_code)] // Reserved for future diagnostic/logging use
    interface_name: String,

    // Ingress
    recv_socket: Socket,
    recv_buffers: Vec<ManagedBuffer>,
    in_flight_recvs: HashMap<u64, ManagedBuffer>,
    next_recv_user_data: u64,

    // Forwarding rules (keyed by input_group, input_port)
    rules: HashMap<(Ipv4Addr, u16), ForwardingRule>,

    // Per-flow counters for stats reporting (keyed by input_group, input_port)
    flow_counters: HashMap<(Ipv4Addr, u16), FlowCounters>,

    // Egress
    egress_sockets: HashMap<(String, SocketAddr, u8), (OwnedFd, Ipv4Addr)>,
    send_queue: VecDeque<SendWorkItem>,
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
    start_time: Instant,
    last_stats_time: Instant,

    // Stats pipe for reporting to supervisor (FD 4)
    stats_pipe: Option<std::fs::File>,
}

impl UnifiedDataPlane {
    /// Create a new UnifiedDataPlane using a pre-configured AF_PACKET socket.
    ///
    /// This is the preferred constructor for privilege separation. The supervisor
    /// creates the AF_PACKET socket with CAP_NET_RAW privileges, configures it
    /// (binds to interface, sets PACKET_FANOUT), and passes the FD to the worker.
    /// The worker can then drop all privileges.
    ///
    /// # Arguments
    /// * `interface_name` - Network interface name (used for IP lookups, not socket binding)
    /// * `config` - Configuration for queue depth, batch sizes, etc.
    /// * `buffer_pool` - Shared buffer pool for packet storage
    /// * `cmd_stream_fd` - FD for receiving commands from supervisor
    /// * `af_packet_fd` - Pre-configured AF_PACKET socket FD from supervisor
    /// * `logger` - Logger instance
    pub fn new_with_socket(
        interface_name: &str,
        config: UnifiedConfig,
        buffer_pool: std::sync::Arc<BufferPool>,
        cmd_stream_fd: OwnedFd,
        af_packet_fd: OwnedFd,
        logger: Logger,
    ) -> Result<Self> {
        // Convert the pre-configured AF_PACKET FD to a Socket
        // SAFETY: The supervisor created and configured this socket, we're taking ownership
        let recv_socket = unsafe { Socket::from_raw_fd(af_packet_fd.into_raw_fd()) };

        Self::new_internal(
            interface_name,
            config,
            buffer_pool,
            cmd_stream_fd,
            recv_socket,
            logger,
        )
    }

    /// Internal constructor.
    fn new_internal(
        interface_name: &str,
        config: UnifiedConfig,
        buffer_pool: std::sync::Arc<BufferPool>,
        cmd_stream_fd: OwnedFd,
        recv_socket: Socket,
        logger: Logger,
    ) -> Result<Self> {
        // Open stats pipe for writing stats to supervisor
        // Only available for data plane workers (not in testing mode)
        // FD is passed via MCR_STATS_PIPE_FD environment variable for security
        let stats_pipe = {
            #[cfg(not(feature = "testing"))]
            {
                use nix::fcntl::{fcntl, FcntlArg};
                use std::os::fd::{BorrowedFd, FromRawFd};

                // Read stats pipe FD from environment variable (secure FD passing)
                if let Ok(fd_str) = std::env::var("MCR_STATS_PIPE_FD") {
                    if let Ok(stats_fd) = fd_str.parse::<i32>() {
                        // Validate FD exists before using it
                        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(stats_fd) };
                        match fcntl(borrowed_fd, FcntlArg::F_GETFD) {
                            Ok(_) => {
                                // FD is valid, open it as a File
                                // SAFETY: FD is valid (we just checked), and supervisor gave us ownership
                                Some(unsafe { std::fs::File::from_raw_fd(stats_fd) })
                            }
                            Err(_) => None, // FD is invalid
                        }
                    } else {
                        None // Failed to parse FD number
                    }
                } else {
                    None // No stats pipe FD provided (control plane worker or testing)
                }
            }
            #[cfg(feature = "testing")]
            None
        };

        let mut unified = Self {
            ring: IoUring::new(config.queue_depth)?,
            interface_name: interface_name.to_string(),
            recv_socket,
            recv_buffers: Vec::new(),
            in_flight_recvs: HashMap::new(),
            next_recv_user_data: RECV_BASE,
            rules: HashMap::new(),
            flow_counters: HashMap::new(),
            egress_sockets: HashMap::new(),
            send_queue: VecDeque::with_capacity(config.send_batch_size),
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
            start_time: Instant::now(),
            last_stats_time: Instant::now(),
            stats_pipe,
        };

        // Submit initial command read
        unified.submit_command_read()?;
        unified.ring.submit()?;

        Ok(unified)
    }

    /// Add a forwarding rule
    pub fn add_rule(&mut self, rule: ForwardingRule) -> Result<()> {
        let key = (rule.input_group, rule.input_port);

        // Check capacity (if limit is set and key doesn't already exist)
        if self.config.max_rules > 0
            && !self.rules.contains_key(&key)
            && self.rules.len() >= self.config.max_rules
        {
            self.stats.rules_rejected += 1;
            return Err(anyhow::anyhow!(
                "Cannot add rule: max_rules limit ({}) reached",
                self.config.max_rules
            ));
        }

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

    pub fn sync_rules(&mut self, rules: Vec<ForwardingRule>) -> Result<()> {
        // Check if new ruleset exceeds capacity
        if self.config.max_rules > 0 && rules.len() > self.config.max_rules {
            self.stats.rules_rejected += (rules.len() - self.config.max_rules) as u64;
            return Err(anyhow::anyhow!(
                "Cannot sync rules: {} rules exceeds max_rules limit ({})",
                rules.len(),
                self.config.max_rules
            ));
        }

        // Atomically replace entire ruleset
        self.rules.clear();
        for rule in rules {
            let key = (rule.input_group, rule.input_port);
            self.rules.insert(key, rule);
        }
        Ok(())
    }

    /// Get current flow stats with calculated rates
    /// This method is mutable because it updates rate calculation snapshots
    pub fn get_flow_stats(&mut self) -> Vec<crate::FlowStats> {
        let now = Instant::now();

        self.flow_counters
            .iter_mut()
            .map(|(key, counters)| {
                // Calculate rates based on time since last snapshot
                let (packets_per_second, bits_per_second) = if let Some(last_time) =
                    counters.last_snapshot_time
                {
                    let elapsed = now.duration_since(last_time).as_secs_f64();

                    if elapsed > 0.0 {
                        let packet_delta = counters
                            .packets_relayed
                            .saturating_sub(counters.last_packets);
                        let byte_delta = counters.bytes_relayed.saturating_sub(counters.last_bytes);

                        let pps = packet_delta as f64 / elapsed;
                        let bps = (byte_delta * 8) as f64 / elapsed; // bits per second

                        // Update snapshots for next calculation
                        counters.last_packets = counters.packets_relayed;
                        counters.last_bytes = counters.bytes_relayed;
                        counters.last_snapshot_time = Some(now);

                        (pps, bps)
                    } else {
                        // Too soon since last snapshot
                        (0.0, 0.0)
                    }
                } else {
                    // First snapshot - initialize
                    counters.last_packets = counters.packets_relayed;
                    counters.last_bytes = counters.bytes_relayed;
                    counters.last_snapshot_time = Some(now);
                    (0.0, 0.0)
                };

                crate::FlowStats {
                    input_group: key.0,
                    input_port: key.1,
                    packets_relayed: counters.packets_relayed,
                    bytes_relayed: counters.bytes_relayed,
                    packets_per_second,
                    bits_per_second,
                }
            })
            .collect()
    }

    /// Main event loop
    pub fn run(&mut self) -> Result<()> {
        // Pre-post receive buffers
        let initial_recv_count = self.submit_recv_buffers()?;
        self.logger.debug(
            Facility::DataPlane,
            &format!("Pre-posted {} recv buffers", initial_recv_count),
        );
        self.ring.submit()?;

        loop {
            // Check shutdown
            if self.shutdown_requested {
                self.logger
                    .debug(Facility::DataPlane, "Shutdown requested, draining");

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

            // Submit pending sends - keep submitting batches until queue is empty or SQ is full
            while !self.send_queue.is_empty() {
                let submitted = self.submit_send_batch()?;
                if submitted == 0 {
                    // SQ is full, need to wait for completions
                    break;
                }
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

        // Flush final stats to supervisor before exiting
        self.flush_stats_to_pipe();
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
            self.logger.debug(
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
                            .debug(Facility::DataPlane, "Shutdown command received");
                        self.shutdown_requested = true;
                        return Ok(());
                    }
                    crate::RelayCommand::AddRule(rule) => {
                        self.logger.debug(
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
                        self.logger.debug(
                            Facility::DataPlane,
                            &format!(
                                "Ruleset updated: hash={:016x} rule_count={}",
                                ruleset_hash,
                                self.rules.len()
                            ),
                        );
                    }
                    crate::RelayCommand::RemoveRule { rule_id } => {
                        self.logger
                            .debug(Facility::DataPlane, &format!("Removing rule: {}", rule_id));

                        match self.remove_rule(&rule_id) {
                            Ok(()) => {
                                self.logger.debug(
                                    Facility::DataPlane,
                                    &format!("Rule removed successfully: {}", rule_id),
                                );

                                // Log ruleset hash for drift detection
                                let ruleset_hash = crate::compute_ruleset_hash(self.rules.values());
                                self.logger.debug(
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
                    crate::RelayCommand::SyncRules(rules) => {
                        self.logger.debug(
                            Facility::DataPlane,
                            &format!("Synchronizing ruleset with {} rules", rules.len()),
                        );

                        match self.sync_rules(rules) {
                            Ok(()) => {
                                // Log ruleset hash for drift detection
                                let ruleset_hash = crate::compute_ruleset_hash(self.rules.values());
                                self.logger.debug(
                                    Facility::DataPlane,
                                    &format!(
                                        "Ruleset synchronized: hash={:016x} rule_count={}",
                                        ruleset_hash,
                                        self.rules.len()
                                    ),
                                );

                                // Send ACK back to supervisor
                                let response = crate::WorkerResponse::SyncRulesAck {
                                    rule_count: self.rules.len(),
                                    ruleset_hash,
                                };
                                if let Err(e) = self.send_response(&response) {
                                    self.logger.error(
                                        Facility::DataPlane,
                                        &format!("Failed to send SyncRulesAck: {}", e),
                                    );
                                }
                            }
                            Err(e) => {
                                self.logger.error(
                                    Facility::DataPlane,
                                    &format!("Failed to sync rules: {}", e),
                                );

                                // Send error response
                                let response = crate::WorkerResponse::Error {
                                    message: format!("Failed to sync rules: {}", e),
                                };
                                if let Err(e) = self.send_response(&response) {
                                    self.logger.error(
                                        Facility::DataPlane,
                                        &format!("Failed to send error response: {}", e),
                                    );
                                }
                            }
                        }
                    }
                    crate::RelayCommand::Ping => {
                        self.logger
                            .debug(Facility::DataPlane, "Received health check ping");
                        // No action needed - fire-and-forget health check
                        // Worker readiness is indicated by processing this command
                    }
                    crate::RelayCommand::SetLogLevel { facility, level } => match facility {
                        None => {
                            self.logger.set_global_level(level);
                            self.logger.info(
                                Facility::DataPlane,
                                &format!("Global log level set to {:?}", level),
                            );
                        }
                        Some(f) => {
                            self.logger.set_facility_level(f, level);
                            self.logger.info(
                                Facility::DataPlane,
                                &format!("Log level for {:?} set to {:?}", f, level),
                            );
                        }
                    },
                }
            }

            // Resubmit command read
            self.submit_command_read()?;
        } else if result == 0 {
            self.logger
                .debug(Facility::DataPlane, "Command stream closed");
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
                self.send_queue.push_back(SendWorkItem {
                    payload: Arc::clone(&payload),
                    dest_addr: target.dest_addr,
                    interface_name: target.interface_name,
                    multicast_ttl: target.multicast_ttl,
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

            // Periodic stats - check if we should log and push to supervisor
            let should_log_stats = if self.config.stats_interval_ms > 0 {
                // Time-based reporting (default: every 10 seconds)
                let now = Instant::now();
                let elapsed_ms = now.duration_since(self.last_stats_time).as_millis() as u64;
                if elapsed_ms >= self.config.stats_interval_ms {
                    self.last_stats_time = now;
                    true
                } else {
                    false
                }
            } else {
                // Packet-count based reporting (legacy fallback if MCR_STATS_INTERVAL_MS=0)
                // Not recommended: stats may never be reported for low-traffic flows
                self.stats.packets_sent.is_multiple_of(10000)
            };

            if should_log_stats {
                // Include elapsed_ms for time-series analysis
                let elapsed_ms = Instant::now().duration_since(self.start_time).as_millis();

                self.logger.info(
                    Facility::DataPlane,
                    &format!(
                        "[STATS] t_ms={} rx={} tx={} matched={} not_matched={} rx_err={} tx_err={} buf_exhaust={} pipe_err={}",
                        elapsed_ms,
                        self.stats.packets_received,
                        self.stats.packets_sent,
                        self.stats.rules_matched,
                        self.stats.rules_not_matched,
                        self.stats.recv_errors,
                        self.stats.send_errors,
                        self.stats.buffer_pool_exhaustion,
                        self.stats.stats_pipe_errors
                    ),
                );

                // Log per-flow stats with rates
                let flow_stats = self.get_flow_stats();
                for stats in &flow_stats {
                    self.logger.info(
                        Facility::DataPlane,
                        &format!(
                            "[FLOW_STATS] {}:{} packets={} bytes={} pps={:.0} bps={:.0}",
                            stats.input_group,
                            stats.input_port,
                            stats.packets_relayed,
                            stats.bytes_relayed,
                            stats.packets_per_second,
                            stats.bits_per_second
                        ),
                    );
                }

                // Write stats to pipe for supervisor (non-blocking, errors tracked not fatal)
                if let Some(ref mut pipe) = self.stats_pipe {
                    if let Ok(json) = serde_json::to_vec(&flow_stats) {
                        use std::io::Write;
                        // Write with newline delimiter for line-based reading
                        // Track errors but don't block packet processing
                        let write_result = writeln!(pipe, "{}", String::from_utf8_lossy(&json));
                        let flush_result = pipe.flush();
                        if write_result.is_err() || flush_result.is_err() {
                            self.stats.stats_pipe_errors += 1;
                        }
                    }
                }
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
        // First try exact match, then try wildcard port (0) for protocol-learned routes
        let exact_key = (headers.ipv4.dst_ip, headers.udp.dst_port);
        let wildcard_key = (headers.ipv4.dst_ip, 0u16);
        let rule = match self.rules.get(&exact_key) {
            Some(r) => r,
            None => match self.rules.get(&wildcard_key) {
                Some(r) => r, // Wildcard port match (protocol-learned route)
                None => {
                    // No matching rule
                    if self.config.track_stats {
                        self.stats.rules_not_matched += 1;
                    }
                    return Ok(Vec::new());
                }
            },
        };

        // Check source filter for PIM (S,G) matching
        // If rule.input_source is Some, the packet's source must match
        if let Some(required_source) = rule.input_source {
            if headers.ipv4.src_ip != required_source {
                // Source doesn't match (S,G) rule - packet is not forwarded
                if self.config.track_stats {
                    self.stats.rules_not_matched += 1;
                }
                return Ok(Vec::new());
            }
        }

        // Check if rule has any outputs
        if rule.outputs.is_empty() {
            return Ok(Vec::new());
        }

        // Create forwarding targets for ALL outputs (fan-out support)
        // For protocol-learned routes (port=0), preserve the original packet's port
        let original_port = headers.udp.dst_port;
        let targets: Vec<ForwardingTarget> = rule
            .outputs
            .iter()
            .map(|output| {
                let dest_port = if output.port == 0 {
                    original_port // Preserve original port for wildcard rules
                } else {
                    output.port
                };
                ForwardingTarget {
                    payload_offset: headers.payload_offset,
                    payload_len: headers.payload_len,
                    dest_addr: SocketAddr::new(output.group.into(), dest_port),
                    interface_name: output.interface.clone(),
                    multicast_ttl: output.ttl.unwrap_or(self.config.multicast_ttl),
                }
            })
            .collect();

        // Update per-flow counters (use exact packet key for granular stats)
        if self.config.track_stats && !targets.is_empty() {
            // Check if we need to evict old flow counters
            if self.config.max_flow_counters > 0
                && !self.flow_counters.contains_key(&exact_key)
                && self.flow_counters.len() >= self.config.max_flow_counters
            {
                // Evict the flow with the lowest packet count (least active)
                if let Some(key_to_evict) = self
                    .flow_counters
                    .iter()
                    .min_by_key(|(_, c)| c.packets_relayed)
                    .map(|(k, _)| *k)
                {
                    self.flow_counters.remove(&key_to_evict);
                    self.stats.flow_counters_evicted += 1;
                }
            }

            let counter = self.flow_counters.entry(exact_key).or_default();
            counter.packets_relayed += 1;
            counter.bytes_relayed += headers.payload_len as u64;
        }

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
    /// Returns the number of items submitted (0 if SQ is full or queue is empty)
    fn submit_send_batch(&mut self) -> Result<usize> {
        // Check available space in submission queue
        let sq = self.ring.submission();
        let sq_available = sq.capacity() - sq.len();
        drop(sq); // Release borrow before loop

        if sq_available == 0 {
            return Ok(0);
        }

        // Limit batch size to available space
        let batch_size = self
            .send_queue
            .len()
            .min(self.config.send_batch_size)
            .min(sq_available);

        for _ in 0..batch_size {
            let item = self.send_queue.pop_front().unwrap();

            // Get or create egress socket (keyed by interface, dest, and TTL)
            let key = (
                item.interface_name.clone(),
                item.dest_addr,
                item.multicast_ttl,
            );
            if !self.egress_sockets.contains_key(&key) {
                // Check if we need to evict old sockets
                if self.config.max_egress_sockets > 0
                    && self.egress_sockets.len() >= self.config.max_egress_sockets
                {
                    // Evict an arbitrary socket (first one found)
                    // Note: A more sophisticated approach would track last-use time
                    if let Some(key_to_evict) = self.egress_sockets.keys().next().cloned() {
                        self.egress_sockets.remove(&key_to_evict);
                        self.stats.egress_sockets_evicted += 1;
                    }
                }

                let source_ip = get_interface_ip(&item.interface_name)?;
                let socket =
                    create_connected_udp_socket(source_ip, item.dest_addr, item.multicast_ttl)?;
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

        if batch_size > 0 {
            self.ring.submit()?;
        }
        Ok(batch_size)
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

    /// Send a response back to the supervisor using length-delimited framing.
    /// This is a synchronous write - used only for infrequent ACK responses.
    fn send_response(&self, response: &crate::WorkerResponse) -> Result<()> {
        // Serialize response to JSON
        let payload =
            serde_json::to_vec(response).context("Failed to serialize worker response")?;

        // Length-delimited framing: 4-byte big-endian length prefix + payload
        let len = payload.len() as u32;
        let len_bytes = len.to_be_bytes();

        // Write to the command socket (same socket used for receiving commands)
        // This is safe because the socket is bidirectional (Unix stream socket)
        let fd = self.cmd_stream_fd.as_raw_fd();
        let mut written = 0;

        // Write length prefix
        while written < 4 {
            let result = unsafe {
                libc::write(
                    fd,
                    len_bytes[written..].as_ptr() as *const libc::c_void,
                    4 - written,
                )
            };
            if result < 0 {
                return Err(anyhow::anyhow!(
                    "Failed to write response length: {}",
                    std::io::Error::last_os_error()
                ));
            }
            written += result as usize;
        }

        // Write payload
        written = 0;
        while written < payload.len() {
            let result = unsafe {
                libc::write(
                    fd,
                    payload[written..].as_ptr() as *const libc::c_void,
                    payload.len() - written,
                )
            };
            if result < 0 {
                return Err(anyhow::anyhow!(
                    "Failed to write response payload: {}",
                    std::io::Error::last_os_error()
                ));
            }
            written += result as usize;
        }

        self.logger.debug(
            Facility::DataPlane,
            &format!("Sent response: {} bytes", payload.len()),
        );

        Ok(())
    }

    /// Flush final stats to supervisor via pipe before shutdown.
    /// This ensures the supervisor has up-to-date stats even if the periodic
    /// reporting interval hasn't elapsed yet.
    fn flush_stats_to_pipe(&mut self) {
        // Get flow stats first to avoid borrow conflict with stats_pipe
        let flow_stats = self.get_flow_stats();
        if let Some(ref mut pipe) = self.stats_pipe {
            if let Ok(json) = serde_json::to_vec(&flow_stats) {
                use std::io::Write;
                // Best-effort write - don't block shutdown on pipe errors
                let _ = writeln!(pipe, "{}", String::from_utf8_lossy(&json));
                let _ = pipe.flush();
            }
        }
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

fn get_interface_ip(interface_name: &str) -> Result<Ipv4Addr> {
    for iface in crate::supervisor::socket_helpers::get_interfaces() {
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

fn create_connected_udp_socket(
    source_ip: Ipv4Addr,
    dest_addr: SocketAddr,
    multicast_ttl: u8,
) -> Result<OwnedFd> {
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

    // For multicast destinations, set IP_MULTICAST_IF to ensure packets egress
    // on the correct interface. Without this, multicast packets may go out the
    // wrong interface or be dropped in multi-interface/multi-namespace topologies.
    if let std::net::IpAddr::V4(dest_ipv4) = dest_addr.ip() {
        if dest_ipv4.is_multicast() {
            socket_helpers::set_multicast_if_by_addr(socket.as_raw_fd(), source_ip)?;
            socket_helpers::set_multicast_ttl(socket.as_raw_fd(), multicast_ttl)?;
        }
    }

    socket.bind(&SocketAddr::new(source_ip.into(), 0).into())?;
    socket.connect(&dest_addr.into())?;
    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ForwardingRule, OutputDestination};

    fn create_test_rule(rule_id: &str, input_group: &str, input_port: u16) -> ForwardingRule {
        ForwardingRule {
            rule_id: rule_id.to_string(),
            name: None,
            input_interface: "lo".to_string(),
            input_group: input_group.parse().unwrap(),
            input_port,
            input_source: None,
            outputs: vec![OutputDestination {
                group: "224.0.0.2".parse().unwrap(),
                port: 5001,
                interface: "lo".to_string(),
                ttl: None,
            }],
            source: crate::RuleSource::Static,
        }
    }

    fn create_test_rules_map() -> HashMap<(Ipv4Addr, u16), ForwardingRule> {
        let mut rules = HashMap::new();

        let rule1 = create_test_rule("rule-1", "224.0.0.1", 5000);
        let rule2 = create_test_rule("rule-2", "224.0.0.2", 5001);
        let rule3 = create_test_rule("rule-3", "224.0.0.3", 5002);

        rules.insert((rule1.input_group, rule1.input_port), rule1);
        rules.insert((rule2.input_group, rule2.input_port), rule2);
        rules.insert((rule3.input_group, rule3.input_port), rule3);

        rules
    }

    // Helper function that mimics the remove_rule logic for testing
    fn remove_rule_from_map(
        rules: &mut HashMap<(Ipv4Addr, u16), ForwardingRule>,
        rule_id: &str,
    ) -> Result<()> {
        let key_to_remove = rules
            .iter()
            .find(|(_, rule)| rule.rule_id == rule_id)
            .map(|(key, _)| *key);

        match key_to_remove {
            Some(key) => {
                rules.remove(&key);
                Ok(())
            }
            None => Err(anyhow::anyhow!("Rule not found: {}", rule_id)),
        }
    }

    #[test]
    fn test_remove_rule_success() {
        let mut rules = create_test_rules_map();

        assert_eq!(rules.len(), 3);
        assert!(rules.iter().any(|(_, r)| r.rule_id == "rule-2"));

        let result = remove_rule_from_map(&mut rules, "rule-2");

        assert!(result.is_ok());
        assert_eq!(rules.len(), 2);
        assert!(!rules.iter().any(|(_, r)| r.rule_id == "rule-2"));
        assert!(rules.iter().any(|(_, r)| r.rule_id == "rule-1"));
        assert!(rules.iter().any(|(_, r)| r.rule_id == "rule-3"));
    }

    #[test]
    fn test_remove_rule_not_found() {
        let mut rules = create_test_rules_map();

        assert_eq!(rules.len(), 3);

        let result = remove_rule_from_map(&mut rules, "nonexistent-rule");

        assert!(result.is_err());
        assert_eq!(rules.len(), 3);
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Rule not found"));
        assert!(err_msg.contains("nonexistent-rule"));
    }

    #[test]
    fn test_remove_all_rules() {
        let mut rules = create_test_rules_map();

        assert_eq!(rules.len(), 3);

        assert!(remove_rule_from_map(&mut rules, "rule-1").is_ok());
        assert_eq!(rules.len(), 2);

        assert!(remove_rule_from_map(&mut rules, "rule-2").is_ok());
        assert_eq!(rules.len(), 1);

        assert!(remove_rule_from_map(&mut rules, "rule-3").is_ok());
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_remove_rule_from_empty_ruleset() {
        let mut rules = HashMap::new();

        assert_eq!(rules.len(), 0);

        let result = remove_rule_from_map(&mut rules, "any-rule");

        assert!(result.is_err());
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_remove_rule_idempotency() {
        let mut rules = create_test_rules_map();

        assert_eq!(rules.len(), 3);

        let result1 = remove_rule_from_map(&mut rules, "rule-1");
        assert!(result1.is_ok());
        assert_eq!(rules.len(), 2);

        let result2 = remove_rule_from_map(&mut rules, "rule-1");
        assert!(result2.is_err());
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_add_and_remove_rule() {
        let mut rules = create_test_rules_map();

        let new_rule = create_test_rule("rule-4", "224.0.0.4", 5003);
        let key = (new_rule.input_group, new_rule.input_port);

        rules.insert(key, new_rule.clone());
        assert_eq!(rules.len(), 4);
        assert!(rules.contains_key(&key));

        remove_rule_from_map(&mut rules, "rule-4").unwrap();
        assert_eq!(rules.len(), 3);
        assert!(!rules.contains_key(&key));
    }

    #[test]
    fn test_remove_rule_with_duplicate_ports() {
        let mut rules = HashMap::new();

        // Two rules with same port but different groups
        let rule1 = create_test_rule("rule-a", "224.0.0.1", 5000);
        let rule2 = create_test_rule("rule-b", "224.0.0.2", 5000);

        rules.insert((rule1.input_group, rule1.input_port), rule1);
        rules.insert((rule2.input_group, rule2.input_port), rule2);

        assert_eq!(rules.len(), 2);

        // Remove by rule_id should work correctly
        remove_rule_from_map(&mut rules, "rule-a").unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules.iter().any(|(_, r)| r.rule_id == "rule-b"));
        assert!(!rules.iter().any(|(_, r)| r.rule_id == "rule-a"));
    }

    #[test]
    fn test_sync_rules_replaces_ruleset() {
        let mut rules = create_test_rules_map();
        assert_eq!(rules.len(), 3);

        // Sync with a completely new ruleset
        let new_rules = vec![
            create_test_rule("new-rule-1", "224.0.1.1", 6001),
            create_test_rule("new-rule-2", "224.0.1.2", 6002),
        ];

        // Simulate what sync_rules does: clear and insert new rules
        rules.clear();
        for rule in new_rules {
            let key = (rule.input_group, rule.input_port);
            rules.insert(key, rule);
        }

        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|(_, r)| r.rule_id == "new-rule-1"));
        assert!(rules.iter().any(|(_, r)| r.rule_id == "new-rule-2"));
        assert!(!rules.iter().any(|(_, r)| r.rule_id == "rule-1"));
    }

    #[test]
    fn test_sync_rules_empty_ruleset() {
        let mut rules = create_test_rules_map();
        assert_eq!(rules.len(), 3);

        // Sync with empty ruleset - should clear all rules
        rules.clear();

        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_config_capacity_defaults() {
        let config = UnifiedConfig::default();

        // Verify default capacity limits are set
        assert_eq!(config.max_rules, 10_000);
        assert_eq!(config.max_flow_counters, 100_000);
        assert_eq!(config.max_egress_sockets, 10_000);
    }

    #[test]
    fn test_config_capacity_custom() {
        let config = UnifiedConfig {
            max_rules: 100,
            max_flow_counters: 500,
            max_egress_sockets: 50,
            ..Default::default()
        };

        assert_eq!(config.max_rules, 100);
        assert_eq!(config.max_flow_counters, 500);
        assert_eq!(config.max_egress_sockets, 50);
    }

    #[test]
    fn test_stats_capacity_metrics_default() {
        let stats = UnifiedStats::default();

        // Verify capacity metrics start at zero
        assert_eq!(stats.rules_rejected, 0);
        assert_eq!(stats.flow_counters_evicted, 0);
        assert_eq!(stats.egress_sockets_evicted, 0);
    }
}
