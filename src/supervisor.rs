// SPDX-License-Identifier: Apache-2.0 OR MIT
// Allow await_holding_lock for std::sync::Mutex - these are intentional short-lived locks
#![allow(clippy::await_holding_lock)]

use anyhow::{Context, Result};
use futures::SinkExt;
use log::error;
use nix::sys::socket::{
    sendmsg, socketpair, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
};
use nix::unistd::{Gid, Group, Uid, User};
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration};

use crate::logging::{AsyncConsumer, Facility, Logger, MPSCRingBuffer};
use crate::{log_info, log_warning, ForwardingRule, RelayCommand, Response};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 16000; // 16 seconds
const SHUTDOWN_TIMEOUT_SECS: u64 = 10; // Timeout for graceful worker shutdown
const PERIODIC_SYNC_INTERVAL_SECS: u64 = 300; // 5 minutes - periodic full ruleset sync to all workers

/// Maximum interface name length (IFNAMSIZ - 1 for null terminator)
const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Validate an interface name according to Linux kernel rules.
/// Returns Ok(()) if valid, Err(reason) if invalid.
fn validate_interface_name(name: &str) -> Result<(), String> {
    // Must not be empty
    if name.is_empty() {
        return Err("interface name cannot be empty".to_string());
    }

    // Must not exceed IFNAMSIZ - 1 (15 chars)
    if name.len() > MAX_INTERFACE_NAME_LEN {
        return Err(format!(
            "interface name '{}' exceeds maximum length of {} characters",
            name, MAX_INTERFACE_NAME_LEN
        ));
    }

    // Must contain only valid characters: alphanumeric, dash, underscore
    // (Linux allows most characters but these are the safe/common ones)
    for (i, c) in name.chars().enumerate() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
            return Err(format!(
                "interface name '{}' contains invalid character '{}' at position {}; \
                only alphanumeric, dash, underscore, and dot are allowed",
                name, c, i
            ));
        }
    }

    // Must not start with a dash or dot (kernel restriction)
    if name.starts_with('-') || name.starts_with('.') {
        return Err(format!(
            "interface name '{}' cannot start with '{}'; must start with alphanumeric or underscore",
            name,
            name.chars().next().unwrap()
        ));
    }

    Ok(())
}

/// Validate a port number.
/// Port 0 is rejected as it's typically reserved and indicates a configuration error.
fn validate_port(port: u16, context: &str) -> Result<(), String> {
    if port == 0 {
        return Err(format!(
            "{} cannot be 0; valid port range is 1-65535",
            context
        ));
    }
    Ok(())
}

// --- WorkerManager Types ---

/// Differentiates worker types for unified handling
#[derive(Debug, Clone, PartialEq)]
enum WorkerType {
    ControlPlane,
    DataPlane { core_id: u32 },
}

/// Holds all information about a single worker process
struct Worker {
    pid: u32,
    worker_type: WorkerType,
    child: Child,
    // Data plane workers have TWO command streams (ingress + egress)
    // Control plane workers have ONE command stream
    ingress_cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
    egress_cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
    #[allow(dead_code)] // Used for Request::ListRules debugging (see Section 8.2.6)
    req_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>, // Request stream for control plane (Request::ListRules etc, used by GetWorkerRules)
    #[allow(dead_code)] // Reserved for future log aggregation feature
    log_pipe: Option<std::os::unix::io::OwnedFd>, // Pipe for reading worker's stderr (JSON logs)
    #[allow(dead_code)] // Reserved for future stats aggregation feature
    stats_pipe: Option<std::os::unix::io::OwnedFd>, // Pipe for reading worker's stats (JSON)
}

/// Centralized manager for all worker lifecycle operations
struct WorkerManager {
    // Configuration
    uid: u32,
    gid: u32,
    interface: String,
    relay_command_socket_path: PathBuf,
    num_cores: usize,
    logger: Logger,
    fanout_group_id: u16,

    // Worker state
    workers: HashMap<u32, Worker>,       // keyed by PID
    backoff_counters: HashMap<u32, u64>, // keyed by core_id (0 for CP, 1+ for DP)
    worker_stats: Arc<Mutex<HashMap<u32, Vec<crate::FlowStats>>>>, // Stats from data plane workers (keyed by PID)
}

/// Action that may need to be taken after handling a supervisor command
#[derive(Debug, Clone, PartialEq)]
pub enum CommandAction {
    /// No further action needed
    None,
    /// Broadcast a relay command to all data plane workers
    BroadcastToDataPlane(RelayCommand),
}

/// Handle a supervisor command by updating state and returning a response + action.
///
/// This function is pure (no I/O) and unit-testable. It handles state updates
/// and returns what async actions need to be taken (like broadcasting to workers).
///
/// # Arguments
/// * `command` - The supervisor command to process
/// * `master_rules` - Shared state of all forwarding rules
/// * `worker_map` - Map of active workers (pid -> WorkerInfo)
/// * `global_min_level` - Global minimum log level
/// * `facility_min_levels` - Per-facility log level overrides
/// * `worker_stats` - Latest stats from all data plane workers (keyed by PID)
///
/// # Returns
/// A tuple of (Response to send to client, Action to take)
pub fn handle_supervisor_command(
    command: crate::SupervisorCommand,
    master_rules: &Mutex<HashMap<String, ForwardingRule>>,
    worker_map: &Mutex<HashMap<u32, crate::WorkerInfo>>,
    global_min_level: &std::sync::atomic::AtomicU8,
    facility_min_levels: &std::sync::RwLock<
        HashMap<crate::logging::Facility, crate::logging::Severity>,
    >,
    worker_stats: &Mutex<HashMap<u32, Vec<crate::FlowStats>>>,
) -> (crate::Response, CommandAction) {
    use crate::{Response, SupervisorCommand};
    use std::sync::atomic::Ordering;

    match command {
        SupervisorCommand::ListWorkers => {
            let workers = worker_map.lock().unwrap().values().cloned().collect();
            (Response::Workers(workers), CommandAction::None)
        }

        SupervisorCommand::AddRule {
            rule_id,
            input_interface,
            input_group,
            input_port,
            outputs,
        } => {
            // Validate input interface name
            if let Err(e) = validate_interface_name(&input_interface) {
                return (
                    Response::Error(format!("Invalid input_interface: {}", e)),
                    CommandAction::None,
                );
            }

            // Validate all output interface names
            for (i, output) in outputs.iter().enumerate() {
                if let Err(e) = validate_interface_name(&output.interface) {
                    return (
                        Response::Error(format!(
                            "Invalid output_interface in output[{}]: {}",
                            i, e
                        )),
                        CommandAction::None,
                    );
                }
            }

            // Validate port numbers (reject port 0)
            if let Err(e) = validate_port(input_port, "input_port") {
                return (Response::Error(e), CommandAction::None);
            }
            for (i, output) in outputs.iter().enumerate() {
                if let Err(e) = validate_port(output.port, &format!("output[{}].port", i)) {
                    return (Response::Error(e), CommandAction::None);
                }
            }

            let rule = ForwardingRule {
                rule_id,
                input_interface,
                input_group,
                input_port,
                outputs,
            };

            // Validate interface configuration to prevent packet loops and reflection
            for output in &rule.outputs {
                // Reject self-loops: input and output on same interface creates packet feedback loops
                if rule.input_interface == output.interface {
                    return (
                        Response::Error(format!(
                            "Rule rejected: input_interface '{}' and output_interface '{}' cannot be the same. \
                            This creates packet loops where transmitted packets are received again by the same interface, \
                            causing exponential packet multiplication and invalid statistics. \
                            Use different interfaces (e.g., eth0 → eth1) for proper forwarding.",
                            rule.input_interface, output.interface
                        )),
                        CommandAction::None,
                    );
                }
            }

            // Warn about loopback interface usage (allowed but not recommended)
            if rule.input_interface == "lo" || rule.outputs.iter().any(|o| o.interface == "lo") {
                eprintln!(
                    "[Supervisor] WARNING: Rule '{}' uses loopback interface. \
                    This can cause packet reflection artifacts where transmitted packets are \
                    received again by AF_PACKET sockets, leading to inflated statistics and \
                    unexpected behavior. Loopback is suitable for local testing only. \
                    For production use, configure rules with real network interfaces (e.g., eth0, eth1) \
                    or use veth pairs for virtual topologies.",
                    rule.rule_id
                );
            }

            master_rules
                .lock()
                .unwrap()
                .insert(rule.rule_id.clone(), rule.clone());

            let response = Response::Success(format!("Rule {} added", rule.rule_id));
            let action = CommandAction::BroadcastToDataPlane(RelayCommand::AddRule(rule));
            (response, action)
        }

        SupervisorCommand::RemoveRule { rule_id } => {
            let removed = master_rules.lock().unwrap().remove(&rule_id).is_some();
            if removed {
                let response = Response::Success(format!("Rule {} removed", rule_id.clone()));
                let action =
                    CommandAction::BroadcastToDataPlane(RelayCommand::RemoveRule { rule_id });
                (response, action)
            } else {
                (
                    Response::Error(format!("Rule {} not found", rule_id)),
                    CommandAction::None,
                )
            }
        }

        SupervisorCommand::ListRules => {
            let rules = master_rules.lock().unwrap().values().cloned().collect();
            (Response::Rules(rules), CommandAction::None)
        }

        SupervisorCommand::GetStats => {
            // Aggregate stats from all data plane workers
            // Multiple workers may report stats for the same flow (same input_group:port)
            // With PACKET_FANOUT_CPU, each worker handles a subset of packets, so we sum
            // both counters and rates to get the total system throughput
            use std::collections::HashMap as StdHashMap;

            let worker_stats_locked = worker_stats.lock().unwrap();
            let mut aggregated: StdHashMap<(std::net::Ipv4Addr, u16), crate::FlowStats> =
                StdHashMap::new();

            // Aggregate stats from all workers
            for stats_vec in worker_stats_locked.values() {
                for stat in stats_vec {
                    let key = (stat.input_group, stat.input_port);
                    aggregated
                        .entry(key)
                        .and_modify(|existing| {
                            // Sum counters
                            existing.packets_relayed += stat.packets_relayed;
                            existing.bytes_relayed += stat.bytes_relayed;
                            // Sum rates (each worker handles distinct packets via fanout)
                            existing.packets_per_second += stat.packets_per_second;
                            existing.bits_per_second += stat.bits_per_second;
                        })
                        .or_insert_with(|| stat.clone());
                }
            }

            let stats: Vec<crate::FlowStats> = aggregated.into_values().collect();
            (Response::Stats(stats), CommandAction::None)
        }

        SupervisorCommand::SetGlobalLogLevel { level } => {
            global_min_level.store(level as u8, Ordering::Relaxed);
            (
                Response::Success(format!("Global log level set to {}", level)),
                CommandAction::None,
            )
        }

        SupervisorCommand::SetFacilityLogLevel { facility, level } => {
            facility_min_levels.write().unwrap().insert(facility, level);
            (
                Response::Success(format!("Log level for {} set to {}", facility, level)),
                CommandAction::None,
            )
        }

        SupervisorCommand::GetLogLevels => {
            let global =
                crate::logging::Severity::from_u8(global_min_level.load(Ordering::Relaxed))
                    .unwrap_or(crate::logging::Severity::Info);
            let facility_overrides = facility_min_levels.read().unwrap().clone();
            (
                Response::LogLevels {
                    global,
                    facility_overrides,
                },
                CommandAction::None,
            )
        }

        SupervisorCommand::Ping => {
            // Health check - broadcast ping to all data plane workers
            // If they can receive and process this command, they're ready
            eprintln!("[PING] Supervisor received ping, broadcasting to workers");
            (
                Response::Success("pong".to_string()),
                CommandAction::BroadcastToDataPlane(RelayCommand::Ping),
            )
        }
    }
}

pub async fn spawn_control_plane_worker(
    uid: u32,
    gid: u32,
    relay_command_socket_path: PathBuf,
    logger: &crate::logging::Logger,
) -> Result<(Child, UnixStream, UnixStream)> {
    logger.info(Facility::Supervisor, "Spawning Control Plane worker");

    // Create the supervisor-worker communication socket pair
    // This will be passed as FD 3 to the worker
    let (supervisor_sock, worker_sock) = UnixStream::pair()?;

    // Keep worker_sock alive as FD 3 for the child process
    let worker_sock_std = worker_sock.into_std()?;
    let worker_fd = worker_sock_std.into_raw_fd();

    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("worker")
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path)
        .process_group(0); // Put worker in its own process group to prevent SIGTERM propagation

    // Ensure worker_sock becomes FD 3 in the child
    unsafe {
        command.pre_exec(move || {
            // Dup worker_fd to FD 3
            if worker_fd != 3 {
                if libc::dup2(worker_fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(worker_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let child = command.spawn()?;

    // Send request socket pair (used for Request::ListRules and similar requests)
    let req_supervisor_stream = create_and_send_socketpair(&supervisor_sock).await?;

    Ok((child, supervisor_sock, req_supervisor_stream))
}

pub async fn spawn_data_plane_worker(
    core_id: u32,
    _uid: u32,
    _gid: u32,
    interface: String,
    relay_command_socket_path: PathBuf,
    fanout_group_id: u16,
    logger: &crate::logging::Logger,
) -> Result<(
    Child,
    UnixStream,
    UnixStream,
    Option<std::os::unix::io::OwnedFd>, // log_pipe
    Option<std::os::unix::io::OwnedFd>, // stats_pipe
)> {
    logger.info(
        Facility::Supervisor,
        &format!("Spawning Data Plane worker for core {}", core_id),
    );

    // Create pipe for worker stderr (for JSON logging)
    #[cfg(not(feature = "testing"))]
    let (log_read_fd, log_write_fd) = {
        use nix::unistd::pipe;
        use std::os::unix::io::IntoRawFd;
        let (read_fd, write_fd) = pipe()?;
        // Convert to raw FDs to prevent auto-close when OwnedFd goes out of scope
        (Some(read_fd.into_raw_fd()), Some(write_fd.into_raw_fd()))
    };
    #[cfg(feature = "testing")]
    let (_log_read_fd, _log_write_fd): (Option<RawFd>, Option<RawFd>) = (None, None);

    // Create pipe for worker stats (JSON stats reporting)
    #[cfg(not(feature = "testing"))]
    let (stats_read_fd, stats_write_fd) = {
        use nix::unistd::pipe;
        use std::os::unix::io::IntoRawFd;
        let (read_fd, write_fd) = pipe()?;
        // Convert to raw FDs to prevent auto-close when OwnedFd goes out of scope
        (Some(read_fd.into_raw_fd()), Some(write_fd.into_raw_fd()))
    };
    #[cfg(feature = "testing")]
    let (_stats_read_fd, _stats_write_fd): (Option<RawFd>, Option<RawFd>) = (None, None);

    // Create the supervisor-worker communication socket pair
    // This will be passed as FD 3 to the worker
    let (supervisor_sock, worker_sock) = UnixStream::pair()?;

    // Keep worker_sock alive as FD 3 for the child process
    let worker_sock_std = worker_sock.into_std()?;
    let worker_fd = worker_sock_std.into_raw_fd();

    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("worker")
        .arg("--core-id")
        .arg(core_id.to_string())
        .arg("--data-plane")
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path)
        .arg("--input-interface-name")
        .arg(interface)
        .arg("--fanout-group-id")
        .arg(fanout_group_id.to_string())
        .process_group(0); // Put worker in its own process group to prevent SIGTERM propagation

    // Pass stats pipe FD via environment variable (secure FD passing)
    // Clear close-on-exec flag so the FD is inherited
    #[cfg(not(feature = "testing"))]
    if let Some(write_fd) = stats_write_fd {
        command.env("MCR_STATS_PIPE_FD", write_fd.to_string());
        // Clear FD_CLOEXEC flag to allow FD to be inherited across exec
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        use std::os::fd::BorrowedFd;
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(write_fd) };
        let flags = fcntl(borrowed_fd, FcntlArg::F_GETFD)?;
        let mut fd_flags = FdFlag::from_bits_truncate(flags);
        fd_flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(borrowed_fd, FcntlArg::F_SETFD(fd_flags))?;
    }

    // Ensure worker_sock becomes FD 3 in the child, and redirect stderr to pipe
    unsafe {
        command.pre_exec(move || {
            // Dup worker_fd to FD 3
            if worker_fd != 3 {
                if libc::dup2(worker_fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(worker_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            // Redirect stderr to pipe write end (for JSON logging)
            #[cfg(not(feature = "testing"))]
            if let Some(write_fd) = log_write_fd {
                if libc::dup2(write_fd, 2) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(write_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                // Also close read end in child (not needed)
                if let Some(read_fd) = log_read_fd {
                    if libc::close(read_fd) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }

            // Close stats read end in child (not needed)
            #[cfg(not(feature = "testing"))]
            if let Some(read_fd) = stats_read_fd {
                if libc::close(read_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }

    let child = command.spawn()?;

    // Close write end in parent (child has it via FD 2)
    // Keep read end open - we'll use it to read worker logs
    #[cfg(not(feature = "testing"))]
    if let Some(write_fd) = log_write_fd {
        nix::unistd::close(write_fd).ok();
    }

    // Convert read end to OwnedFd (it's still open, we didn't close it)
    #[cfg(not(feature = "testing"))]
    let log_pipe = log_read_fd.map(|fd| unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) });
    #[cfg(feature = "testing")]
    let log_pipe = None;

    // Close stats write end in parent (child has it via FD 4)
    // Keep read end open - we'll use it to read worker stats
    #[cfg(not(feature = "testing"))]
    if let Some(write_fd) = stats_write_fd {
        nix::unistd::close(write_fd).ok();
    }

    // Convert stats read end to OwnedFd (it's still open, we didn't close it)
    #[cfg(not(feature = "testing"))]
    let stats_pipe = stats_read_fd.map(|fd| unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) });
    #[cfg(feature = "testing")]
    let stats_pipe = None;

    // Send TWO command sockets to the child process (one for ingress, one for egress)
    let ingress_cmd_supervisor_stream = create_and_send_socketpair(&supervisor_sock).await?;
    let egress_cmd_supervisor_stream = create_and_send_socketpair(&supervisor_sock).await?;

    Ok((
        child,
        ingress_cmd_supervisor_stream,
        egress_cmd_supervisor_stream,
        log_pipe,
        stats_pipe,
    ))
}

// --- WorkerManager Implementation ---

impl WorkerManager {
    /// Create a new WorkerManager with the given configuration
    #[allow(clippy::too_many_arguments)]
    fn new(
        uid: u32,
        gid: u32,
        interface: String,
        relay_command_socket_path: PathBuf,
        num_cores: usize,
        logger: Logger,
        fanout_group_id: u16,
    ) -> Self {
        Self {
            uid,
            gid,
            interface,
            relay_command_socket_path,
            num_cores,
            logger,
            fanout_group_id,
            workers: HashMap::new(),
            backoff_counters: HashMap::new(),
            worker_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Spawn the control plane worker
    async fn spawn_control_plane(&mut self) -> Result<()> {
        let (child, cmd_stream, req_stream) = spawn_control_plane_worker(
            self.uid,
            self.gid,
            self.relay_command_socket_path.clone(),
            &self.logger,
        )
        .await?;

        let pid = child.id().unwrap();
        let cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(cmd_stream));
        let req_stream_arc = Arc::new(tokio::sync::Mutex::new(req_stream));

        // Store worker info - control plane only has one command stream
        self.workers.insert(
            pid,
            Worker {
                pid,
                worker_type: WorkerType::ControlPlane,
                child,
                ingress_cmd_stream: Some(cmd_stream_arc.clone()),
                egress_cmd_stream: Some(cmd_stream_arc), // Same stream for CP
                req_stream: Some(req_stream_arc),
                log_pipe: None,   // Control plane uses MPSC ring buffer
                stats_pipe: None, // Control plane doesn't have stats pipe
            },
        );

        // Initialize backoff counter (core_id 0 for CP)
        self.backoff_counters.insert(0, INITIAL_BACKOFF_MS);

        Ok(())
    }

    /// Spawn a data plane worker for the given core
    async fn spawn_data_plane(&mut self, core_id: u32) -> Result<()> {
        let (child, ingress_cmd_stream, egress_cmd_stream, log_pipe, stats_pipe) =
            spawn_data_plane_worker(
                core_id,
                self.uid,
                self.gid,
                self.interface.clone(),
                self.relay_command_socket_path.clone(),
                self.fanout_group_id,
                &self.logger,
            )
            .await?;

        let pid = child.id().unwrap();
        let ingress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(ingress_cmd_stream));
        let egress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(egress_cmd_stream));

        // Store worker info with separate command streams
        self.workers.insert(
            pid,
            Worker {
                pid,
                worker_type: WorkerType::DataPlane { core_id },
                child,
                ingress_cmd_stream: Some(ingress_cmd_stream_arc),
                egress_cmd_stream: Some(egress_cmd_stream_arc),
                req_stream: None, // Data plane workers don't use req_stream
                log_pipe,
                stats_pipe,
            },
        );

        // Initialize backoff counter
        self.backoff_counters
            .insert(core_id + 1, INITIAL_BACKOFF_MS);

        // Spawn log consumer task for this worker
        #[cfg(not(feature = "testing"))]
        if let Some(pipe_fd) = self.workers.get(&pid).and_then(|w| w.log_pipe.as_ref()) {
            self.spawn_log_consumer(pid, pipe_fd)?;
        }

        // Spawn stats consumer task for this worker
        #[cfg(not(feature = "testing"))]
        if let Some(pipe_fd) = self.workers.get(&pid).and_then(|w| w.stats_pipe.as_ref()) {
            self.spawn_stats_consumer(pid, pipe_fd)?;
        }

        Ok(())
    }

    /// Spawn all initial workers (1 CP + N DP workers)
    async fn spawn_all_initial_workers(&mut self) -> Result<()> {
        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("Starting with {} data plane workers", self.num_cores)
        );

        // Spawn control plane worker
        log_info!(
            self.logger,
            Facility::Supervisor,
            "Spawning Control Plane worker"
        );
        self.spawn_control_plane().await?;

        // Spawn data plane workers
        for core_id in 0..self.num_cores as u32 {
            self.spawn_data_plane(core_id).await?;
        }

        Ok(())
    }

    /// Check for exited workers and restart them with exponential backoff
    /// Returns Some((pid, was_dataplane)) if a worker exited, None otherwise
    async fn check_and_restart_worker(&mut self) -> Result<Option<(u32, bool)>> {
        // Check each worker to see if it has exited
        let mut exited_workers = Vec::new();
        for (pid, worker) in &mut self.workers {
            // Try to check if the worker has exited (non-blocking)
            match worker.child.try_wait()? {
                Some(status) => {
                    exited_workers.push((*pid, worker.worker_type.clone(), status));
                }
                None => continue,
            }
        }

        // If no workers exited, return None
        if exited_workers.is_empty() {
            return Ok(None);
        }

        // Handle the first exited worker
        let (pid, worker_type, status) = exited_workers.remove(0);

        // Remove from workers map
        let _worker = self.workers.remove(&pid).unwrap();

        // Restart logic based on worker type
        match worker_type {
            WorkerType::ControlPlane => {
                let backoff = self.backoff_counters.entry(0).or_insert(INITIAL_BACKOFF_MS);
                if status.success() {
                    log_info!(
                        self.logger,
                        Facility::Supervisor,
                        "Control Plane worker exited gracefully, restarting immediately"
                    );
                    *backoff = INITIAL_BACKOFF_MS;
                } else {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!(
                            "Control Plane worker failed (status: {}), restarting after {}ms",
                            status, *backoff
                        )
                    );
                    sleep(Duration::from_millis(*backoff)).await;
                    *backoff = (*backoff * 2).min(MAX_BACKOFF_MS);
                }
                self.spawn_control_plane().await?;
                Ok(Some((pid, false)))
            }
            WorkerType::DataPlane { core_id } => {
                let backoff = self
                    .backoff_counters
                    .entry(core_id + 1)
                    .or_insert(INITIAL_BACKOFF_MS);
                if status.success() {
                    log_info!(
                        self.logger,
                        Facility::Supervisor,
                        &format!(
                            "Data Plane worker (core {}) exited gracefully, restarting immediately",
                            core_id
                        )
                    );
                    *backoff = INITIAL_BACKOFF_MS;
                } else {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!(
                            "Data Plane worker (core {}) failed (status: {}), restarting after {}ms",
                            core_id, status, *backoff
                        )
                    );
                    sleep(Duration::from_millis(*backoff)).await;
                    *backoff = (*backoff * 2).min(MAX_BACKOFF_MS);
                }
                self.spawn_data_plane(core_id).await?;
                Ok(Some((pid, true)))
            }
        }
    }

    /// Initiate graceful shutdown of all workers with timeout
    async fn shutdown_all(&mut self, timeout: Duration) {
        log_info!(
            self.logger,
            Facility::Supervisor,
            "Graceful shutdown initiated, signaling workers"
        );

        // Collect join handles for shutdown command sends
        let mut shutdown_tasks = Vec::new();

        // Signal all workers to shut down by sending explicit Shutdown command
        for worker in self.workers.values() {
            let cmd_bytes = serde_json::to_vec(&RelayCommand::Shutdown).unwrap();

            // Send to ingress stream if present
            if let Some(ingress_stream) = &worker.ingress_cmd_stream {
                let stream_mutex = ingress_stream.clone();
                let worker_type_desc = format!("{:?}", worker.worker_type);
                let cmd_bytes_clone = cmd_bytes.clone();

                let task = tokio::spawn(async move {
                    let mut stream = stream_mutex.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    if let Err(e) = framed.send(cmd_bytes_clone.into()).await {
                        eprintln!(
                            "[Supervisor] Failed to send Shutdown to {} ingress: {}",
                            worker_type_desc, e
                        );
                    }
                });
                shutdown_tasks.push(task);
            }

            // Send to egress stream if present (for data plane workers, this is a separate stream)
            if let Some(egress_stream) = &worker.egress_cmd_stream {
                let stream_mutex = egress_stream.clone();
                let worker_type_desc = format!("{:?}", worker.worker_type);
                let cmd_bytes_clone = cmd_bytes.clone();

                let task = tokio::spawn(async move {
                    let mut stream = stream_mutex.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    if let Err(e) = framed.send(cmd_bytes_clone.into()).await {
                        eprintln!(
                            "[Supervisor] Failed to send Shutdown to {} egress: {}",
                            worker_type_desc, e
                        );
                    }
                });
                shutdown_tasks.push(task);
            }
        }

        // Wait for all shutdown commands to be sent (with 1 second timeout)
        let send_timeout = Duration::from_secs(1);
        match tokio::time::timeout(send_timeout, futures::future::join_all(shutdown_tasks)).await {
            Ok(_) => {
                eprintln!("[Supervisor] All shutdown commands sent successfully");
            }
            Err(_) => {
                eprintln!("[Supervisor] Warning: Timeout sending shutdown commands");
            }
        }

        // Grace period: Give workers time to process shutdown and print final stats
        // This allows workers to cleanly exit their event loops and call print_final_stats()
        let grace_period = Duration::from_millis(500);
        eprintln!(
            "[Supervisor] Waiting {:?} grace period for workers to process shutdown",
            grace_period
        );
        tokio::time::sleep(grace_period).await;

        // Wait for all workers to exit with timeout
        let num_workers = self.workers.len();
        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Waiting for {} workers to exit (timeout: {:?})",
                num_workers, timeout
            )
        );

        let shutdown_start = tokio::time::Instant::now();
        let mut exited_count = 0;

        while !self.workers.is_empty() {
            // Check if we've exceeded the timeout
            if shutdown_start.elapsed() >= timeout {
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "Shutdown timeout exceeded, {} workers still running, force killing",
                        self.workers.len()
                    )
                );

                // Force kill any remaining workers
                for (pid, worker) in self.workers.iter_mut() {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("Force killing worker {} ({:?})", pid, worker.worker_type)
                    );
                    let _ = worker.child.kill().await;
                }
                break;
            }

            // Check for exited workers (non-blocking)
            let mut exited_pids = Vec::new();
            for (pid, worker) in &mut self.workers {
                match worker.child.try_wait() {
                    Ok(Some(status)) => {
                        log_info!(
                            self.logger,
                            Facility::Supervisor,
                            &format!(
                                "Worker {} ({:?}) exited with status: {}",
                                pid, worker.worker_type, status
                            )
                        );
                        exited_pids.push(*pid);
                        exited_count += 1;
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        log_warning!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("Error checking worker {}: {}", pid, e)
                        );
                        exited_pids.push(*pid);
                    }
                }
            }

            // Remove exited workers
            for pid in exited_pids {
                self.workers.remove(&pid);
            }

            // Brief sleep before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("All workers exited ({} total)", exited_count)
        );
    }

    /// Get all data plane command streams for broadcasting
    /// Returns pairs of (ingress_stream, egress_stream) for each worker
    #[allow(clippy::type_complexity)]
    fn get_all_dp_cmd_streams(
        &self,
    ) -> Vec<(
        Arc<tokio::sync::Mutex<UnixStream>>,
        Arc<tokio::sync::Mutex<UnixStream>>,
    )> {
        self.workers
            .values()
            .filter(|w| matches!(w.worker_type, WorkerType::DataPlane { .. }))
            .filter_map(|w| match (&w.ingress_cmd_stream, &w.egress_cmd_stream) {
                (Some(ingress), Some(egress)) => Some((ingress.clone(), egress.clone())),
                _ => None,
            })
            .collect()
    }

    /// Get worker info for all workers (for ListWorkers command)
    fn get_worker_info(&self) -> Vec<crate::WorkerInfo> {
        self.workers
            .values()
            .map(|w| crate::WorkerInfo {
                pid: w.pid,
                worker_type: match &w.worker_type {
                    WorkerType::ControlPlane => "ControlPlane".to_string(),
                    WorkerType::DataPlane { .. } => "DataPlane".to_string(),
                },
                core_id: match &w.worker_type {
                    WorkerType::ControlPlane => None,
                    WorkerType::DataPlane { core_id } => Some(*core_id),
                },
            })
            .collect()
    }

    /// Spawn async task to consume JSON logs from worker's stderr pipe
    #[cfg(not(feature = "testing"))]
    fn spawn_log_consumer(
        &self,
        worker_pid: u32,
        pipe_fd: &std::os::unix::io::OwnedFd,
    ) -> Result<()> {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        use tokio::io::{AsyncBufReadExt, BufReader};

        // Duplicate the FD so we can convert to tokio File
        let dup_fd_owned = nix::unistd::dup(pipe_fd)?;
        let dup_fd = dup_fd_owned.into_raw_fd(); // Transfer ownership out of OwnedFd

        // Convert to tokio async file
        let std_file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let tokio_file = tokio::fs::File::from_std(std_file);
        let reader = BufReader::new(tokio_file);
        let mut lines = reader.lines();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                // For now, just print raw lines to supervisor's stderr
                // In Phase 2.2, worker will output JSON and we'll parse it here
                eprintln!("[Worker {}] {}", worker_pid, line);
            }
            eprintln!("[Supervisor] Worker {} log stream closed", worker_pid);
        });

        Ok(())
    }

    /// Spawn async task to consume JSON stats from worker's stats pipe (FD 4)
    #[cfg(not(feature = "testing"))]
    fn spawn_stats_consumer(
        &self,
        worker_pid: u32,
        pipe_fd: &std::os::unix::io::OwnedFd,
    ) -> Result<()> {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        use tokio::io::{AsyncBufReadExt, BufReader};

        // Duplicate the FD so we can convert to tokio File
        let dup_fd_owned = nix::unistd::dup(pipe_fd)?;
        let dup_fd = dup_fd_owned.into_raw_fd(); // Transfer ownership out of OwnedFd

        // Convert to tokio async file
        let std_file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let tokio_file = tokio::fs::File::from_std(std_file);
        let reader = BufReader::new(tokio_file);
        let mut lines = reader.lines();

        // Clone Arc for async task
        let worker_stats = self.worker_stats.clone();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                // Parse JSON stats from worker
                match serde_json::from_str::<Vec<crate::FlowStats>>(&line) {
                    Ok(stats) => {
                        // Store latest stats for this worker
                        worker_stats.lock().unwrap().insert(worker_pid, stats);
                    }
                    Err(e) => {
                        eprintln!(
                            "[Supervisor] Failed to parse stats from worker {}: {}",
                            worker_pid, e
                        );
                    }
                }
            }
            eprintln!("[Supervisor] Worker {} stats stream closed", worker_pid);
            // Remove stats for this worker when stream closes
            worker_stats.lock().unwrap().remove(&worker_pid);
        });

        Ok(())
    }
}

// --- Client Handling ---

/// Handle a single client connection on the control socket
async fn handle_client(
    mut client_stream: tokio::net::UnixStream,
    worker_manager: Arc<Mutex<WorkerManager>>,
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
    global_min_level: Arc<std::sync::atomic::AtomicU8>,
    facility_min_levels: Arc<
        std::sync::RwLock<
            std::collections::HashMap<crate::logging::Facility, crate::logging::Severity>,
        >,
    >,
) -> Result<()> {
    use crate::SupervisorCommand;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = Vec::new();
    client_stream.read_to_end(&mut buffer).await?;

    let command: SupervisorCommand = serde_json::from_slice(&buffer)?;

    // Get worker info and stats from WorkerManager (locked access)
    let (worker_info, worker_stats_arc) = {
        let manager = worker_manager.lock().unwrap();
        (manager.get_worker_info(), manager.worker_stats.clone())
    };

    // Create a temporary HashMap for handle_supervisor_command (to keep it pure)
    let worker_map_temp = Mutex::new(
        worker_info
            .iter()
            .map(|w| (w.pid, w.clone()))
            .collect::<HashMap<u32, crate::WorkerInfo>>(),
    );

    // Use the extracted, testable command handler
    let (response, action) = handle_supervisor_command(
        command,
        &master_rules,
        &worker_map_temp,
        &global_min_level,
        &facility_min_levels,
        &worker_stats_arc,
    );

    // Log ruleset hash for drift detection if rules changed
    if matches!(action, CommandAction::BroadcastToDataPlane(_)) {
        let ruleset_hash = {
            let rules = master_rules.lock().unwrap();
            crate::compute_ruleset_hash(rules.values())
        };
        let rule_count = master_rules.lock().unwrap().len();

        // Get logger from worker_manager
        let logger = {
            let manager = worker_manager.lock().unwrap();
            manager.logger.clone()
        };

        log_info!(
            logger,
            Facility::Supervisor,
            &format!(
                "Ruleset updated: hash={:016x} rule_count={}",
                ruleset_hash, rule_count
            )
        );
    }

    // Handle async actions BEFORE sending response for Ping
    let mut final_response = response;
    match action {
        CommandAction::None => {
            // Nothing to do
        }
        CommandAction::BroadcastToDataPlane(relay_cmd) => {
            let is_ping = matches!(relay_cmd, RelayCommand::Ping);
            let cmd_bytes = serde_json::to_vec(&relay_cmd)?;

            // Get cmd stream pairs from WorkerManager
            let stream_pairs = {
                let manager = worker_manager.lock().unwrap();
                manager.get_all_dp_cmd_streams()
            };

            if is_ping {
                // For ping, wait for all sends to complete and verify success
                let mut send_tasks = Vec::new();

                for (ingress_stream, egress_stream) in stream_pairs {
                    // Send to ingress
                    let cmd_bytes_clone = cmd_bytes.clone();
                    let task = tokio::spawn(async move {
                        let mut stream = ingress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        framed.send(cmd_bytes_clone.into()).await
                    });
                    send_tasks.push(task);

                    // Send to egress
                    let cmd_bytes_clone = cmd_bytes.clone();
                    let task = tokio::spawn(async move {
                        let mut stream = egress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        framed.send(cmd_bytes_clone.into()).await
                    });
                    send_tasks.push(task);
                }

                // Wait for all sends and check for errors
                let total_streams = send_tasks.len();
                let mut ready_count = 0;
                for task in send_tasks {
                    match task.await {
                        Ok(Ok(_)) => {
                            // Send succeeded - worker stream is ready
                            ready_count += 1;
                        }
                        Ok(Err(e)) => {
                            eprintln!("[PING] Failed to send ping to worker: {}", e);
                        }
                        Err(e) => {
                            eprintln!("[PING] Task join error: {}", e);
                        }
                    }
                }

                if ready_count == total_streams {
                    final_response = Response::Success(format!(
                        "pong: {}/{} worker streams ready",
                        ready_count, total_streams
                    ));
                } else {
                    final_response = Response::Error(format!(
                        "Only {}/{} worker streams ready",
                        ready_count, total_streams
                    ));
                }
            } else {
                // For non-ping commands, fire and forget
                for (ingress_stream, egress_stream) in stream_pairs {
                    // Send to ingress
                    let cmd_bytes_clone = cmd_bytes.clone();
                    tokio::spawn(async move {
                        let mut stream = ingress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        let _ = framed.send(cmd_bytes_clone.into()).await;
                    });

                    // Send to egress
                    let cmd_bytes_clone = cmd_bytes.clone();
                    tokio::spawn(async move {
                        let mut stream = egress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        let _ = framed.send(cmd_bytes_clone.into()).await;
                    });
                }
            }
        }
    }

    // Send final response to client
    let response_bytes = serde_json::to_vec(&final_response)?;
    client_stream.write_all(&response_bytes).await?;

    Ok(())
}

// --- Supervisor Core Logic ---

#[allow(clippy::too_many_arguments)]
pub async fn run(
    user: &str,
    group: &str,
    interface: &str,
    relay_command_socket_path: PathBuf,
    control_socket_path: PathBuf,
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
    num_workers: Option<usize>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    let uid = User::from_name(user)
        .with_context(|| format!("User '{}' not found", user))?
        .map(|u| u.uid.as_raw())
        .with_context(|| format!("User '{}' not found", user))?;
    let gid = Group::from_name(group)
        .with_context(|| format!("Group '{}' not found", group))?
        .map(|g| g.gid.as_raw())
        .with_context(|| format!("Group '{}' not found", group))?;

    // Determine number of cores to use
    // TODO: ARCHITECTURAL FIX NEEDED
    // Per architecture (D21, D23): One worker per CPU core, rules hashed to cores.
    // The --num-workers override exists to avoid resource exhaustion on single-interface tests
    // until lazy socket creation is implemented.
    let detected_cores = num_cpus::get();
    let num_cores = num_workers.unwrap_or(detected_cores);

    // Initialize logging early (before spawning workers)
    let supervisor_ringbuffer = Arc::new(MPSCRingBuffer::new(Facility::Supervisor.buffer_size()));

    // Initialize log-level filtering (default: Info)
    let global_min_level = Arc::new(std::sync::atomic::AtomicU8::new(
        crate::logging::Severity::Info as u8,
    ));
    let facility_min_levels = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

    let supervisor_logger = Logger::from_mpsc(
        Arc::clone(&supervisor_ringbuffer),
        Arc::clone(&global_min_level),
        Arc::clone(&facility_min_levels),
    );
    let ringbuffers_for_consumer = vec![(Facility::Supervisor, Arc::clone(&supervisor_ringbuffer))];
    let _log_consumer_handle = tokio::spawn(async move {
        AsyncConsumer::stderr(ringbuffers_for_consumer).run().await;
    });

    log_info!(
        supervisor_logger,
        Facility::Supervisor,
        &format!(
            "Detected {} CPU cores, using {} data plane workers",
            detected_cores, num_cores
        )
    );

    // Create the relay command socket (not currently used but keep for compatibility)
    if relay_command_socket_path.exists() {
        std::fs::remove_file(&relay_command_socket_path)?;
    }
    let _relay_command_listener = {
        let std_listener = std::os::unix::net::UnixListener::bind(&relay_command_socket_path)?;
        std_listener.set_nonblocking(true)?;
        tokio::net::UnixListener::from_std(std_listener)?
    };
    nix::unistd::chown(
        &relay_command_socket_path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )?;

    // Set up control socket for client connections
    if control_socket_path.exists() {
        std::fs::remove_file(&control_socket_path)?;
    }
    let listener = {
        let std_listener = std::os::unix::net::UnixListener::bind(&control_socket_path)?;
        std_listener.set_nonblocking(true)?;
        tokio::net::UnixListener::from_std(std_listener)?
    };
    log_info!(
        supervisor_logger,
        Facility::Supervisor,
        &format!("Control socket listening on {:?}", &control_socket_path)
    );

    // Generate a fanout group ID for all data plane workers
    // Only use PACKET_FANOUT when there are multiple workers (num_cores > 1)
    // With a single worker, PACKET_FANOUT is not needed and can cause issues
    let fanout_group_id = if num_cores > 1 {
        let id = (std::process::id() & 0xFFFF) as u16;
        log_info!(
            supervisor_logger,
            Facility::Supervisor,
            &format!("PACKET_FANOUT group ID: {} ({} workers)", id, num_cores)
        );
        id
    } else {
        log_info!(
            supervisor_logger,
            Facility::Supervisor,
            "PACKET_FANOUT disabled (single worker)"
        );
        0
    };

    // Initialize WorkerManager and wrap it in Arc<Mutex<>>
    let worker_manager = {
        let mut manager = WorkerManager::new(
            uid,
            gid,
            interface.to_string(),
            relay_command_socket_path,
            num_cores,
            supervisor_logger.clone(),
            fanout_group_id,
        );

        // Spawn all initial workers
        manager.spawn_all_initial_workers().await?;

        // Send initial ruleset sync to all data plane workers
        // This ensures workers start with the same ruleset as the supervisor
        let rules_snapshot: Vec<ForwardingRule> = {
            let rules = master_rules.lock().unwrap();
            rules.values().cloned().collect()
        };

        if !rules_snapshot.is_empty() {
            log_info!(
                supervisor_logger,
                Facility::Supervisor,
                &format!(
                    "Sending initial ruleset sync ({} rules) to all data plane workers",
                    rules_snapshot.len()
                )
            );

            let sync_cmd = RelayCommand::SyncRules(rules_snapshot);
            let cmd_bytes = serde_json::to_vec(&sync_cmd)?;

            // Get command streams and send SyncRules to all data plane workers
            let stream_pairs = manager.get_all_dp_cmd_streams();
            for (ingress_stream, egress_stream) in stream_pairs {
                let mut ingress = ingress_stream.lock().await;
                let mut egress = egress_stream.lock().await;

                // Send to both ingress and egress workers (fire-and-forget)
                let _ = ingress.write_all(&cmd_bytes).await;
                let _ = egress.write_all(&cmd_bytes).await;
            }
        } else {
            log_info!(
                supervisor_logger,
                Facility::Supervisor,
                "No rules to sync on startup (empty ruleset)"
            );
        }

        Arc::new(Mutex::new(manager))
    };

    // Main supervisor loop
    loop {
        tokio::select! {
            // Shutdown signal received
            _ = &mut shutdown_rx => {
                let mut manager = worker_manager.lock().unwrap();
                manager.shutdown_all(Duration::from_secs(SHUTDOWN_TIMEOUT_SECS)).await;
                drop(manager);
                break;
            }

            // New client connection
            Ok((client_stream, _)) = listener.accept() => {
                // Handle client inline to avoid unbounded task spawning
                // Client operations are fast (read, execute, write) and don't block data plane
                if let Err(e) = handle_client(
                    client_stream,
                    Arc::clone(&worker_manager),
                    Arc::clone(&master_rules),
                    Arc::clone(&global_min_level),
                    Arc::clone(&facility_min_levels),
                )
                .await
                {
                    error!("Error handling client: {}", e);
                }
            }

            // Periodic worker health check (every 250ms)
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                // Check for crashed workers and restart them
                let restart_result = {
                    let mut manager = worker_manager.lock().unwrap();
                    manager.check_and_restart_worker().await
                };

                match restart_result {
                    Ok(Some((_pid, was_dataplane))) if was_dataplane => {
                        // A data plane worker was restarted - send SyncRules to ensure it has current ruleset
                        let rules_snapshot: Vec<ForwardingRule> = {
                            let rules = master_rules.lock().unwrap();
                            rules.values().cloned().collect()
                        };

                        if !rules_snapshot.is_empty() {
                            let sync_cmd = RelayCommand::SyncRules(rules_snapshot);
                            if let Ok(cmd_bytes) = serde_json::to_vec(&sync_cmd) {
                                // Send to all data plane workers (simpler than targeting just the new one)
                                let stream_pairs = {
                                    let manager = worker_manager.lock().unwrap();
                                    manager.get_all_dp_cmd_streams()
                                };

                                for (ingress_stream, egress_stream) in stream_pairs {
                                    let mut ingress = ingress_stream.lock().await;
                                    let mut egress = egress_stream.lock().await;

                                    // Fire-and-forget: ignore errors
                                    let _ = ingress.write_all(&cmd_bytes).await;
                                    let _ = egress.write_all(&cmd_bytes).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error checking/restarting worker: {}", e);
                    }
                    _ => {
                        // No worker restarted or control plane worker restarted (no action needed)
                    }
                }
            }

            // Periodic ruleset sync (every 5 minutes)
            // Part of Option C (Hybrid Approach) for fire-and-forget broadcast reliability
            // Recovers from any missed broadcasts due to transient failures
            _ = tokio::time::sleep(Duration::from_secs(PERIODIC_SYNC_INTERVAL_SECS)) => {
                let rules_snapshot: Vec<ForwardingRule> = {
                    let rules = master_rules.lock().unwrap();
                    rules.values().cloned().collect()
                };

                if !rules_snapshot.is_empty() {
                    log_info!(
                        supervisor_logger,
                        Facility::Supervisor,
                        &format!(
                            "Periodic ruleset sync: sending {} rules to all data plane workers",
                            rules_snapshot.len()
                        )
                    );

                    let sync_cmd = RelayCommand::SyncRules(rules_snapshot);
                    if let Ok(cmd_bytes) = serde_json::to_vec(&sync_cmd) {
                        let stream_pairs = {
                            let manager = worker_manager.lock().unwrap();
                            manager.get_all_dp_cmd_streams()
                        };

                        for (ingress_stream, egress_stream) in stream_pairs {
                            let mut ingress = ingress_stream.lock().await;
                            let mut egress = egress_stream.lock().await;

                            // Fire-and-forget: ignore errors (recovery will happen on next periodic sync)
                            let _ = ingress.write_all(&cmd_bytes).await;
                            let _ = egress.write_all(&cmd_bytes).await;
                        }
                    }
                } else {
                    log_info!(
                        supervisor_logger,
                        Facility::Supervisor,
                        "Periodic ruleset sync: no rules to sync (empty ruleset)"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Send a file descriptor to a worker process via SCM_RIGHTS
///
/// # Safety
/// This function uses unsafe FFI to send file descriptors. The caller must ensure:
/// - `sock` is a valid Unix domain socket
/// - `fd` is a valid open file descriptor
async fn send_fd(sock: &UnixStream, fd: RawFd) -> Result<()> {
    let data = [0u8; 1];
    let iov = [std::io::IoSlice::new(&data)];
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    sock.ready(tokio::io::Interest::WRITABLE).await?;
    sock.try_io(tokio::io::Interest::WRITABLE, || {
        sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .map_err(std::io::Error::other)
    })?;

    Ok(())
}

/// Create a socketpair and send one end to the worker, returning the supervisor's end
///
/// This helper reduces duplication when setting up IPC channels with workers.
/// Creates a Unix domain socket pair with CLOEXEC and NONBLOCK flags, then
/// sends the worker's end via file descriptor passing.
async fn create_and_send_socketpair(supervisor_sock: &UnixStream) -> Result<UnixStream> {
    let (supervisor_fd, worker_fd) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )?;

    send_fd(supervisor_sock, worker_fd.into_raw_fd()).await?;

    Ok(UnixStream::from_std(unsafe {
        std::os::unix::net::UnixStream::from_raw_fd(supervisor_fd.into_raw_fd())
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Unit Tests for handle_supervisor_command ---

    #[test]
    fn test_handle_list_workers() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        worker_map.lock().unwrap().insert(
            1234,
            crate::WorkerInfo {
                pid: 1234,
                worker_type: "DataPlane".to_string(),
                core_id: None,
            },
        );
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::ListWorkers,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        assert!(matches!(response, crate::Response::Workers(workers) if workers.len() == 1));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_add_rule() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert!(matches!(action, CommandAction::BroadcastToDataPlane(_)));
        assert_eq!(master_rules.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_handle_remove_rule_exists() {
        let master_rules = Mutex::new(HashMap::new());
        master_rules.lock().unwrap().insert(
            "test-rule".to_string(),
            ForwardingRule {
                rule_id: "test-rule".to_string(),
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![],
            },
        );
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::RemoveRule {
                rule_id: "test-rule".to_string(),
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert!(matches!(action, CommandAction::BroadcastToDataPlane(_)));
        assert_eq!(master_rules.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_handle_remove_rule_not_found() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::RemoveRule {
                rule_id: "nonexistent".to_string(),
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        assert!(matches!(response, crate::Response::Error(_)));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_list_rules() {
        let master_rules = Mutex::new(HashMap::new());
        master_rules.lock().unwrap().insert(
            "test-rule".to_string(),
            ForwardingRule {
                rule_id: "test-rule".to_string(),
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![],
            },
        );
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::ListRules,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        assert!(matches!(response, crate::Response::Rules(rules) if rules.len() == 1));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_stats() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetStats,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        assert!(matches!(response, crate::Response::Stats(_)));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_set_global_log_level() {
        use std::sync::atomic::Ordering;

        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::SetGlobalLogLevel {
                level: crate::logging::Severity::Debug,
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert_eq!(action, CommandAction::None);
        assert_eq!(
            global_min_level.load(Ordering::Relaxed),
            crate::logging::Severity::Debug as u8
        );
    }

    #[test]
    fn test_handle_set_facility_log_level() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::SetFacilityLogLevel {
                facility: crate::logging::Facility::Ingress,
                level: crate::logging::Severity::Debug,
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert_eq!(action, CommandAction::None);
        assert_eq!(
            facility_min_levels
                .read()
                .unwrap()
                .get(&crate::logging::Facility::Ingress),
            Some(&crate::logging::Severity::Debug)
        );
    }

    #[test]
    fn test_handle_get_log_levels() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Warning as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        facility_min_levels.write().unwrap().insert(
            crate::logging::Facility::Ingress,
            crate::logging::Severity::Debug,
        );

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetLogLevels,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        match response {
            crate::Response::LogLevels {
                global,
                facility_overrides,
            } => {
                assert_eq!(global, crate::logging::Severity::Warning);
                assert_eq!(
                    facility_overrides.get(&crate::logging::Facility::Ingress),
                    Some(&crate::logging::Severity::Debug)
                );
            }
            _ => panic!("Expected LogLevels response"),
        }
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_stats_multi_worker_aggregation() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        // Simulate stats from 3 data plane workers reporting for the same flow
        let mut worker_stats_map = HashMap::new();

        // Worker 1: 100 packets, 10000 bytes, 50 pps, 4000 bps
        worker_stats_map.insert(
            1001,
            vec![crate::FlowStats {
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                packets_relayed: 100,
                bytes_relayed: 10000,
                packets_per_second: 50.0,
                bits_per_second: 4000.0,
            }],
        );

        // Worker 2: 200 packets, 20000 bytes, 100 pps, 8000 bps
        worker_stats_map.insert(
            1002,
            vec![crate::FlowStats {
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                packets_relayed: 200,
                bytes_relayed: 20000,
                packets_per_second: 100.0,
                bits_per_second: 8000.0,
            }],
        );

        // Worker 3: 150 packets, 15000 bytes, 75 pps, 6000 bps
        worker_stats_map.insert(
            1003,
            vec![crate::FlowStats {
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                packets_relayed: 150,
                bytes_relayed: 15000,
                packets_per_second: 75.0,
                bits_per_second: 6000.0,
            }],
        );

        let worker_stats = Mutex::new(worker_stats_map);

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetStats,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        match response {
            crate::Response::Stats(stats) => {
                assert_eq!(stats.len(), 1, "Should have one aggregated flow");
                let flow = &stats[0];

                // Check aggregated counters (should be summed)
                assert_eq!(
                    flow.packets_relayed, 450,
                    "Should sum packets from all workers: 100+200+150"
                );
                assert_eq!(
                    flow.bytes_relayed, 45000,
                    "Should sum bytes from all workers: 10000+20000+15000"
                );

                // Check aggregated rates (currently summed, not averaged)
                assert_eq!(
                    flow.packets_per_second, 225.0,
                    "Should sum pps from all workers: 50+100+75"
                );
                assert_eq!(
                    flow.bits_per_second, 18000.0,
                    "Should sum bps from all workers: 4000+8000+6000"
                );

                // Check flow identification
                assert_eq!(
                    flow.input_group,
                    "224.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
                );
                assert_eq!(flow.input_port, 5000);
            }
            _ => panic!("Expected Response::Stats, got {:?}", response),
        }

        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_stats_multiple_flows() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        // Simulate 2 workers with different flows
        let mut worker_stats_map = HashMap::new();

        // Worker 1: Flow A (224.0.0.1:5000) and Flow B (224.0.0.2:5001)
        worker_stats_map.insert(
            2001,
            vec![
                crate::FlowStats {
                    input_group: "224.0.0.1".parse().unwrap(),
                    input_port: 5000,
                    packets_relayed: 100,
                    bytes_relayed: 10000,
                    packets_per_second: 10.0,
                    bits_per_second: 8000.0,
                },
                crate::FlowStats {
                    input_group: "224.0.0.2".parse().unwrap(),
                    input_port: 5001,
                    packets_relayed: 50,
                    bytes_relayed: 5000,
                    packets_per_second: 5.0,
                    bits_per_second: 4000.0,
                },
            ],
        );

        // Worker 2: Only Flow A (224.0.0.1:5000)
        worker_stats_map.insert(
            2002,
            vec![crate::FlowStats {
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                packets_relayed: 200,
                bytes_relayed: 20000,
                packets_per_second: 20.0,
                bits_per_second: 16000.0,
            }],
        );

        let worker_stats = Mutex::new(worker_stats_map);

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetStats,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        match response {
            crate::Response::Stats(stats) => {
                assert_eq!(stats.len(), 2, "Should have two distinct flows");

                // Find Flow A and Flow B in the results
                let flow_a = stats
                    .iter()
                    .find(|s| s.input_port == 5000)
                    .expect("Should have Flow A");
                let flow_b = stats
                    .iter()
                    .find(|s| s.input_port == 5001)
                    .expect("Should have Flow B");

                // Flow A: aggregated from both workers
                assert_eq!(flow_a.packets_relayed, 300, "Flow A packets: 100+200");
                assert_eq!(flow_a.bytes_relayed, 30000, "Flow A bytes: 10000+20000");
                assert_eq!(flow_a.packets_per_second, 30.0, "Flow A pps: 10+20");

                // Flow B: only from worker 1
                assert_eq!(flow_b.packets_relayed, 50, "Flow B packets: 50");
                assert_eq!(flow_b.bytes_relayed, 5000, "Flow B bytes: 5000");
                assert_eq!(flow_b.packets_per_second, 5.0, "Flow B pps: 5.0");
            }
            _ => panic!("Expected Response::Stats, got {:?}", response),
        }

        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_reject_self_loop_same_interface() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        // Attempt to create a self-loop: eth0 -> eth0
        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "bad-loop".to_string(),
                input_interface: "eth0".to_string(),
                input_group: "239.1.1.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth0".to_string(), // Same as input!
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        // Should reject with error
        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("cannot be the same"));
                assert!(msg.contains("packet loops"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }

        assert_eq!(action, CommandAction::None);

        // Verify rule was not added
        assert_eq!(master_rules.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_accept_valid_different_interfaces() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        // Valid rule: eth0 -> eth1 (different interfaces)
        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "valid-rule".to_string(),
                input_interface: "eth0".to_string(),
                input_group: "239.1.1.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(), // Different from input
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        // Should succeed
        match response {
            crate::Response::Success(msg) => {
                assert!(msg.contains("valid-rule"));
                assert!(msg.contains("added"));
            }
            _ => panic!("Expected Success response, got {:?}", response),
        }

        // Should broadcast to data plane
        match action {
            CommandAction::BroadcastToDataPlane(_) => {}
            _ => panic!("Expected BroadcastToDataPlane action, got {:?}", action),
        }

        // Verify rule was added
        assert_eq!(master_rules.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_loopback_allowed_with_warning() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        // Loopback should be allowed but warned
        let (response, _action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "loopback-rule".to_string(),
                input_interface: "eth0".to_string(),
                input_group: "239.1.1.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 5001,
                    interface: "lo".to_string(), // Loopback output
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        // Should succeed (loopback allowed, just warned)
        match response {
            crate::Response::Success(_) => {}
            _ => panic!("Expected Success response for loopback, got {:?}", response),
        }

        // Rule should be added despite loopback warning
        assert_eq!(master_rules.lock().unwrap().len(), 1);
    }

    // --- Interface Name Validation Tests ---

    #[test]
    fn test_validate_interface_name_valid() {
        // Standard interface names
        assert!(validate_interface_name("lo").is_ok());
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("eth1").is_ok());
        assert!(validate_interface_name("enp0s3").is_ok());
        assert!(validate_interface_name("wlan0").is_ok());
        assert!(validate_interface_name("br0").is_ok());
        assert!(validate_interface_name("docker0").is_ok());
        assert!(validate_interface_name("veth123abc").is_ok());

        // Names with underscores and dashes
        assert!(validate_interface_name("my_bridge").is_ok());
        assert!(validate_interface_name("veth-peer").is_ok());
        assert!(validate_interface_name("tap_vm1").is_ok());

        // Names with dots
        assert!(validate_interface_name("eth0.100").is_ok()); // VLAN interface

        // Maximum length (15 chars)
        assert!(validate_interface_name("123456789012345").is_ok());
    }

    #[test]
    fn test_validate_interface_name_empty() {
        let result = validate_interface_name("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_interface_name_too_long() {
        // 16 characters - too long
        let result = validate_interface_name("1234567890123456");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum length"));

        // 20 characters - definitely too long
        let result = validate_interface_name("12345678901234567890");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_interface_name_invalid_chars() {
        // Space
        let result = validate_interface_name("eth 0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid character"));

        // Slash
        let result = validate_interface_name("eth/0");
        assert!(result.is_err());

        // Colon
        let result = validate_interface_name("eth:0");
        assert!(result.is_err());

        // At sign
        let result = validate_interface_name("eth@0");
        assert!(result.is_err());

        // Unicode
        let result = validate_interface_name("ethö0");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_interface_name_invalid_start() {
        // Cannot start with dash
        let result = validate_interface_name("-eth0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot start with"));

        // Cannot start with dot
        let result = validate_interface_name(".eth0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot start with"));
    }

    #[test]
    fn test_add_rule_rejects_invalid_input_interface() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                input_interface: "this_interface_name_is_way_too_long".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(),
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("Invalid input_interface"));
                assert!(msg.contains("exceeds maximum length"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
    }

    #[test]
    fn test_add_rule_rejects_invalid_output_interface() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                input_interface: "eth0".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "invalid/name".to_string(),
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("Invalid output_interface"));
                assert!(msg.contains("output[0]"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
    }

    // --- Port Number Validation Tests ---

    #[test]
    fn test_validate_port_valid() {
        assert!(validate_port(1, "test").is_ok());
        assert!(validate_port(80, "test").is_ok());
        assert!(validate_port(5000, "test").is_ok());
        assert!(validate_port(65535, "test").is_ok());
    }

    #[test]
    fn test_validate_port_zero() {
        let result = validate_port(0, "input_port");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("input_port"));
        assert!(err.contains("cannot be 0"));
        assert!(err.contains("1-65535"));
    }

    #[test]
    fn test_add_rule_rejects_zero_input_port() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                input_interface: "eth0".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 0, // Invalid
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(),
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("input_port"));
                assert!(msg.contains("cannot be 0"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
    }

    #[test]
    fn test_add_rule_rejects_zero_output_port() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                input_interface: "eth0".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 0, // Invalid
                    interface: "eth1".to_string(),
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("output[0].port"));
                assert!(msg.contains("cannot be 0"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
    }
}
