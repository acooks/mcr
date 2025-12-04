// SPDX-License-Identifier: Apache-2.0 OR MIT
// Allow await_holding_lock for std::sync::Mutex - these are intentional short-lived locks
#![allow(clippy::await_holding_lock)]

use anyhow::{Context, Result};
use futures::SinkExt;
use log::error;
use nix::sys::socket::{
    sendmsg, socketpair, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
};
use nix::unistd::{Gid, Uid};
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
    DataPlane { interface: String, core_id: u32 },
}

/// Holds all information about a single worker process
struct Worker {
    pid: u32,
    worker_type: WorkerType,
    child: Child,
    // Data plane workers have TWO command streams (ingress + egress)
    ingress_cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
    egress_cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
    #[allow(dead_code)] // Used in production only (not with feature="testing")
    log_pipe: Option<std::os::unix::io::OwnedFd>, // Pipe for reading worker's stderr (JSON logs)
    #[allow(dead_code)] // Used in production only (not with feature="testing")
    stats_pipe: Option<std::os::unix::io::OwnedFd>, // Pipe for reading worker's stats (JSON)
}

/// Per-interface worker configuration and state
struct InterfaceWorkers {
    /// Number of workers for this interface (from pinning config or default 1)
    num_workers: usize,
    /// Fanout group ID for this interface (auto-assigned, unique per interface)
    fanout_group_id: u16,
    /// Whether this interface was from startup config (pinned) or dynamic
    #[allow(dead_code)] // Will be used for dynamic worker lifecycle management
    is_pinned: bool,
}

/// Centralized manager for all worker lifecycle operations
struct WorkerManager {
    // Configuration
    default_interface: String, // CLI --interface (for backward compat)
    relay_command_socket_path: PathBuf,
    num_cores_per_interface: usize, // Default workers per interface
    logger: Logger,

    // Per-interface state
    interfaces: HashMap<String, InterfaceWorkers>,
    next_fanout_group_id: u16, // Auto-increment for new interfaces

    // Worker state
    workers: HashMap<u32, Worker>,                 // keyed by PID
    backoff_counters: HashMap<(String, u32), u64>, // keyed by (interface, core_id)
    worker_stats: Arc<Mutex<HashMap<u32, Vec<crate::FlowStats>>>>, // Stats from data plane workers (keyed by PID)
}

/// Action that may need to be taken after handling a supervisor command
#[derive(Debug, Clone, PartialEq)]
pub enum CommandAction {
    /// No further action needed
    None,
    /// Broadcast a relay command to all data plane workers
    BroadcastToDataPlane(RelayCommand),
    /// Ensure workers exist for interface, then broadcast command
    /// (interface, is_pinned, command)
    EnsureWorkersAndBroadcast {
        interface: String,
        is_pinned: bool,
        command: RelayCommand,
    },
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
            name: _, // TODO: Store name in ForwardingRule for display
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

            // Generate stable rule ID if not provided
            let rule_id = if rule_id.is_empty() {
                crate::generate_rule_id(&input_interface, input_group, input_port)
            } else {
                rule_id
            };

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

            // Extract input_interface before inserting
            let input_interface = rule.input_interface.clone();

            master_rules
                .lock()
                .unwrap()
                .insert(rule.rule_id.clone(), rule.clone());

            let response = Response::Success(format!("Rule {} added", rule.rule_id));
            // Use EnsureWorkersAndBroadcast to dynamically spawn workers for new interfaces
            let action = CommandAction::EnsureWorkersAndBroadcast {
                interface: input_interface,
                is_pinned: false, // Runtime rules create dynamic (non-pinned) workers
                command: RelayCommand::AddRule(rule),
            };
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

        SupervisorCommand::GetVersion => (
            Response::Version {
                protocol_version: crate::PROTOCOL_VERSION,
            },
            CommandAction::None,
        ),

        SupervisorCommand::Ping => {
            // Health check - broadcast ping to all data plane workers
            // If they can receive and process this command, they're ready
            eprintln!("[PING] Supervisor received ping, broadcasting to workers");
            (
                Response::Success("pong".to_string()),
                CommandAction::BroadcastToDataPlane(RelayCommand::Ping),
            )
        }

        SupervisorCommand::RemoveRuleByName { name } => {
            // Find rule by name and remove it
            // Note: Names are optional and not currently stored in ForwardingRule
            // This is a placeholder that will need ForwardingRule to be extended
            let rules = master_rules.lock().unwrap();
            // For now, return an error since names aren't stored yet
            drop(rules);
            (
                Response::Error(format!(
                    "RemoveRuleByName not yet implemented (rule name: {}). Use --id instead.",
                    name
                )),
                CommandAction::None,
            )
        }

        SupervisorCommand::GetConfig => {
            // Return current running configuration
            let rules = master_rules.lock().unwrap();
            let rules_vec: Vec<crate::ForwardingRule> = rules.values().cloned().collect();
            let config = crate::Config::from_forwarding_rules(&rules_vec);
            (Response::Config(config), CommandAction::None)
        }

        SupervisorCommand::LoadConfig { config, replace } => {
            // Validate the config first
            if let Err(e) = config.validate() {
                return (
                    Response::Error(format!("Invalid configuration: {}", e)),
                    CommandAction::None,
                );
            }

            let new_rules = config.to_forwarding_rules();

            if replace {
                // Replace all existing rules
                let mut rules = master_rules.lock().unwrap();
                rules.clear();
                for rule in new_rules {
                    rules.insert(rule.rule_id.clone(), rule);
                }
                let rules_for_sync: Vec<crate::ForwardingRule> = rules.values().cloned().collect();
                drop(rules);
                (
                    Response::Success(format!(
                        "Configuration loaded ({} rules, replaced existing)",
                        rules_for_sync.len()
                    )),
                    CommandAction::BroadcastToDataPlane(RelayCommand::SyncRules(rules_for_sync)),
                )
            } else {
                // Merge: add new rules that don't conflict
                let mut rules = master_rules.lock().unwrap();
                let mut added = 0;
                let mut skipped = 0;
                for new_rule in new_rules {
                    // Check for duplicate input tuple
                    let exists = rules.values().any(|r| {
                        r.input_interface == new_rule.input_interface
                            && r.input_group == new_rule.input_group
                            && r.input_port == new_rule.input_port
                    });
                    if exists {
                        skipped += 1;
                    } else {
                        rules.insert(new_rule.rule_id.clone(), new_rule);
                        added += 1;
                    }
                }
                let rules_for_sync: Vec<crate::ForwardingRule> = rules.values().cloned().collect();
                drop(rules);
                (
                    Response::Success(format!(
                        "Configuration merged ({} rules added, {} skipped as duplicates)",
                        added, skipped
                    )),
                    CommandAction::BroadcastToDataPlane(RelayCommand::SyncRules(rules_for_sync)),
                )
            }
        }

        SupervisorCommand::SaveConfig { path } => {
            // Save running config to a file
            let rules = master_rules.lock().unwrap();
            let rules_vec: Vec<crate::ForwardingRule> = rules.values().cloned().collect();
            let config = crate::Config::from_forwarding_rules(&rules_vec);
            drop(rules);

            match path {
                Some(p) => match config.save_to_file(&p) {
                    Ok(()) => (
                        Response::Success(format!("Configuration saved to {}", p.display())),
                        CommandAction::None,
                    ),
                    Err(e) => (
                        Response::Error(format!("Failed to save configuration: {}", e)),
                        CommandAction::None,
                    ),
                },
                None => (
                    Response::Error(
                        "No path specified and no startup config path available".to_string(),
                    ),
                    CommandAction::None,
                ),
            }
        }

        SupervisorCommand::CheckConfig { config } => {
            // Validate configuration without loading
            match config.validate() {
                Ok(()) => (
                    Response::ConfigValidation {
                        valid: true,
                        errors: vec![],
                    },
                    CommandAction::None,
                ),
                Err(e) => (
                    Response::ConfigValidation {
                        valid: false,
                        errors: vec![e.to_string()],
                    },
                    CommandAction::None,
                ),
            }
        }
    }
}

pub async fn spawn_data_plane_worker(
    core_id: u32,
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
        .arg(&interface)
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

    // Create the AF_PACKET socket in the supervisor (requires CAP_NET_RAW/root)
    // and send it to the worker. This enables full privilege separation:
    // the worker can drop all privileges after receiving this pre-configured socket.
    let af_packet_socket = create_af_packet_socket(&interface, fanout_group_id, logger)?;
    send_fd(&supervisor_sock, af_packet_socket.as_raw_fd()).await?;
    // Keep the socket alive until the worker receives it
    drop(af_packet_socket);

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
        default_interface: String,
        relay_command_socket_path: PathBuf,
        num_cores_per_interface: usize,
        logger: Logger,
        initial_fanout_group_id: u16,
    ) -> Self {
        Self {
            default_interface,
            relay_command_socket_path,
            num_cores_per_interface,
            logger,
            interfaces: HashMap::new(),
            next_fanout_group_id: initial_fanout_group_id,
            workers: HashMap::new(),
            backoff_counters: HashMap::new(),
            worker_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create fanout group ID for an interface
    fn get_or_create_interface(&mut self, interface: &str, is_pinned: bool) -> u16 {
        if let Some(iface_workers) = self.interfaces.get(interface) {
            return iface_workers.fanout_group_id;
        }

        // Allocate new fanout group ID
        let fanout_group_id = self.next_fanout_group_id;
        self.next_fanout_group_id = self.next_fanout_group_id.wrapping_add(1);

        // Determine number of workers (for now, use default; pinning support added later)
        let num_workers = if is_pinned {
            self.num_cores_per_interface
        } else {
            1 // Dynamic interfaces get 1 worker by default
        };

        self.interfaces.insert(
            interface.to_string(),
            InterfaceWorkers {
                num_workers,
                fanout_group_id,
                is_pinned,
            },
        );

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Registered interface '{}' with fanout_group_id={}, workers={}, pinned={}",
                interface, fanout_group_id, num_workers, is_pinned
            )
        );

        fanout_group_id
    }

    /// Check if workers exist for a given interface
    fn has_workers_for_interface(&self, interface: &str) -> bool {
        self.workers.values().any(|w| {
            matches!(&w.worker_type, WorkerType::DataPlane { interface: iface, .. } if iface == interface)
        })
    }

    /// Get the number of workers for a given interface
    #[allow(dead_code)] // Will be used for worker management features
    fn worker_count_for_interface(&self, interface: &str) -> usize {
        self.workers
            .values()
            .filter(|w| {
                matches!(&w.worker_type, WorkerType::DataPlane { interface: iface, .. } if iface == interface)
            })
            .count()
    }

    /// Spawn a data plane worker for the given interface and core
    async fn spawn_data_plane_for_interface(
        &mut self,
        interface: &str,
        core_id: u32,
        fanout_group_id: u16,
    ) -> Result<()> {
        let (child, ingress_cmd_stream, egress_cmd_stream, log_pipe, stats_pipe) =
            spawn_data_plane_worker(
                core_id,
                interface.to_string(),
                self.relay_command_socket_path.clone(),
                fanout_group_id,
                &self.logger,
            )
            .await?;

        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("Worker process exited immediately after spawn"))?;
        let ingress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(ingress_cmd_stream));
        let egress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(egress_cmd_stream));

        // Store worker info with separate command streams
        self.workers.insert(
            pid,
            Worker {
                pid,
                worker_type: WorkerType::DataPlane {
                    interface: interface.to_string(),
                    core_id,
                },
                child,
                ingress_cmd_stream: Some(ingress_cmd_stream_arc),
                egress_cmd_stream: Some(egress_cmd_stream_arc),
                log_pipe,
                stats_pipe,
            },
        );

        // Initialize backoff counter - key by (interface, core_id) tuple
        self.backoff_counters
            .insert((interface.to_string(), core_id), INITIAL_BACKOFF_MS);

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

    /// Spawn workers for an interface (if not already spawned)
    /// Returns true if workers were spawned, false if they already existed
    async fn ensure_workers_for_interface(
        &mut self,
        interface: &str,
        is_pinned: bool,
    ) -> Result<bool> {
        if self.has_workers_for_interface(interface) {
            return Ok(false);
        }

        // Get or create interface config (assigns fanout group ID)
        let fanout_group_id = self.get_or_create_interface(interface, is_pinned);
        let num_workers = self
            .interfaces
            .get(interface)
            .map(|i| i.num_workers)
            .unwrap_or(1);

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Spawning {} worker(s) for interface '{}' (fanout_group_id={})",
                num_workers, interface, fanout_group_id
            )
        );

        // Spawn workers for this interface
        for core_id in 0..num_workers as u32 {
            self.spawn_data_plane_for_interface(interface, core_id, fanout_group_id)
                .await?;
        }

        Ok(true)
    }

    /// Spawn all initial data plane workers for the default interface
    async fn spawn_all_initial_workers(&mut self) -> Result<()> {
        let interface = self.default_interface.clone();
        let num_workers = self.num_cores_per_interface;

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Starting with {} data plane workers for interface '{}'",
                num_workers, interface
            )
        );

        // Register the default interface as pinned (from CLI)
        let fanout_group_id = self.get_or_create_interface(&interface, true);

        // Spawn data plane workers for the default interface
        for core_id in 0..num_workers as u32 {
            self.spawn_data_plane_for_interface(&interface, core_id, fanout_group_id)
                .await?;
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

        // Remove from workers map (should always exist, but handle gracefully)
        if self.workers.remove(&pid).is_none() {
            log_warning!(
                self.logger,
                Facility::Supervisor,
                &format!("Worker {} not found in workers map during restart", pid)
            );
        }

        // Restart the data plane worker
        let WorkerType::DataPlane { interface, core_id } = worker_type;
        let backoff_key = (interface.clone(), core_id);
        let backoff = self
            .backoff_counters
            .entry(backoff_key)
            .or_insert(INITIAL_BACKOFF_MS);
        if status.success() {
            log_info!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Data Plane worker (interface={}, core={}) exited gracefully, restarting immediately",
                    interface, core_id
                )
            );
            *backoff = INITIAL_BACKOFF_MS;
        } else {
            log_warning!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Data Plane worker (interface={}, core={}) failed (status: {}), restarting after {}ms",
                    interface, core_id, status, *backoff
                )
            );
            sleep(Duration::from_millis(*backoff)).await;
            *backoff = (*backoff * 2).min(MAX_BACKOFF_MS);
        }

        // Get the fanout group ID for this interface (should exist since worker was running)
        let fanout_group_id = self
            .interfaces
            .get(&interface)
            .map(|i| i.fanout_group_id)
            .unwrap_or(0);

        self.spawn_data_plane_for_interface(&interface, core_id, fanout_group_id)
            .await?;
        Ok(Some((pid, true)))
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
            .map(|w| {
                let WorkerType::DataPlane {
                    interface: _,
                    core_id,
                } = &w.worker_type;
                crate::WorkerInfo {
                    pid: w.pid,
                    worker_type: "DataPlane".to_string(),
                    core_id: Some(*core_id),
                }
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
    if matches!(
        action,
        CommandAction::BroadcastToDataPlane(_) | CommandAction::EnsureWorkersAndBroadcast { .. }
    ) {
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
        CommandAction::EnsureWorkersAndBroadcast {
            interface,
            is_pinned,
            command,
        } => {
            // First, ensure workers exist for the interface
            {
                let manager = worker_manager.lock().unwrap();
                if !manager.has_workers_for_interface(&interface) {
                    // Drop lock before async operation
                    drop(manager);

                    // Re-acquire lock and spawn workers
                    let mut manager = worker_manager.lock().unwrap();
                    if let Err(e) = manager
                        .ensure_workers_for_interface(&interface, is_pinned)
                        .await
                    {
                        error!(
                            "Failed to spawn workers for interface '{}': {}",
                            interface, e
                        );
                    }
                }
            }

            // Now broadcast the command to all workers
            let cmd_bytes = serde_json::to_vec(&command)?;
            let stream_pairs = {
                let manager = worker_manager.lock().unwrap();
                manager.get_all_dp_cmd_streams()
            };

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

    // Send final response to client
    let response_bytes = serde_json::to_vec(&final_response)?;
    client_stream.write_all(&response_bytes).await?;

    Ok(())
}

// --- Supervisor Core Logic ---

#[allow(clippy::too_many_arguments)]
pub async fn run(
    interface: &str,
    relay_command_socket_path: PathBuf,
    control_socket_path: PathBuf,
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
    num_workers: Option<usize>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
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
    // Workers run as nobody:nobody, so chown the socket to match
    const NOBODY_UID: u32 = 65534;
    const NOBODY_GID: u32 = 65534;
    nix::unistd::chown(
        &relay_command_socket_path,
        Some(Uid::from_raw(NOBODY_UID)),
        Some(Gid::from_raw(NOBODY_GID)),
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

/// Create and configure an AF_PACKET socket bound to a specific interface.
///
/// This function creates the socket with CAP_NET_RAW privileges in the supervisor,
/// then the socket FD can be passed to unprivileged workers via SCM_RIGHTS.
///
/// # Arguments
/// * `interface_name` - Network interface to bind to (e.g., "eth0")
/// * `fanout_group_id` - PACKET_FANOUT group ID for load balancing (0 = disabled)
/// * `logger` - Logger instance for status messages
///
/// # Returns
/// An owned file descriptor for the configured AF_PACKET socket
fn create_af_packet_socket(
    interface_name: &str,
    fanout_group_id: u16,
    logger: &Logger,
) -> Result<std::os::fd::OwnedFd> {
    use socket2::{Domain, Protocol, Socket, Type};

    logger.info(
        Facility::Supervisor,
        &format!(
            "Creating AF_PACKET socket for interface {} (fanout_group_id={})",
            interface_name, fanout_group_id
        ),
    );

    // Create AF_PACKET socket for receiving
    let recv_socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0x0003)))
        .context("Failed to create AF_PACKET socket")?;

    // Set large receive buffer to prevent drops during traffic bursts.
    // Default system buffer (~212KB) can only hold ~150 packets at 1400 bytes each.
    // At 100k pps, that's only 1.5ms of buffering - not enough for io_uring latency.
    // We request 16MB which gives ~11k packets / ~110ms of burst tolerance.
    // Note: Actual size may be limited by net.core.rmem_max sysctl.
    const RECV_BUFFER_SIZE: i32 = 16 * 1024 * 1024; // 16MB
    unsafe {
        let ret = libc::setsockopt(
            recv_socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &RECV_BUFFER_SIZE as *const _ as *const _,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret < 0 {
            // Log warning but don't fail - system may have lower limits
            logger.warning(
                Facility::Supervisor,
                &format!(
                    "Failed to set SO_RCVBUF to {}MB, using system default",
                    RECV_BUFFER_SIZE / 1024 / 1024
                ),
            );
        } else {
            // Read back actual size (kernel may have adjusted it)
            let mut actual_size: i32 = 0;
            let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;
            libc::getsockopt(
                recv_socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &mut actual_size as *mut _ as *mut _,
                &mut len,
            );
            logger.info(
                Facility::Supervisor,
                &format!(
                    "AF_PACKET SO_RCVBUF set to {}KB (requested {}MB)",
                    actual_size / 1024,
                    RECV_BUFFER_SIZE / 1024 / 1024
                ),
            );
        }
    }

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
            return Err(anyhow::anyhow!(
                "Failed to bind AF_PACKET socket to {}: {}",
                interface_name,
                std::io::Error::last_os_error()
            ));
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
                return Err(anyhow::anyhow!(
                    "PACKET_FANOUT failed for {}: {}",
                    interface_name,
                    std::io::Error::last_os_error()
                ));
            }
        }
        logger.info(
            Facility::Supervisor,
            &format!(
                "PACKET_FANOUT configured for {} (group_id={}, mode=CPU)",
                interface_name, fanout_group_id
            ),
        );
    }

    // Set non-blocking
    recv_socket.set_nonblocking(true)?;

    logger.info(
        Facility::Supervisor,
        &format!(
            "AF_PACKET socket created successfully for interface {}",
            interface_name
        ),
    );

    // Convert to OwnedFd
    Ok(std::os::fd::OwnedFd::from(recv_socket))
}

/// Get network interface index by name
fn get_interface_index(interface_name: &str) -> Result<i32> {
    for iface in pnet::datalink::interfaces() {
        if iface.name == interface_name {
            return Ok(iface.index as i32);
        }
    }
    Err(anyhow::anyhow!("Interface not found: {}", interface_name))
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
                name: None,
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
        assert!(matches!(
            action,
            CommandAction::EnsureWorkersAndBroadcast { .. }
        ));
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
    fn test_handle_get_version() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetVersion,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
        );

        match response {
            crate::Response::Version { protocol_version } => {
                assert_eq!(protocol_version, crate::PROTOCOL_VERSION);
            }
            _ => panic!("Expected Version response"),
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
                name: None,
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
                name: None,
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

        // Should ensure workers and broadcast to data plane
        match action {
            CommandAction::EnsureWorkersAndBroadcast { .. } => {}
            _ => panic!(
                "Expected EnsureWorkersAndBroadcast action, got {:?}",
                action
            ),
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
                name: None,
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
                name: None,
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
                name: None,
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
                name: None,
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
                name: None,
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
