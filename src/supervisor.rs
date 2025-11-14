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
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::logging::{AsyncConsumer, Facility, Logger, MPSCRingBuffer, SharedMemoryLogManager};
use crate::{log_info, log_warning, ForwardingRule, RelayCommand};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 16000; // 16 seconds
const SHUTDOWN_TIMEOUT_SECS: u64 = 10; // Timeout for graceful worker shutdown

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
    cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>, // Used for RelayCommand (shutdown, etc.)
    req_stream: Arc<tokio::sync::Mutex<UnixStream>>,
    #[cfg(not(feature = "testing"))]
    log_manager: Option<SharedMemoryLogManager>, // Data plane only
}

/// Centralized manager for all worker lifecycle operations
struct WorkerManager {
    // Configuration
    uid: u32,
    gid: u32,
    interface: String,
    relay_command_socket_path: PathBuf,
    prometheus_addr: Option<std::net::SocketAddr>,
    num_cores: usize,
    logger: Logger,

    // Worker state
    workers: HashMap<u32, Worker>, // keyed by PID
    backoff_counters: HashMap<u32, u64>, // keyed by core_id (0 for CP, 1+ for DP)
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
            dtls_enabled,
        } => {
            let rule = ForwardingRule {
                rule_id,
                input_interface,
                input_group,
                input_port,
                outputs,
                dtls_enabled,
            };
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
            // Return FlowStats for each configured rule
            // TODO: In the future, query data plane workers for actual stats via worker communication
            // Currently returns configured rules with zero counters as a placeholder
            let stats: Vec<crate::FlowStats> = master_rules
                .lock()
                .unwrap()
                .values()
                .map(|rule| crate::FlowStats {
                    input_group: rule.input_group,
                    input_port: rule.input_port,
                    packets_relayed: 0,
                    bytes_relayed: 0,
                    packets_per_second: 0.0,
                    bits_per_second: 0.0,
                })
                .collect();
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

        SupervisorCommand::GetWorkerRules { .. } => {
            // This command requires async worker communication, not handled here
            (
                Response::Error("GetWorkerRules not supported in synchronous handler".to_string()),
                CommandAction::None,
            )
        }
    }
}

pub async fn spawn_control_plane_worker(
    uid: u32,
    gid: u32,
    relay_command_socket_path: PathBuf,
    prometheus_addr: Option<std::net::SocketAddr>,
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
        .arg(relay_command_socket_path);

    if let Some(addr) = prometheus_addr {
        command.arg("--prometheus-addr").arg(addr.to_string());
    }

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

    // Send the request/response socket to the child process via SCM_RIGHTS
    let req_supervisor_stream = create_and_send_socketpair(&supervisor_sock).await?;

    Ok((child, supervisor_sock, req_supervisor_stream))
}

pub async fn spawn_data_plane_worker(
    core_id: u32,
    _uid: u32,
    _gid: u32,
    interface: String,
    relay_command_socket_path: PathBuf,
    logger: &crate::logging::Logger,
) -> Result<(Child, UnixStream, UnixStream)> {
    logger.info(
        Facility::Supervisor,
        &format!("Spawning Data Plane worker for core {}", core_id),
    );

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
        .arg(interface);

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

    // Send the request/response socket to the child process
    let req_supervisor_stream = create_and_send_socketpair(&supervisor_sock).await?;

    // Send the command socket to the child process
    let cmd_supervisor_stream = create_and_send_socketpair(&supervisor_sock).await?;

    Ok((child, cmd_supervisor_stream, req_supervisor_stream))
}

// --- WorkerManager Implementation ---

impl WorkerManager {
    /// Create a new WorkerManager with the given configuration
    fn new(
        uid: u32,
        gid: u32,
        interface: String,
        relay_command_socket_path: PathBuf,
        prometheus_addr: Option<std::net::SocketAddr>,
        num_cores: usize,
        logger: Logger,
    ) -> Self {
        Self {
            uid,
            gid,
            interface,
            relay_command_socket_path,
            prometheus_addr,
            num_cores,
            logger,
            workers: HashMap::new(),
            backoff_counters: HashMap::new(),
        }
    }

    /// Spawn the control plane worker
    async fn spawn_control_plane(&mut self) -> Result<()> {
        let (child, cmd_stream, req_stream) = spawn_control_plane_worker(
            self.uid,
            self.gid,
            self.relay_command_socket_path.clone(),
            self.prometheus_addr,
            &self.logger,
        )
        .await?;

        let pid = child.id().unwrap();
        let cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(cmd_stream));
        let req_stream_arc = Arc::new(tokio::sync::Mutex::new(req_stream));

        // Store worker info
        self.workers.insert(
            pid,
            Worker {
                pid,
                worker_type: WorkerType::ControlPlane,
                child,
                cmd_stream: Some(cmd_stream_arc),
                req_stream: req_stream_arc,
                #[cfg(not(feature = "testing"))]
                log_manager: None,
            },
        );

        // Initialize backoff counter (core_id 0 for CP)
        self.backoff_counters.insert(0, INITIAL_BACKOFF_MS);

        Ok(())
    }

    /// Spawn a data plane worker for the given core
    async fn spawn_data_plane(&mut self, core_id: u32) -> Result<()> {
        let supervisor_pid = std::process::id();

        // Create shared memory for this worker's logging (REQUIRED in production)
        #[cfg(not(feature = "testing"))]
        let log_manager = SharedMemoryLogManager::create_for_worker(supervisor_pid, core_id as u8, 16384)
            .with_context(|| format!("Failed to create shared memory for worker {}", core_id))?;

        let (child, cmd_stream, req_stream) = spawn_data_plane_worker(
            core_id,
            self.uid,
            self.gid,
            self.interface.clone(),
            self.relay_command_socket_path.clone(),
            &self.logger,
        )
        .await?;

        let pid = child.id().unwrap();
        let cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(cmd_stream));
        let req_stream_arc = Arc::new(tokio::sync::Mutex::new(req_stream));

        // Store worker info
        self.workers.insert(
            pid,
            Worker {
                pid,
                worker_type: WorkerType::DataPlane { core_id },
                child,
                cmd_stream: Some(cmd_stream_arc),
                req_stream: req_stream_arc,
                #[cfg(not(feature = "testing"))]
                log_manager: Some(log_manager),
            },
        );

        // Initialize backoff counter
        self.backoff_counters
            .insert(core_id + 1, INITIAL_BACKOFF_MS);

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

        // Clean up any stale shared memory from previous crashed/killed instances
        #[cfg(not(feature = "testing"))]
        SharedMemoryLogManager::cleanup_stale_shared_memory(std::process::id(), Some(self.num_cores as u8));

        // Spawn data plane workers
        for core_id in 0..self.num_cores as u32 {
            self.spawn_data_plane(core_id).await?;
        }

        Ok(())
    }

    /// Check for exited workers and restart them with exponential backoff
    /// Returns Some(pid) if a worker exited, None otherwise
    async fn check_and_restart_worker(&mut self) -> Result<Option<u32>> {
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
            }
        }

        Ok(Some(pid))
    }

    /// Initiate graceful shutdown of all workers with timeout
    async fn shutdown_all(&mut self, timeout: Duration) {
        log_info!(
            self.logger,
            Facility::Supervisor,
            "Graceful shutdown initiated, signaling workers"
        );

        // Signal all workers to shut down by sending explicit Shutdown command
        for (_pid, worker) in &self.workers {
            if let Some(cmd_stream) = &worker.cmd_stream {
                let cmd_bytes = serde_json::to_vec(&RelayCommand::Shutdown).unwrap();
                let stream_mutex = cmd_stream.clone();
                let worker_type_desc = format!("{:?}", worker.worker_type);

                tokio::spawn(async move {
                    let mut stream = stream_mutex.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    if let Err(e) = framed.send(cmd_bytes.into()).await {
                        eprintln!("[Supervisor] Failed to send Shutdown to {}: {}", worker_type_desc, e);
                    }
                });
            }
        }

        // Wait for all workers to exit with timeout
        let num_workers = self.workers.len();
        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("Waiting for {} workers to exit (timeout: {:?})", num_workers, timeout)
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
    fn get_all_dp_cmd_streams(&self) -> Vec<Arc<tokio::sync::Mutex<UnixStream>>> {
        self.workers
            .values()
            .filter_map(|w| w.cmd_stream.clone())
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
}

// --- Client Handling ---

/// Handle a single client connection on the control socket
async fn handle_client(
    mut client_stream: tokio::net::UnixStream,
    worker_manager: Arc<Mutex<WorkerManager>>,
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
    global_min_level: Arc<std::sync::atomic::AtomicU8>,
    facility_min_levels: Arc<
        std::sync::RwLock<std::collections::HashMap<crate::logging::Facility, crate::logging::Severity>>,
    >,
) -> Result<()> {
    use crate::SupervisorCommand;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = Vec::new();
    client_stream.read_to_end(&mut buffer).await?;

    let command: SupervisorCommand = serde_json::from_slice(&buffer)?;

    // Get worker info from WorkerManager (locked access)
    let worker_info = {
        let manager = worker_manager.lock().unwrap();
        manager.get_worker_info()
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
    );

    // Send response to client
    let response_bytes = serde_json::to_vec(&response)?;
    client_stream.write_all(&response_bytes).await?;

    // Handle async actions
    match action {
        CommandAction::None => {
            // Nothing to do
        }
        CommandAction::BroadcastToDataPlane(relay_cmd) => {
            let cmd_bytes = serde_json::to_vec(&relay_cmd)?;

            // Get cmd streams from WorkerManager
            let streams_to_send = {
                let manager = worker_manager.lock().unwrap();
                manager.get_all_dp_cmd_streams()
            };

            for stream_mutex in streams_to_send {
                let cmd_bytes_clone = cmd_bytes.clone();
                tokio::spawn(async move {
                    let mut stream = stream_mutex.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    let _ = framed.send(cmd_bytes_clone.into()).await;
                });
            }
        }
    }

    Ok(())
}

// --- Supervisor Core Logic ---

#[allow(clippy::too_many_arguments)]
pub async fn run(
    user: &str,
    group: &str,
    interface: &str,
    prometheus_addr: Option<std::net::SocketAddr>,
    _relay_command_rx: mpsc::Receiver<RelayCommand>,
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

    // Initialize WorkerManager and wrap it in Arc<Mutex<>>
    let worker_manager = {
        let mut manager = WorkerManager::new(
            uid,
            gid,
            interface.to_string(),
            relay_command_socket_path,
            prometheus_addr,
            num_cores,
            supervisor_logger.clone(),
        );

        // Spawn all initial workers
        manager.spawn_all_initial_workers().await?;

        Arc::new(Mutex::new(manager))
    };

    // Main supervisor loop
    loop {
        tokio::select! {
            // Shutdown signal received
            _ = &mut shutdown_rx => {
                worker_manager.lock().unwrap().shutdown_all(Duration::from_secs(SHUTDOWN_TIMEOUT_SECS)).await;
                break;
            }

            // New client connection
            Ok((client_stream, _)) = listener.accept() => {
                let worker_manager = Arc::clone(&worker_manager);
                let master_rules = Arc::clone(&master_rules);
                let global_min_level = Arc::clone(&global_min_level);
                let facility_min_levels = Arc::clone(&facility_min_levels);

                tokio::spawn(async move {
                    if let Err(e) = handle_client(
                        client_stream,
                        worker_manager,
                        master_rules,
                        global_min_level,
                        facility_min_levels,
                    )
                    .await
                    {
                        error!("Error handling client: {}", e);
                    }
                });
            }

            // Periodic worker health check (every 250ms)
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                if let Err(e) = worker_manager.lock().unwrap().check_and_restart_worker().await {
                    error!("Error checking/restarting worker: {}", e);
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
    use std::time::Instant;
    use tempfile::tempdir;

    /// Clean up leftover shared memory from previous test runs
    fn cleanup_shared_memory() {
        for core_id in 0..4 {
            for facility in ["dataplane", "ingress", "egress", "bufferpool"] {
                let _ = std::fs::remove_file(format!("/dev/shm/mcr_dp_c{}_{}", core_id, facility));
            }
        }
    }

    // --- Test Helpers ---

    #[allow(clippy::type_complexity)] // Test helper with intentionally complex return type
    fn create_test_logger() -> (
        Logger,
        Arc<std::sync::atomic::AtomicU8>,
        Arc<
            std::sync::RwLock<
                std::collections::HashMap<crate::logging::Facility, crate::logging::Severity>,
            >,
        >,
    ) {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(64));
        let global_min_level = Arc::new(std::sync::atomic::AtomicU8::new(
            crate::logging::Severity::Info as u8,
        ));
        let facility_min_levels =
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let logger = Logger::from_mpsc(
            ringbuffer,
            Arc::clone(&global_min_level),
            Arc::clone(&facility_min_levels),
        );
        (logger, global_min_level, facility_min_levels)
    }

    fn spawn_failing_worker() -> anyhow::Result<Child> {
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg("exit 1");
        command
            .spawn()
            .map_err(anyhow::Error::from)
            .context("Failed to spawn failing worker")
    }

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

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::ListWorkers,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![],
                dtls_enabled: false,
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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
                dtls_enabled: false,
            },
        );
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::RemoveRule {
                rule_id: "test-rule".to_string(),
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::RemoveRule {
                rule_id: "nonexistent".to_string(),
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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
                dtls_enabled: false,
            },
        );
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::ListRules,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetStats,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::SetGlobalLogLevel {
                level: crate::logging::Severity::Debug,
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::SetFacilityLogLevel {
                facility: crate::logging::Facility::Ingress,
                level: crate::logging::Severity::Debug,
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetLogLevels,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
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

    // --- Existing Integration Tests ---

    fn spawn_sleeping_worker() -> anyhow::Result<Child> {
        let mut command = tokio::process::Command::new("sleep");
        command.arg("30");
        command
            .spawn()
            .map_err(anyhow::Error::from)
            .context("Failed to spawn sleeping worker")
    }
}
