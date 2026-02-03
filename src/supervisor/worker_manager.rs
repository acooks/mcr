// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Worker process lifecycle management.
//!
//! This module handles spawning, monitoring, and managing data plane worker processes.
//! Workers are spawned per-interface with configurable core pinning and fanout groups.

use anyhow::Result;
use futures::SinkExt;
use std::collections::HashMap;
#[cfg(not(feature = "testing"))]
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::sync::{Arc, Mutex};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::Duration;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::logging::{Facility, Logger};
use crate::{log_debug, log_info, log_warning, RelayCommand};

use super::socket_helpers;

/// Initial backoff delay for restarting failed workers
pub(super) const INITIAL_BACKOFF_MS: u64 = 250;
/// Maximum backoff delay for restarting failed workers (16 seconds)
pub(super) const MAX_BACKOFF_MS: u64 = 16000;

/// Type alias for a pair of async command streams (ingress, egress)
pub(super) type CmdStreamPair = (
    Arc<tokio::sync::Mutex<UnixStream>>,
    Arc<tokio::sync::Mutex<UnixStream>>,
);

/// Type alias for command streams with associated interface name
pub(super) type CmdStreamWithInterface = (
    String,
    Arc<tokio::sync::Mutex<UnixStream>>,
    Arc<tokio::sync::Mutex<UnixStream>>,
);

/// Result of spawning a data plane worker process.
///
/// Bundles the child process handle, command streams, and optional pipes
/// returned by `spawn_data_plane_worker()`.
pub(super) struct SpawnedWorker {
    pub child: tokio::process::Child,
    pub ingress_cmd_stream: UnixStream,
    pub egress_cmd_stream: UnixStream,
    pub log_pipe: Option<std::os::unix::io::OwnedFd>,
    pub stats_pipe: Option<std::os::unix::io::OwnedFd>,
}

/// Differentiates worker types for unified handling
#[derive(Debug, Clone, PartialEq)]
pub(super) enum WorkerType {
    DataPlane { interface: String, core_id: u32 },
}

/// Holds all information about a single worker process
pub(super) struct Worker {
    pub(super) pid: u32,
    pub(super) worker_type: WorkerType,
    pub(super) child: Child,
    // Data plane workers have TWO command streams (ingress + egress)
    pub(super) ingress_cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
    pub(super) egress_cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
    #[cfg_attr(feature = "testing", allow(dead_code))]
    pub(super) log_pipe: Option<std::os::unix::io::OwnedFd>,
    #[cfg_attr(feature = "testing", allow(dead_code))]
    pub(super) stats_pipe: Option<std::os::unix::io::OwnedFd>,
}

/// Per-interface worker configuration and state
pub(super) struct InterfaceWorkers {
    /// Number of workers for this interface (from pinning config or default 1)
    pub(super) num_workers: usize,
    /// Fanout group ID for this interface (auto-assigned, unique per interface)
    pub(super) fanout_group_id: u16,
    /// Specific core IDs to pin workers to (from config pinning section)
    /// If None, workers use sequential core IDs starting from 0
    pub(super) pinned_cores: Option<Vec<u32>>,
}

/// Centralized manager for all worker lifecycle operations
pub(super) struct WorkerManager {
    // Configuration
    pub(super) num_cores_per_interface: usize,
    pub(super) logger: Logger,
    /// Core pinning configuration from startup config (interface -> core list)
    pub(super) pinning: HashMap<String, Vec<u32>>,

    // Per-interface state
    pub(super) interfaces: HashMap<String, InterfaceWorkers>,
    pub(super) next_fanout_group_id: u16,

    // Worker state
    pub(super) workers: HashMap<u32, Worker>,
    pub(super) backoff_counters: HashMap<(String, u32), u64>,
    pub(super) worker_stats: Arc<Mutex<HashMap<u32, Vec<crate::FlowStats>>>>,

    /// Tracks workers currently being restarted (interface, core_id) -> backoff_ms
    pub(super) restarting: HashMap<(String, u32), u64>,

    /// Tracks failed initial spawns pending retry (interface, core_id) -> (backoff_ms, fanout_group_id)
    pub(super) pending_spawns: HashMap<(String, u32), (u64, u16)>,
}

/// Information about a worker that has exited, for async restart handling
pub(super) struct ExitedWorkerInfo {
    pub(super) interface: String,
    pub(super) core_id: u32,
    pub(super) graceful: bool,
    pub(super) backoff_ms: u64,
    pub(super) fanout_group_id: u16,
}

/// Spawn a data plane worker process for the given interface and core.
///
/// Creates necessary IPC channels (command streams, log pipe, stats pipe) and
/// spawns the worker subprocess. The worker receives AF_PACKET socket from
/// the supervisor via SCM_RIGHTS for privilege separation.
///
/// IMPORTANT: The AF_PACKET socket is created BEFORE spawning the child process.
/// This ensures that if socket creation fails (e.g., interface doesn't exist),
/// no orphaned child process is left running.
pub async fn spawn_data_plane_worker(
    core_id: u32,
    interface: String,
    fanout_group_id: u16,
    logger: &Logger,
) -> Result<SpawnedWorker> {
    logger.debug(
        Facility::Supervisor,
        &format!(
            "Spawning worker for interface '{}' core {} (fanout_group_id={})",
            interface, core_id, fanout_group_id
        ),
    );

    // Create AF_PACKET socket FIRST - if this fails (e.g., interface doesn't exist),
    // we return early without spawning a child process. This prevents orphaned workers.
    let af_packet_socket =
        socket_helpers::create_af_packet_socket(&interface, fanout_group_id, logger)?;

    log_debug!(
        logger,
        Facility::Supervisor,
        &format!(
            "AF_PACKET socket created for interface '{}' (fd={})",
            interface,
            af_packet_socket.as_raw_fd()
        )
    );

    // Create pipe for worker stderr (for JSON logging).
    // Keep as OwnedFd to ensure cleanup on error paths.
    #[cfg(not(feature = "testing"))]
    let (log_read_fd, log_write_fd) = {
        use nix::unistd::pipe;
        let (read_fd, write_fd) = pipe()?;
        (Some(read_fd), Some(write_fd))
    };
    #[cfg(feature = "testing")]
    let (log_read_fd, log_write_fd): (
        Option<std::os::unix::io::OwnedFd>,
        Option<std::os::unix::io::OwnedFd>,
    ) = (None, None);

    // Create pipe for worker stats (JSON stats reporting).
    // Keep as OwnedFd to ensure cleanup on error paths.
    #[cfg(not(feature = "testing"))]
    let (stats_read_fd, stats_write_fd) = {
        use nix::unistd::pipe;
        let (read_fd, write_fd) = pipe()?;
        (Some(read_fd), Some(write_fd))
    };
    #[cfg(feature = "testing")]
    let (stats_read_fd, stats_write_fd): (
        Option<std::os::unix::io::OwnedFd>,
        Option<std::os::unix::io::OwnedFd>,
    ) = (None, None);

    // Extract raw FD values for the pre_exec closure (raw FDs are Copy).
    // The OwnedFds above ensure cleanup if spawn fails.
    #[cfg(not(feature = "testing"))]
    let (log_read_raw, log_write_raw) = (
        log_read_fd.as_ref().map(|fd| fd.as_raw_fd()),
        log_write_fd.as_ref().map(|fd| fd.as_raw_fd()),
    );
    #[cfg(not(feature = "testing"))]
    let stats_read_raw = stats_read_fd.as_ref().map(|fd| fd.as_raw_fd());

    // Create the supervisor-worker communication socket pair
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
        .arg("--input-interface-name")
        .arg(&interface)
        .arg("--fanout-group-id")
        .arg(fanout_group_id.to_string())
        .process_group(0);

    // Pass stats pipe FD via environment variable
    #[cfg(not(feature = "testing"))]
    if let Some(ref write_fd) = stats_write_fd {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        use std::os::fd::AsFd;
        command.env("MCR_STATS_PIPE_FD", write_fd.as_raw_fd().to_string());
        let flags = fcntl(write_fd.as_fd(), FcntlArg::F_GETFD)?;
        let mut fd_flags = FdFlag::from_bits_truncate(flags);
        fd_flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(write_fd.as_fd(), FcntlArg::F_SETFD(fd_flags))?;
    }

    // Ensure worker_sock becomes FD 3 in the child, and redirect stderr to pipe.
    // The closure captures raw FD values (Copy) so OwnedFds remain in parent for cleanup.
    unsafe {
        command.pre_exec(move || {
            if worker_fd != 3 {
                if libc::dup2(worker_fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(worker_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            #[cfg(not(feature = "testing"))]
            if let Some(write_fd) = log_write_raw {
                if libc::dup2(write_fd, 2) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(write_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(read_fd) = log_read_raw {
                    if libc::close(read_fd) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }

            #[cfg(not(feature = "testing"))]
            if let Some(read_fd) = stats_read_raw {
                if libc::close(read_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }

    let child = command.spawn()?;

    // Close write ends in parent by dropping the OwnedFds.
    // Read ends are kept for log/stats consumption.
    drop(log_write_fd);
    drop(stats_write_fd);

    // log_read_fd and stats_read_fd are already OwnedFd
    let log_pipe = log_read_fd;
    let stats_pipe = stats_read_fd;

    // Send TWO command sockets to the child process
    let ingress_cmd_supervisor_stream =
        socket_helpers::create_and_send_socketpair(&supervisor_sock).await?;
    let egress_cmd_supervisor_stream =
        socket_helpers::create_and_send_socketpair(&supervisor_sock).await?;

    // Send the pre-created AF_PACKET socket to the worker
    socket_helpers::send_fd(&supervisor_sock, af_packet_socket.as_raw_fd()).await?;
    drop(af_packet_socket);

    Ok(SpawnedWorker {
        child,
        ingress_cmd_stream: ingress_cmd_supervisor_stream,
        egress_cmd_stream: egress_cmd_supervisor_stream,
        log_pipe,
        stats_pipe,
    })
}

impl WorkerManager {
    /// Create a new WorkerManager with the given configuration
    pub(super) fn new(
        num_cores_per_interface: usize,
        logger: Logger,
        initial_fanout_group_id: u16,
        pinning: HashMap<String, Vec<u32>>,
    ) -> Self {
        Self {
            num_cores_per_interface,
            logger,
            pinning,
            interfaces: HashMap::new(),
            next_fanout_group_id: initial_fanout_group_id,
            workers: HashMap::new(),
            backoff_counters: HashMap::new(),
            worker_stats: Arc::new(Mutex::new(HashMap::new())),
            restarting: HashMap::new(),
            pending_spawns: HashMap::new(),
        }
    }

    /// Get or create fanout group ID for an interface
    pub(super) fn get_or_create_interface(&mut self, interface: &str, is_pinned: bool) -> u16 {
        if let Some(iface_workers) = self.interfaces.get(interface) {
            return iface_workers.fanout_group_id;
        }

        let fanout_group_id = self.next_fanout_group_id;
        self.next_fanout_group_id = self.next_fanout_group_id.wrapping_add(1);

        let pinned_cores = self.pinning.get(interface).cloned();

        let num_workers = if let Some(ref cores) = pinned_cores {
            cores.len()
        } else if is_pinned {
            self.num_cores_per_interface
        } else {
            1
        };

        self.interfaces.insert(
            interface.to_string(),
            InterfaceWorkers {
                num_workers,
                fanout_group_id,
                pinned_cores: pinned_cores.clone(),
            },
        );

        if let Some(ref cores) = pinned_cores {
            log_debug!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Registered interface '{}' with fanout_group_id={}, pinned to cores {:?}",
                    interface, fanout_group_id, cores
                )
            );
        } else {
            log_debug!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Registered interface '{}' with fanout_group_id={}, workers={}",
                    interface, fanout_group_id, num_workers
                )
            );
        }

        fanout_group_id
    }

    /// Check if workers exist (or are being restarted) for a given interface
    pub(super) fn has_workers_for_interface(&self, interface: &str) -> bool {
        self.workers.values().any(|w| {
            matches!(&w.worker_type, WorkerType::DataPlane { interface: iface, .. } if iface == interface)
        }) || self.is_restarting_for_interface(interface)
    }

    /// Spawn a data plane worker for the given interface and core
    pub(super) async fn spawn_data_plane_for_interface(
        &mut self,
        interface: &str,
        core_id: u32,
        fanout_group_id: u16,
    ) -> Result<()> {
        let spawned = spawn_data_plane_worker(
            core_id,
            interface.to_string(),
            fanout_group_id,
            &self.logger,
        )
        .await?;

        let pid = spawned
            .child
            .id()
            .ok_or_else(|| anyhow::anyhow!("Worker process exited immediately after spawn"))?;
        let ingress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(spawned.ingress_cmd_stream));
        let egress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(spawned.egress_cmd_stream));

        self.workers.insert(
            pid,
            Worker {
                pid,
                worker_type: WorkerType::DataPlane {
                    interface: interface.to_string(),
                    core_id,
                },
                child: spawned.child,
                ingress_cmd_stream: Some(ingress_cmd_stream_arc),
                egress_cmd_stream: Some(egress_cmd_stream_arc),
                log_pipe: spawned.log_pipe,
                stats_pipe: spawned.stats_pipe,
            },
        );

        log_debug!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Worker spawned for interface '{}' (PID={}, core={})",
                interface, pid, core_id
            )
        );

        self.backoff_counters
            .insert((interface.to_string(), core_id), INITIAL_BACKOFF_MS);

        #[cfg(not(feature = "testing"))]
        if let Some(pipe_fd) = self.workers.get(&pid).and_then(|w| w.log_pipe.as_ref()) {
            self.spawn_log_consumer(pid, pipe_fd)?;
        }

        #[cfg(not(feature = "testing"))]
        if let Some(pipe_fd) = self.workers.get(&pid).and_then(|w| w.stats_pipe.as_ref()) {
            self.spawn_stats_consumer(pid, pipe_fd)?;
        }

        Ok(())
    }

    /// Plan which workers need spawning for an interface (non-async).
    ///
    /// Returns None if workers already exist, or Some((core_ids, fanout_group_id))
    /// with the list of core IDs to spawn. The caller should drop the lock,
    /// spawn workers using `spawn_data_plane_worker()`, then call
    /// `register_spawned_worker()` to register them.
    pub(super) fn plan_workers_for_interface(
        &mut self,
        interface: &str,
        is_pinned: bool,
    ) -> Option<(Vec<u32>, u16)> {
        if self.has_workers_for_interface(interface) {
            return None;
        }

        let fanout_group_id = self.get_or_create_interface(interface, is_pinned);

        let (num_workers, pinned_cores) = self
            .interfaces
            .get(interface)
            .map(|i| (i.num_workers, i.pinned_cores.clone()))
            .unwrap_or((1, None));

        log_debug!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Planning {} worker(s) for interface '{}' (fanout_group_id={}{})",
                num_workers,
                interface,
                fanout_group_id,
                if pinned_cores.is_some() {
                    ", pinned"
                } else {
                    ""
                }
            )
        );

        let core_ids = if let Some(cores) = pinned_cores {
            cores
        } else {
            (0..num_workers as u32).collect()
        };

        Some((core_ids, fanout_group_id))
    }

    /// Spawn workers for an interface (if not already spawned).
    ///
    /// Note: This method holds &mut self across .await points. It is safe to call
    /// from contexts that don't need to remain responsive (e.g. startup), but
    /// should NOT be called from inside the main select! loop. Use
    /// plan_workers_for_interface() + tokio::spawn for non-blocking spawning.
    pub(super) async fn ensure_workers_for_interface(
        &mut self,
        interface: &str,
        is_pinned: bool,
    ) -> Result<bool> {
        let plan = self.plan_workers_for_interface(interface, is_pinned);
        let (core_ids, fanout_group_id) = match plan {
            Some(p) => p,
            None => return Ok(false),
        };

        for core_id in core_ids {
            self.spawn_data_plane_for_interface(interface, core_id, fanout_group_id)
                .await?;
        }

        Ok(true)
    }

    /// Detect exited workers (non-blocking) and return info needed for async restart.
    ///
    /// This is the fast detection phase: calls try_wait() on all workers,
    /// removes dead workers, updates backoff counters, and marks entries in
    /// `self.restarting`. The caller handles the slow work (sleep + spawn)
    /// outside the select! loop via tokio::spawn.
    pub(super) fn detect_exited_workers(&mut self) -> Vec<ExitedWorkerInfo> {
        let mut exited_workers = Vec::new();
        for (pid, worker) in &mut self.workers {
            match worker.child.try_wait() {
                Ok(Some(status)) => {
                    exited_workers.push((*pid, worker.worker_type.clone(), status));
                }
                Ok(None) => continue,
                Err(e) => {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("Error checking worker {}: {}", pid, e)
                    );
                    continue;
                }
            }
        }

        let mut result = Vec::new();
        for (pid, worker_type, status) in exited_workers {
            self.workers.remove(&pid);

            let WorkerType::DataPlane { interface, core_id } = worker_type;
            let backoff_key = (interface.clone(), core_id);
            let graceful = status.success();

            let backoff_ms = if graceful {
                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "Data Plane worker PID {} (interface={}, core={}) exited gracefully, restarting immediately",
                        pid, interface, core_id
                    )
                );
                // Reset backoff for graceful exits
                self.backoff_counters
                    .insert(backoff_key.clone(), INITIAL_BACKOFF_MS);
                0 // no sleep needed
            } else {
                let backoff = self
                    .backoff_counters
                    .entry(backoff_key.clone())
                    .or_insert(INITIAL_BACKOFF_MS);
                let current_backoff = *backoff;
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "Data Plane worker PID {} (interface={}, core={}) failed (status: {}), restarting after {}ms",
                        pid, interface, core_id, status, current_backoff
                    )
                );
                *backoff = (*backoff * 2).min(MAX_BACKOFF_MS);
                current_backoff
            };

            let fanout_group_id = self
                .interfaces
                .get(&interface)
                .map(|i| i.fanout_group_id)
                .unwrap_or(0);

            // Mark as restarting so get_worker_info() reports it
            self.restarting.insert(backoff_key, backoff_ms);

            result.push(ExitedWorkerInfo {
                interface,
                core_id,
                graceful,
                backoff_ms,
                fanout_group_id,
            });
        }

        result
    }

    /// Track a failed initial spawn attempt for retry with exponential backoff.
    /// Returns the backoff duration in milliseconds.
    pub(super) fn track_failed_spawn(
        &mut self,
        interface: &str,
        core_id: u32,
        fanout_group_id: u16,
    ) -> u64 {
        let key = (interface.to_string(), core_id);

        // Calculate backoff using existing exponential pattern
        let backoff = self
            .backoff_counters
            .entry(key.clone())
            .or_insert(INITIAL_BACKOFF_MS);
        let current_backoff = *backoff;
        *backoff = (*backoff * 2).min(MAX_BACKOFF_MS);

        // Track as pending spawn and in restarting (for ListWorkers visibility)
        self.pending_spawns
            .insert(key.clone(), (current_backoff, fanout_group_id));
        self.restarting.insert(key, current_backoff);

        current_backoff
    }

    /// Drain pending spawn retries, returning them as ExitedWorkerInfo for unified handling.
    pub(super) fn drain_pending_spawns(&mut self) -> Vec<ExitedWorkerInfo> {
        self.pending_spawns
            .drain()
            .map(
                |((interface, core_id), (backoff_ms, fanout_group_id))| ExitedWorkerInfo {
                    interface,
                    core_id,
                    graceful: false, // always apply backoff
                    backoff_ms,
                    fanout_group_id,
                },
            )
            .collect()
    }

    /// Drain pending spawns for a specific interface (called on netlink interface-up event).
    ///
    /// This enables immediate retry when an interface appears, rather than waiting
    /// for the next health check tick.
    pub(super) fn drain_pending_spawns_for_interface(
        &mut self,
        interface: &str,
    ) -> Vec<ExitedWorkerInfo> {
        let keys_to_remove: Vec<_> = self
            .pending_spawns
            .keys()
            .filter(|(iface, _)| iface == interface)
            .cloned()
            .collect();

        keys_to_remove
            .into_iter()
            .filter_map(|key| {
                let (backoff_ms, fanout_group_id) = self.pending_spawns.remove(&key)?;
                // Also remove from restarting since we're handling it now
                self.restarting.remove(&key);
                Some(ExitedWorkerInfo {
                    interface: key.0,
                    core_id: key.1,
                    graceful: true, // Skip backoff - interface just came up
                    backoff_ms,
                    fanout_group_id,
                })
            })
            .collect()
    }

    /// Register a newly spawned worker after async restart completes.
    ///
    /// Inserts the worker, clears the restarting entry, resets backoff,
    /// and spawns log/stats consumers.
    pub(super) fn register_spawned_worker(
        &mut self,
        spawned: SpawnedWorker,
        interface: &str,
        core_id: u32,
    ) -> Result<u32> {
        let pid = spawned
            .child
            .id()
            .ok_or_else(|| anyhow::anyhow!("Worker process exited immediately after spawn"))?;

        let ingress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(spawned.ingress_cmd_stream));
        let egress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(spawned.egress_cmd_stream));

        self.workers.insert(
            pid,
            Worker {
                pid,
                worker_type: WorkerType::DataPlane {
                    interface: interface.to_string(),
                    core_id,
                },
                child: spawned.child,
                ingress_cmd_stream: Some(ingress_cmd_stream_arc),
                egress_cmd_stream: Some(egress_cmd_stream_arc),
                log_pipe: spawned.log_pipe,
                stats_pipe: spawned.stats_pipe,
            },
        );

        // Clear restarting state
        self.restarting.remove(&(interface.to_string(), core_id));

        // Reset backoff on successful spawn
        self.backoff_counters
            .insert((interface.to_string(), core_id), INITIAL_BACKOFF_MS);

        log_debug!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Worker registered for interface '{}' (PID={}, core={})",
                interface, pid, core_id
            )
        );

        #[cfg(not(feature = "testing"))]
        if let Some(pipe_fd) = self.workers.get(&pid).and_then(|w| w.log_pipe.as_ref()) {
            self.spawn_log_consumer(pid, pipe_fd)?;
        }

        #[cfg(not(feature = "testing"))]
        if let Some(pipe_fd) = self.workers.get(&pid).and_then(|w| w.stats_pipe.as_ref()) {
            self.spawn_stats_consumer(pid, pipe_fd)?;
        }

        Ok(pid)
    }

    /// Check if an interface has workers currently being restarted
    pub(super) fn is_restarting_for_interface(&self, interface: &str) -> bool {
        self.restarting.keys().any(|(iface, _)| iface == interface)
    }

    /// Initiate graceful shutdown of all workers with timeout
    pub(super) async fn shutdown_all(&mut self, timeout: Duration) {
        log_info!(
            self.logger,
            Facility::Supervisor,
            "Graceful shutdown initiated, signaling workers"
        );

        let mut shutdown_tasks = Vec::new();

        for worker in self.workers.values() {
            let cmd_bytes = serde_json::to_vec(&RelayCommand::Shutdown).unwrap();

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

        let send_timeout = Duration::from_secs(1);
        match tokio::time::timeout(send_timeout, futures::future::join_all(shutdown_tasks)).await {
            Ok(_) => {
                eprintln!("[Supervisor] All shutdown commands sent successfully");
            }
            Err(_) => {
                eprintln!("[Supervisor] Warning: Timeout sending shutdown commands");
            }
        }

        let grace_period = Duration::from_millis(500);
        eprintln!(
            "[Supervisor] Waiting {:?} grace period for workers to process shutdown",
            grace_period
        );
        tokio::time::sleep(grace_period).await;

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
            if shutdown_start.elapsed() >= timeout {
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "Shutdown timeout exceeded, {} workers still running, force killing",
                        self.workers.len()
                    )
                );

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

            for pid in exited_pids {
                self.workers.remove(&pid);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("All workers exited ({} total)", exited_count)
        );
    }

    /// Get all data plane command streams for broadcasting
    pub(super) fn get_all_dp_cmd_streams(&self) -> Vec<CmdStreamPair> {
        self.workers
            .values()
            .filter(|w| matches!(w.worker_type, WorkerType::DataPlane { .. }))
            .filter_map(|w| match (&w.ingress_cmd_stream, &w.egress_cmd_stream) {
                (Some(ingress), Some(egress)) => Some((ingress.clone(), egress.clone())),
                _ => None,
            })
            .collect()
    }

    /// Get all data plane command streams with interface name
    pub(super) fn get_all_dp_cmd_streams_with_interface(&self) -> Vec<CmdStreamWithInterface> {
        self.workers
            .values()
            .filter_map(|w| {
                let WorkerType::DataPlane { interface, .. } = &w.worker_type;
                match (&w.ingress_cmd_stream, &w.egress_cmd_stream) {
                    (Some(ingress), Some(egress)) => {
                        Some((interface.clone(), ingress.clone(), egress.clone()))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// Get worker info for all workers (for ListWorkers command)
    ///
    /// Includes both running workers and workers currently being restarted.
    pub(super) fn get_worker_info(&self) -> Vec<crate::WorkerInfo> {
        let mut info: Vec<crate::WorkerInfo> = self
            .workers
            .values()
            .map(|w| {
                let WorkerType::DataPlane { interface, core_id } = &w.worker_type;
                crate::WorkerInfo {
                    pid: w.pid,
                    worker_type: "DataPlane".to_string(),
                    core_id: Some(*core_id),
                    interface: Some(interface.clone()),
                    status: crate::WorkerStatus::Running,
                }
            })
            .collect();

        // Add entries for workers currently being restarted
        for ((interface, core_id), backoff_ms) in &self.restarting {
            info.push(crate::WorkerInfo {
                pid: 0,
                worker_type: "DataPlane".to_string(),
                core_id: Some(*core_id),
                interface: Some(interface.clone()),
                status: crate::WorkerStatus::Restarting {
                    backoff_ms: *backoff_ms,
                },
            });
        }

        info
    }

    /// Spawn async task to consume JSON logs from worker's stderr pipe
    #[cfg(not(feature = "testing"))]
    pub(super) fn spawn_log_consumer(
        &self,
        worker_pid: u32,
        pipe_fd: &std::os::unix::io::OwnedFd,
    ) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let dup_fd_owned = nix::unistd::dup(pipe_fd)?;
        let dup_fd = dup_fd_owned.into_raw_fd();

        let std_file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let tokio_file = tokio::fs::File::from_std(std_file);
        let reader = BufReader::new(tokio_file);
        let mut lines = reader.lines();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[Worker {}] {}", worker_pid, line);
            }
            eprintln!("[Supervisor] Worker {} log stream closed", worker_pid);
        });

        Ok(())
    }

    /// Spawn async task to consume JSON stats from worker's stats pipe
    #[cfg(not(feature = "testing"))]
    pub(super) fn spawn_stats_consumer(
        &self,
        worker_pid: u32,
        pipe_fd: &std::os::unix::io::OwnedFd,
    ) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let dup_fd_owned = nix::unistd::dup(pipe_fd)?;
        let dup_fd = dup_fd_owned.into_raw_fd();

        let std_file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let tokio_file = tokio::fs::File::from_std(std_file);
        let reader = BufReader::new(tokio_file);
        let mut lines = reader.lines();

        let worker_stats = self.worker_stats.clone();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                match serde_json::from_str::<Vec<crate::FlowStats>>(&line) {
                    Ok(stats) => {
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
            worker_stats.lock().unwrap().remove(&worker_pid);
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{MPSCRingBuffer, Severity};
    use std::sync::atomic::AtomicU8;
    use std::sync::{Arc, RwLock};

    fn create_test_logger() -> Logger {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Debug as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));
        Logger::from_mpsc(ringbuffer, global_min_level, facility_min_levels)
    }

    fn create_test_manager() -> WorkerManager {
        WorkerManager::new(1, create_test_logger(), 1, HashMap::new())
    }

    #[test]
    fn test_track_failed_spawn_initial_backoff() {
        let mut mgr = create_test_manager();

        let backoff = mgr.track_failed_spawn("eth0", 0, 1);

        assert_eq!(backoff, INITIAL_BACKOFF_MS);
        assert!(mgr.pending_spawns.contains_key(&("eth0".to_string(), 0)));
        assert!(mgr.restarting.contains_key(&("eth0".to_string(), 0)));
    }

    #[test]
    fn test_track_failed_spawn_exponential_backoff() {
        let mut mgr = create_test_manager();

        // First failure: 250ms
        let backoff1 = mgr.track_failed_spawn("eth0", 0, 1);
        assert_eq!(backoff1, 250);

        // Drain to simulate retry
        mgr.drain_pending_spawns();

        // Second failure: 500ms
        let backoff2 = mgr.track_failed_spawn("eth0", 0, 1);
        assert_eq!(backoff2, 500);

        mgr.drain_pending_spawns();

        // Third failure: 1000ms
        let backoff3 = mgr.track_failed_spawn("eth0", 0, 1);
        assert_eq!(backoff3, 1000);
    }

    #[test]
    fn test_track_failed_spawn_max_backoff() {
        let mut mgr = create_test_manager();

        // Simulate many failures to reach max backoff
        for _ in 0..10 {
            mgr.track_failed_spawn("eth0", 0, 1);
            mgr.drain_pending_spawns();
        }

        let backoff = mgr.track_failed_spawn("eth0", 0, 1);
        assert_eq!(backoff, MAX_BACKOFF_MS);
    }

    #[test]
    fn test_drain_pending_spawns_empties_map() {
        let mut mgr = create_test_manager();

        mgr.track_failed_spawn("eth0", 0, 1);
        mgr.track_failed_spawn("eth1", 0, 2);

        assert_eq!(mgr.pending_spawns.len(), 2);

        let drained = mgr.drain_pending_spawns();

        assert_eq!(drained.len(), 2);
        assert!(mgr.pending_spawns.is_empty());
    }

    #[test]
    fn test_drain_pending_spawns_returns_correct_info() {
        let mut mgr = create_test_manager();

        mgr.track_failed_spawn("eth0", 0, 1);

        let drained = mgr.drain_pending_spawns();

        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].interface, "eth0");
        assert_eq!(drained[0].core_id, 0);
        assert_eq!(drained[0].fanout_group_id, 1);
        assert_eq!(drained[0].backoff_ms, INITIAL_BACKOFF_MS);
        assert!(!drained[0].graceful); // Should apply backoff
    }

    #[test]
    fn test_drain_pending_spawns_for_interface_filters_correctly() {
        let mut mgr = create_test_manager();

        mgr.track_failed_spawn("eth0", 0, 1);
        mgr.track_failed_spawn("eth0", 1, 1);
        mgr.track_failed_spawn("eth1", 0, 2);

        let drained = mgr.drain_pending_spawns_for_interface("eth0");

        assert_eq!(drained.len(), 2);
        assert!(drained.iter().all(|info| info.interface == "eth0"));

        // eth1 should still be pending
        assert_eq!(mgr.pending_spawns.len(), 1);
        assert!(mgr.pending_spawns.contains_key(&("eth1".to_string(), 0)));
    }

    #[test]
    fn test_drain_pending_spawns_for_interface_removes_from_restarting() {
        let mut mgr = create_test_manager();

        mgr.track_failed_spawn("eth0", 0, 1);

        assert!(mgr.restarting.contains_key(&("eth0".to_string(), 0)));

        mgr.drain_pending_spawns_for_interface("eth0");

        assert!(!mgr.restarting.contains_key(&("eth0".to_string(), 0)));
    }

    #[test]
    fn test_drain_pending_spawns_for_interface_sets_graceful_true() {
        let mut mgr = create_test_manager();

        mgr.track_failed_spawn("eth0", 0, 1);

        let drained = mgr.drain_pending_spawns_for_interface("eth0");

        assert_eq!(drained.len(), 1);
        assert!(drained[0].graceful); // Should skip backoff since interface just came up
    }

    #[test]
    fn test_drain_pending_spawns_for_interface_nonexistent() {
        let mut mgr = create_test_manager();

        mgr.track_failed_spawn("eth0", 0, 1);

        let drained = mgr.drain_pending_spawns_for_interface("eth1");

        assert!(drained.is_empty());
        // eth0 should still be pending
        assert_eq!(mgr.pending_spawns.len(), 1);
    }

    #[test]
    fn test_pending_spawns_visible_in_restarting() {
        let mut mgr = create_test_manager();

        mgr.track_failed_spawn("eth0", 0, 1);

        // is_restarting_for_interface should return true
        assert!(mgr.is_restarting_for_interface("eth0"));
        assert!(!mgr.is_restarting_for_interface("eth1"));
    }

    #[test]
    fn test_multiple_cores_same_interface() {
        let mut mgr = create_test_manager();

        mgr.track_failed_spawn("eth0", 0, 1);
        mgr.track_failed_spawn("eth0", 1, 1);
        mgr.track_failed_spawn("eth0", 2, 1);

        assert_eq!(mgr.pending_spawns.len(), 3);

        let drained = mgr.drain_pending_spawns_for_interface("eth0");

        assert_eq!(drained.len(), 3);
        let core_ids: Vec<u32> = drained.iter().map(|info| info.core_id).collect();
        assert!(core_ids.contains(&0));
        assert!(core_ids.contains(&1));
        assert!(core_ids.contains(&2));
    }
}
