// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Worker process lifecycle management.
//!
//! This module handles spawning, monitoring, and managing data plane worker processes.
//! Workers are spawned per-interface with configurable core pinning and fanout groups.

use anyhow::Result;
use futures::SinkExt;
use std::collections::HashMap;
#[cfg(feature = "testing")]
use std::os::unix::io::RawFd;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::sync::{Arc, Mutex};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::logging::{Facility, Logger};
use crate::{log_debug, log_info, log_warning, RelayCommand};

use super::socket_helpers;

/// Initial backoff delay for restarting failed workers
pub(super) const INITIAL_BACKOFF_MS: u64 = 250;
/// Maximum backoff delay for restarting failed workers (16 seconds)
pub(super) const MAX_BACKOFF_MS: u64 = 16000;

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
}

/// Spawn a data plane worker process for the given interface and core.
///
/// Creates necessary IPC channels (command streams, log pipe, stats pipe) and
/// spawns the worker subprocess. The worker receives AF_PACKET socket from
/// the supervisor via SCM_RIGHTS for privilege separation.
pub async fn spawn_data_plane_worker(
    core_id: u32,
    interface: String,
    fanout_group_id: u16,
    logger: &Logger,
) -> Result<(
    Child,
    UnixStream,
    UnixStream,
    Option<std::os::unix::io::OwnedFd>,
    Option<std::os::unix::io::OwnedFd>,
)> {
    logger.debug(
        Facility::Supervisor,
        &format!("Spawning worker for core {}", core_id),
    );

    // Create pipe for worker stderr (for JSON logging)
    #[cfg(not(feature = "testing"))]
    let (log_read_fd, log_write_fd) = {
        use nix::unistd::pipe;
        let (read_fd, write_fd) = pipe()?;
        (Some(read_fd.into_raw_fd()), Some(write_fd.into_raw_fd()))
    };
    #[cfg(feature = "testing")]
    let (_log_read_fd, _log_write_fd): (Option<RawFd>, Option<RawFd>) = (None, None);

    // Create pipe for worker stats (JSON stats reporting)
    #[cfg(not(feature = "testing"))]
    let (stats_read_fd, stats_write_fd) = {
        use nix::unistd::pipe;
        let (read_fd, write_fd) = pipe()?;
        (Some(read_fd.into_raw_fd()), Some(write_fd.into_raw_fd()))
    };
    #[cfg(feature = "testing")]
    let (_stats_read_fd, _stats_write_fd): (Option<RawFd>, Option<RawFd>) = (None, None);

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
    if let Some(write_fd) = stats_write_fd {
        command.env("MCR_STATS_PIPE_FD", write_fd.to_string());
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
            if worker_fd != 3 {
                if libc::dup2(worker_fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(worker_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            #[cfg(not(feature = "testing"))]
            if let Some(write_fd) = log_write_fd {
                if libc::dup2(write_fd, 2) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(write_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(read_fd) = log_read_fd {
                    if libc::close(read_fd) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }

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

    // Close write end in parent
    #[cfg(not(feature = "testing"))]
    if let Some(write_fd) = log_write_fd {
        nix::unistd::close(write_fd).ok();
    }

    #[cfg(not(feature = "testing"))]
    let log_pipe = log_read_fd.map(|fd| unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) });
    #[cfg(feature = "testing")]
    let log_pipe = None;

    #[cfg(not(feature = "testing"))]
    if let Some(write_fd) = stats_write_fd {
        nix::unistd::close(write_fd).ok();
    }

    #[cfg(not(feature = "testing"))]
    let stats_pipe = stats_read_fd.map(|fd| unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) });
    #[cfg(feature = "testing")]
    let stats_pipe = None;

    // Send TWO command sockets to the child process
    let ingress_cmd_supervisor_stream =
        socket_helpers::create_and_send_socketpair(&supervisor_sock).await?;
    let egress_cmd_supervisor_stream =
        socket_helpers::create_and_send_socketpair(&supervisor_sock).await?;

    // Create the AF_PACKET socket and send it to the worker
    let af_packet_socket =
        socket_helpers::create_af_packet_socket(&interface, fanout_group_id, logger)?;
    socket_helpers::send_fd(&supervisor_sock, af_packet_socket.as_raw_fd()).await?;
    drop(af_packet_socket);

    Ok((
        child,
        ingress_cmd_supervisor_stream,
        egress_cmd_supervisor_stream,
        log_pipe,
        stats_pipe,
    ))
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

    /// Check if workers exist for a given interface
    pub(super) fn has_workers_for_interface(&self, interface: &str) -> bool {
        self.workers.values().any(|w| {
            matches!(&w.worker_type, WorkerType::DataPlane { interface: iface, .. } if iface == interface)
        })
    }

    /// Spawn a data plane worker for the given interface and core
    pub(super) async fn spawn_data_plane_for_interface(
        &mut self,
        interface: &str,
        core_id: u32,
        fanout_group_id: u16,
    ) -> Result<()> {
        let (child, ingress_cmd_stream, egress_cmd_stream, log_pipe, stats_pipe) =
            spawn_data_plane_worker(
                core_id,
                interface.to_string(),
                fanout_group_id,
                &self.logger,
            )
            .await?;

        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("Worker process exited immediately after spawn"))?;
        let ingress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(ingress_cmd_stream));
        let egress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(egress_cmd_stream));

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

    /// Spawn workers for an interface (if not already spawned)
    pub(super) async fn ensure_workers_for_interface(
        &mut self,
        interface: &str,
        is_pinned: bool,
    ) -> Result<bool> {
        if self.has_workers_for_interface(interface) {
            return Ok(false);
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
                "Spawning {} worker(s) for interface '{}' (fanout_group_id={}{})",
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

        if let Some(ref cores) = pinned_cores {
            for &core_id in cores {
                self.spawn_data_plane_for_interface(interface, core_id, fanout_group_id)
                    .await?;
            }
        } else {
            for core_id in 0..num_workers as u32 {
                self.spawn_data_plane_for_interface(interface, core_id, fanout_group_id)
                    .await?;
            }
        }

        Ok(true)
    }

    /// Check for exited workers and restart them with exponential backoff
    pub(super) async fn check_and_restart_worker(&mut self) -> Result<Option<(u32, bool)>> {
        let mut exited_workers = Vec::new();
        for (pid, worker) in &mut self.workers {
            match worker.child.try_wait()? {
                Some(status) => {
                    exited_workers.push((*pid, worker.worker_type.clone(), status));
                }
                None => continue,
            }
        }

        if exited_workers.is_empty() {
            return Ok(None);
        }

        let (pid, worker_type, status) = exited_workers.remove(0);

        if self.workers.remove(&pid).is_none() {
            log_warning!(
                self.logger,
                Facility::Supervisor,
                &format!("Worker {} not found in workers map during restart", pid)
            );
        }

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
    #[allow(clippy::type_complexity)]
    pub(super) fn get_all_dp_cmd_streams(
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

    /// Get all data plane command streams with interface name
    #[allow(clippy::type_complexity)]
    pub(super) fn get_all_dp_cmd_streams_with_interface(
        &self,
    ) -> Vec<(
        String,
        Arc<tokio::sync::Mutex<UnixStream>>,
        Arc<tokio::sync::Mutex<UnixStream>>,
    )> {
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
    pub(super) fn get_worker_info(&self) -> Vec<crate::WorkerInfo> {
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
