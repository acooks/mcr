use anyhow::{Context, Result};
use futures::stream::FuturesUnordered;
use futures::Future;
use log::error;
use nix::sys::socket::{sendmsg, socketpair, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType};
use nix::unistd::{Group, User, Gid, Uid};
use std::collections::HashMap;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd, AsRawFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::{ForwardingRule, RelayCommand};
use futures::{stream::StreamExt, SinkExt};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 16000; // 16 seconds



pub async fn spawn_control_plane_worker(
    uid: u32,
    gid: u32,
    relay_command_socket_path: PathBuf,
    prometheus_addr: Option<std::net::SocketAddr>,
) -> Result<(Child, UnixStream, UnixStream)> {
    println!("[Supervisor] Spawning Control Plane worker.");

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
    uid: u32,
    gid: u32,
    relay_command_socket_path: PathBuf,
) -> Result<(Child, UnixStream, UnixStream)> {
    println!(
        "[Supervisor] Spawning Data Plane worker for core {}.",
        core_id
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
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .arg("--core-id")
        .arg(core_id.to_string())
        .arg("--data-plane")
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path);

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

// --- Supervisor Core Logic ---

pub async fn run(
    user: &str,
    group: &str,
    prometheus_addr: Option<std::net::SocketAddr>,
    _relay_command_rx: mpsc::Receiver<RelayCommand>,
    relay_command_socket_path: PathBuf,
    control_socket_path: PathBuf, // New parameter
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
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
    // TODO: Make this configurable via command-line arg
    let num_cores = num_cpus::get();
    println!("[Supervisor] Detected {} CPU cores", num_cores);

    let cp_socket_path = relay_command_socket_path.clone();
    let dp_socket_path = relay_command_socket_path.clone();

    // Create the relay command socket
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

    run_generic(
        move || {
            let cp_socket_path = cp_socket_path.clone();
            async move {
                spawn_control_plane_worker(uid, gid, cp_socket_path, prometheus_addr).await
            }
        },
        num_cores,
        move |core_id| {
            let dp_socket_path = dp_socket_path.clone();
            async move { spawn_data_plane_worker(core_id, uid, gid, dp_socket_path).await }
        },
        _relay_command_rx,
        control_socket_path, // Pass down
        master_rules,
    )
    .await
}

pub async fn run_generic<F, G, FutCp, FutDp>(
    mut spawn_cp: F,
    num_cores: usize,
    mut spawn_dp: G,
    _relay_command_rx: mpsc::Receiver<RelayCommand>,
    control_socket_path: PathBuf, // New parameter
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
) -> Result<()>
where
    F: FnMut() -> FutCp,
    G: FnMut(u32) -> FutDp,
    FutCp: Future<Output = Result<(Child, UnixStream, UnixStream)>> + Send + 'static,
    FutDp: Future<Output = Result<(Child, UnixStream, UnixStream)>> + Send + 'static,
{
    let worker_map: Arc<Mutex<HashMap<u32, crate::WorkerInfo>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let worker_req_streams: Arc<Mutex<HashMap<u32, Arc<tokio::sync::Mutex<UnixStream>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let dp_cmd_streams: Arc<Mutex<HashMap<u32, Arc<tokio::sync::Mutex<UnixStream>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    println!(
        "[Supervisor] Starting with {} data plane workers.",
        num_cores
    );

    if control_socket_path.exists() {
        std::fs::remove_file(&control_socket_path)?;
    }
    let listener = {
        let std_listener = std::os::unix::net::UnixListener::bind(&control_socket_path)?;
        std_listener.set_nonblocking(true)?;
        tokio::net::UnixListener::from_std(std_listener)?
    };
    println!(
        "[Supervisor] Control socket listening on {:?}",
        &control_socket_path
    );

    let (mut cp_child, mut cp_stream, cp_req_stream) = spawn_cp().await?;
    let mut cp_pid = cp_child.id().unwrap();
    worker_map.lock().unwrap().insert(
        cp_pid,
        crate::WorkerInfo {
            pid: cp_pid,
            worker_type: "ControlPlane".to_string(),
            core_id: None,
        },
    );
    worker_req_streams
        .lock()
        .unwrap()
        .insert(cp_pid, Arc::new(tokio::sync::Mutex::new(cp_req_stream)));

    #[allow(clippy::type_complexity)]
    let mut cp_child_future: Pin<
        Box<dyn Future<Output = (u32, Result<std::process::ExitStatus, std::io::Error>, Child)>>,
    > = Box::pin(async move {
        let res = cp_child.wait().await;
        (cp_pid, res, cp_child)
    });

    // Use FuturesUnordered to manage all data plane worker futures
    #[allow(clippy::type_complexity)]
    let mut dp_futs: FuturesUnordered<
        Pin<Box<dyn Future<Output = (u32, u32, Result<std::process::ExitStatus, std::io::Error>)>>>,
    > = FuturesUnordered::new();
    let mut dp_backoffs = HashMap::new();

    for core_id in 0..num_cores as u32 {
        let (mut child, dp_cmd_stream, dp_req_stream) = spawn_dp(core_id).await?;
        let pid = child.id().unwrap();
        worker_map.lock().unwrap().insert(
            pid,
            crate::WorkerInfo {
                pid,
                worker_type: "DataPlane".to_string(),
                core_id: Some(core_id),
            },
        );
        worker_req_streams
            .lock()
            .unwrap()
            .insert(pid, Arc::new(tokio::sync::Mutex::new(dp_req_stream)));
        dp_cmd_streams
            .lock()
            .unwrap()
            .insert(pid, Arc::new(tokio::sync::Mutex::new(dp_cmd_stream)));
        dp_backoffs.insert(core_id, INITIAL_BACKOFF_MS);
        dp_futs.push(Box::pin(async move {
            let res = child.wait().await;
            (core_id, pid, res)
        }));
    }

    let mut cp_backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        tokio::select! {
            // Branch 1: A control plane worker exited
            (pid, result, mut cp_child) = &mut cp_child_future => {
                worker_map.lock().unwrap().remove(&pid);

                if let Ok(status) = result {
                    if status.success() {
                        println!("[Supervisor] Control Plane worker exited gracefully. Restarting immediately.");
                        cp_backoff_ms = INITIAL_BACKOFF_MS;
                    } else {
                        println!("[Supervisor] Control Plane worker failed (status: {}). Restarting after {}ms.", status, cp_backoff_ms);
                        sleep(Duration::from_millis(cp_backoff_ms)).await;
                        cp_backoff_ms = (cp_backoff_ms * 2).min(MAX_BACKOFF_MS);
                    }
                }
                let (cp_child_new, cp_stream_new, cp_req_stream_new) = spawn_cp().await?;
                cp_child = cp_child_new;
                cp_stream = cp_stream_new;
                cp_pid = cp_child.id().unwrap();
                worker_map.lock().unwrap().insert(
                    cp_pid,
                    crate::WorkerInfo {
                        pid: cp_pid,
                        worker_type: "ControlPlane".to_string(),
                        core_id: None,
                    },
                );
                worker_req_streams
                    .lock()
                    .unwrap()
                    .insert(cp_pid, Arc::new(tokio::sync::Mutex::new(cp_req_stream_new)));
                cp_child_future = Box::pin(async move {
                    let res = cp_child.wait().await;
                    (cp_pid, res, cp_child)
                });
            }

            // Branch 2: A data plane worker exited
            Some((core_id, pid, result)) = dp_futs.next() => {
                worker_map.lock().unwrap().remove(&pid);
                dp_cmd_streams.lock().unwrap().remove(&pid);
                if let Ok(status) = result {
                    let backoff = dp_backoffs.entry(core_id).or_insert(INITIAL_BACKOFF_MS);
                    if status.success() {
                        println!("[Supervisor] Data Plane worker (core {}) exited gracefully. Restarting immediately.", core_id);
                        *backoff = INITIAL_BACKOFF_MS;
                    } else {
                        println!("[Supervisor] Data Plane worker (core {}) failed (status: {}). Restarting after {}ms.", core_id, status, *backoff);
                        sleep(Duration::from_millis(*backoff)).await;
                        *backoff = (*backoff * 2).min(MAX_BACKOFF_MS);
                    }
                    // Restart the worker for the specific core
                    let (mut new_child, new_cmd_stream, new_req_stream) = spawn_dp(core_id).await?;
                    let new_pid = new_child.id().unwrap();
                    worker_map.lock().unwrap().insert(
                        new_pid,
                        crate::WorkerInfo {
                            pid: new_pid,
                            worker_type: "DataPlane".to_string(),
                            core_id: Some(core_id),
                        },
                    );
                    worker_req_streams
                        .lock()
                        .unwrap()
                        .insert(new_pid, Arc::new(tokio::sync::Mutex::new(new_req_stream)));
                    dp_cmd_streams
                        .lock()
                        .unwrap()
                        .insert(new_pid, Arc::new(tokio::sync::Mutex::new(new_cmd_stream)));
                    dp_futs.push(Box::pin(async move {
                        let res = new_child.wait().await;
                        (core_id, new_pid, res)
                    }));
                }
            }

            // Branch 3: A new client connected to the control socket
                        Ok((mut client_stream, _)) = listener.accept() => {
                            let worker_map_clone = worker_map.clone();
                            let worker_req_streams_clone = worker_req_streams.clone();
                            let dp_cmd_streams_clone = dp_cmd_streams.clone();
                            let master_rules_clone = master_rules.clone();
                            let mut current_cp_stream = std::mem::replace(&mut cp_stream, UnixStream::pair()?.0);

                            tokio::spawn(async move {
                                use crate::{Response, SupervisorCommand};
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                                let mut buffer = Vec::new();
                                if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(100), client_stream.read_to_end(&mut buffer)).await {
                                    let command: Result<SupervisorCommand, _> = serde_json::from_slice(&buffer);

                                    match command {
                                        Ok(SupervisorCommand::ListWorkers) => {
                                            let workers = worker_map_clone.lock().unwrap().values().cloned().collect();
                                            let response = Response::Workers(workers);
                                            let response_bytes = serde_json::to_vec(&response).unwrap();
                                            client_stream.write_all(&response_bytes).await.unwrap();
                                        }
                                        Ok(SupervisorCommand::AddRule { rule_id, input_interface, input_group, input_port, outputs, dtls_enabled }) => {
                                            let rule = ForwardingRule { rule_id, input_interface, input_group, input_port, outputs, dtls_enabled };
                                            master_rules_clone.lock().unwrap().insert(rule.rule_id.clone(), rule.clone());

                                            let relay_cmd = RelayCommand::AddRule(rule.clone());
                                            let cmd_bytes = serde_json::to_vec(&relay_cmd).unwrap();

                                            let streams_to_send: Vec<_> = dp_cmd_streams_clone.lock().unwrap().values().cloned().collect();
                                            for stream_mutex in streams_to_send {
                                                let cmd_bytes_clone = cmd_bytes.clone();
                                                tokio::spawn(async move {
                                                    let mut stream = stream_mutex.lock().await;
                                                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                                                    if let Err(e) = framed.send(cmd_bytes_clone.into()).await {
                                                        error!("Failed to send AddRule to worker: {}", e);
                                                    }
                                                });
                                            }

                                            let response = Response::Success(format!("Rule {} added", rule.rule_id));
                                            let response_bytes = serde_json::to_vec(&response).unwrap();
                                            client_stream.write_all(&response_bytes).await.unwrap();
                                        }
                                        Ok(SupervisorCommand::RemoveRule { rule_id }) => {
                                            let removed = master_rules_clone.lock().unwrap().remove(&rule_id).is_some();
                                            let response = if removed {
                                                let relay_cmd = RelayCommand::RemoveRule { rule_id: rule_id.clone() };
                                                let cmd_bytes = serde_json::to_vec(&relay_cmd).unwrap();

                                                let streams_to_send: Vec<_> = dp_cmd_streams_clone.lock().unwrap().values().cloned().collect();
                                                for stream_mutex in streams_to_send {
                                                    let cmd_bytes_clone = cmd_bytes.clone();
                                                    tokio::spawn(async move {
                                                        let mut stream = stream_mutex.lock().await;
                                                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                                                        if let Err(e) = framed.send(cmd_bytes_clone.into()).await {
                                                            error!("Failed to send RemoveRule to worker: {}", e);
                                                        }
                                                    });
                                                }
                                                Response::Success(format!("Rule {} removed", rule_id))
                                            } else {
                                                Response::Error(format!("Rule {} not found", rule_id))
                                            };
                                            let response_bytes = serde_json::to_vec(&response).unwrap();
                                            client_stream.write_all(&response_bytes).await.unwrap();
                                        }
                                                                    Ok(SupervisorCommand::GetWorkerRules { worker_pid }) => {
                                                                        let stream_mutex = {
                                                                            let req_streams = worker_req_streams_clone.lock().unwrap();
                                                                            req_streams.get(&worker_pid).cloned()
                                                                        };

                                                                        if let Some(stream_mutex) = stream_mutex {
                                                                            tokio::spawn(async move {
                                                                                let mut stream = stream_mutex.lock().await;
                                                                                let mut framed =
                                                                                    Framed::new(&mut *stream, LengthDelimitedCodec::new());
                                                                                let request = crate::ipc::Request::ListRules;
                                                                                let bytes = serde_json::to_vec(&request).unwrap();
                                                                                if framed.send(bytes.into()).await.is_ok() {
                                                                                    if let Some(Ok(bytes)) = framed.next().await {
                                                                                        let response: crate::ipc::Response =
                                                                                            serde_json::from_slice(&bytes).unwrap();
                                                                                        if let crate::ipc::Response::Rules(rules) = response
                                                                                        {
                                                                                            let response = Response::Rules(rules);
                                                                                            let response_bytes =
                                                                                                serde_json::to_vec(&response).unwrap();
                                                                                            if client_stream
                                                                                                .write_all(&response_bytes)
                                                                                                .await
                                                                                                .is_err()
                                                                                            {
                                                                                                error!("Failed to send response to client");
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            });
                                                                        }
                                                                    }                            _ => {
                                // Forward to control plane worker
                                let (_, mut client_writer) = client_stream.split();
                                let (mut cp_reader, mut cp_writer) = current_cp_stream.split();

                                cp_writer.write_all(&buffer).await.unwrap();

                                let worker_to_client = tokio::io::copy(&mut cp_reader, &mut client_writer);
                                tokio::select! {
                                    _ = worker_to_client => {},
                                }
                            }
                        }
                    }
                });
            }
        }
    }
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
        sendmsg::<()>(
            sock.as_raw_fd(),
            &iov,
            &cmsg,
            MsgFlags::empty(),
            None,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
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

    // --- Test Helpers ---

    fn spawn_failing_worker() -> anyhow::Result<Child> {
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg("exit 1");
        command
            .spawn()
            .map_err(anyhow::Error::from)
            .context("Failed to spawn failing worker")
    }

    fn spawn_sleeping_worker() -> anyhow::Result<Child> {
        let mut command = tokio::process::Command::new("sleep");
        command.arg("30");
        command
            .spawn()
            .map_err(anyhow::Error::from)
            .context("Failed to spawn sleeping worker")
    }

    // --- Tests ---

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify that the supervisor restarts a consistently failing Control Plane worker.
    /// - **Method:** A mock `spawn_cp` closure is created that always returns a process that immediately fails.
    ///   The test runs the supervisor for a short period and then inspects a shared vector of spawn timestamps
    ///   to ensure at least two spawns occurred and that the time between them respects the initial backoff period.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    async fn test_supervisor_restarts_cp_worker_with_backoff() {
        let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));
        let cp_spawn_times_clone = cp_spawn_times.clone();

        let spawn_cp = move || {
            let cp_spawn_times = cp_spawn_times_clone.clone();
            async move {
                cp_spawn_times.lock().unwrap().push(Instant::now());
                let (stream, _) = UnixStream::pair()?;
                let (req_stream, _) = UnixStream::pair()?;
                Ok((spawn_failing_worker()?, stream, req_stream))
            }
        };
        let spawn_dp = |_core_id: u32| async {
            let (req_stream, _) = UnixStream::pair()?;
            let (cmd_stream, _) = UnixStream::pair()?;
            Ok((spawn_sleeping_worker()?, cmd_stream, req_stream))
        };

        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let supervisor_future =
            run_generic(spawn_cp, 1, spawn_dp, rx, socket_path, master_rules.clone());
        let _ = tokio::time::timeout(Duration::from_millis(1000), supervisor_future).await;

        let spawn_times = cp_spawn_times.lock().unwrap();
        assert!(spawn_times.len() > 1, "Should have restarted at least once");

        let backoff1 = spawn_times[1].duration_since(spawn_times[0]);
        assert!(backoff1 >= Duration::from_millis(250));
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify that the supervisor restarts a consistently failing Data Plane worker.
    /// - **Method:** Similar to the CP worker test, but the mock `spawn_dp` closure is the one that fails.
    ///   The test verifies that the DP worker is restarted after the initial backoff period.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    async fn test_supervisor_restarts_dp_worker_with_backoff() {
        let dp_spawn_times = Arc::new(Mutex::new(Vec::new()));
        let spawn_cp = move || async {
            let (stream, _) = UnixStream::pair()?;
            let (req_stream, _) = UnixStream::pair()?;
            Ok((spawn_sleeping_worker()?, stream, req_stream))
        };
        let dp_spawn_times_clone = dp_spawn_times.clone();
        let spawn_dp = move |_core_id: u32| {
            let dp_spawn_times = dp_spawn_times_clone.clone();
            async move {
                dp_spawn_times.lock().unwrap().push(Instant::now());
                let (req_stream, _) = UnixStream::pair()?;
                let (cmd_stream, _) = UnixStream::pair()?;
                Ok((spawn_failing_worker()?, cmd_stream, req_stream))
            }
        };

        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let supervisor_future =
            run_generic(spawn_cp, 1, spawn_dp, rx, socket_path, master_rules.clone());
        let _ = tokio::time::timeout(Duration::from_millis(1000), supervisor_future).await;

        let spawn_times = dp_spawn_times.lock().unwrap();
        assert!(spawn_times.len() > 1, "Should have restarted at least once");

        let backoff1 = spawn_times[1].duration_since(spawn_times[0]);
        assert!(backoff1 >= Duration::from_millis(250));
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify that the supervisor's main loop can be started and runs without immediate panic.
    /// - **Method:** The test provides mock spawners that create long-lived (sleeping) processes. It runs the
    ///   supervisor for a very short duration. The test passes if the supervisor future doesn't complete and
    ///   can be successfully timed out, implying it has entered the main `loop` and is waiting for events.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    async fn test_supervisor_spawns_workers() {
        let pids = Arc::new(Mutex::new(Vec::new()));
        let pids_clone = pids.clone();
        let spawn_cp = move || {
            let pids = pids_clone.clone();
            async move {
                let child = spawn_sleeping_worker()?;
                pids.lock().unwrap().push(child.id().unwrap());
                let (stream, _) = UnixStream::pair()?;
                let (req_stream, _) = UnixStream::pair()?;
                Ok((child, stream, req_stream))
            }
        };
        let pids_clone2 = pids.clone();
        let spawn_dp = move |_core_id: u32| {
            let pids = pids_clone2.clone();
            async move {
                let child = spawn_sleeping_worker()?;
                pids.lock().unwrap().push(child.id().unwrap());
                let (req_stream, _) = UnixStream::pair()?;
                let (cmd_stream, _) = UnixStream::pair()?;
                Ok((child, cmd_stream, req_stream))
            }
        };

        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));
        let num_cores = 2;
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let supervisor_future = run_generic(
            spawn_cp,
            num_cores,
            spawn_dp,
            rx,
            socket_path,
            master_rules.clone(),
        );
        let _ = tokio::time::timeout(Duration::from_millis(200), supervisor_future).await;

        let spawned_pids = pids.lock().unwrap().clone();
        assert_eq!(
            spawned_pids.len(),
            num_cores + 1,
            "Should have spawned one CP and {} DP workers.",
            num_cores
        );

        // Cleanup spawned processes
        for pid in spawned_pids.iter() {
            let _ = Command::new("kill").arg(pid.to_string()).status().await;
        }
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify that the supervisor's exponential backoff is reset for a worker after it exits gracefully.
    /// - **Method:** A mock spawner is used that exits gracefully on the first spawn, then fails on all subsequent spawns.
    ///   The test inspects the timestamps of the spawns. It asserts that the delay between the 1st (graceful) and 2nd
    ///   (failed) spawn is near-zero, and the delay between the 2nd (failed) and 3rd (failed) spawn is >= the initial backoff delay.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    async fn test_supervisor_resets_backoff_on_graceful_exit() {
        let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));
        let cp_spawn_times_clone = cp_spawn_times.clone();
        let cp_spawn_count = Arc::new(Mutex::new(0));

        let spawn_cp = move || {
            let cp_spawn_times = cp_spawn_times_clone.clone();
            let cp_spawn_count = cp_spawn_count.clone();
            async move {
                let mut count = cp_spawn_count.lock().unwrap();
                *count += 1;
                let mut command = tokio::process::Command::new("sh");

                // Fail on the first two spawns to establish a backoff, then exit gracefully.
                match *count {
                    1 => command.arg("-c").arg("exit 1"), // Fail
                    2 => command.arg("-c").arg("exit 0"), // Graceful exit
                    _ => command.arg("-c").arg("exit 1"), // Fail again
                };
                drop(count); // Release the lock before awaiting

                cp_spawn_times.lock().unwrap().push(Instant::now());
                let (stream, _) = UnixStream::pair()?;
                let (req_stream, _) = UnixStream::pair()?;
                Ok((command.spawn()?, stream, req_stream))
            }
        };

        let spawn_dp = |_core_id: u32| async {
            let (req_stream, _) = UnixStream::pair()?;
            let (cmd_stream, _) = UnixStream::pair()?;
            Ok((spawn_sleeping_worker()?, cmd_stream, req_stream))
        };

        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let supervisor_future =
            run_generic(spawn_cp, 1, spawn_dp, rx, socket_path, master_rules.clone());

        // Run long enough for three spawns: fail -> graceful -> fail
        let _ = tokio::time::timeout(Duration::from_millis(1000), supervisor_future).await;

        let spawn_times = cp_spawn_times.lock().unwrap();
        assert!(
            spawn_times.len() >= 3,
            "Expected at least 3 spawns, but got {}",
            spawn_times.len()
        );

        // Backoff after first failure should be >= INITIAL_BACKOFF_MS
        let backoff_after_failure = spawn_times[1].duration_since(spawn_times[0]);
        assert!(backoff_after_failure >= Duration::from_millis(INITIAL_BACKOFF_MS));

        // Backoff after graceful exit should be very short (i.e., reset)
        let backoff_after_graceful = spawn_times[2].duration_since(spawn_times[1]);
        assert!(
            backoff_after_graceful < Duration::from_millis(50),
            "Backoff was not reset after graceful exit"
        );
    }
}
