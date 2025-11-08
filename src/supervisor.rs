use anyhow::{Context, Result};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::unistd::{Group, User};
use std::collections::HashMap;
use std::os::unix::io::IntoRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::{ForwardingRule, RelayCommand};

const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 16000; // 16 seconds

// --- Production Spawning Logic ---

fn get_production_base_command() -> Command {
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");
    Command::new(current_exe)
}

pub fn spawn_control_plane_worker(
    uid: u32,
    gid: u32,
    relay_command_socket_path: PathBuf,
    prometheus_addr: Option<std::net::SocketAddr>,
) -> Result<(Child, UnixStream)> {
    println!("[Supervisor] Spawning Control Plane worker.");

    // Create a private socket pair for communication.
    let (supervisor_stream, worker_stream) = UnixStream::pair()?;

    // Remove the CLO_EXEC flag to allow inheritance.
    let flags = fcntl(&worker_stream, FcntlArg::F_GETFD)?;
    let mut new_flags = FdFlag::from_bits_truncate(flags);
    new_flags.remove(FdFlag::FD_CLOEXEC);
    fcntl(&worker_stream, FcntlArg::F_SETFD(new_flags))
        .context("Failed to remove CLO_EXEC flag from worker FD")?;

    // The worker no longer needs the listener object, just the FD.
    // We must convert to std stream to get ownership of the FD.
    let owned_worker_fd = worker_stream.into_std()?.into_raw_fd();

    let mut command = get_production_base_command();
    command
        .arg("worker")
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path)
        .arg("--socket-fd") // Tell the worker to use the passed FD
        .arg(owned_worker_fd.to_string());

    if let Some(addr) = prometheus_addr {
        command.arg("--prometheus-addr").arg(addr.to_string());
    }

    let child = command.spawn()?;
    Ok((child, supervisor_stream))
}

pub fn spawn_data_plane_worker(
    core_id: u32,
    uid: u32,
    gid: u32,
    relay_command_socket_path: PathBuf,
) -> Result<Child> {
    println!(
        "[Supervisor] Spawning Data Plane worker for core {}.",
        core_id
    );
    let mut command = get_production_base_command();
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
    command.spawn().map_err(anyhow::Error::from)
}

// --- Supervisor Core Logic ---

pub async fn run(
    user: &str,
    group: &str,
    prometheus_addr: Option<std::net::SocketAddr>,
    _relay_command_rx: mpsc::Receiver<RelayCommand>,
    relay_command_socket_path: PathBuf,
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

    run_generic(
        move || spawn_control_plane_worker(uid, gid, cp_socket_path.clone(), prometheus_addr),
        num_cores,
        move |core_id| spawn_data_plane_worker(core_id, uid, gid, dp_socket_path.clone()),
        _relay_command_rx,
        master_rules,
    )
    .await
}

pub async fn run_generic<F, G>(
    mut spawn_cp: F,
    num_cores: usize,
    mut spawn_dp: G,
    _relay_command_rx: mpsc::Receiver<RelayCommand>,
    _master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
) -> Result<()>
where
    F: FnMut() -> Result<(Child, UnixStream)>,
    G: FnMut(u32) -> Result<Child>,
{
    println!(
        "[Supervisor] Starting with {} data plane workers.",
        num_cores
    );

    let control_socket_path = PathBuf::from("/tmp/multicast_relay_control.sock");
    if control_socket_path.exists() {
        std::fs::remove_file(&control_socket_path)?;
    }
    let listener = UnixListener::bind(&control_socket_path)?;

    let (mut cp_child, mut cp_stream) = spawn_cp()?;

    // Spawn data plane workers for each core
    let mut dp_children: Vec<(u32, Child, u64)> = Vec::with_capacity(num_cores);
    for core_id in 0..num_cores as u32 {
        let child = spawn_dp(core_id)?;
        dp_children.push((core_id, child, INITIAL_BACKOFF_MS));
    }

    let mut cp_backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        tokio::select! {
            Ok(status) = cp_child.wait() => {
                if status.success() {
                    println!("[Supervisor] Control Plane worker exited gracefully. Restarting immediately.");
                    cp_backoff_ms = INITIAL_BACKOFF_MS;
                } else {
                    println!("[Supervisor] Control Plane worker failed (status: {}). Restarting after {}ms.", status, cp_backoff_ms);
                    sleep(Duration::from_millis(cp_backoff_ms)).await;
                    cp_backoff_ms = (cp_backoff_ms * 2).min(MAX_BACKOFF_MS);
                }
                (cp_child, cp_stream) = spawn_cp()?;
            }

            // Monitor all data plane workers
            result = async {
                for (core_id, child, _backoff) in &mut dp_children {
                    if let Ok(Some(status)) = child.try_wait() {
                        return Some((*core_id, status));
                    }
                }
                // If no worker has exited, sleep briefly and return None
                // Use shorter sleep for faster restart detection
                sleep(Duration::from_millis(10)).await;
                None::<(u32, std::process::ExitStatus)>
            } => {
                if let Some((core_id, status)) = result {
                    // Find the worker in our list
                    if let Some(idx) = dp_children.iter().position(|(id, _, _)| *id == core_id) {
                        let (_,_, backoff) = &mut dp_children[idx];
                        if status.success() {
                            println!("[Supervisor] Data Plane worker (core {}) exited gracefully. Restarting immediately.", core_id);
                            *backoff = INITIAL_BACKOFF_MS;
                        } else {
                            println!("[Supervisor] Data Plane worker (core {}) failed (status: {}). Restarting after {}ms.", core_id, status, backoff);
                            sleep(Duration::from_millis(*backoff)).await;
                            *backoff = (*backoff * 2).min(MAX_BACKOFF_MS);
                        }
                        // Restart the worker
                        let new_child = spawn_dp(core_id)?;
                        dp_children[idx] = (core_id, new_child, *backoff);
                    }
                }
            }

            Ok((mut client_stream, _)) = listener.accept() => {
                // We can't clone the stream, so we have to move it. This means the supervisor
                // can only handle one client at a time. This is a limitation of this design,
                // but acceptable for the current use case. A more complex implementation
                // would involve a pool of worker connections or a more sophisticated proxy.
                // For now, we will take the stream, and it will be replaced when the worker
                // restarts.
                let mut current_cp_stream = std::mem::replace(&mut cp_stream, UnixStream::pair()?.0);

                tokio::spawn(async move {
                    let (mut client_reader, mut client_writer) = client_stream.split();
                    let (mut cp_reader, mut cp_writer) = current_cp_stream.split();

                    // Forward client -> worker
                    let client_to_worker = tokio::io::copy(&mut client_reader, &mut cp_writer);
                    // Forward worker -> client
                    let worker_to_client = tokio::io::copy(&mut cp_reader, &mut client_writer);

                    tokio::select! {
                        _ = client_to_worker => {},
                        _ = worker_to_client => {},
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // --- Test Helpers ---

    fn spawn_failing_worker() -> anyhow::Result<Child> {
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg("exit 1");
        command.spawn().map_err(anyhow::Error::from)
    }

    fn spawn_sleeping_worker() -> anyhow::Result<Child> {
        let mut command = tokio::process::Command::new("sleep");
        command.arg("30");
        command.spawn().map_err(anyhow::Error::from)
    }

    fn spawn_once_gracefully_then_fail(spawn_count: Arc<Mutex<u32>>) -> anyhow::Result<Child> {
        let mut count = spawn_count.lock().unwrap();
        *count += 1;
        let mut command = tokio::process::Command::new("sh");
        if *count == 1 {
            // First spawn exits gracefully
            command.arg("-c").arg("exit 0");
        } else {
            // Subsequent spawns fail
            command.arg("-c").arg("exit 1");
        }
        command.spawn().map_err(anyhow::Error::from)
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
    #[ignore]
    async fn test_supervisor_restarts_cp_worker_with_backoff() {
        let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));
        let cp_spawn_times_clone = cp_spawn_times.clone();

        let spawn_cp = move || -> Result<(Child, UnixStream)> {
            cp_spawn_times_clone.lock().unwrap().push(Instant::now());
            let (stream, _) = UnixStream::pair()?;
            Ok((spawn_failing_worker()?, stream))
        };
        let spawn_dp = |_core_id: u32| spawn_failing_worker();

        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));

        let supervisor_future = run_generic(spawn_cp, 1, spawn_dp, rx, master_rules.clone());
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
    #[ignore]
    async fn test_supervisor_restarts_dp_worker_with_backoff() {
        let dp_spawn_times = Arc::new(Mutex::new(Vec::new()));
        let dp_spawn_times_clone = dp_spawn_times.clone();

        let spawn_cp = || -> Result<(Child, UnixStream)> {
            let (stream, _) = UnixStream::pair()?;
            Ok((spawn_sleeping_worker()?, stream))
        };
        let spawn_dp = move |_core_id: u32| {
            dp_spawn_times_clone.lock().unwrap().push(Instant::now());
            spawn_failing_worker()
        };

        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));

        let supervisor_future = run_generic(spawn_cp, 1, spawn_dp, rx, master_rules.clone());
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
    async fn test_supervisor_runs_without_panic() {
        let spawn_cp = || -> Result<(Child, UnixStream)> {
            let (stream, _) = UnixStream::pair()?;
            Ok((spawn_sleeping_worker()?, stream))
        };
        let spawn_dp = |_core_id: u32| spawn_sleeping_worker();

        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));

        let supervisor_future = run_generic(spawn_cp, 1, spawn_dp, rx, master_rules.clone());
        let result = tokio::time::timeout(Duration::from_millis(100), supervisor_future).await;
        assert!(
            result.is_err(),
            "Supervisor should not have exited and should time out."
        );
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify that the supervisor's exponential backoff is reset for a worker after it exits gracefully.
    /// - **Method:** A mock spawner is used that exits gracefully on the first spawn, then fails on all subsequent spawns.
    ///   The test inspects the timestamps of the spawns. It asserts that the delay between the 1st (graceful) and 2nd
    ///   (failed) spawn is near-zero, and the delay between the 2nd (failed) and 3rd (failed) spawn is >= the initial backoff delay.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    #[ignore]
    async fn test_supervisor_resets_backoff_on_graceful_exit() {
        let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));
        let cp_spawn_times_clone = cp_spawn_times.clone();
        let cp_spawn_count = Arc::new(Mutex::new(0));
        let cp_spawn_count_clone = cp_spawn_count.clone();

        let spawn_cp = move || -> Result<(Child, UnixStream)> {
            cp_spawn_times_clone.lock().unwrap().push(Instant::now());
            let (stream, _) = UnixStream::pair()?;
            Ok((
                spawn_once_gracefully_then_fail(cp_spawn_count_clone.clone())?,
                stream,
            ))
        };
        let spawn_dp = |_core_id: u32| spawn_failing_worker();

        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));

        let supervisor_future = run_generic(spawn_cp, 1, spawn_dp, rx, master_rules.clone());
        let _ = tokio::time::timeout(Duration::from_millis(1000), supervisor_future).await;

        let spawn_times = cp_spawn_times.lock().unwrap();
        assert!(spawn_times.len() > 1, "Should have restarted at least once");

        // The first restart (after graceful exit) should be immediate.
        let backoff1 = spawn_times[1].duration_since(spawn_times[0]);
        assert!(backoff1 < Duration::from_millis(50)); // Immediate restart

        // If there was a second restart, check its backoff
        if spawn_times.len() > 2 {
            let backoff2 = spawn_times[2].duration_since(spawn_times[1]);
            assert!(backoff2 >= Duration::from_millis(250));
        }
    }
}
