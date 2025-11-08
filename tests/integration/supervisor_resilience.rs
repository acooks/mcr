//! **Tier 2 Integration Tests: Supervisor Resilience**
//!
//! **Priority: CRITICAL - Sprint 1, Day 3**
//!
//! These tests verify that the supervisor correctly handles worker failures
//! and restarts them with proper state synchronization.
//!
//! ## Design References
//! - D18: Supervisor monitors and restarts failed workers
//! - D23: Workers receive all active rules upon restart
//! - TESTING_PLAN.md Phase 3: Namespace-based supervisor tests
//!
//! ## Implementation Status
//! - [ ] Basic worker restart test
//! - [ ] Worker restart with active rules (state resync)
//! - [ ] Multiple worker failure handling
//! - [ ] Exponential backoff testing
//! - [ ] Namespace isolation setup

use anyhow::{Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use tests::{cleanup_socket, unique_socket_path_with_prefix};

/// Helper to start supervisor in background for testing
async fn start_supervisor() -> Result<(Child, PathBuf)> {
    // 1. Generate unique socket paths
    let control_socket = unique_socket_path_with_prefix("supervisor_control");
    let relay_socket = unique_socket_path_with_prefix("supervisor_relay");

    // 2. Clean up any existing sockets
    cleanup_socket(&control_socket);
    cleanup_socket(&relay_socket);

    // 3. Get path to the multicast_relay binary
    let binary = env!("CARGO_BIN_EXE_multicast_relay");

    // 4. Spawn supervisor process
    let supervisor = Command::new(binary)
        .arg("supervisor")
        .arg("--control-socket-path")
        .arg(&control_socket)
        .arg("--relay-command-socket-path")
        .arg(&relay_socket)
        .spawn()?;

    // 5. Wait for socket to be created (with timeout)
    for _ in 0..30 {
        // 3 second timeout
        if control_socket.exists() {
            sleep(Duration::from_millis(100)).await; // Give it a moment to stabilize
            return Ok((supervisor, control_socket));
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Supervisor did not create socket within timeout")
}

/// Helper to forcibly kill a worker process by PID
async fn kill_worker(pid: u32) -> Result<()> {
    // Send SIGKILL to the process
    kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
        .context(format!("Failed to kill worker {}", pid))?;

    // Give the OS a moment to process the signal
    sleep(Duration::from_millis(50)).await;

    Ok(())
}

/// Helper to check if a process is running
fn is_process_running(pid: u32) -> bool {
    // Sending signal 0 doesn't actually send a signal,
    // but checks if we have permission to send one
    // (i.e., if the process exists)
    kill(Pid::from_raw(pid as i32), Signal::from_c_int(0).unwrap()).is_ok()
}

/// **Tier 2 Integration Test**
///
/// - **Purpose:** Verify supervisor detects and restarts a failed control plane worker
/// - **Method:**
///   1. Start supervisor
///   2. Identify control plane worker PID via `list-workers` command
///   3. Kill the worker using SIGKILL
///   4. Poll `list-workers` until a new control plane worker appears
///   5. Verify the new worker has a different PID and is running
/// - **Tier:** 2 (Integration)
#[tokio::test]
async fn test_supervisor_restarts_control_plane_worker() -> Result<()> {
    // Step 1: Start supervisor
    let (mut supervisor, socket_path) = start_supervisor().await?;
    let client = control_client::ControlClient::new(&socket_path);

    // Step 2: Get control plane worker PID
    let workers = client.list_workers().await?;
    let cp_worker = workers
        .iter()
        .find(|w| w.worker_type == "ControlPlane")
        .ok_or_else(|| anyhow::anyhow!("No control plane worker found"))?;
    let original_pid = cp_worker.pid;
    println!("[TEST] Original control plane worker PID: {}", original_pid);

    // Step 3: Kill the worker
    kill_worker(original_pid).await?;
    sleep(Duration::from_millis(200)).await; // Give supervisor time to notice
    assert!(!is_process_running(original_pid), "Worker should be dead");
    println!("[TEST] Worker {} killed successfully", original_pid);

    // Step 4 & 5: Wait for supervisor to restart the worker
    let mut new_pid = None;
    for _ in 0..50 { // 5 second timeout
        if let Ok(workers) = client.list_workers().await {
            if let Some(cp) = workers.iter().find(|w| w.worker_type == "ControlPlane") {
                if cp.pid != original_pid && is_process_running(cp.pid) {
                    new_pid = Some(cp.pid);
                    println!("[TEST] Worker restarted with new PID: {}", cp.pid);
                    break;
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Step 6: Verify restart succeeded
    assert!(new_pid.is_some(), "Supervisor should have restarted the worker");
    let new_pid = new_pid.unwrap();
    assert_ne!(new_pid, original_pid, "New worker should have a different PID");
    assert!(is_process_running(new_pid), "New worker should be running");

    // Cleanup
    supervisor.kill().await?;
    cleanup_socket(&socket_path);
    Ok(())
}

mod control_client {
    use super::*;
    use multicast_relay::{Response, SupervisorCommand, WorkerInfo, ForwardingRule};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    pub struct ControlClient {
        socket_path: PathBuf,
    }

    impl ControlClient {
        pub fn new(socket_path: &PathBuf) -> Self {
            Self {
                socket_path: socket_path.clone(),
            }
        }

        async fn send_command(&self, command: SupervisorCommand) -> Result<Response> {
            let mut stream = UnixStream::connect(&self.socket_path).await?;
            let command_bytes = serde_json::to_vec(&command)?;
            stream.write_all(&command_bytes).await?;
            stream.shutdown().await?;

            let mut response_bytes = Vec::new();
            stream.read_to_end(&mut response_bytes).await?;

            let response: Response = serde_json::from_slice(&response_bytes)?;
            Ok(response)
        }

        pub async fn list_workers(&self) -> Result<Vec<WorkerInfo>> {
            match self.send_command(SupervisorCommand::ListWorkers).await? {
                Response::Workers(workers) => Ok(workers),
                Response::Error(e) => anyhow::bail!("Failed to list workers: {}", e),
                _ => anyhow::bail!("Unexpected response from supervisor"),
            }
        }

        pub async fn add_rule(&self, rule: ForwardingRule) -> Result<()> {
            match self.send_command(SupervisorCommand::AddRule {
                rule_id: rule.rule_id,
                input_interface: rule.input_interface,
                input_group: rule.input_group,
                input_port: rule.input_port,
                outputs: rule.outputs,
                dtls_enabled: rule.dtls_enabled,
            }).await? {
                Response::Success(_) => Ok(()),
                Response::Error(e) => anyhow::bail!("Failed to add rule: {}", e),
                _ => anyhow::bail!("Unexpected response from supervisor"),
            }
        }
    }
}


#[tokio::test]
async fn test_supervisor_restarts_data_plane_worker() -> Result<()> {
    // Step 1: Start supervisor
    let (mut supervisor, socket_path) = start_supervisor().await?;
    let client = control_client::ControlClient::new(&socket_path);

    // Step 2: Get a data plane worker PID
    let workers = client.list_workers().await?;
    let dp_worker = workers
        .iter()
        .find(|w| w.worker_type == "DataPlane")
        .ok_or_else(|| anyhow::anyhow!("No data plane worker found"))?;
    let original_pid = dp_worker.pid;
    println!("[TEST] Original data plane worker PID: {}", original_pid);

    // Step 3: Kill the worker
    kill_worker(original_pid).await?;
    sleep(Duration::from_millis(200)).await;
    assert!(!is_process_running(original_pid), "Worker should be dead");
    println!("[TEST] Worker {} killed successfully", original_pid);

    // Step 4 & 5: Wait for supervisor to restart the worker
    let mut new_pid = None;
    for _ in 0..50 { // 5 second timeout
        if let Ok(workers) = client.list_workers().await {
            if let Some(dp) = workers.iter().find(|w| {
                w.worker_type == "DataPlane" && w.pid != original_pid && is_process_running(w.pid)
            }) {
                new_pid = Some(dp.pid);
                println!("[TEST] Worker restarted with new PID: {}", dp.pid);
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Step 6: Verify restart succeeded
    assert!(new_pid.is_some(), "Supervisor should have restarted the worker");
    let new_pid = new_pid.unwrap();
    assert_ne!(new_pid, original_pid, "New worker should have a different PID");
    assert!(is_process_running(new_pid), "New worker should be running");

    // Cleanup
    supervisor.kill().await?;
    cleanup_socket(&socket_path);
    Ok(())
}

/// **Tier 2 Integration Test**
///
/// - **Purpose:** Verify supervisor restarts data plane worker and resyncs rules
/// - **Method:**
///   1. Start supervisor with active forwarding rules
///   2. Kill a data plane worker
///   3. Verify supervisor restarts the worker
///   4. Verify the new worker receives all active rules (state resync)
/// - **Tier:** 2 (Integration)
///
/// **TODO: IMPLEMENT THIS - CRITICAL**
///
/// This tests both restart logic AND rule resynchronization (D23).
#[tokio::test]
async fn test_supervisor_resyncs_rules_on_restart() -> Result<()> {
    // 1. Start supervisor
    let (mut supervisor, socket_path) = start_supervisor().await?;
    let client = control_client::ControlClient::new(&socket_path);

    // 2. Add a forwarding rule
    let rule = multicast_relay::ForwardingRule {
        rule_id: "test-rule".to_string(),
        input_interface: "lo".to_string(),
        input_group: "239.0.0.1".parse()?,
        input_port: 5001,
        outputs: vec![],
        dtls_enabled: false,
    };
    client.add_rule(rule).await?;
    sleep(Duration::from_millis(200)).await; // Give rule time to propagate

    // 3. Kill a data plane worker
    let workers = client.list_workers().await?;
    let dp_worker = workers
        .iter()
        .find(|w| w.worker_type == "DataPlane")
        .ok_or_else(|| anyhow::anyhow!("No data plane worker found"))?;
    kill_worker(dp_worker.pid).await?;

    // 4. Wait for restart
    sleep(Duration::from_millis(500)).await;

    // 5. Verify the supervisor still has the rule
    // Note: This doesn't verify the worker received it, but it's a good first step
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_id, "test-rule");

    // Cleanup
    supervisor.kill().await?;
    cleanup_socket(&socket_path);
    Ok(())
}

use multicast_relay::supervisor::run_generic;
use std::sync::{Arc, Mutex};
use tokio::time::{Instant, sleep};

/// **Tier 2 Integration Test**
///
/// - **Purpose:** Verify exponential backoff on repeated worker failures
/// - **Method:**
///   1. Start supervisor
///   2. Create a worker that crashes immediately on startup
///   3. Verify restart delays increase exponentially
///   4. Verify maximum backoff is respected
/// - **Tier:** 2 (Integration)
///
/// This validates the backoff logic prevents restart storms.
#[tokio::test]
async fn test_supervisor_applies_exponential_backoff() -> Result<()> {
    let timestamps = Arc::new(Mutex::new(Vec::new()));
    let timestamps_clone = timestamps.clone();

    // Mock spawner that records the time and spawns a failing process
    let spawn_cp = move || {
        let mut locked_timestamps = timestamps_clone.lock().unwrap();
        locked_timestamps.push(Instant::now());
        Command::new("sh").arg("-c").arg("exit 1").spawn()
    };

    // Mock spawner for a stable data plane worker
    let spawn_dp = || Command::new("sleep").arg("5").spawn();

    let supervisor_future = run_generic(
        "backoff_test".to_string(),
        Box::new(spawn_cp),
        Box::new(spawn_dp),
    );

    // Run the supervisor for a short period to observe a few restarts
    let _ = tokio::time::timeout(Duration::from_millis(1500), supervisor_future).await;

    // Analyze the timestamps
    let locked_timestamps = timestamps.lock().unwrap();
    assert!(locked_timestamps.len() >= 4, "Expected at least 4 restart attempts");

    let delays: Vec<Duration> = locked_timestamps
        .windows(2)
        .map(|w| w[1].duration_since(w[0]))
        .collect();

    println!("Observed delays: {:?}", delays);

    // Check that delays are exponentially increasing (within a margin of error)
    // Expected: ~100ms, ~200ms, ~400ms, ~800ms
    let expected_delays_ms = [100, 200, 400, 800];
    for i in 0..delays.len() {
        if i >= expected_delays_ms.len() { break; }
        let delay_ms = delays[i].as_millis() as u64;
        let expected = expected_delays_ms[i];
        let tolerance = expected / 2; // 50% tolerance
        assert!(
            delay_ms >= expected - tolerance && delay_ms <= expected + tolerance,
            "Delay {} ({}ms) is not close to expected {}ms",
            i, delay_ms, expected
        );
    }

    Ok(())
}

/// **Tier 2 Integration Test**
///
/// - **Purpose:** Verify supervisor handles multiple simultaneous worker failures
/// - **Method:**
///   1. Start supervisor with multiple data plane workers
///   2. Kill all data plane workers simultaneously
///   3. Verify supervisor restarts all of them
///   4. Verify system returns to operational state
/// - **Tier:** 2 (Integration)
///
/// **TODO: IMPLEMENT THIS - MEDIUM PRIORITY**
#[tokio::test]
#[ignore] // Remove when implemented
async fn test_supervisor_handles_multiple_failures() -> Result<()> {
    // Proposed Implementation:
    // 1.  **Start Supervisor:** Use the `start_supervisor` helper.
    // 2.  **Get Worker PIDs:** Use the `control_client` to call `list-workers` and
    //     collect the PIDs of all `DataPlane` workers into a Vec. Assert that
    //     more than one data plane worker exists (the default should be the number
    //     of CPU cores).
    // 3.  **Kill All Workers:** Iterate through the collected PIDs and kill each
    //     worker using the `kill_worker` helper.
    // 4.  **Verify Restarts:** Poll the `list-workers` command in a loop for a
    //     few seconds until the number of `DataPlane` workers matches the
    //     original count.
    // 5.  **Check PIDs:** Verify that all the new worker PIDs are different from the
    //     original PIDs, confirming that they were all restarted.

    todo!("Implement multiple failure test")
}

/// **Tier 2 Integration Test - Namespace Isolation**
///
/// - **Purpose:** Run supervisor tests in isolated network namespace
/// - **Method:**
///   1. Create new network namespace
///   2. Run supervisor inside namespace
///   3. Perform tests without affecting host system
/// - **Tier:** 2 (Integration)
///
/// **TODO: IMPLEMENT THIS - MEDIUM PRIORITY**
///
/// This is the "namespace-based test" mentioned in TESTING_PLAN.md.
/// It provides complete isolation from the host system.
///
/// ## Implementation Notes
/// - Use `ip netns add test-{uuid}` to create namespace
/// - Use `ip netns exec test-{uuid} command` to run supervisor
/// - Clean up namespace with `ip netns delete` in test cleanup
/// - May require elevated privileges
#[tokio::test]
#[ignore] // Remove when implemented - requires root
async fn test_supervisor_in_namespace() -> Result<()> {
    // Proposed Implementation:
    // 1.  **Check for Root:** Use `nix::unistd::getuid().is_root()` to check if the
    //     test is running with root privileges. If not, print a message and return
    //     `Ok(())` to skip the test.
    // 2.  **Generate Namespace Name:** Create a unique name for the namespace to
    //     avoid collisions, e.g., `mcr-test-ns-{uuid}`.
    // 3.  **Create Namespace:** Use `tokio::process::Command` to run `ip netns add {ns_name}`.
    //     Await its completion and check for errors.
    // 4.  **Run Supervisor in Namespace:**
    //     a.  Construct a `Command` to run the supervisor: `ip netns exec {ns_name} {path_to_binary} supervisor ...`.
    //     b.  Use a temporary directory for socket paths.
    //     c.  Spawn the command.
    // 5.  **Perform a Simple Test:** Run a simplified version of the restart test
    //     (e.g., `test_supervisor_restarts_control_plane_worker`) against the
    //     supervisor running inside the namespace.
    // 6.  **Cleanup:** Ensure the namespace is deleted at the end of the test, even
    //     if it fails. An RAII guard or a `defer` block would be ideal, but a
    //     simple `finally` block (e.g., using `tokio::spawn` and awaiting) will
    //     work. The cleanup command is `ip netns delete {ns_name}`.

    todo!("Implement namespace isolation test")
}

// TODO: Additional test ideas:
// - test_supervisor_graceful_shutdown
// - test_supervisor_handles_worker_spawn_failure
// - test_supervisor_rate_limits_restart_attempts
// - test_supervisor_logs_worker_failures
