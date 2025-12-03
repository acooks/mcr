// SPDX-License-Identifier: Apache-2.0 OR MIT
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
use tokio::time::{sleep, timeout};

use crate::tests::{cleanup_socket, unique_socket_path_with_prefix};

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
            }).await? {
                Response::Success(_) => Ok(()),
                Response::Error(e) => anyhow::bail!("Failed to add rule: {}", e),
                _ => anyhow::bail!("Unexpected response from supervisor"),
            }
        }

        pub async fn list_rules(&self) -> Result<Vec<ForwardingRule>> {
            match self.send_command(SupervisorCommand::ListRules).await? {
                Response::Rules(rules) => Ok(rules),
                Response::Error(e) => anyhow::bail!("Failed to list rules: {}", e),
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

// NOTE: This test is disabled because run_generic was removed from the supervisor module
// TODO: Rewrite this test to use the actual run() function or mock the supervisor properly
// use multicast_relay::supervisor::run;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

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
#[ignore = "Test disabled: run_generic function was removed from supervisor module"]
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
#[tokio::test]
async fn test_supervisor_handles_multiple_failures() -> Result<()> {
    // 1. Start supervisor
    let (mut supervisor, socket_path) = start_supervisor().await?;
    let client = control_client::ControlClient::new(&socket_path);

    // 2. Get original worker PIDs
    let original_workers = client.list_workers().await?;
    let original_dp_workers: Vec<_> = original_workers
        .into_iter()
        .filter(|w| w.worker_type == "DataPlane")
        .collect();
    let original_dp_pids: std::collections::HashSet<u32> =
        original_dp_workers.iter().map(|w| w.pid).collect();

    assert!(
        original_dp_pids.len() > 1,
        "Expected more than one data plane worker for this test"
    );
    println!("[TEST] Original data plane PIDs: {:?}", original_dp_pids);

    // 3. Kill all data plane workers
    for pid in &original_dp_pids {
        kill_worker(*pid).await?;
    }
    println!("[TEST] All data plane workers killed");

    // 4. Wait for them all to be restarted
    for _ in 0..50 { // 5 second timeout
        if let Ok(current_workers) = client.list_workers().await {
            let current_dp_workers: Vec<_> = current_workers
                .into_iter()
                .filter(|w| w.worker_type == "DataPlane")
                .collect();
            let current_dp_pids: std::collections::HashSet<u32> =
                current_dp_workers.iter().map(|w| w.pid).collect();

            // Check if all original PIDs have been replaced and all new workers are running
            if current_dp_pids.len() == original_dp_pids.len()
                && current_dp_pids.is_disjoint(&original_dp_pids)
                && current_dp_workers.iter().all(|w| is_process_running(w.pid))
            {
                println!("[TEST] All workers restarted with new PIDs: {:?}", current_dp_pids);
                // Success
                supervisor.kill().await?;
                cleanup_socket(&socket_path);
                return Ok(());
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Supervisor did not restart all workers within the timeout")
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
    //     (e.g., `test_supervisor_restarts_data_plane_worker`) against the
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

#[tokio::test]
async fn test_supervisor_handles_concurrent_requests() -> Result<()> {
    // 1. Start supervisor
    let (mut supervisor, socket_path) = start_supervisor().await?;
    let client = control_client::ControlClient::new(&socket_path);

    // 2. Add a rule so we have something to query
    let rule = multicast_relay::ForwardingRule {
        rule_id: "concurrent-rule".to_string(),
        input_interface: "lo".to_string(),
        input_group: "239.0.0.2".parse()?,
        input_port: 5002,
        outputs: vec![],
    };
    client.add_rule(rule).await?;
    sleep(Duration::from_millis(200)).await;

    // 3. Spawn multiple concurrent requests to list rules
    let mut tasks = Vec::new();
    for i in 0..10 {
        let client = control_client::ControlClient::new(&socket_path);
        let task = tokio::spawn(async move {
            println!("[TEST] Starting concurrent request {}", i);
            let result = client.list_rules().await;
            println!("[TEST] Finished concurrent request {}", i);
            result
        });
        tasks.push(task);
    }

    // 5. Await all requests and verify they all succeeded
    for task in tasks {
        let result = task.await?;
        assert!(result.is_ok(), "Concurrent request should succeed");
        let rules = result.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_id, "concurrent-rule");
    }

    // Cleanup
    supervisor.kill().await?;
    cleanup_socket(&socket_path);
    Ok(())
}
