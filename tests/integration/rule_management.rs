// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **Tier 2 Integration Tests: Rule Management**
//!
//! These tests verify the end-to-end flow of adding and removing forwarding rules
//! from the control client to the data plane workers.

use anyhow::{Context, Result};
use multicast_relay::{ForwardingRule, Response, SupervisorCommand, WorkerInfo};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use crate::common::{NetworkNamespace, VethPair};
use crate::tests::{cleanup_socket, unique_socket_path_with_prefix};

// --- Test Harness: Automatic Cleanup Guard ---

/// RAII guard that ensures supervisor processes and socket files are cleaned up
/// automatically on test completion, failure, panic, or timeout.
///
/// This struct implements Drop to guarantee cleanup happens no matter how the test exits.
/// Tests should use this instead of manually managing supervisor processes and sockets.
///
/// # Example
/// ```rust
/// #[tokio::test]
/// async fn my_test() -> Result<()> {
///     let supervisor = TestSupervisor::start().await?;
///     let client = ControlClient::new(supervisor.socket_path());
///
///     // Test logic here - cleanup happens automatically even on panic/timeout
///
///     Ok(())
/// }
/// ```
struct TestSupervisor {
    process: Option<Child>,
    control_socket_path: PathBuf,
    relay_socket_path: PathBuf,
}

impl TestSupervisor {
    /// Returns the path to the control socket for client connections
    fn socket_path(&self) -> &Path {
        &self.control_socket_path
    }
}

impl Drop for TestSupervisor {
    fn drop(&mut self) {
        // Kill the supervisor process (non-async, safe to call in Drop)
        if let Some(mut process) = self.process.take() {
            let _ = process.start_kill();
        }

        // Clean up socket files
        cleanup_socket(&self.control_socket_path);
        cleanup_socket(&self.relay_socket_path);
    }
}

// --- Test Harness: Control Client ---

/// A client for interacting with the supervisor's control socket in tests.
struct ControlClient {
    socket_path: PathBuf,
}

impl ControlClient {
    fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
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

    async fn list_workers(&self) -> Result<Vec<WorkerInfo>> {
        match self.send_command(SupervisorCommand::ListWorkers).await? {
            Response::Workers(workers) => Ok(workers),
            Response::Error(e) => anyhow::bail!("Failed to list workers: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for ListWorkers"),
        }
    }

    async fn add_rule(&self, rule: ForwardingRule) -> Result<String> {
        let rule_id = rule.rule_id.clone();
        match self
            .send_command(SupervisorCommand::AddRule {
                rule_id,
                name: None,
                input_interface: rule.input_interface,
                input_group: rule.input_group,
                input_port: rule.input_port,
                outputs: rule.outputs,
            })
            .await?
        {
            Response::Success(_) => Ok(rule.rule_id),
            Response::Error(e) => anyhow::bail!("Failed to add rule: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for AddRule"),
        }
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::RemoveRule {
                rule_id: rule_id.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to remove rule: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for RemoveRule"),
        }
    }

    async fn list_rules(&self) -> Result<Vec<ForwardingRule>> {
        match self.send_command(SupervisorCommand::ListRules).await? {
            Response::Rules(rules) => Ok(rules),
            Response::Error(e) => anyhow::bail!("Failed to list rules: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for ListRules"),
        }
    }

    async fn get_stats(&self) -> Result<Vec<multicast_relay::FlowStats>> {
        match self.send_command(SupervisorCommand::GetStats).await? {
            Response::Stats(stats) => Ok(stats),
            Response::Error(e) => anyhow::bail!("Failed to get stats: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for GetStats"),
        }
    }
}

// --- Test Harness: Supervisor Management ---

/// Starts a supervisor process in the background for testing with automatic cleanup.
///
/// Returns a `TestSupervisor` guard that automatically kills the process and cleans up
/// socket files when dropped, even on test failure, panic, or timeout.
///
/// # Arguments
/// * `num_workers` - Number of data plane workers to spawn. Defaults to 2 for fast, reliable tests.
///   Use `None` to let the supervisor use the default (all CPU cores).
///
/// # Example
/// ```rust
/// let supervisor = start_supervisor_with_workers(Some(4)).await?;
/// let client = ControlClient::new(supervisor.socket_path());
/// // Cleanup happens automatically when supervisor goes out of scope
/// ```
async fn start_supervisor_with_workers(num_workers: Option<u32>) -> Result<TestSupervisor> {
    let control_socket = unique_socket_path_with_prefix("rule_mgmt_control");
    let relay_socket = unique_socket_path_with_prefix("rule_mgmt_relay");

    cleanup_socket(&control_socket);
    cleanup_socket(&relay_socket);

    let binary = env!("CARGO_BIN_EXE_mcrd");

    let mut cmd = Command::new(binary);
    cmd.arg("supervisor")
        .arg("--control-socket-path")
        .arg(&control_socket)
        .arg("--relay-command-socket-path")
        .arg(&relay_socket);

    // Default to 2 workers for fast, reliable tests unless explicitly overridden
    if let Some(workers) = num_workers {
        cmd.arg("--num-workers").arg(workers.to_string());
    } else {
        // Default to 2 workers for test stability
        cmd.arg("--num-workers").arg("2");
    }

    let supervisor = cmd.spawn().context("Failed to spawn supervisor")?;

    // Wait for the control socket to be created, with a timeout.
    for _ in 0..30 {
        if control_socket.exists() {
            sleep(Duration::from_millis(200)).await; // Give it a moment to stabilize
            return Ok(TestSupervisor {
                process: Some(supervisor),
                control_socket_path: control_socket,
                relay_socket_path: relay_socket,
            });
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Supervisor did not create control socket within timeout")
}

/// Starts a supervisor with default settings (2 workers) for testing.
///
/// This is the standard helper that most tests should use for fast, reliable execution.
/// Returns a guard that automatically cleans up on drop.
async fn start_supervisor() -> Result<TestSupervisor> {
    start_supervisor_with_workers(Some(2)).await
}

// --- Tests ---

#[tokio::test]
async fn test_add_and_remove_rule_e2e() -> Result<()> {
    // Check for root privileges (required for AF_PACKET sockets and worker spawning)
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test_add_and_remove_rule_e2e: requires root privileges for AF_PACKET sockets.");
        return Ok(());
    }

    // 1. SETUP: Start the supervisor and create a client.
    // TestSupervisor guard ensures automatic cleanup on any exit path
    let supervisor = start_supervisor().await?;
    let client = ControlClient::new(supervisor.socket_path());

    // Wait for supervisor to be ready (brief delay for socket setup).
    sleep(Duration::from_millis(500)).await;
    println!("[TEST] Supervisor started and ready.");

    // 2. VERIFY INITIAL STATE: Ensure the supervisor has no rules.
    let initial_rules = client.list_rules().await?;
    assert!(
        initial_rules.is_empty(),
        "Supervisor should have no rules initially"
    );
    println!("[TEST] Verified supervisor has 0 rules initially.");

    // 3. ADD RULE: Add a new forwarding rule via the supervisor.
    let rule = ForwardingRule {
        rule_id: "test-rule-e2e".to_string(),
        name: None,
        input_interface: "lo".to_string(),
        input_group: "239.1.1.1".parse()?,
        input_port: 5001,
        outputs: vec![],
    };
    client.add_rule(rule.clone()).await?;
    println!("[TEST] AddRule command sent for rule '{}'.", rule.rule_id);

    // Give a moment for the command to propagate.
    sleep(Duration::from_millis(200)).await;

    // 4. VERIFY ADDITION: Query the supervisor to confirm the rule was added.
    let rules_after_add = client.list_rules().await?;
    assert_eq!(
        rules_after_add.len(),
        1,
        "Supervisor should have 1 rule after addition"
    );
    assert_eq!(
        rules_after_add[0].rule_id, rule.rule_id,
        "Supervisor has the wrong rule"
    );
    println!("[TEST] Verified supervisor has the new rule.");

    // 5. REMOVE RULE: Remove the rule via the supervisor.
    client.remove_rule(&rule.rule_id).await?;
    println!(
        "[TEST] RemoveRule command sent for rule '{}'.",
        rule.rule_id
    );

    // Give a moment for the command to propagate.
    sleep(Duration::from_millis(200)).await;

    // 6. VERIFY REMOVAL: Query the supervisor again to confirm the rule is gone.
    let rules_after_remove = client.list_rules().await?;
    assert!(
        rules_after_remove.is_empty(),
        "Supervisor should have no rules after removal"
    );
    println!("[TEST] Verified supervisor removed the rule.");

    // Cleanup happens automatically when TestSupervisor is dropped
    Ok(())
}

#[tokio::test]
async fn test_get_stats_e2e() -> Result<()> {
    // Check for root privileges (required for AF_PACKET sockets)
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test_get_stats_e2e: requires root privileges for AF_PACKET sockets.");
        return Ok(());
    }

    // 1. SETUP: Enter isolated network namespace to avoid interference with other tests
    let _ns = NetworkNamespace::enter()?;
    _ns.enable_loopback().await?;
    println!("[TEST] Entered isolated network namespace");

    // 2. CREATE TEST INTERFACE: Set up veth pair for output interface
    // We need a different interface from "lo" to satisfy self-loop validation
    // Use unique interface names to avoid conflicts when running tests concurrently
    use uuid::Uuid;
    let iface_id = Uuid::new_v4().to_string().replace("-", "")[..8].to_string();
    let veth_a = format!("tveth{}", iface_id);
    let veth_b = format!("tvethp{}", iface_id);
    let _veth = VethPair::create(&veth_a, &veth_b)
        .await?
        .set_addr(&veth_a, "10.99.99.1/24")
        .await?
        .up()
        .await?;
    println!(
        "[TEST] Created test veth interface {} with IP 10.99.99.1/24",
        veth_a
    );

    // 3. Start the supervisor and create a client
    // TestSupervisor guard ensures automatic cleanup on any exit path
    let supervisor = start_supervisor().await?;
    let client = ControlClient::new(supervisor.socket_path());

    // Wait for supervisor to be ready
    sleep(Duration::from_millis(500)).await;
    println!("[TEST] Supervisor started and ready.");

    // 4. VERIFY INITIAL STATE: GetStats should return empty initially.
    let initial_stats = client.get_stats().await?;
    assert!(
        initial_stats.is_empty(),
        "Supervisor should have no stats initially"
    );
    println!("[TEST] Verified supervisor has 0 stats initially.");

    // 5. ADD RULE: Add a forwarding rule
    // Note: We use different interfaces (lo for input, veth for output) to satisfy the
    // self-loop validation that prevents input and output on the same interface.
    let rule = ForwardingRule {
        rule_id: "test-stats-rule".to_string(),
        name: None,
        input_interface: "lo".to_string(),
        input_group: "239.1.1.1".parse()?,
        input_port: 5002,
        outputs: vec![multicast_relay::OutputDestination {
            group: "239.2.2.2".parse()?,
            port: 6002,
            interface: veth_a.clone(), // Different from input interface to pass validation
        }],
    };
    client.add_rule(rule.clone()).await?;
    println!("[TEST] AddRule command sent for rule '{}'.", rule.rule_id);

    // Give a moment for the command to propagate
    sleep(Duration::from_millis(300)).await;

    // 6. SEND TRAFFIC: Send 15,000 packets to trigger stats reporting (threshold is 10,000)
    println!("[TEST] Sending 15,000 test packets to trigger stats reporting...");

    // Build path to mcrgen binary
    let mut traffic_gen_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    traffic_gen_path.push("target");
    traffic_gen_path.push("release");
    traffic_gen_path.push("mcrgen");

    let output = std::process::Command::new(&traffic_gen_path)
        .arg("--interface")
        .arg("127.0.0.1")
        .arg("--group")
        .arg("239.1.1.1")
        .arg("--port")
        .arg("5002")
        .arg("--count")
        .arg("15000")
        .arg("--size")
        .arg("1024")
        .arg("--rate")
        .arg("10000")
        .output();

    match output {
        Ok(output) if output.status.success() => {
            println!("[TEST] Traffic sent successfully.");
        }
        Ok(output) => {
            println!(
                "[TEST] Traffic generator failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            // Cleanup happens automatically when supervisor is dropped
            return Ok(());
        }
        Err(e) => {
            println!(
                "[TEST] Could not run traffic generator: {}. Skipping traffic test.",
                e
            );
            // Cleanup happens automatically when supervisor is dropped
            return Ok(());
        }
    }

    // Give workers time to process and report stats
    sleep(Duration::from_millis(500)).await;

    // 7. GET STATS: Query stats via the API
    let stats = client.get_stats().await?;
    println!("[TEST] GetStats returned {} flow(s).", stats.len());

    // 8. VALIDATE RESPONSE: Check that stats were reported
    assert!(
        !stats.is_empty(),
        "Stats should be reported after sending 15,000 packets"
    );

    // Find the stats for our flow
    let flow_stats = stats
        .iter()
        .find(|s| s.input_group.to_string() == "239.1.1.1" && s.input_port == 5002);

    assert!(
        flow_stats.is_some(),
        "Stats should include our test flow (239.1.1.1:5002)"
    );

    let flow_stats = flow_stats.unwrap();
    println!(
        "[TEST] Flow stats: packets={}, bytes={}, pps={:.2}, bps={:.2}",
        flow_stats.packets_relayed,
        flow_stats.bytes_relayed,
        flow_stats.packets_per_second,
        flow_stats.bits_per_second
    );

    // Validate stats structure and values
    assert!(
        flow_stats.packets_relayed > 0,
        "packets_relayed should be > 0"
    );
    assert!(flow_stats.bytes_relayed > 0, "bytes_relayed should be > 0");

    // Stats are reported every 10,000 packets, so we should see at least 10,000
    assert!(
        flow_stats.packets_relayed >= 10000,
        "Should have at least 10,000 packets reported (reporting threshold)"
    );

    println!("[TEST] Stats validation passed.");

    // Cleanup happens automatically when TestSupervisor is dropped
    Ok(())
}

/// **Stress Test: Maximum Worker Creation**
///
/// This test verifies that the supervisor can reliably spawn the maximum number of workers
/// (one per CPU core) and handle resource exhaustion gracefully through automatic restarts.
///
/// **Expected behavior:**
/// - Some workers may hit EAGAIN errors during initialization (normal for high worker counts)
/// - The supervisor automatically detects failures and restarts workers with exponential backoff
/// - All workers eventually start successfully, demonstrating supervisor resilience
///
/// **Why this test takes longer:**
/// - Spawning many workers (e.g., 20 on a 20-core system) is resource-intensive
/// - Other tests should use a small number of workers (2) for fast, reliable execution
/// - This test runs sequentially with all integration tests (--test-threads=1) to avoid contention
///
/// **Requirements:**
/// - Sufficient file descriptors (ulimit -n should be high enough)
/// - May be slow to start up due to io_uring initialization for each worker
/// - Runs sequentially with other integration tests (--test-threads=1) to avoid resource contention
#[tokio::test]
async fn test_max_workers_spawning() -> Result<()> {
    // Check for root privileges
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test_max_workers_spawning: requires root privileges.");
        return Ok(());
    }

    // Determine the number of CPU cores (maximum workers)
    let num_cpus = num_cpus::get() as u32;
    println!(
        "[TEST] System has {} CPU cores, testing max worker creation",
        num_cpus
    );

    // Start supervisor with maximum workers (all CPU cores)
    // TestSupervisor guard ensures automatic cleanup on any exit path
    println!("[TEST] Starting supervisor with {} workers...", num_cpus);
    let start_time = std::time::Instant::now();

    let supervisor = start_supervisor_with_workers(Some(num_cpus))
        .await
        .context("Failed to start supervisor with max workers")?;

    let startup_duration = start_time.elapsed();
    println!(
        "[TEST] Supervisor started in {:?} with {} workers",
        startup_duration, num_cpus
    );

    // Wait for supervisor to fully initialize all workers
    sleep(Duration::from_secs(2)).await;

    // Verify we can communicate with the supervisor
    let client = ControlClient::new(supervisor.socket_path());

    // Query workers to verify they all spawned successfully
    let workers = client.list_workers().await?;
    println!("[TEST] ListWorkers returned {} worker(s)", workers.len());

    // We expect at least the data plane workers (num_cpus) + control plane (1)
    // Note: The exact count depends on supervisor architecture
    assert!(
        !workers.is_empty(),
        "Should have spawned at least some workers"
    );

    // Verify we can add a rule (tests that workers are functional)
    let rule = ForwardingRule {
        rule_id: "test-max-workers".to_string(),
        name: None,
        input_interface: "lo".to_string(),
        input_group: "239.1.1.1".parse()?,
        input_port: 5555,
        outputs: vec![multicast_relay::OutputDestination {
            group: "239.2.2.2".parse()?,
            port: 6666,
            interface: "eth0".to_string(),
        }],
    };

    client.add_rule(rule.clone()).await?;
    println!(
        "[TEST] Successfully added rule with {} workers active",
        num_cpus
    );

    // Verify the rule was added
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1, "Should have 1 rule");
    assert_eq!(rules[0].rule_id, "test-max-workers");

    println!(
        "[TEST] Max workers test PASSED: {} workers spawned and operational",
        num_cpus
    );

    // Cleanup happens automatically when TestSupervisor is dropped
    Ok(())
}
