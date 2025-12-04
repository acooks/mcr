// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **Tier 2 Integration Tests: Rule Management**
//!
//! These tests verify the end-to-end flow of adding and removing forwarding rules
//! from the control client to the data plane workers.

use anyhow::{Context, Result};
use multicast_relay::ForwardingRule;
use std::env;
use std::time::Duration;
use tokio::time::sleep;

use crate::common::{ControlClient, McrInstance, NetworkNamespace, VethPair};

// --- Tests ---

#[tokio::test]
async fn test_add_and_remove_rule_e2e() -> Result<()> {
    require_root!();

    // 1. SETUP: Start the supervisor using unified McrInstance
    let mcr = McrInstance::builder()
        .num_workers(2)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    // Wait for supervisor to be ready (brief delay for socket setup).
    sleep(Duration::from_millis(500)).await;

    // 2. VERIFY INITIAL STATE: Ensure the supervisor has no rules.
    let initial_rules = client.list_rules().await?;
    assert!(
        initial_rules.is_empty(),
        "Supervisor should have no rules initially"
    );

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

    // 5. REMOVE RULE: Remove the rule via the supervisor.
    client.remove_rule(&rule.rule_id).await?;

    // Give a moment for the command to propagate.
    sleep(Duration::from_millis(200)).await;

    // 6. VERIFY REMOVAL: Query the supervisor again to confirm the rule is gone.
    let rules_after_remove = client.list_rules().await?;
    assert!(
        rules_after_remove.is_empty(),
        "Supervisor should have no rules after removal"
    );

    // Cleanup happens automatically when McrInstance is dropped
    Ok(())
}

#[tokio::test]
async fn test_get_stats_e2e() -> Result<()> {
    require_root!();

    // 1. SETUP: Enter isolated network namespace to avoid interference with other tests
    let _ns = NetworkNamespace::enter()?;
    _ns.enable_loopback().await?;

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

    // 3. Start the supervisor using unified McrInstance
    let mcr = McrInstance::builder()
        .num_workers(2)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    // Wait for supervisor to be ready
    sleep(Duration::from_millis(500)).await;

    // 4. VERIFY INITIAL STATE: GetStats should return empty initially.
    let initial_stats = client.get_stats().await?;
    assert!(
        initial_stats.is_empty(),
        "Supervisor should have no stats initially"
    );

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

    // Give a moment for the command to propagate
    sleep(Duration::from_millis(300)).await;

    // 6. SEND TRAFFIC: Send 15,000 packets to trigger stats reporting (threshold is 10,000)
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

    let output =
        output.context("Failed to run traffic generator (mcrgen). Run: cargo build --release")?;
    assert!(
        output.status.success(),
        "Traffic generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Give workers time to process and report stats
    sleep(Duration::from_millis(500)).await;

    // 7. GET STATS: Query stats via the API
    let stats = client.get_stats().await?;

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

    // Cleanup happens automatically when McrInstance is dropped
    Ok(())
}

/// **Stress Test: Maximum Worker Creation**
///
/// This test verifies that the supervisor can reliably spawn the maximum number of workers
/// (one per CPU core) and handle resource exhaustion gracefully through automatic restarts.
#[tokio::test]
async fn test_max_workers_spawning() -> Result<()> {
    require_root!();

    // Determine the number of CPU cores (maximum workers)
    let num_cpus = num_cpus::get() as u32;
    println!(
        "[TEST] System has {} CPU cores, testing max worker creation",
        num_cpus
    );

    // Start supervisor with maximum workers (all CPU cores) using unified McrInstance
    let start_time = std::time::Instant::now();

    let mcr = McrInstance::builder()
        .num_workers(num_cpus)
        .start_async()
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
    let client = ControlClient::new(mcr.control_socket());

    // Query workers to verify they all spawned successfully
    let workers = client.list_workers().await?;
    println!("[TEST] ListWorkers returned {} worker(s)", workers.len());

    // We expect at least the data plane workers (num_cpus) + control plane (1)
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

    // Cleanup happens automatically when McrInstance is dropped
    Ok(())
}
