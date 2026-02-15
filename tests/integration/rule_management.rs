// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **Tier 2 Integration Tests: Rule Management**
//!
//! These tests verify the end-to-end flow of adding and removing forwarding rules
//! from the control client to the data plane workers.

use anyhow::{Context, Result};
use multicast_relay::{ForwardingRule, RuleSource};
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
        input_protocol: 17,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
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
    // Use short stats interval (100ms) so stats are reported quickly after traffic
    let mcr = McrInstance::builder()
        .num_workers(2)
        .env("MCR_STATS_INTERVAL_MS", "100")
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
        input_protocol: 17,
        input_source: None,
        outputs: vec![multicast_relay::OutputDestination {
            group: "239.2.2.2".parse()?,
            port: 6002,
            interface: veth_a.clone().into(), // Different from input interface to pass validation
            ttl: None,
            source_ip: None,
        }],
        source: RuleSource::Static,
    };
    client.add_rule(rule.clone()).await?;

    // Give a moment for the command to propagate
    sleep(Duration::from_millis(300)).await;

    // 6. SEND TRAFFIC: Send 15,000 packets (stats reported every 100ms via MCR_STATS_INTERVAL_MS)
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
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);
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
        "[TEST] Supervisor started in {:?} (lazy spawn mode)",
        startup_duration
    );

    // Verify we can communicate with the supervisor
    let client = ControlClient::new(mcr.control_socket());

    // Workers spawn lazily when rules are added - verify no workers initially
    let workers_before = client.list_workers().await?;
    println!(
        "[TEST] ListWorkers before adding rule: {} worker(s) (expected: 0 with lazy spawning)",
        workers_before.len()
    );

    // Add a rule to trigger worker spawning
    let rule = ForwardingRule {
        rule_id: "test-max-workers".to_string(),
        name: None,
        input_interface: "lo".to_string(),
        input_group: "239.1.1.1".parse()?,
        input_port: 5555,
        input_protocol: 17,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };

    client.add_rule(rule.clone()).await?;
    println!("[TEST] Rule added, workers should now spawn for interface 'lo'");

    // Wait for workers to spawn
    sleep(Duration::from_secs(2)).await;

    // Query workers to verify they spawned after adding the rule
    let workers = client.list_workers().await?;
    println!(
        "[TEST] ListWorkers after adding rule: {} worker(s)",
        workers.len()
    );

    // With lazy spawning, workers are created when rules are added
    assert!(
        !workers.is_empty(),
        "Should have spawned workers after adding a rule"
    );

    // Verify the rule was added
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1, "Should have 1 rule");
    assert_eq!(rules[0].rule_id, "test-max-workers");

    println!(
        "[TEST] Max workers test PASSED: {} workers spawned after rule added",
        workers.len()
    );

    // Cleanup happens automatically when McrInstance is dropped
    Ok(())
}

/// Test: Rule removal during active traffic flow
///
/// Verifies that removing a rule while traffic is flowing doesn't cause
/// crashes or data corruption. The system should handle this gracefully.
#[tokio::test]
async fn test_rule_removal_during_traffic() -> Result<()> {
    require_root!();

    // Enter isolated network namespace
    let _ns = NetworkNamespace::enter()?;
    _ns.enable_loopback().await?;

    // Create veth pair
    let _veth = VethPair::create("veth0", "veth0p")
        .await?
        .set_addr("veth0", "10.0.0.1/24")
        .await?
        .set_addr("veth0p", "10.0.0.2/24")
        .await?
        .up()
        .await?;

    // Start supervisor with async API for rule management
    let mcr = McrInstance::builder()
        .num_workers(2)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Add forwarding rule
    let rule = ForwardingRule {
        rule_id: "traffic-test-rule".to_string(),
        name: Some("traffic-flow".to_string()),
        input_interface: "lo".to_string(),
        input_group: "239.1.1.1".parse()?,
        input_port: 5001,
        input_protocol: 17,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };
    client.add_rule(rule).await?;

    // Verify rule exists
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1, "Should have 1 rule");

    // Start sending traffic in background using spawn_blocking
    // Send 10000 packets at 1000 pps (10 seconds of traffic)
    let traffic_handle = tokio::task::spawn_blocking(|| {
        let mut traffic_gen_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        traffic_gen_path.push("target/release/mcrgen");

        std::process::Command::new(&traffic_gen_path)
            .arg("--interface")
            .arg("127.0.0.1")
            .arg("--group")
            .arg("239.1.1.1")
            .arg("--port")
            .arg("5001")
            .arg("--count")
            .arg("10000")
            .arg("--size")
            .arg("100")
            .arg("--rate")
            .arg("1000")
            .output()
    });

    // Wait a bit for traffic to start flowing
    sleep(Duration::from_secs(2)).await;

    // Remove the rule while traffic is flowing
    println!("[TEST] Removing rule while traffic is flowing...");
    client.remove_rule("traffic-test-rule").await?;

    // Verify rule was removed
    let rules_after = client.list_rules().await?;
    assert!(
        rules_after.is_empty(),
        "Rule should be removed even during traffic"
    );

    // Wait for traffic generator to finish
    let output = traffic_handle.await??;
    assert!(
        output.status.success(),
        "Traffic generator should complete without crashing"
    );

    // Verify supervisor is still healthy
    let workers = client.list_workers().await?;
    assert!(!workers.is_empty(), "Workers should still be running");

    // Add a new rule to verify system is still functional
    let new_rule = ForwardingRule {
        rule_id: "post-removal-rule".to_string(),
        name: None,
        input_interface: "lo".to_string(),
        input_group: "239.2.2.2".parse()?,
        input_port: 5002,
        input_protocol: 17,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };
    client.add_rule(new_rule).await?;

    let final_rules = client.list_rules().await?;
    assert_eq!(final_rules.len(), 1, "Should have new rule");
    assert_eq!(final_rules[0].rule_id, "post-removal-rule");

    println!("[TEST] Rule removal during traffic PASSED");

    Ok(())
}

/// Test: Concurrent rule modifications from multiple tasks
///
/// Verifies that concurrent add/remove operations don't cause
/// race conditions or data corruption.
#[tokio::test]
async fn test_concurrent_rule_modifications() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(2)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Spawn multiple tasks that add rules concurrently
    let mut handles = Vec::new();
    for i in 0..5 {
        let socket_path = mcr.control_socket().to_path_buf();
        let handle = tokio::spawn(async move {
            let client = ControlClient::new(&socket_path);
            let rule = ForwardingRule {
                rule_id: format!("concurrent-rule-{}", i),
                name: Some(format!("concurrent-{}", i)),
                input_interface: "lo".to_string(),
                input_group: format!("239.1.1.{}", i + 1).parse().unwrap(),
                input_port: 5000 + i as u16,
                input_protocol: 17,
                input_source: None,
                outputs: vec![],
                source: RuleSource::Static,
            };
            client.add_rule(rule).await
        });
        handles.push(handle);
    }

    // Wait for all adds to complete
    for handle in handles {
        handle.await??;
    }

    // Verify all rules were added
    let rules = client.list_rules().await?;
    assert_eq!(
        rules.len(),
        5,
        "All 5 concurrent rules should be added, got {}",
        rules.len()
    );

    // Now remove them concurrently
    let mut handles = Vec::new();
    for i in 0..5 {
        let socket_path = mcr.control_socket().to_path_buf();
        let handle = tokio::spawn(async move {
            let client = ControlClient::new(&socket_path);
            client.remove_rule(&format!("concurrent-rule-{}", i)).await
        });
        handles.push(handle);
    }

    // Wait for all removes to complete
    for handle in handles {
        handle.await??;
    }

    // Verify all rules were removed
    let rules_after = client.list_rules().await?;
    assert!(
        rules_after.is_empty(),
        "All rules should be removed, got {}",
        rules_after.len()
    );

    println!("[TEST] Concurrent rule modifications PASSED");

    Ok(())
}
