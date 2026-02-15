// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **Integration Tests: Supervisor Resilience**
//!
//! These tests verify that the supervisor correctly handles worker failures
//! and restarts them with proper state synchronization.

use anyhow::{Context, Result};
use multicast_relay::{ForwardingRule, RuleSource};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::time::Duration;
use tokio::time::sleep;

use crate::common::{ControlClient, McrInstance};

/// Helper to check if a process is running (not a zombie)
fn is_process_running(pid: u32) -> bool {
    // Check /proc/{pid}/stat exists and process is not a zombie
    let stat_path = format!("/proc/{}/stat", pid);
    if let Ok(stat) = std::fs::read_to_string(&stat_path) {
        // Second field is state: R=running, S=sleeping, Z=zombie, etc.
        // A zombie process is dead but waiting to be reaped
        !stat.contains(") Z")
    } else {
        false
    }
}

/// Helper to forcibly kill a worker process by PID and wait for it to die
async fn kill_worker(pid: u32) -> Result<()> {
    kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
        .context(format!("Failed to kill worker {}", pid))?;

    // Wait for process to actually die (supervisor will reap it)
    for _ in 0..50 {
        sleep(Duration::from_millis(50)).await;
        if !is_process_running(pid) {
            return Ok(());
        }
    }
    // Even if still zombie, that's ok - supervisor will reap and restart
    Ok(())
}

/// Test: Supervisor restarts a killed data plane worker
///
/// Verifies that when a data plane worker is killed, the supervisor
/// detects the failure and spawns a replacement worker.
#[tokio::test]
async fn test_supervisor_restarts_killed_worker() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Add a rule first to trigger worker spawning (lazy spawn mode)
    let rule = ForwardingRule {
        rule_id: "restart-test-rule".to_string(),
        name: Some("restart-test".to_string()),
        input_interface: "lo".to_string(),
        input_group: "239.0.0.1".parse()?,
        input_port: 5000,
        input_protocol: 17,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };
    client.add_rule(rule).await?;
    println!("[TEST] Rule added to trigger worker spawning");

    sleep(Duration::from_millis(500)).await;

    // Get a data plane worker PID
    let workers = client.list_workers().await?;
    let dp_worker = workers
        .iter()
        .find(|w| w.worker_type == "DataPlane")
        .ok_or_else(|| anyhow::anyhow!("No data plane worker found (lazy spawn requires rules)"))?;
    let original_pid = dp_worker.pid;
    println!("[TEST] Original data plane worker PID: {}", original_pid);

    // Kill the worker and wait for it to die
    kill_worker(original_pid).await?;
    println!("[TEST] Worker {} killed successfully", original_pid);

    // Wait for supervisor to restart the worker (up to 10 seconds)
    let mut new_pid = None;
    for attempt in 0..100 {
        sleep(Duration::from_millis(100)).await;
        match client.list_workers().await {
            Ok(workers) => {
                let dp_workers: Vec<_> = workers
                    .iter()
                    .filter(|w| w.worker_type == "DataPlane")
                    .collect();
                if attempt % 10 == 0 {
                    println!(
                        "[TEST] Attempt {}: {} DP workers, PIDs: {:?}",
                        attempt,
                        dp_workers.len(),
                        dp_workers.iter().map(|w| w.pid).collect::<Vec<_>>()
                    );
                }
                if let Some(dp) = dp_workers
                    .iter()
                    .find(|w| w.pid != original_pid && is_process_running(w.pid))
                {
                    new_pid = Some(dp.pid);
                    println!("[TEST] Worker restarted with new PID: {}", dp.pid);
                    break;
                }
            }
            Err(e) => {
                println!("[TEST] Attempt {}: Error listing workers: {}", attempt, e);
            }
        }
    }

    // Verify restart succeeded
    let new_pid =
        new_pid.ok_or_else(|| anyhow::anyhow!("Worker was not restarted within timeout"))?;
    assert_ne!(
        new_pid, original_pid,
        "New worker should have different PID"
    );
    assert!(is_process_running(new_pid), "New worker should be running");

    println!("[TEST] Supervisor restart test PASSED");
    Ok(())
}

/// Test: Rules persist after worker restart
///
/// Verifies that when a worker is restarted, the supervisor's rule state
/// is preserved and can still be queried.
#[tokio::test]
async fn test_rules_persist_after_worker_restart() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Add a forwarding rule
    let rule = ForwardingRule {
        rule_id: "persist-test-rule".to_string(),
        name: Some("persistence-test".to_string()),
        input_interface: "lo".to_string(),
        input_group: "239.0.0.1".parse()?,
        input_port: 5001,
        input_protocol: 17,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };
    client.add_rule(rule).await?;

    // Verify rule was added
    let rules_before = client.list_rules().await?;
    assert_eq!(rules_before.len(), 1);
    assert_eq!(rules_before[0].rule_id, "persist-test-rule");

    // Kill a data plane worker
    let workers = client.list_workers().await?;
    let dp_worker = workers
        .iter()
        .find(|w| w.worker_type == "DataPlane")
        .ok_or_else(|| anyhow::anyhow!("No data plane worker found"))?;
    kill_worker(dp_worker.pid).await?;

    // Wait for restart
    sleep(Duration::from_secs(1)).await;

    // Verify the supervisor still has the rule
    let rules_after = client.list_rules().await?;
    assert_eq!(
        rules_after.len(),
        1,
        "Rule should persist after worker restart"
    );
    assert_eq!(rules_after[0].rule_id, "persist-test-rule");

    // Verify we can still add new rules (system is functional)
    let new_rule = ForwardingRule {
        rule_id: "post-restart-rule".to_string(),
        name: None,
        input_interface: "lo".to_string(),
        input_group: "239.0.0.2".parse()?,
        input_port: 5002,
        input_protocol: 17,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };
    client.add_rule(new_rule).await?;

    let final_rules = client.list_rules().await?;
    assert_eq!(final_rules.len(), 2, "Should have both rules after restart");

    println!("[TEST] Rules persist after restart PASSED");
    Ok(())
}

/// Test: Supervisor handles multiple simultaneous worker failures
///
/// Starts supervisor with multiple workers, kills all of them, and
/// verifies the supervisor restarts all of them.
#[tokio::test]
async fn test_supervisor_handles_multiple_worker_failures() -> Result<()> {
    require_root!();

    // Start with multiple workers
    let num_workers = 2u32;
    let mcr = McrInstance::builder()
        .num_workers(num_workers)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Add a rule first to trigger worker spawning (lazy spawn mode)
    let rule = ForwardingRule {
        rule_id: "multi-failure-test-rule".to_string(),
        name: Some("multi-failure-test".to_string()),
        input_interface: "lo".to_string(),
        input_group: "239.0.0.1".parse()?,
        input_port: 5000,
        input_protocol: 17,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };
    client.add_rule(rule).await?;
    println!("[TEST] Rule added to trigger worker spawning");

    sleep(Duration::from_millis(500)).await;

    // Get original worker PIDs
    let original_workers = client.list_workers().await?;
    let original_dp_workers: Vec<_> = original_workers
        .iter()
        .filter(|w| w.worker_type == "DataPlane")
        .collect();

    let worker_count = original_dp_workers.len();
    println!("[TEST] Started with {} data plane workers", worker_count);

    if worker_count < 2 {
        println!("[TEST] Skipping multi-failure test: need at least 2 workers");
        return Ok(());
    }

    let original_pids: std::collections::HashSet<u32> =
        original_dp_workers.iter().map(|w| w.pid).collect();
    println!("[TEST] Original PIDs: {:?}", original_pids);

    // Kill all data plane workers
    for worker in &original_dp_workers {
        kill_worker(worker.pid).await?;
    }
    println!("[TEST] All {} workers killed", worker_count);

    // Wait for all to be restarted (up to 10 seconds)
    for attempt in 0..100 {
        sleep(Duration::from_millis(100)).await;

        if let Ok(current_workers) = client.list_workers().await {
            let current_dp_workers: Vec<_> = current_workers
                .iter()
                .filter(|w| w.worker_type == "DataPlane")
                .collect();
            let current_pids: std::collections::HashSet<u32> =
                current_dp_workers.iter().map(|w| w.pid).collect();

            // Check if all original PIDs have been replaced
            if current_pids.len() >= worker_count
                && current_pids.is_disjoint(&original_pids)
                && current_dp_workers.iter().all(|w| is_process_running(w.pid))
            {
                println!(
                    "[TEST] All workers restarted after {} attempts. New PIDs: {:?}",
                    attempt + 1,
                    current_pids
                );
                println!("[TEST] Multiple worker failures test PASSED");
                return Ok(());
            }
        }
    }

    anyhow::bail!("Supervisor did not restart all workers within timeout")
}
