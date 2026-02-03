// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **Integration Tests: Control Socket Responsiveness**
//!
//! These tests verify that the supervisor control socket remains responsive
//! during worker lifecycle events (restarts, spawning) that block the
//! main select! loop.
//!
//! Bug context: The supervisor's select! loop handles client connections
//! inline (not spawned as separate tasks). Long-running operations in
//! other select branches (e.g. health check backoff sleep, worker spawning)
//! block the loop and prevent new client connections from being accepted.

use anyhow::{Context, Result};
use multicast_relay::{ForwardingRule, RuleSource, WorkerStatus};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::common::{ControlClient, McrInstance};

/// Maximum acceptable response time for any single control socket query.
/// The health check backoff starts at 250ms and doubles up to 16s.
/// If the select! loop blocks during backoff sleep, individual queries
/// will see latency equal to the remaining sleep duration.
/// This threshold is set to catch the known bug where the select! loop blocks
/// during worker restart backoff sleep. The initial backoff is 250ms, which
/// causes ~260ms query latency. Set above that to allow the test to pass for
/// now; lower to 100ms once the fix is applied to verify the fix works.
const MAX_RESPONSE_MS: u64 = 100;

/// Helper to kill a worker process
async fn kill_worker(pid: u32) -> Result<()> {
    kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
        .context(format!("Failed to kill worker {}", pid))?;
    sleep(Duration::from_millis(50)).await;
    Ok(())
}

/// Send rapid-fire ListRules queries for `duration` and return the worst
/// (maximum) response time observed across all queries.
async fn measure_worst_latency(
    client: &ControlClient<'_>,
    duration: Duration,
) -> (u128, usize, usize) {
    let deadline = Instant::now() + duration;
    let mut worst_ms: u128 = 0;
    let mut total_queries: usize = 0;
    let mut failed_queries: usize = 0;

    while Instant::now() < deadline {
        let start = Instant::now();
        let timeout = Duration::from_secs(5);
        match tokio::time::timeout(timeout, client.list_rules()).await {
            Ok(Ok(_)) => {
                let elapsed = start.elapsed().as_millis();
                if elapsed > worst_ms {
                    worst_ms = elapsed;
                }
                total_queries += 1;
            }
            Ok(Err(_)) | Err(_) => {
                let elapsed = start.elapsed().as_millis();
                if elapsed > worst_ms {
                    worst_ms = elapsed;
                }
                total_queries += 1;
                failed_queries += 1;
            }
        }
        // Small gap between queries to avoid overwhelming the socket
        sleep(Duration::from_millis(20)).await;
    }

    (worst_ms, total_queries, failed_queries)
}

/// Test: Control socket responds promptly during worker restart backoff
///
/// When a worker crashes (non-zero exit), the health check branch calls
/// sleep(backoff).await inside the select! loop, blocking all other
/// branches including client accept. This test kills a worker and then
/// sends rapid queries for several seconds to catch the blocking window.
#[tokio::test]
async fn test_control_socket_responsive_during_worker_restart() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());
    sleep(Duration::from_millis(500)).await;

    // Add a rule to trigger worker spawning
    let rule = ForwardingRule {
        rule_id: "responsiveness-test".to_string(),
        name: Some("responsiveness-test".to_string()),
        input_interface: "lo".to_string(),
        input_group: "239.0.0.1".parse()?,
        input_port: 5000,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };
    client.add_rule(rule).await?;
    sleep(Duration::from_millis(500)).await;

    // Measure baseline worst-case latency (no worker churn)
    let (baseline_worst, baseline_count, _) =
        measure_worst_latency(&client, Duration::from_secs(1)).await;
    println!(
        "[TEST] Baseline: worst={}ms over {} queries",
        baseline_worst, baseline_count
    );

    // Kill the worker to trigger the backoff sleep path
    let workers = client.list_workers().await?;
    let dp_worker = workers
        .iter()
        .find(|w| w.worker_type == "DataPlane")
        .ok_or_else(|| anyhow::anyhow!("No data plane worker found"))?;
    println!("[TEST] Killing worker PID {}", dp_worker.pid);
    kill_worker(dp_worker.pid).await?;

    // Poll ListWorkers until we see a worker with Restarting status.
    // The health check interval is 250ms, so it should be detected quickly.
    let mut saw_restarting = false;
    for _ in 0..20 {
        if let Ok(workers) = client.list_workers().await {
            if workers
                .iter()
                .any(|w| matches!(w.status, WorkerStatus::Restarting { .. }))
            {
                saw_restarting = true;
                println!("[TEST] Saw worker with Restarting status in ListWorkers");
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        saw_restarting,
        "Expected to see a worker with Restarting status in ListWorkers after kill"
    );

    // Immediately start sending queries for 2 seconds to overlap with
    // the health check tick (250ms interval) and its backoff sleep (250ms).
    let (worst_ms, total, failed) = measure_worst_latency(&client, Duration::from_secs(2)).await;
    println!(
        "[TEST] During restart: worst={}ms, total={}, failed={} queries",
        worst_ms, total, failed
    );

    assert_eq!(
        failed, 0,
        "Control socket had {} failed/timed-out queries during worker restart",
        failed
    );
    assert!(
        worst_ms < MAX_RESPONSE_MS as u128,
        "Worst response {}ms exceeds {}ms limit -- \
         select! loop likely blocked by health check backoff sleep (baseline: {}ms)",
        worst_ms,
        MAX_RESPONSE_MS,
        baseline_worst
    );

    println!("[TEST] Control socket responsiveness during restart PASSED");
    Ok(())
}

/// Test: Control socket responds promptly during repeated worker failures
///
/// Repeatedly killing the worker causes escalating backoff delays (250ms,
/// 500ms, 1s, 2s, ..., up to 16s). Each backoff sleep blocks the entire
/// select! loop for its full duration. This test sends continuous queries
/// across multiple crash/restart cycles to catch the increasingly long
/// blocking windows.
#[tokio::test]
async fn test_control_socket_responsive_during_repeated_failures() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());
    sleep(Duration::from_millis(500)).await;

    let rule = ForwardingRule {
        rule_id: "repeated-failure-test".to_string(),
        name: Some("repeated-failure-test".to_string()),
        input_interface: "lo".to_string(),
        input_group: "239.0.0.1".parse()?,
        input_port: 5000,
        input_source: None,
        outputs: vec![],
        source: RuleSource::Static,
    };
    client.add_rule(rule).await?;
    sleep(Duration::from_millis(500)).await;

    let mut overall_worst: u128 = 0;

    for crash_num in 1..=4 {
        // Wait for the worker to be (re)spawned
        let mut worker_pid = None;
        for _ in 0..60 {
            sleep(Duration::from_millis(500)).await;
            if let Ok(workers) = client.list_workers().await {
                if let Some(dp) = workers.iter().find(|w| w.worker_type == "DataPlane") {
                    worker_pid = Some(dp.pid);
                    break;
                }
            }
        }

        let pid = worker_pid
            .ok_or_else(|| anyhow::anyhow!("No worker found before crash #{}", crash_num))?;

        let expected_backoff_ms = 250 * (1u64 << (crash_num - 1)); // 250, 500, 1000, 2000
        println!(
            "[TEST] Crash #{}: killing PID {} (expected backoff ~{}ms)",
            crash_num, pid, expected_backoff_ms
        );
        kill_worker(pid).await?;

        // Query continuously for longer than the expected backoff to ensure
        // we overlap with the blocking window.
        let probe_duration = Duration::from_millis(expected_backoff_ms + 500);
        let (worst_ms, total, failed) = measure_worst_latency(&client, probe_duration).await;
        println!(
            "[TEST] Crash #{}: worst={}ms, total={}, failed={} queries",
            crash_num, worst_ms, total, failed
        );

        if worst_ms > overall_worst {
            overall_worst = worst_ms;
        }

        assert_eq!(
            failed, 0,
            "Crash #{}: {} queries failed/timed-out (backoff ~{}ms)",
            crash_num, failed, expected_backoff_ms
        );
        assert!(
            worst_ms < MAX_RESPONSE_MS as u128,
            "Crash #{}: worst response {}ms exceeds {}ms -- \
             backoff sleep (~{}ms) likely blocking select! loop",
            crash_num,
            worst_ms,
            MAX_RESPONSE_MS,
            expected_backoff_ms
        );
    }

    println!(
        "[TEST] Overall worst latency across all crashes: {}ms",
        overall_worst
    );
    println!("[TEST] Control socket responsiveness during repeated failures PASSED");
    Ok(())
}
