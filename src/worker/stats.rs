// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::{FlowStats, ForwardingRule};

type SharedFlows = Arc<Mutex<HashMap<String, (ForwardingRule, FlowStats)>>>;

pub async fn stats_aggregator_task(
    mut stats_rx: mpsc::Receiver<(ForwardingRule, FlowStats)>,
    shared_flows: SharedFlows,
) -> Result<()> {
    while let Some((rule, stats)) = stats_rx.recv().await {
        let mut flows = shared_flows.lock().await;
        flows.insert(rule.rule_id.clone(), (rule, stats));

        // Log ruleset hash for drift detection
        let ruleset_hash = crate::compute_ruleset_hash(flows.values().map(|(r, _)| r));
        eprintln!(
            "[ControlPlane] Ruleset updated: hash={:016x} rule_count={}",
            ruleset_hash,
            flows.len()
        );
    }
    Ok(())
}

pub async fn monitoring_task(shared_flows: SharedFlows, reporting_interval: u64) -> Result<()> {
    let mut sys = System::new_all();
    let pid = Pid::from(std::process::id() as usize);
    let reporting_duration = Duration::from_secs(reporting_interval);

    loop {
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        if let Some(process) = sys.process(pid) {
            let memory_usage = process.memory();
            // Log memory usage for debugging (stats are available via GetStats API)
            eprintln!(
                "[ControlPlane] Memory usage: {} bytes, flows: {}",
                memory_usage,
                shared_flows.lock().await.len()
            );
        }

        // Stats are available via GetStats API call - no prometheus endpoint
        let _ = &shared_flows; // Keep shared_flows in scope for future use

        tokio::time::sleep(reporting_duration).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OutputDestination;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_stats_aggregator_task() {
        let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
        let (stats_tx, stats_rx) = mpsc::channel(10);

        let aggregator_task = tokio::spawn(stats_aggregator_task(stats_rx, shared_flows.clone()));

        let rule = ForwardingRule {
            rule_id: "test-rule".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![OutputDestination {
                group: "224.0.0.2".parse().unwrap(),
                port: 5001,
                interface: "lo".to_string(),
            }],
        };

        let stats = FlowStats {
            input_group: rule.input_group,
            input_port: rule.input_port,
            packets_relayed: 0,
            bytes_relayed: 0,
            packets_per_second: 100.0,
            bits_per_second: 1000.0,
        };

        stats_tx.send((rule.clone(), stats.clone())).await.unwrap();

        // Give the aggregator a moment to process the message
        tokio::time::sleep(Duration::from_millis(10)).await;

        let flows = shared_flows.lock().await;
        let (agg_rule, agg_stats) = flows.get("test-rule").unwrap();

        assert_eq!(agg_rule, &rule);
        assert_eq!(agg_stats.packets_per_second, stats.packets_per_second);
        assert_eq!(agg_stats.bits_per_second, stats.bits_per_second);

        // Drop the sender to terminate the aggregator task
        drop(stats_tx);
        let _ = timeout(Duration::from_secs(1), aggregator_task)
            .await
            .expect("Aggregator task should terminate gracefully");
    }

    #[tokio::test]
    async fn test_monitoring_task() {
        let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
        let reporting_interval = 1; // 1 second

        let rule = ForwardingRule {
            rule_id: "monitor-rule".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![],
        };

        let stats = FlowStats {
            input_group: rule.input_group,
            input_port: rule.input_port,
            packets_relayed: 0,
            bytes_relayed: 0,
            packets_per_second: 123.0,
            bits_per_second: 456.0,
        };

        {
            let mut flows = shared_flows.lock().await;
            flows.insert(rule.rule_id.clone(), (rule, stats));
        }

        let monitoring = tokio::spawn(monitoring_task(shared_flows.clone(), reporting_interval));

        // Let the task run for a short period to execute its loop once
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // The main verification is that the task doesn't panic and runs.
        // In a real-world scenario, we would capture stdout or use a mock logger
        // to verify the output, but for this test, we'll just ensure it runs.
        monitoring.abort();
        let result = monitoring.await;
        assert!(result.is_err(), "Task should be aborted");
    }
}
