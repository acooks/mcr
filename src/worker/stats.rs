use anyhow::Result;
use metrics::gauge;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, System};
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
    }
    Ok(())
}

pub async fn monitoring_task(_shared_flows: SharedFlows, reporting_interval: u64) {
    let mut sys = System::new_all();
    let pid = Pid::from(std::process::id() as usize);
    loop {
        tokio::time::sleep(Duration::from_secs(reporting_interval)).await;
        sys.refresh_process(pid);
        if let Some(process) = sys.process(pid) {
            gauge!("cpu_usage_percent").set(process.cpu_usage() as f64);
            gauge!("memory_usage_bytes").set(process.memory() as f64);
        }
    }
}
