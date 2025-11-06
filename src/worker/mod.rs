mod args;
mod control_plane;
mod data_plane;
mod stats;

use anyhow::Result;
use metrics::{describe_counter, describe_gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use privdrop::PrivDrop;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use self::args::Args;
use self::control_plane::control_plane_task;
use self::stats::{monitoring_task, stats_aggregator_task};
use crate::{FlowStats, ForwardingRule, OutputDestination, RelayCommand};
use clap::Parser;

type SharedFlows = Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>>;

pub async fn run(user: String, group: String) -> Result<()> {
    let args = Args::parse();

    let ingress_socket_fd = if let Some(interface_name) = &args.input_interface_name {
        Some(Arc::new(data_plane::setup_ingress_socket(interface_name)?))
    } else {
        None
    };

    println!(
        "Worker process started. Attempting to drop privileges to user '{}' and group '{}'.",
        user, group
    );

    PrivDrop::default()
        .user(&user)
        .group(&group)
        .apply()
        .map_err(|e| anyhow::anyhow!("Failed to drop privileges: {}", e))?;

    println!("Successfully dropped privileges.");

    let builder = PrometheusBuilder::new();
    builder.with_http_listener(args.prometheus_addr).install()?;
    describe_counter!("packets_relayed_total", "Total packets relayed");
    describe_gauge!("memory_usage_bytes", "Current memory usage");

    let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let (relay_command_tx, mut relay_command_rx) = mpsc::channel(100);
    let (stats_tx, stats_rx) = mpsc::channel(100);

    let initial_rule = if let (Some(ig), Some(ip), Some(og), Some(op), Some(oi)) = (
        args.input_group,
        args.input_port,
        args.output_group,
        args.output_port,
        args.output_interface,
    ) {
        Some(ForwardingRule {
            input_group: ig,
            input_port: ip,
            outputs: vec![OutputDestination {
                group: og,
                port: op,
                interface: oi,
                dtls_enabled: false,
            }],
            dtls_enabled: false,
        })
    } else {
        None
    };

    let control_socket_path = Path::new("/tmp/multicast_relay_control.sock");

    let relay_task = async {
        let mut flow_tasks = HashMap::new();
        if let (Some(rule), Some(fd)) = (initial_rule, &ingress_socket_fd) {
            let stats_tx_clone = stats_tx.clone();
            let key = (rule.input_group, rule.input_port);
            let fd_clone = Arc::clone(fd);
            let task = tokio::spawn(async move {
                if let Err(e) =
                    data_plane::run_flow_task(rule.clone(), fd_clone, stats_tx_clone).await
                {
                    eprintln!("Flow task failed: {}", e);
                }
            });
            flow_tasks.insert(key, task);
        }

        while let Some(command) = relay_command_rx.recv().await {
            match command {
                RelayCommand::AddRule(rule) => {
                    let key = (rule.input_group, rule.input_port);
                    if let Some(existing_task) = flow_tasks.remove(&key) {
                        existing_task.abort();
                    }
                    if let Some(fd) = &ingress_socket_fd {
                        let stats_tx_clone = stats_tx.clone();
                        let fd_clone = Arc::clone(fd);
                        let task = tokio::spawn(async move {
                            if let Err(e) =
                                data_plane::run_flow_task(rule.clone(), fd_clone, stats_tx_clone)
                                    .await
                            {
                                eprintln!("Flow task failed: {}", e);
                            }
                        });
                        flow_tasks.insert(key, task);
                    }
                }
                RelayCommand::RemoveRule {
                    input_group,
                    input_port,
                } => {
                    if let Some(task) = flow_tasks.remove(&(input_group, input_port)) {
                        task.abort();
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = relay_task => {},
        _ = stats_aggregator_task(stats_rx, shared_flows.clone()) => {},
        _ = control_plane_task(control_socket_path, relay_command_tx, shared_flows.clone()) => {},
        _ = monitoring_task(shared_flows.clone(), args.reporting_interval) => {},
    }

    Ok(())
}
