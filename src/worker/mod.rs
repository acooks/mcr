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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use self::args::Args;
use self::control_plane::control_plane_task;
use self::stats::{monitoring_task, stats_aggregator_task};
use crate::{FlowStats, ForwardingRule, OutputDestination, RelayCommand};
use clap::Parser;
use tokio::task::JoinHandle;

type SharedFlows = Arc<Mutex<HashMap<String, (ForwardingRule, FlowStats)>>>;

// A custom sender that serializes RelayCommands and sends them over a UnixStream
pub struct UnixSocketRelayCommandSender {
    stream: Mutex<UnixStream>,
}

impl UnixSocketRelayCommandSender {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }

    pub async fn send(&self, command: RelayCommand) -> Result<()> {
        let command_bytes = serde_json::to_vec(&command)?;
        let mut stream = self.stream.lock().await;
        stream.write_all(&command_bytes).await?;
        Ok(())
    }
}

async fn setup_worker_environment(
    user: String,
    group: String,
    prometheus_addr: std::net::SocketAddr,
) -> Result<()> {
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
    builder.with_http_listener(prometheus_addr).install()?;
    describe_counter!("packets_relayed_total", "Total packets relayed");
    describe_gauge!("memory_usage_bytes", "Current memory usage");
    Ok(())
}

pub async fn run_control_plane(
    user: String,
    group: String,
    relay_command_socket_path: PathBuf,
) -> Result<()> {
    let args = Args::parse();
    setup_worker_environment(user, group, args.prometheus_addr).await?;

    let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let (_stats_tx, stats_rx) = mpsc::channel(100);

    let control_socket_path = Path::new("/tmp/multicast_relay_control.sock");

    // Connect to the supervisor's relay command socket
    let supervisor_stream = UnixStream::connect(&relay_command_socket_path).await?;
    let supervisor_relay_command_tx =
        Arc::new(UnixSocketRelayCommandSender::new(supervisor_stream));

    // Spawn the static, long-running tasks locally.
    tokio::task::spawn_local(stats_aggregator_task(stats_rx, shared_flows.clone()));
    tokio::task::spawn_local(control_plane_task(
        control_socket_path,
        supervisor_relay_command_tx.clone(), // Pass the Unix socket sender
        shared_flows.clone(),
    ));
    tokio::task::spawn_local(monitoring_task(
        shared_flows.clone(),
        args.reporting_interval,
    ));

    // The control plane worker runs indefinitely, serving RPC requests.
    // It doesn't have its own internal command loop like the data plane.
    // We just need to keep the runtime alive.
    std::future::pending::<()>().await;

    Ok(())
}

pub async fn run_data_plane(user: String, group: String, _core_id: u32) -> Result<()> {
    let args = Args::parse();
    setup_worker_environment(user, group, args.prometheus_addr).await?;

    let ingress_socket_fd = if let Some(interface_name) = &args.input_interface_name {
        Some(Arc::new(data_plane::setup_ingress_socket(interface_name)?))
    } else {
        None
    };

    let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let (_internal_relay_command_tx, mut internal_relay_command_rx) = mpsc::channel(100);
    let (_stats_tx, stats_rx) = mpsc::channel(100);

    let initial_rule = if let (Some(ig), Some(ip), Some(og), Some(op), Some(oi)) = (
        args.input_group,
        args.input_port,
        args.output_group,
        args.output_port,
        args.output_interface,
    ) {
        Some(ForwardingRule {
            rule_id: Uuid::new_v4().to_string(), // Generate a rule_id for initial rule
            input_interface: args.input_interface_name.clone().unwrap(),
            input_group: ig,
            input_port: ip,
            outputs: vec![OutputDestination {
                group: og,
                port: op,
                interface: oi.to_string(),
                dtls_enabled: false,
            }],
            dtls_enabled: false,
        })
    } else {
        None
    };

    // Spawn the static, long-running tasks locally.
    tokio::task::spawn_local(stats_aggregator_task(stats_rx, shared_flows.clone()));
    // The data plane worker does not run the control_plane_task directly.
    tokio::task::spawn_local(monitoring_task(
        shared_flows.clone(),
        args.reporting_interval,
    ));

    // Handle for the dynamic, replaceable flow task.
    let mut flow_task_handle: Option<JoinHandle<()>> = None;

    // Start the initial flow task if a rule was provided via CLI args.
    if let (Some(rule), Some(fd)) = (initial_rule, &ingress_socket_fd) {
        let _stats_tx_clone = _stats_tx.clone();
        let fd_clone = Arc::clone(fd);
        flow_task_handle = Some(tokio::task::spawn_local(async move {
            if let Err(e) = data_plane::run_flow_task(rule.clone(), fd_clone, _stats_tx_clone).await
            {
                eprintln!("Flow task failed: {}", e);
            }
        }));
    }

    let igmp_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let mut joined_groups = HashMap::new();

    // Main event loop: listen for commands to manage the flow task.
    loop {
        // This now listens for internal commands, not from supervisor directly
        if let Some(command) = internal_relay_command_rx.recv().await {
            match command {
                RelayCommand::AddRule(rule) => {
                    println!("Received AddRule command.");
                    if let Some(handle) = flow_task_handle.take() {
                        println!("Aborting previous flow task.");
                        handle.abort();
                    }

                    if let Some(_interface_name) = &args.input_interface_name {
                        let interface_addr = Ipv4Addr::UNSPECIFIED; // Let the OS choose
                        igmp_socket.join_multicast_v4(&rule.input_group, &interface_addr)?;
                        joined_groups.insert((rule.input_group, rule.input_port), ());
                    }

                    if let Some(fd) = &ingress_socket_fd {
                        println!("Spawning new flow task.");
                        let _stats_tx_clone = _stats_tx.clone();
                        let fd_clone = Arc::clone(fd);
                        flow_task_handle = Some(tokio::task::spawn_local(async move {
                            if let Err(e) =
                                data_plane::run_flow_task(rule.clone(), fd_clone, _stats_tx_clone)
                                    .await
                            {
                                eprintln!("Flow task failed: {}", e);
                            }
                        }));
                    }
                }
                RelayCommand::RemoveRule { rule_id } => {
                    println!("Received RemoveRule command for rule_id: {}", rule_id);
                    if let Some(handle) = flow_task_handle.take() {
                        println!("Aborting flow task.");
                        handle.abort();
                    }

                    // TODO: Need to find the rule by rule_id to get input_group and input_port
                    // For now, we'll just abort the current flow task.
                }
            }
        } else {
            // The internal command channel was closed.
            println!("Internal command channel closed. Worker shutting down.");
            break;
        }
    }

    Ok(())
}
