mod control_plane;
mod data_plane;
mod stats;

use anyhow::Result;
use metrics::{describe_counter, describe_gauge};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::{
    worker::control_plane::control_plane_task,
    worker::stats::{monitoring_task, stats_aggregator_task},
    ControlPlaneConfig, DataPlaneConfig, FlowStats, ForwardingRule, OutputDestination, RelayCommand,
};

type SharedFlows = Arc<Mutex<HashMap<String, (ForwardingRule, FlowStats)>>>;

// A custom sender that serializes RelayCommands and sends them over a UnixStream
pub struct UnixSocketRelayCommandSender<S> {
    stream: Mutex<S>,
}

impl<S: tokio::io::AsyncWriteExt + Unpin> UnixSocketRelayCommandSender<S> {
    pub fn new(stream: S) -> Self {
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

#[cfg(not(test))]
fn drop_privileges(user: &str, group: &str) -> Result<()> {
    use privdrop::PrivDrop;
    PrivDrop::default()
        .user(user)
        .group(group)
        .apply()
        .map_err(|e| anyhow::anyhow!("Failed to drop privileges: {}", e))
}

#[cfg(test)]
fn drop_privileges(_user: &str, _group: &str) -> Result<()> {
    // Do nothing in tests
    Ok(())
}

#[cfg(not(test))]
fn install_prometheus_recorder(prometheus_addr: std::net::SocketAddr) -> Result<()> {
    use metrics_exporter_prometheus::PrometheusBuilder;
    let builder = PrometheusBuilder::new();
    builder
        .with_http_listener(prometheus_addr)
        .install()
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
fn install_prometheus_recorder(_prometheus_addr: std::net::SocketAddr) -> Result<()> {
    // Do nothing in tests to avoid starting a server and hanging.
    Ok(())
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

    drop_privileges(&user, &group)?;

    println!("Successfully dropped privileges.");

    install_prometheus_recorder(prometheus_addr)?;
    describe_counter!("packets_relayed_total", "Total packets relayed");
    describe_gauge!("memory_usage_bytes", "Current memory usage");
    Ok(())
}

pub async fn run_control_plane(config: ControlPlaneConfig) -> Result<()> {
    setup_worker_environment(config.user, config.group, config.prometheus_addr).await?;

    let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let (_stats_tx, stats_rx) = mpsc::channel(100);

    let control_socket_path = Path::new("/tmp/multicast_relay_control.sock");

    // Connect to the supervisor's relay command socket
    let supervisor_stream = UnixStream::connect(&config.relay_command_socket_path).await?;
    let supervisor_relay_command_tx =
        Arc::new(UnixSocketRelayCommandSender::new(supervisor_stream));

    // Spawn the static, long-running tasks locally.
    tokio::task::spawn_local(stats_aggregator_task(stats_rx, shared_flows.clone()));
    tokio::task::spawn_local(control_plane_task(
        control_socket_path,
        supervisor_relay_command_tx.clone(),
        shared_flows.clone(),
    ));
    tokio::task::spawn_local(monitoring_task(
        shared_flows.clone(),
        config.reporting_interval,
    ));

    // The control plane worker runs indefinitely, serving RPC requests.
    // It doesn't have its own internal command loop like the data plane.
    // We just need to keep the runtime alive.
    std::future::pending::<()>().await;

    Ok(())
}

pub async fn run_data_plane(config: DataPlaneConfig) -> Result<()> {
    setup_worker_environment(config.user, config.group, config.prometheus_addr).await?;

    let _ingress_socket_fd = if let Some(interface_name) = &config.input_interface_name {
        Some(Arc::new(data_plane::setup_ingress_socket(interface_name)?))
    } else {
        None
    };

    let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let (_internal_relay_command_tx, _internal_relay_command_rx) =
        mpsc::channel::<RelayCommand>(100);
    let (_stats_tx, stats_rx) = mpsc::channel(100);

    let _initial_rule = if let (
        Some(ig),
        Some(ip),
        Some(og),
        Some(op),
        Some(oi),
    ) = (
        config.input_group,
        config.input_port,
        config.output_group,
        config.output_port,
        config.output_interface,
    ) {
        Some(ForwardingRule {
            rule_id: Uuid::new_v4().to_string(), // Generate a rule_id for initial rule
            input_interface: config.input_interface_name.clone().unwrap_or_default(),
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
    tokio::task::spawn_local(monitoring_task(
        shared_flows.clone(),
        config.reporting_interval,
    ));

    if let (Some(rule), Some(fd)) = (_initial_rule, _ingress_socket_fd) {
        let stats_tx = _stats_tx.clone();
        // The Arc should have only one owner here, so we can safely unwrap it.
        let owned_fd = Arc::try_unwrap(fd).expect("Failed to unwrap Arc<OwnedFd>");
        tokio::task::spawn_local(data_plane::run_flow_task(rule, owned_fd, stats_tx));
    }

    // The data plane worker runs indefinitely.
    std::future::pending::<()>().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForwardingRule;
    use std::path::PathBuf;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn test_unix_socket_relay_command_sender() {
        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        let sender = UnixSocketRelayCommandSender::new(server_stream);

        let command = RelayCommand::AddRule(ForwardingRule {
            rule_id: "test-rule-1".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![],
            dtls_enabled: false,
        });

        sender.send(command.clone()).await.unwrap();
        drop(sender); // Drop the sender to close the server_stream

        let mut buffer = Vec::new();
        client_stream.read_to_end(&mut buffer).await.unwrap();

        let received_command: RelayCommand = serde_json::from_slice(&buffer).unwrap();
        assert_eq!(command, received_command);
    }

    #[tokio::test]
    async fn test_setup_worker_environment_success() {
        let user = "nobody".to_string();
        let group = "nogroup".to_string();
        let prometheus_addr = "127.0.0.1:9000".parse().unwrap();

        let result = setup_worker_environment(user, group, prometheus_addr).await;
        assert!(result.is_ok(), "setup_worker_environment should succeed");
    }

    #[tokio::test]
    async fn test_run_control_plane_starts_successfully() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let socket_path =
                    PathBuf::from(format!("/tmp/test_supervisor_{}.sock", Uuid::new_v4()));
                let _listener = UnixListener::bind(&socket_path).unwrap();

                let config = ControlPlaneConfig {
                    user: "nobody".to_string(),
                    group: "nogroup".to_string(),
                    relay_command_socket_path: socket_path.clone(),
                    prometheus_addr: "127.0.0.1:9001".parse().unwrap(),
                    reporting_interval: 1,
                };

                let task = tokio::task::spawn_local(run_control_plane(config));

                // Let the task run for a short time to ensure it doesn't panic immediately.
                let result =
                    tokio::time::timeout(std::time::Duration::from_millis(100), task).await;

                // The task is expected to run indefinitely, so a timeout is expected.
                // We are checking that it didn't complete (or panic).
                assert!(result.is_err(), "run_control_plane should not complete");

                // Clean up the temporary socket file
                std::fs::remove_file(&socket_path).unwrap();
            })
            .await;
    }

    #[tokio::test]
    async fn test_run_data_plane_starts_successfully() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let config = DataPlaneConfig {
                    user: "nobody".to_string(),
                    group: "nogroup".to_string(),
                    core_id: 0,
                    prometheus_addr: "127.0.0.1:9002".parse().unwrap(),
                    input_interface_name: None,
                    input_group: None,
                    input_port: None,
                    output_group: None,
                    output_port: None,
                    output_interface: None,
                    reporting_interval: 1,
                };

                let task = tokio::task::spawn_local(run_data_plane(config));

                // Let the task run for a short time to ensure it doesn't panic immediately.
                let result =
                    tokio::time::timeout(std::time::Duration::from_millis(100), task).await;

                // The task is expected to run indefinitely, so a timeout is expected.
                // We are checking that it didn't complete (or panic).
                assert!(result.is_err(), "run_data_plane should not complete");
            })
            .await;
    }
}