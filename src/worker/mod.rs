//! # Worker Module
//!
//! This file, `mod.rs`, serves as the central hub for the `worker` module in the `multicast-relay`
//! architecture. In Rust, `mod.rs` acts as the module declaration file for a directory, defining
//! its structure and public interface.
//!
//! ## Architectural Role
//!
//! The `worker` module encapsulates all logic that runs in the unprivileged worker processes.
//! This `mod.rs` file performs several key functions:
//!
//! 1.  **Module Definition and Re-exporting:** It declares the sub-modules that constitute the
//!     worker's functionality (e.g., `control_plane`, `data_plane`, `stats`). It then uses `pub use`
//!     to re-export essential types, creating a clean, unified public API. This allows other parts
//!     of the application to access worker components through a single, consistent path.
//!
//! 2.  **Entry Point for Worker Processes:** It contains the main entry point functions for the
//!     worker processes: `run_control_plane` and `run_data_plane`. When the `supervisor` spawns a
//!     new worker, the `main` function calls one of these to start the worker's lifecycle.
//!
//! 3.  **Shared Worker Logic:** It centralizes logic common to all worker types. This includes:
//!     - `setup_worker_environment`: Initializes the common environment for any worker, most
//!       importantly handling the **privilege drop** to a less privileged user/group.
//!     - `UnixSocketRelayCommandSender`: Provides a shared mechanism for workers to communicate
//!       commands back to the supervisor over a Unix socket.
//!
//! In essence, this file acts as the **façade and coordinator** for the entire worker subsystem.
//! It defines what a "worker" is, exposes its public components, and provides the common logic
//! required to launch and manage any type of worker in a consistent and safe manner.

mod buffer_pool;
mod control_plane;
mod data_plane;
pub mod data_plane_integrated;
mod egress;
mod ingress;
mod metrics;
mod packet_parser;
mod stats;

// Re-export buffer pool types for convenience
pub use buffer_pool::{AggregateStats, Buffer, BufferPool, BufferSize, PoolStats, SizeClassPool};

// Re-export egress types for convenience
pub use egress::{EgressConfig, EgressLoop, EgressPacket, EgressStats};

// Re-export ingress types for convenience
pub use ingress::{
    setup_af_packet_socket, setup_helper_socket, IngressConfig, IngressLoop, IngressStats,
};

// Re-export packet parser types for convenience
pub use packet_parser::{
    parse_packet, EthernetHeader, Ipv4Header, PacketHeaders, ParseError, UdpHeader,
};

use ::metrics::{describe_counter, describe_gauge};
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::{mpsc as tokio_mpsc, Mutex};
use uuid::Uuid;

use crate::{
    worker::control_plane::control_plane_task,
    worker::stats::{monitoring_task, stats_aggregator_task},
    ControlPlaneConfig, DataPlaneConfig, FlowStats, ForwardingRule, OutputDestination,
    RelayCommand,
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
fn drop_privileges(uid: u32, gid: u32) -> Result<()> {
    use privdrop::PrivDrop;
    PrivDrop::default()
        .user(uid.to_string())
        .group(gid.to_string())
        .fallback_to_ids_if_names_are_numeric()
        .apply()
        .map_err(|e| anyhow::anyhow!("Failed to drop privileges: {}", e))
}

#[cfg(test)]
fn drop_privileges(_uid: u32, _gid: u32) -> Result<()> {
    // Do nothing in tests
    Ok(())
}

async fn setup_worker_environment(uid: u32, gid: u32) -> Result<()> {
    println!(
        "Worker process started. Attempting to drop privileges to UID '{}' and GID '{}'.",
        uid, gid
    );

    drop_privileges(uid, gid)?;

    println!("Successfully dropped privileges.");

    describe_counter!("packets_relayed_total", "Total packets relayed");
    describe_gauge!("memory_usage_bytes", "Current memory usage");
    Ok(())
}

pub async fn run_control_plane(config: ControlPlaneConfig) -> Result<()> {
    setup_worker_environment(config.uid, config.gid).await?;

    // Install the Prometheus recorder only in the control plane, and only if an address is provided.
    if let Some(addr) = config.prometheus_addr {
        metrics::install_prometheus_recorder(addr)?;
    }

    let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let (_stats_tx, stats_rx) = tokio_mpsc::channel(100);

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
    std::future::pending::<()>().await;

    Ok(())
}

pub async fn run_data_plane(config: DataPlaneConfig) -> Result<()> {
    setup_worker_environment(config.uid, config.gid).await?;

    let _ingress_socket_fd = if let Some(interface_name) = &config.input_interface_name {
        Some(Arc::new(ingress::setup_af_packet_socket(interface_name)?))
    } else {
        None
    };

    let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let (_internal_relay_command_tx, _internal_relay_command_rx) =
        tokio_mpsc::channel::<RelayCommand>(100);
    let (_stats_tx, stats_rx) = tokio_mpsc::channel(100);

    let _initial_rule = if let (Some(ig), Some(ip), Some(og), Some(op), Some(oi)) = (
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
        let uid = 65534;
        let gid = 65534;

        let result = setup_worker_environment(uid, gid).await;
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
                    uid: 65534,
                    gid: 65534,
                    relay_command_socket_path: socket_path.clone(),
                    prometheus_addr: None,
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
                    uid: 65534,
                    gid: 65534,
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
