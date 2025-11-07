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
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
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

#[cfg(not(feature = "integration_test"))]
fn drop_privileges(uid: u32, gid: u32) -> Result<()> {
    use privdrop::PrivDrop;
    PrivDrop::default()
        .user(uid.to_string())
        .group(gid.to_string())
        .fallback_to_ids_if_names_are_numeric()
        .apply()
        .map_err(|e| anyhow::anyhow!("Failed to drop privileges: {}", e))
}

#[cfg(feature = "integration_test")]
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

// ... (imports)

pub async fn run_control_plane(config: ControlPlaneConfig) -> Result<()> {
    setup_worker_environment(config.uid, config.gid).await?;

    // Install the Prometheus recorder only in the control plane, and only if an address is provided.
    if let Some(addr) = config.prometheus_addr {
        metrics::install_prometheus_recorder(addr)?;
    }

    let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let (_stats_tx, stats_rx) = tokio_mpsc::channel(100);

    let listener = if let Some(fd) = config.socket_fd {
        // A socket file descriptor was passed, use it.
        let std_listener = unsafe { StdUnixListener::from_raw_fd(fd) };
        std_listener.set_nonblocking(true)?;
        UnixListener::from_std(std_listener)
            .context("Failed to convert std UnixListener to tokio UnixListener")?
    } else {
        // Fallback for testing or direct execution: bind to a default path.
        let control_socket_path = Path::new("/tmp/multicast_relay_control.sock");
        if control_socket_path.exists() {
            std::fs::remove_file(control_socket_path)?;
        }
        UnixListener::bind(control_socket_path)?
    };

    // Connect to the supervisor's relay command socket
    let supervisor_stream = UnixStream::connect(&config.relay_command_socket_path).await?;
    let supervisor_relay_command_tx =
        Arc::new(UnixSocketRelayCommandSender::new(supervisor_stream));

    // Spawn the static, long-running tasks locally.
    tokio::task::spawn_local(stats_aggregator_task(stats_rx, shared_flows.clone()));
    tokio::task::spawn_local(control_plane_task(
        listener,
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
