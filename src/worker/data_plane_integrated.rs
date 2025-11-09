//! Integrated Data Plane
//!
//! This module provides the integrated data plane that combines ingress and egress
//! into a complete packet processing pipeline.
//!
//! ## Architecture
//!
//! ```
//! ┌──────────────┐         ┌──────────────┐
//! │   Ingress    │─────────▶│   Egress     │
//! │   Loop       │ Channel │   Loop       │
//! │ (io_uring)   │         │  (io_uring)  │
//! └──────────────┘         └──────────────┘
//!        │                        │
//!        ▼                        ▼
//!   Buffer Pool           Buffer Pool
//!   (shared)              (deallocation)
//! ```
//!
//! The ingress and egress loops run in separate threads and communicate via
//! an std::sync::mpsc channel for zero-copy packet forwarding.

use anyhow::{Context, Result};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use crate::worker::{
    buffer_pool::BufferPool,
    egress::{EgressConfig, EgressLoop, EgressPacket},
    ingress::{IngressConfig, IngressLoop},
};
use crate::{DataPlaneConfig, RelayCommand};

/// Integrated data plane runner
///
/// This function sets up and runs the complete data plane pipeline with
/// ingress and egress loops communicating via a channel.
///
/// # Arguments
///
/// * `config` - Data plane configuration
///
/// # Returns
///
/// This function runs indefinitely until an error occurs or the loops terminate.
///
/// # Example
///
/// ```no_run
/// use multicast_relay::worker::data_plane_integrated::{DataPlaneConfig, run_data_plane};
/// use multicast_relay::ForwardingRule;
/// use std::net::Ipv4Addr;
///
/// let mut config = DataPlaneConfig::default();
/// config.interface_name = "eth0".to_string();
///
/// // Add a forwarding rule
/// let rule = ForwardingRule {
///     rule_id: "rule-1".to_string(),
///     input_interface: "eth0".to_string(),
///     input_group: "224.0.0.1".parse().unwrap(),
///     input_port: 5000,
///     outputs: vec![],
///     dtls_enabled: false,
/// };
/// config.initial_rules.push(rule);
///
/// // Run the data plane (blocks indefinitely)
/// run_data_plane(config).expect("Data plane failed");
/// ```
pub fn run_data_plane(
    config: DataPlaneConfig,
    command_rx: mpsc::Receiver<RelayCommand>,
    event_fd: nix::sys::eventfd::EventFd,
) -> Result<()> {
    println!(
        "[DataPlane] Starting integrated data plane on {}",
        config.input_interface_name.as_deref().unwrap_or("default")
    );

    let ingress_config = IngressConfig {
        ..Default::default()
    };

    let egress_config = EgressConfig {
        ..Default::default()
    };

    // Create channel for ingress→egress communication
    let (egress_tx, egress_rx) = mpsc::channel::<EgressPacket>();

    // Create shared buffer pool (Arc<Mutex<>> for thread-safe shared access)
    let buffer_pool = Arc::new(std::sync::Mutex::new(BufferPool::new(
        ingress_config.track_stats,
    )));

    // Clone config for threads
    // TODO: ARCHITECTURAL FIX NEEDED
    // This creates AF_PACKET socket eagerly on startup. Per architecture (D21, D23):
    // - Workers should start with NO sockets
    // - Sockets should be created LAZILY when rules are assigned to this worker
    // - Each worker can handle multiple interfaces based on its assigned rules
    // Current approach causes resource exhaustion when spawning many workers.
    let interface_name = config
        .input_interface_name
        .clone()
        .unwrap_or_else(|| "lo".to_string());
    let initial_rules = Vec::new(); // TODO: Pass rules from control plane

    // Spawn ingress thread
    let ingress_handle = {
        let interface_name = interface_name.clone();
        let egress_tx = egress_tx.clone();
        let buffer_pool_for_ingress = buffer_pool.clone();

        thread::Builder::new()
            .name("ingress".to_string())
            .spawn(move || -> Result<()> {
                println!("[DataPlane] Ingress thread started");

                // Debug: Check if CAP_NET_RAW is available in this thread
                use caps::{CapSet, Capability};
                match caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW) {
                    Ok(true) => {
                        println!("[DataPlane] Ingress thread has CAP_NET_RAW in Effective set")
                    }
                    Ok(false) => eprintln!(
                        "[DataPlane] WARNING: Ingress thread missing CAP_NET_RAW in Effective set!"
                    ),
                    Err(e) => eprintln!("[DataPlane] ERROR checking capabilities: {}", e),
                }

                // Create ingress loop
                let mut ingress = match IngressLoop::new(
                    &interface_name,
                    ingress_config,
                    buffer_pool_for_ingress,
                    Some(egress_tx),
                    command_rx,
                    event_fd,
                ) {
                    Ok(ingress) => {
                        println!("[DataPlane] Ingress loop created successfully");
                        ingress
                    }
                    Err(e) => {
                        eprintln!("[DataPlane] FATAL: IngressLoop::new() failed: {}", e);
                        return Err(e);
                    }
                };

                // Add initial rules
                for rule in initial_rules {
                    ingress.add_rule(Arc::new(rule))?;
                }

                println!("[DataPlane] Starting ingress run loop");
                // Run ingress loop (blocks forever)
                if let Err(e) = ingress.run() {
                    eprintln!("[DataPlane] FATAL: Ingress run() failed: {}", e);
                    return Err(e);
                }

                Ok(())
            })
            .context("Failed to spawn ingress thread")?
    };

    // Spawn egress thread
    let egress_handle = {
        let egress_rx = egress_rx;

        thread::Builder::new()
            .name("egress".to_string())
            .spawn(move || -> Result<()> {
                println!("[DataPlane] Egress thread started");

                // Create egress loop
                let mut egress = EgressLoop::new(egress_config.clone(), buffer_pool.clone())?;

                // Main egress loop: receive packets from channel and send in batches
                loop {
                    // Receive packets from ingress (blocking)
                    match egress_rx.recv_timeout(Duration::from_millis(10)) {
                        Ok(packet) => {
                            // Add destination socket if not already present
                            if let Err(e) =
                                egress.add_destination(&packet.interface_name, packet.dest_addr)
                            {
                                eprintln!("[DataPlane] Failed to add egress destination: {}", e);
                                continue;
                            }

                            // Queue packet
                            egress.queue_packet(packet);

                            // If queue is full, send batch
                            if egress.queue_len() >= egress_config.batch_size {
                                if let Err(e) = egress.send_batch() {
                                    eprintln!("[DataPlane] Egress send batch failed: {}", e);
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            // No packets available, flush pending packets
                            if !egress.is_queue_empty() {
                                if let Err(e) = egress.send_batch() {
                                    eprintln!("[DataPlane] Egress send batch failed: {}", e);
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            println!("[DataPlane] Ingress channel closed, shutting down egress");
                            break;
                        }
                    }
                }

                Ok(())
            })
            .context("Failed to spawn egress thread")?
    };

    // Wait for both threads to complete
    println!("[DataPlane] Data plane running, waiting for threads...");

    let ingress_result = ingress_handle
        .join()
        .map_err(|e| anyhow::anyhow!("Ingress thread panicked: {:?}", e))?;

    let egress_result = egress_handle
        .join()
        .map_err(|e| anyhow::anyhow!("Egress thread panicked: {:?}", e))?;

    // Propagate any errors
    ingress_result?;
    egress_result?;

    Ok(())
}
