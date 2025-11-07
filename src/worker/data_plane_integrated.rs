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
    BufferPool, EgressConfig, EgressLoop, EgressPacket, IngressConfig, IngressLoop,
};
use crate::ForwardingRule;

/// Configuration for the integrated data plane
#[derive(Debug, Clone)]
pub struct DataPlaneConfig {
    /// Network interface to capture packets from
    pub interface_name: String,
    /// Ingress configuration
    pub ingress_config: IngressConfig,
    /// Egress configuration
    pub egress_config: EgressConfig,
    /// Initial forwarding rules to install
    pub initial_rules: Vec<ForwardingRule>,
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            interface_name: "lo".to_string(),
            ingress_config: IngressConfig::default(),
            egress_config: EgressConfig::default(),
            initial_rules: Vec::new(),
        }
    }
}

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
pub fn run_data_plane(config: DataPlaneConfig) -> Result<()> {
    println!(
        "[DataPlane] Starting integrated data plane on {}",
        config.interface_name
    );

    // Create channel for ingress→egress communication
    let (egress_tx, egress_rx) = mpsc::channel::<EgressPacket>();

    // Create shared buffer pool (Arc for shared ownership)
    let buffer_pool = Arc::new(BufferPool::new(config.ingress_config.track_stats));

    // Clone config for threads
    let interface_name = config.interface_name.clone();
    let ingress_config = config.ingress_config.clone();
    let egress_config = config.egress_config.clone();
    let initial_rules = config.initial_rules.clone();

    // Spawn ingress thread
    let ingress_handle = {
        let interface_name = interface_name.clone();
        let egress_tx = egress_tx.clone();

        thread::Builder::new()
            .name("ingress".to_string())
            .spawn(move || -> Result<()> {
                println!("[DataPlane] Ingress thread started");

                // Create ingress loop
                let mut ingress =
                    IngressLoop::new(&interface_name, ingress_config, Some(egress_tx))?;

                // Add initial rules
                for rule in initial_rules {
                    ingress.add_rule(Arc::new(rule))?;
                }

                // Run ingress loop (blocks forever)
                ingress.run()?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_plane_config_default() {
        let config = DataPlaneConfig::default();
        assert_eq!(config.interface_name, "lo");
        assert_eq!(config.ingress_config.batch_size, 32);
        assert_eq!(config.egress_config.batch_size, 32);
        assert!(config.initial_rules.is_empty());
    }

    // Note: Full end-to-end data plane tests require root privileges
    // and actual network interfaces. These are tested in integration tests.
}
