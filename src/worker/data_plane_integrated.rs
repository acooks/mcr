//! Integrated Data Plane
//!
//! This module provides the integrated data plane that combines ingress and egress
//! into a complete packet processing pipeline.
//!
//! ## Architecture
//!
//! ```text
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
/// ```ignore
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
/// run_data_plane(config, command_rx, event_fd).expect("Data plane failed");
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

    // Allow buffer pool sizing via environment variables for testing/tuning
    let buffer_pool_small = std::env::var("MCR_BUFFER_POOL_SMALL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1000); // Default from IngressConfig

    let buffer_pool_standard = std::env::var("MCR_BUFFER_POOL_STANDARD")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(500);

    let buffer_pool_jumbo = std::env::var("MCR_BUFFER_POOL_JUMBO")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200);

    // Log buffer pool configuration for visibility
    println!(
        "[DataPlane] Buffer pool config: small={}, standard={}, jumbo={} (total ~{:.1} MB)",
        buffer_pool_small,
        buffer_pool_standard,
        buffer_pool_jumbo,
        (buffer_pool_small * 1500 + buffer_pool_standard * 4096 + buffer_pool_jumbo * 9000) as f64
            / 1024.0
            / 1024.0
    );

    let ingress_config = IngressConfig {
        buffer_pool_small,
        buffer_pool_standard,
        buffer_pool_jumbo,
        ..Default::default()
    };

    let egress_config = EgressConfig {
        ..Default::default()
    };

    // Create channel for ingress→egress communication
    let (egress_tx, egress_rx) = mpsc::channel::<EgressPacket>();

    // Create shared buffer pool with configurable capacities
    // (Arc<Mutex<>> for thread-safe shared access between ingress/egress threads)
    let buffer_pool = Arc::new(std::sync::Mutex::new(BufferPool::with_capacities(
        ingress_config.buffer_pool_small,
        ingress_config.buffer_pool_standard,
        ingress_config.buffer_pool_jumbo,
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
                let result = ingress.run();

                // Print final stats before thread exits
                ingress.print_final_stats();

                if let Err(e) = result {
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

                // Stats reporting
                let mut last_stats_report = std::time::Instant::now();
                let mut last_packets_sent = 0u64;

                // DEBUG: Track channel receives
                let mut debug_channel_receives = 0u64;

                // Main egress loop: receive packets from channel and send in batches
                loop {
                    // Reap completions first to free buffers ASAP
                    // This is critical to prevent buffer pool exhaustion
                    let _reaped = match egress.reap_available_completions() {
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("[DataPlane] Failed to reap completions: {}", e);
                            0
                        }
                    };

                    // Try to receive a packet without blocking
                    match egress_rx.try_recv() {
                        Ok(packet) => {
                            debug_channel_receives += 1;

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
                        Err(mpsc::TryRecvError::Empty) => {
                            // No packets available, flush pending packets
                            if !egress.is_queue_empty() {
                                if let Err(e) = egress.send_batch() {
                                    eprintln!("[DataPlane] Egress send batch failed: {}", e);
                                }
                            } else {
                                // Queue is empty, do a short blocking wait for next packet
                                // This prevents tight-looping while remaining responsive
                                match egress_rx.recv_timeout(Duration::from_micros(50)) {
                                    Ok(packet) => {
                                        debug_channel_receives += 1;

                                        if let Err(e) = egress.add_destination(&packet.interface_name, packet.dest_addr) {
                                            eprintln!("[DataPlane] Failed to add egress destination: {}", e);
                                            continue;
                                        }
                                        egress.queue_packet(packet);
                                    }
                                    Err(mpsc::RecvTimeoutError::Timeout) => {
                                        // No packet within 50μs, continue loop (will reap completions)
                                    }
                                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                                        println!("[DataPlane] Ingress channel closed, shutting down egress");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(mpsc::TryRecvError::Disconnected) => {
                            println!("[DataPlane] Ingress channel closed, shutting down egress");
                            break;
                        }
                    }

                    // Periodic stats reporting (every second)
                    // TODO: Replace println! with proper logging system (Facility::Stats, Severity::Info)
                    if egress_config.track_stats {
                        let now = std::time::Instant::now();
                        if now.duration_since(last_stats_report).as_secs() >= 1 {
                            let stats = egress.stats();
                            let packets_delta = stats.packets_sent - last_packets_sent;
                            let interval_secs = now.duration_since(last_stats_report).as_secs_f64();
                            let pps = packets_delta as f64 / interval_secs;

                            println!(
                                "[STATS:Egress] total: sent={} submitted={} ch_recv={} errors={} bytes={} | interval: +{} pkts ({:.0} pps)",
                                stats.packets_sent,
                                stats.packets_submitted,
                                debug_channel_receives,
                                stats.send_errors,
                                stats.bytes_sent,
                                packets_delta,
                                pps
                            );

                            last_stats_report = now;
                            last_packets_sent = stats.packets_sent;
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


// Note: Integration tests for this module are in tests/integration/test_*.rs
// Those tests actually run run_integrated_data_plane() with real network interfaces.
// Unit tests for individual components are in their respective modules:
// - packet_parser.rs tests packet parsing
// - buffer_pool.rs tests buffer allocation
// - ingress.rs tests ingress logic
// - egress.rs tests egress logic
