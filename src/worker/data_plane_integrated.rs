// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integrated Data Plane
//!
//! This module provides the integrated data plane that combines ingress and egress
//! into a complete packet processing pipeline using a lock-free architecture.

use crate::logging::{Facility, Logger};
use crate::worker::{
    adaptive_wakeup::HybridWakeup,
    buffer_pool::BufferPool,
    egress::{EgressConfig, EgressLoop, EgressWorkItem},
    ingress::{EgressQueueDirect, IngressConfig, IngressLoop},
    unified_loop::{UnifiedConfig, UnifiedDataPlane},
    EgressChannelSet, IngressChannelSet,
};
use crate::DataPlaneConfig;
use anyhow::{Context, Result};
use crossbeam_queue::SegQueue;
use std::io::Write;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;
use std::thread;

pub fn run_data_plane(
    config: DataPlaneConfig,
    ingress_channels: IngressChannelSet,
    egress_channels: EgressChannelSet,
    logger: Logger,
) -> Result<()> {
    eprintln!("[run_data_plane] Entry point reached");
    std::io::stderr().flush().ok();

    logger.info(Facility::DataPlane, "Data plane starting (lock-free mode)");

    eprintln!("[run_data_plane] About to destructure channel sets");
    std::io::stderr().flush().ok();

    // Destructure channel sets
    let ingress_cmd_stream_fd = ingress_channels.cmd_stream_fd;

    eprintln!("[run_data_plane] Ingress channels destructured");
    std::io::stderr().flush().ok();

    // Extract egress channel components
    let egress_cmd_stream_fd = egress_channels.cmd_stream_fd;
    let egress_shutdown_eventfd = egress_channels.shutdown_event_fd;

    let buffer_pool_small = std::env::var("MCR_BUFFER_POOL_SMALL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let buffer_pool_standard = std::env::var("MCR_BUFFER_POOL_STANDARD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500);
    let buffer_pool_jumbo = std::env::var("MCR_BUFFER_POOL_JUMBO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    let ingress_config = IngressConfig {
        buffer_pool_small,
        buffer_pool_standard,
        buffer_pool_jumbo,
        fanout_group_id: config.fanout_group_id.unwrap_or(0),
        ..Default::default()
    };
    let egress_config = EgressConfig {
        ..Default::default()
    };

    let egress_queue = Arc::new(SegQueue::<EgressWorkItem>::new());
    let buffer_pool = BufferPool::new(
        ingress_config.buffer_pool_small,
        ingress_config.buffer_pool_standard,
        ingress_config.buffer_pool_jumbo,
    );
    let interface_name = config
        .input_interface_name
        .clone()
        .unwrap_or_else(|| "lo".to_string());

    // Create eventfd for wakeup strategy (blocking mode for wait())
    let wakeup_fd = unsafe {
        let fd = libc::eventfd(0, libc::EFD_CLOEXEC); // No EFD_NONBLOCK
        if fd < 0 {
            return Err(anyhow::anyhow!("Failed to create wakeup eventfd"));
        }
        OwnedFd::from_raw_fd(fd)
    };
    let wakeup_fd = Arc::new(wakeup_fd);

    // Create hybrid wakeup strategy
    let wakeup_strategy = Arc::new(HybridWakeup::new(wakeup_fd.clone()));

    eprintln!("[run_data_plane] About to spawn ingress thread");
    std::io::stderr().flush().ok();

    let ingress_handle = {
        let interface_name = interface_name.clone();
        let egress_queue_for_ingress = egress_queue.clone();
        let buffer_pool_for_ingress = buffer_pool.clone();
        let ingress_logger = logger.clone();
        let wakeup_strategy_for_ingress = wakeup_strategy.clone();
        thread::Builder::new()
            .name("ingress".to_string())
            .spawn(move || -> Result<()> {
                eprintln!("[ingress-thread] Thread started");
                std::io::stderr().flush().ok();

                // Queue with wakeup strategy signaling
                let egress_channel =
                    EgressQueueDirect::new(egress_queue_for_ingress, wakeup_strategy_for_ingress);

                eprintln!("[ingress-thread] About to create IngressLoop");
                std::io::stderr().flush().ok();

                let mut ingress = IngressLoop::new(
                    &interface_name,
                    ingress_config,
                    buffer_pool_for_ingress,
                    Some(egress_channel),
                    ingress_cmd_stream_fd,
                    ingress_logger,
                )?;

                eprintln!("[ingress-thread] IngressLoop created, calling run()");
                std::io::stderr().flush().ok();

                let result = ingress.run();

                eprintln!("[ingress-thread] run() returned: {:?}", result);
                std::io::stderr().flush().ok();

                result
            })
            .context("Failed to spawn ingress thread")?
    };

    eprintln!("[run_data_plane] Ingress thread spawned");
    std::io::stderr().flush().ok();

    let egress_handle = {
        let egress_rx = egress_queue;
        let egress_logger = logger.clone();
        let shutdown_event_fd: OwnedFd = egress_shutdown_eventfd.into();
        thread::Builder::new()
            .name("egress".to_string())
            .spawn(move || -> Result<()> {
                let mut egress = EgressLoop::new(
                    egress_config.clone(),
                    buffer_pool.clone(),
                    shutdown_event_fd,
                    egress_cmd_stream_fd,
                    wakeup_strategy,
                    egress_logger,
                )?;
                egress.run(&egress_rx)?;
                Ok(())
            })
            .context("Failed to spawn egress thread")?
    };

    ingress_handle
        .join()
        .map_err(|e| anyhow::anyhow!("Ingress thread panicked: {:?}", e))??;
    egress_handle
        .join()
        .map_err(|e| anyhow::anyhow!("Egress thread panicked: {:?}", e))??;
    Ok(())
}

/// Run unified single-threaded data plane (Option 4)
///
/// This version eliminates cross-thread communication by handling both
/// ingress and egress in a single thread with one io_uring instance.
pub fn run_unified_data_plane(
    config: DataPlaneConfig,
    ingress_channels: IngressChannelSet,
    _egress_channels: EgressChannelSet, // Not used in unified mode
    logger: Logger,
) -> Result<()> {
    eprintln!("[run_unified_data_plane] Entry point reached");
    std::io::stderr().flush().ok();

    logger.info(Facility::DataPlane, "Unified data plane starting");

    // Extract command stream FD
    let cmd_stream_fd = ingress_channels.cmd_stream_fd;

    // Get buffer pool configuration from environment
    let buffer_pool_small = std::env::var("MCR_BUFFER_POOL_SMALL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let buffer_pool_standard = std::env::var("MCR_BUFFER_POOL_STANDARD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500);
    let buffer_pool_jumbo = std::env::var("MCR_BUFFER_POOL_JUMBO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    // Create buffer pool
    let buffer_pool = BufferPool::new(buffer_pool_small, buffer_pool_standard, buffer_pool_jumbo);

    // Get interface name
    let interface_name = config
        .input_interface_name
        .clone()
        .unwrap_or_else(|| "lo".to_string());

    // Create unified data plane configuration
    let unified_config = UnifiedConfig::default();

    eprintln!("[run_unified_data_plane] Creating UnifiedDataPlane");
    std::io::stderr().flush().ok();

    // Get PACKET_FANOUT group ID
    let fanout_group_id = config.fanout_group_id.unwrap_or(0);

    // Create and run unified data plane
    let mut unified = UnifiedDataPlane::new(
        &interface_name,
        unified_config,
        buffer_pool,
        cmd_stream_fd,
        fanout_group_id,
        logger.clone(),
    )?;

    eprintln!("[run_unified_data_plane] Starting event loop");
    std::io::stderr().flush().ok();

    logger.info(Facility::DataPlane, "Unified event loop starting");

    unified.run()
}
