//! Integrated Data Plane
//!
//! This module provides the integrated data plane that combines ingress and egress
//! into a complete packet processing pipeline using a lock-free architecture.

use crate::logging::{Facility, Logger};
use crate::worker::{
    buffer_pool::BufferPool,
    egress::{EgressConfig, EgressLoop, EgressWorkItem},
    ingress::{EgressQueueWithWakeup, IngressConfig, IngressLoop},
    EgressChannelSet, IngressChannelSet,
};
use crate::DataPlaneConfig;
use anyhow::{Context, Result};
use crossbeam_queue::SegQueue;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread;

pub fn run_data_plane(
    config: DataPlaneConfig,
    ingress_channels: IngressChannelSet,
    egress_channels: EgressChannelSet,
    logger: Logger,
) -> Result<()> {
    logger.info(Facility::DataPlane, "Data plane starting (lock-free mode)");

    // Destructure channel sets
    let ingress_command_rx = ingress_channels.command_rx;
    let ingress_event_fd = ingress_channels.event_fd;

    // Get raw FD for egress wakeup before moving egress_channels
    let egress_wakeup_fd = egress_channels.event_fd.as_raw_fd();

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

    let ingress_handle = {
        let interface_name = interface_name.clone();
        let egress_queue_for_ingress = egress_queue.clone();
        let buffer_pool_for_ingress = buffer_pool.clone();
        let ingress_logger = logger.clone();
        thread::Builder::new()
            .name("ingress".to_string())
            .spawn(move || -> Result<()> {
                // Wrap the queue with wakeup eventfd
                let egress_channel =
                    EgressQueueWithWakeup::new(egress_queue_for_ingress, egress_wakeup_fd);

                let mut ingress = IngressLoop::new(
                    &interface_name,
                    ingress_config,
                    buffer_pool_for_ingress,
                    Some(egress_channel),
                    ingress_command_rx,
                    ingress_event_fd,
                    ingress_logger,
                )?;
                ingress.run()
            })
            .context("Failed to spawn ingress thread")?
    };

    let egress_handle = {
        let egress_rx = egress_queue;
        let egress_logger = logger.clone();
        thread::Builder::new()
            .name("egress".to_string())
            .spawn(move || -> Result<()> {
                let mut egress = EgressLoop::new(
                    egress_config.clone(),
                    buffer_pool.clone(),
                    egress_channels, // Pass the whole struct
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
