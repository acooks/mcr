//! Integrated Data Plane
//!
//! This module provides the integrated data plane that combines ingress and egress
//! into a complete packet processing pipeline. It uses conditional compilation
//! to select between a Mutex-based backend and a high-performance lock-free backend.

use crate::logging::{Facility, Logger};
use crate::worker::{EgressChannelSet, IngressChannelSet};
use crate::DataPlaneConfig;
use anyhow::Result;

// =================================================================================
// Public API - Dispatches to the correct backend based on feature flags
// =================================================================================

pub fn run_data_plane(
    config: DataPlaneConfig,
    ingress_channels: IngressChannelSet,
    egress_channels: EgressChannelSet,
    logger: Logger,
) -> Result<()> {
    #[cfg(feature = "lock_free_buffer_pool")]
    {
        logger.info(Facility::DataPlane, "Using Lock-Free Backend");
        lock_free_backend::run(config, ingress_channels, egress_channels, logger)
    }
    #[cfg(not(feature = "lock_free_buffer_pool"))]
    {
        logger.info(Facility::DataPlane, "Using Mutex Backend");
        mutex_backend::run(config, ingress_channels, egress_channels, logger)
    }
}

// =================================================================================
// Backend 1: Original Mutex-based Implementation
// =================================================================================

#[cfg(not(feature = "lock_free_buffer_pool"))]
mod mutex_backend {
    use anyhow::{Context, Result};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    use crate::logging::Logger;
    use crate::worker::{
        buffer_pool::BufferPool,
        egress::{EgressConfig, EgressLoop, EgressPacket},
        ingress::{IngressConfig, IngressLoop},
    };
    use crate::{DataPlaneConfig, RelayCommand};

    pub fn run(
        config: DataPlaneConfig,
        ingress_channels: super::IngressChannelSet,
        egress_channels: super::EgressChannelSet,
        logger: Logger,
    ) -> Result<()> {
        // Destructure channel sets
        let ingress_command_rx = ingress_channels.command_rx;
        let ingress_event_fd = ingress_channels.event_fd;
        let egress_command_rx = egress_channels.command_rx;

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
        let (egress_tx, egress_rx) = mpsc::channel::<EgressPacket>();

        let buffer_pool = Arc::new(std::sync::Mutex::new(BufferPool::with_capacities(
            ingress_config.buffer_pool_small,
            ingress_config.buffer_pool_standard,
            ingress_config.buffer_pool_jumbo,
            ingress_config.track_stats,
        )));

        let interface_name = config
            .input_interface_name
            .clone()
            .unwrap_or_else(|| "lo".to_string());

        logger.debug(crate::logging::Facility::DataPlane, "Spawning ingress thread");
        let ingress_handle = {
            let interface_name = interface_name.clone();
            let egress_tx = egress_tx.clone();
            let buffer_pool_for_ingress = buffer_pool.clone();
            let ingress_logger = logger.clone();
            thread::Builder::new()
                .name("ingress".to_string())
                .spawn(move || -> Result<()> {
                    let mut ingress = IngressLoop::new(
                        &interface_name,
                        ingress_config,
                        buffer_pool_for_ingress,
                        Some(egress_tx),
                        ingress_command_rx,
                        ingress_event_fd,
                        ingress_logger,
                    )?;
                    ingress.run()
                })
                .context("Failed to spawn ingress thread")?
        };
        logger.debug(crate::logging::Facility::DataPlane, "Ingress thread spawned successfully");

        logger.debug(crate::logging::Facility::DataPlane, "Spawning egress thread");
        let egress_handle = {
            let egress_logger = logger.clone();
            let egress_logger_clone = egress_logger.clone();
            thread::Builder::new()
                .name("egress".to_string())
                .spawn(move || -> Result<()> {
                    let mut egress =
                        EgressLoop::new(egress_config.clone(), buffer_pool.clone(), egress_command_rx, egress_logger_clone)?;

                    // Event-driven loop with single blocking point: io_uring's submit_and_wait
                    loop {
                        // Process any commands (non-blocking)
                        let _ = egress.process_commands();

                        // Check if shutdown was requested (either via command or eventfd)
                        if egress.shutdown_requested() {
                            break;
                        }

                        // Process io_uring completions (non-blocking)
                        egress.reap_available_completions()?;

                        // Try to receive packets from ingress (non-blocking)
                        match egress_rx.try_recv() {
                            Ok(packet) => {
                                egress.add_destination(&packet.interface_name, packet.dest_addr)?;
                                egress.queue_packet(packet);
                                if egress.queue_len() >= egress_config.batch_size {
                                    egress.send_batch()?;
                                }
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                // No packets available - flush any queued packets
                                if !egress.is_queue_empty() {
                                    egress.send_batch()?;
                                }
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                egress_logger.info(crate::logging::Facility::Egress, "Ingress disconnected, shutting down");
                                break;
                            }
                        }

                        // Brief sleep to avoid busy-waiting
                        // The io_uring eventfd read will wake us up on shutdown signals
                        thread::sleep(Duration::from_micros(10));
                    }

                    egress_logger.info(crate::logging::Facility::Egress, "Egress loop exiting");
                    egress.print_final_stats();
                    egress_logger.info(crate::logging::Facility::Egress, "Egress shutdown complete");
                    Ok(())
                })
                .context("Failed to spawn egress thread")?
        };
        logger.debug(crate::logging::Facility::DataPlane, "Egress thread spawned successfully");

        logger.info(crate::logging::Facility::DataPlane, "Waiting for ingress thread to exit");
        ingress_handle
            .join()
            .map_err(|e| anyhow::anyhow!("Ingress thread panicked: {:?}", e))??;
        logger.info(crate::logging::Facility::DataPlane, "Ingress thread exited");

        logger.info(crate::logging::Facility::DataPlane, "Waiting for egress thread to exit");
        egress_handle
            .join()
            .map_err(|e| anyhow::anyhow!("Egress thread panicked: {:?}", e))??;
        logger.info(crate::logging::Facility::DataPlane, "Egress thread exited");

        logger.info(crate::logging::Facility::DataPlane, "Data plane shutdown complete");
        Ok(())
    }
}

// =================================================================================
// Backend 2: Lock-Free Implementation
// =================================================================================

#[cfg(feature = "lock_free_buffer_pool")]
mod lock_free_backend {
    use anyhow::{Context, Result};
    use crossbeam_queue::SegQueue;
    use std::sync::Arc;
    use std::thread;

    use crate::logging::Logger;
    use crate::worker::{
        buffer_pool::BufferPool,
        egress::{EgressConfig, EgressLoop, EgressWorkItem},
        ingress::{IngressConfig, IngressLoop},
    };
    use crate::DataPlaneConfig;

    pub fn run(
        config: DataPlaneConfig,
        ingress_channels: super::IngressChannelSet,
        egress_channels: super::EgressChannelSet,
        logger: Logger,
    ) -> Result<()> {
        // Destructure channel sets
        let ingress_command_rx = ingress_channels.command_rx;
        let ingress_event_fd = ingress_channels.event_fd;
        // Note: egress_channels is moved as a whole to EgressLoop::new()

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
            let egress_queue = egress_queue.clone();
            let buffer_pool_for_ingress = buffer_pool.clone();
            let ingress_logger = logger.clone();
            thread::Builder::new()
                .name("ingress".to_string())
                .spawn(move || -> Result<()> {
                    let mut ingress = IngressLoop::new(
                        &interface_name,
                        ingress_config,
                        buffer_pool_for_ingress,
                        Some(egress_queue),
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
                        egress_channels,  // Pass the whole struct
                        egress_logger
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
}
