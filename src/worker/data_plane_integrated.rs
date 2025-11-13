//! Integrated Data Plane
//!
//! This module provides the integrated data plane that combines ingress and egress
//! into a complete packet processing pipeline. It uses conditional compilation
//! to select between a Mutex-based backend and a high-performance lock-free backend.

use crate::logging::{Facility, Logger};
use crate::{DataPlaneConfig, RelayCommand};
use anyhow::Result;

// =================================================================================
// Public API - Dispatches to the correct backend based on feature flags
// =================================================================================

pub fn run_data_plane(
    config: DataPlaneConfig,
    command_rx: std::sync::mpsc::Receiver<RelayCommand>,
    event_fd: nix::sys::eventfd::EventFd,
    logger: Logger,
) -> Result<()> {
    #[cfg(feature = "lock_free_buffer_pool")]
    {
        logger.info(Facility::DataPlane, "Using Lock-Free Backend");
        lock_free_backend::run(config, command_rx, event_fd, logger)
    }
    #[cfg(not(feature = "lock_free_buffer_pool"))]
    {
        logger.info(Facility::DataPlane, "Using Mutex Backend");
        mutex_backend::run(config, command_rx, event_fd, logger)
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
        command_rx: mpsc::Receiver<RelayCommand>,
        event_fd: nix::sys::eventfd::EventFd,
        logger: Logger,
    ) -> Result<()> {
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
                        command_rx,
                        event_fd,
                        ingress_logger,
                    )?;
                    ingress.run()
                })
                .context("Failed to spawn ingress thread")?
        };

        let egress_handle = {
            thread::Builder::new()
                .name("egress".to_string())
                .spawn(move || -> Result<()> {
                    let mut egress = EgressLoop::new(egress_config.clone(), buffer_pool.clone())?;
                    loop {
                        egress.reap_available_completions()?;
                        match egress_rx.try_recv() {
                            Ok(packet) => {
                                egress.add_destination(&packet.interface_name, packet.dest_addr)?;
                                egress.queue_packet(packet);
                                if egress.queue_len() >= egress_config.batch_size {
                                    egress.send_batch()?;
                                }
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                if !egress.is_queue_empty() {
                                    egress.send_batch()?;
                                } else {
                                    match egress_rx.recv_timeout(Duration::from_micros(50)) {
                                        Ok(packet) => {
                                            egress.add_destination(
                                                &packet.interface_name,
                                                packet.dest_addr,
                                            )?;
                                            egress.queue_packet(packet);
                                        }
                                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                                        _ => {}
                                    }
                                }
                            }
                            Err(mpsc::TryRecvError::Disconnected) => break,
                        }
                    }
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

// =================================================================================
// Backend 2: Lock-Free Implementation
// =================================================================================

#[cfg(feature = "lock_free_buffer_pool")]
mod lock_free_backend {
    use anyhow::{Context, Result};
    use crossbeam_queue::SegQueue;
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    use crate::logging::Logger;
    use crate::worker::{
        buffer_pool::BufferPool,
        egress::{EgressConfig, EgressLoop, EgressWorkItem},
        ingress::{IngressConfig, IngressLoop},
    };
    use crate::{DataPlaneConfig, RelayCommand};

    pub fn run(
        config: DataPlaneConfig,
        command_rx: mpsc::Receiver<RelayCommand>,
        event_fd: nix::sys::eventfd::EventFd,
        logger: Logger,
    ) -> Result<()> {
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
                        command_rx,
                        event_fd,
                        ingress_logger,
                    )?;
                    ingress.run()
                })
                .context("Failed to spawn ingress thread")?
        };

        let egress_handle = {
            let egress_rx = egress_queue;
            thread::Builder::new()
                .name("egress".to_string())
                .spawn(move || -> Result<()> {
                    let mut egress = EgressLoop::new(egress_config.clone(), buffer_pool.clone())?;
                    loop {
                        egress.reap_available_completions()?;
                        match egress_rx.pop() {
                            Some(packet) => {
                                egress.add_destination(&packet.interface_name, packet.dest_addr)?;
                                egress.queue_packet(packet);
                                if egress.queue_len() >= egress_config.batch_size {
                                    egress.send_batch()?;
                                }
                            }
                            None => {
                                // The queue is empty
                                if !egress.is_queue_empty() {
                                    egress.send_batch()?;
                                } else {
                                    // Wait briefly for new packets.
                                    // This is a simple spin-wait with a short sleep to prevent pegging the CPU.
                                    // A more advanced implementation might use a condvar or other notification mechanism.
                                    thread::sleep(Duration::from_micros(10));
                                }
                            }
                        }
                    }
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
