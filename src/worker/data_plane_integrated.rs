// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integrated Data Plane
//!
//! This module provides the integrated data plane that combines ingress and egress
//! into a complete packet processing pipeline using a lock-free architecture.

use crate::logging::{Facility, Logger};
use crate::worker::{
    buffer_pool::BufferPool,
    unified_loop::{UnifiedConfig, UnifiedDataPlane},
    IngressChannelSet,
};
use crate::DataPlaneConfig;
use anyhow::Result;

/// Run unified single-threaded data plane
///
/// This version eliminates cross-thread communication by handling both
/// ingress and egress in a single thread with one io_uring instance.
pub fn run_unified_data_plane(
    config: DataPlaneConfig,
    ingress_channels: IngressChannelSet,
    logger: Logger,
) -> Result<()> {
    // Extract FDs from channel sets
    let cmd_stream_fd = ingress_channels.cmd_stream_fd;
    let af_packet_fd = ingress_channels.af_packet_fd;

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

    // Get interface name (still needed for IP lookups)
    let interface_name = config
        .input_interface_name
        .clone()
        .unwrap_or_else(|| "lo".to_string());

    // Create unified data plane configuration
    let unified_config = UnifiedConfig::default();

    // Create and run unified data plane using the pre-configured AF_PACKET socket
    // from the supervisor (privilege separation - worker doesn't need CAP_NET_RAW)
    let mut unified = UnifiedDataPlane::new_with_socket(
        &interface_name,
        unified_config,
        buffer_pool,
        cmd_stream_fd,
        af_packet_fd,
        logger.clone(),
    )?;

    logger.debug(Facility::DataPlane, "Event loop starting");

    unified.run()
}
