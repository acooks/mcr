//! # Metrics Module
//!
//! This module encapsulates the logic for exposing application metrics to external
//! observability systems. Currently, it provides an exporter for the Prometheus
//! monitoring system.

use anyhow::Result;
use std::net::SocketAddr;

#[cfg(not(test))]
pub fn install_prometheus_recorder(prometheus_addr: SocketAddr) -> Result<()> {
    use metrics_exporter_prometheus::PrometheusBuilder;
    use socket2::{Domain, Socket, Type};

    // Fragile workaround for SO_REUSEADDR with metrics-exporter-prometheus.
    // Create a socket, set SO_REUSEADDR, bind it, and then immediately close it.
    // This *might* leave the port in a reusable state for the PrometheusBuilder
    // to bind to, but it's not guaranteed and relies on OS behavior.
    let socket = Socket::new(Domain::for_address(prometheus_addr), Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    socket.bind(&prometheus_addr.into())?;
    // The socket is implicitly closed when it goes out of scope.

    let builder = PrometheusBuilder::new();
    builder
        .with_http_listener(prometheus_addr)
        .install()
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
pub fn install_prometheus_recorder(_prometheus_addr: SocketAddr) -> Result<()> {
    // Do nothing in tests to avoid starting a server and hanging.
    Ok(())
}
