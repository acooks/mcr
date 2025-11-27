// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Traffic generation utilities for integration tests

use anyhow::Result;
use std::process::Command;

/// Send multicast packets using the traffic_generator binary
///
/// # Arguments
/// * `source_ip` - Source IP address to bind to
/// * `dest_group` - Destination multicast group
/// * `dest_port` - Destination UDP port
/// * `count` - Number of packets to send
/// * `size` - Optional packet size in bytes (default: 1400)
/// * `rate` - Optional packet rate in packets/sec (default: 1000)
pub fn send_packets(source_ip: &str, dest_group: &str, dest_port: u16, count: u32) -> Result<()> {
    send_packets_with_options(source_ip, dest_group, dest_port, count, 1400, 1000)
}

/// Send multicast packets with custom size and rate
pub fn send_packets_with_options(
    source_ip: &str,
    dest_group: &str,
    dest_port: u16,
    count: u32,
    size: u32,
    rate: u32,
) -> Result<()> {
    let traffic_bin = super::binary_path("traffic_generator");

    let output = Command::new(traffic_bin)
        .arg("--interface")
        .arg(source_ip)
        .arg("--group")
        .arg(dest_group)
        .arg("--port")
        .arg(dest_port.to_string())
        .arg("--count")
        .arg(count.to_string())
        .arg("--size")
        .arg(size.to_string())
        .arg("--rate")
        .arg(rate.to_string())
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Traffic generator stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!("Traffic generator failed");
    }

    Ok(())
}
