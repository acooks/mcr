// Scaling tests - verify 1:1 forwarding at multiple packet counts
//
// Run with: sudo cargo test --test test_scaling -- --ignored --test-threads=1
//
// Tests require:
// - Root privileges (for network namespaces)
// - Release binaries built: cargo build --release --bins
// - Single-threaded execution (network namespaces can conflict)

mod common;

use anyhow::Result;
use common::{McrInstance, NetworkNamespace, VethPair};
use mcr_test_macros::requires_root;
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Helper to send multicast packets using traffic_generator
fn send_packets(source_ip: &str, dest_group: &str, dest_port: u16, count: u32) -> Result<()> {
    let traffic_bin = common::binary_path("traffic_generator");

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
        .arg("1400")
        .arg("--rate")
        .arg(count.to_string()) // Use count as rate for faster tests
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

#[tokio::test]
#[ignore]
#[requires_root]
async fn test_scale_1000_packets() -> Result<()> {
    println!("\n=== Scaling Test: 1,000 packets ===\n");

    let _ns = NetworkNamespace::enter()?;
    _ns.enable_loopback().await?;

    let _veth = VethPair::create("veth0", "veth0p")
        .await?
        .set_addr("veth0", "10.0.0.1/24")
        .await?
        .set_addr("veth0p", "10.0.0.2/24")
        .await?
        .up()
        .await?;

    let mut mcr = McrInstance::start("veth0p", Some(0))?;
    mcr.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:lo"])?;

    send_packets("10.0.0.1", "239.1.1.1", 5001, 1000)?;
    thread::sleep(Duration::from_secs(3));

    let stats = mcr.shutdown_and_get_stats()?;

    println!("\n=== Results ===");
    println!(
        "Ingress: recv={} matched={} egr_sent={} filtered={} no_match={} buf_exhaust={}",
        stats.ingress.recv,
        stats.ingress.matched,
        stats.ingress.egr_sent,
        stats.ingress.filtered,
        stats.ingress.no_match,
        stats.ingress.buf_exhaust
    );
    println!(
        "Egress: sent={} submitted={} ch_recv={} errors={} bytes={}",
        stats.egress.sent,
        stats.egress.submitted,
        stats.egress.ch_recv,
        stats.egress.errors,
        stats.egress.bytes
    );

    // Validate perfect 1:1 forwarding
    assert!(stats.ingress.matched > 0, "Should forward some packets");
    assert_eq!(
        stats.ingress.matched, stats.ingress.egr_sent,
        "Ingress matched should equal egr_sent"
    );
    assert_eq!(
        stats.egress.ch_recv, stats.ingress.egr_sent,
        "Egress ch_recv should equal ingress egr_sent"
    );
    assert_eq!(
        stats.egress.sent, stats.egress.ch_recv,
        "Egress sent should equal ch_recv"
    );
    assert_eq!(
        stats.egress.sent, stats.egress.submitted,
        "Egress sent should equal submitted"
    );

    // No errors
    assert_eq!(
        stats.ingress.buf_exhaust, 0,
        "Should have no buffer exhaustion"
    );
    assert_eq!(stats.egress.errors, 0, "Should have no egress errors");

    println!("\n=== ✅ Test passed ===\n");
    Ok(())
}

#[tokio::test]
#[ignore]
#[requires_root]
async fn test_scale_10000_packets() -> Result<()> {
    println!("\n=== Scaling Test: 10,000 packets ===\n");

    let _ns = NetworkNamespace::enter()?;
    _ns.enable_loopback().await?;

    let _veth = VethPair::create("veth0", "veth0p")
        .await?
        .set_addr("veth0", "10.0.0.1/24")
        .await?
        .set_addr("veth0p", "10.0.0.2/24")
        .await?
        .up()
        .await?;

    let mut mcr = McrInstance::start("veth0p", Some(0))?;
    mcr.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:lo"])?;

    send_packets("10.0.0.1", "239.1.1.1", 5001, 10000)?;
    thread::sleep(Duration::from_secs(4));

    let stats = mcr.shutdown_and_get_stats()?;

    println!("\n=== Results ===");
    println!(
        "Ingress: recv={} matched={} egr_sent={} filtered={} no_match={} buf_exhaust={}",
        stats.ingress.recv,
        stats.ingress.matched,
        stats.ingress.egr_sent,
        stats.ingress.filtered,
        stats.ingress.no_match,
        stats.ingress.buf_exhaust
    );
    println!(
        "Egress: sent={} submitted={} ch_recv={} errors={} bytes={}",
        stats.egress.sent,
        stats.egress.submitted,
        stats.egress.ch_recv,
        stats.egress.errors,
        stats.egress.bytes
    );

    // Validate perfect 1:1 forwarding
    assert!(stats.ingress.matched > 0, "Should forward some packets");
    assert_eq!(
        stats.ingress.matched, stats.ingress.egr_sent,
        "Ingress matched should equal egr_sent"
    );
    assert_eq!(
        stats.egress.ch_recv, stats.ingress.egr_sent,
        "Egress ch_recv should equal ingress egr_sent"
    );
    assert_eq!(
        stats.egress.sent, stats.egress.ch_recv,
        "Egress sent should equal ch_recv"
    );
    assert_eq!(
        stats.egress.sent, stats.egress.submitted,
        "Egress sent should equal submitted"
    );

    // No errors
    assert_eq!(
        stats.ingress.buf_exhaust, 0,
        "Should have no buffer exhaustion"
    );
    assert_eq!(stats.egress.errors, 0, "Should have no egress errors");

    println!("\n=== ✅ Test passed ===\n");
    Ok(())
}

#[tokio::test]
#[ignore]
#[requires_root]
async fn test_scale_1m_packets() -> Result<()> {
    println!("\n=== Scaling Test: 1,000,000 packets ===\n");

    let _ns = NetworkNamespace::enter()?;
    _ns.enable_loopback().await?;

    let _veth = VethPair::create("veth0", "veth0p")
        .await?
        .set_addr("veth0", "10.0.0.1/24")
        .await?
        .set_addr("veth0p", "10.0.0.2/24")
        .await?
        .up()
        .await?;

    let mut mcr = McrInstance::start("veth0p", Some(0))?;
    mcr.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:lo"])?;

    // Send at 50k pps for 1M packets = 20 seconds send + 5 seconds drain
    let traffic_bin = common::binary_path("traffic_generator");
    let output = Command::new(traffic_bin)
        .arg("--interface")
        .arg("10.0.0.1")
        .arg("--group")
        .arg("239.1.1.1")
        .arg("--port")
        .arg("5001")
        .arg("--count")
        .arg("1000000")
        .arg("--size")
        .arg("1400")
        .arg("--rate")
        .arg("50000")
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Traffic generator stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!("Traffic generator failed");
    }

    println!("Waiting for pipeline to drain...");
    thread::sleep(Duration::from_secs(25));

    let stats = mcr.shutdown_and_get_stats()?;

    println!("\n=== Results ===");
    println!(
        "Ingress: recv={} matched={} egr_sent={} filtered={} no_match={} buf_exhaust={}",
        stats.ingress.recv,
        stats.ingress.matched,
        stats.ingress.egr_sent,
        stats.ingress.filtered,
        stats.ingress.no_match,
        stats.ingress.buf_exhaust
    );
    println!(
        "Egress: sent={} submitted={} ch_recv={} errors={} bytes={}",
        stats.egress.sent,
        stats.egress.submitted,
        stats.egress.ch_recv,
        stats.egress.errors,
        stats.egress.bytes
    );

    // Validate perfect 1:1 forwarding
    assert!(stats.ingress.matched > 0, "Should forward some packets");
    assert_eq!(
        stats.ingress.matched, stats.ingress.egr_sent,
        "Ingress matched should equal egr_sent"
    );
    assert_eq!(
        stats.egress.ch_recv, stats.ingress.egr_sent,
        "Egress ch_recv should equal ingress egr_sent"
    );
    assert_eq!(
        stats.egress.sent, stats.egress.ch_recv,
        "Egress sent should equal ch_recv"
    );
    assert_eq!(
        stats.egress.sent, stats.egress.submitted,
        "Egress sent should equal submitted"
    );

    // No errors
    assert_eq!(
        stats.ingress.buf_exhaust, 0,
        "Should have no buffer exhaustion"
    );
    assert_eq!(stats.egress.errors, 0, "Should have no egress errors");

    println!("\n=== ✅ Test passed: 1M packets with perfect 1:1 forwarding ===\n");
    Ok(())
}
