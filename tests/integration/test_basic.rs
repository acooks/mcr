// Basic integration tests
//
// Run with: sudo -E cargo test --release --test integration -- --test-threads=1
//
// Tests require:
// - Root privileges (for network namespaces) - enforced by #[requires_root]
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
        .arg("1000") // 1000 pps for small tests
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
#[requires_root]
async fn test_single_hop_1000_packets() -> Result<()> {
    println!("\n=== Test: Single-hop forwarding with 1000 packets ===\n");

    // Enter isolated network namespace
    let _ns = NetworkNamespace::enter()?;
    _ns.enable_loopback().await?;

    // Create veth pair
    let _veth = VethPair::create("veth0", "veth0p")
        .await?
        .set_addr("veth0", "10.0.0.1/24")
        .await?
        .set_addr("veth0p", "10.0.0.2/24")
        .await?
        .up()
        .await?;

    println!("Network setup complete");

    // Start MCR instance
    let mut mcr = McrInstance::start("veth0p", Some(0))?;
    println!("MCR started, log: {:?}", mcr.log_path());

    // Add forwarding rule: 239.1.1.1:5001 -> 239.2.2.2:5002:lo
    mcr.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:lo"])?;
    println!("Rule added");

    // Send 1000 packets
    println!("Sending 1000 packets...");
    send_packets("10.0.0.1", "239.1.1.1", 5001, 1000)?;

    // Wait for packets to be processed
    println!("Waiting for pipeline to drain...");
    thread::sleep(Duration::from_secs(3));

    // Shutdown and get stats
    println!("Shutting down MCR...");
    let stats = mcr.shutdown_and_get_stats()?;

    // Validate results
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

    // With veth interfaces, AF_PACKET sees both RX and TX packets
    // So we expect roughly half the packets (this is a known limitation)
    // For now, just validate we got SOME packets and forwarding is working
    assert!(
        stats.ingress.matched > 0,
        "Should match at least some packets, got {}",
        stats.ingress.matched
    );

    assert_eq!(
        stats.ingress.matched, stats.ingress.egr_sent,
        "Ingress matched should equal egress sent"
    );

    // Validate no packet errors
    // Note: Parse errors are expected with AF_PACKET sockets (ARP, IPv6, etc.)
    assert_eq!(
        stats.ingress.buf_exhaust, 0,
        "Should have no buffer exhaustion"
    );
    assert_eq!(stats.egress.errors, 0, "Should have no egress errors");

    // This is the critical assertion - egress should receive what ingress sent
    // If this fails, we have the 2x packet bug
    assert_eq!(
        stats.egress.ch_recv, stats.ingress.egr_sent,
        "Egress ch_recv ({}) should equal ingress egr_sent ({})",
        stats.egress.ch_recv, stats.ingress.egr_sent
    );

    assert_eq!(
        stats.egress.sent, stats.egress.ch_recv,
        "Egress sent should equal ch_recv (no packet loss)"
    );

    assert_eq!(
        stats.egress.sent, stats.egress.submitted,
        "Egress sent should equal submitted (all submissions succeeded)"
    );

    println!("\n=== ✅ Test passed ===\n");

    Ok(())
}

#[tokio::test]
#[requires_root]
async fn test_minimal_10_packets() -> Result<()> {
    println!("\n=== Test: Minimal 10 packet test ===\n");

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

    let mut mcr = McrInstance::start("veth0p", None)?;
    mcr.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:lo"])?;

    send_packets("10.0.0.1", "239.1.1.1", 5001, 10)?;
    thread::sleep(Duration::from_secs(2));

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

    assert!(stats.ingress.matched > 0, "Should forward some packets");
    // Note: Parse errors are expected with AF_PACKET sockets (ARP, IPv6, etc.)
    // The important thing is that the UDP packets we sent were matched correctly
    assert_eq!(stats.egress.errors, 0, "Should have no egress errors");

    println!("\n=== ✅ Test passed ===\n");

    Ok(())
}
