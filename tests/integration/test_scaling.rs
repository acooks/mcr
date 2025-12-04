// SPDX-License-Identifier: Apache-2.0 OR MIT
// Scaling tests - verify 1:1 forwarding at multiple packet counts
//
// Run with: sudo -E cargo test --release --test integration -- --test-threads=1
//
// Tests require:
// - Root privileges (for network namespaces) - enforced by #[requires_root]
// - Release binaries built: cargo build --release --bins
// - Single-threaded execution (network namespaces can conflict)

use anyhow::Result;

mod privileged {
    use super::*;
    use crate::common::{McrInstance, NetworkNamespace, VethPair};
    use std::thread;
    use std::time::Duration;

    /// Helper to send multicast packets using mcrgen
    /// Uses count as rate for faster scaling tests
    fn send_packets(source_ip: &str, dest_group: &str, dest_port: u16, count: u32) -> Result<()> {
        crate::common::traffic::send_packets_with_options(
            source_ip, dest_group, dest_port, count, 1400, count,
        )
    }

    #[tokio::test]
    async fn test_scale_1000_packets() -> Result<()> {
        require_root!();
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

        let mut mcr = McrInstance::builder().interface("veth0p").core(0).start()?;
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
    async fn test_scale_10000_packets() -> Result<()> {
        require_root!();
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

        let mut mcr = McrInstance::builder().interface("veth0p").core(0).start()?;
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
    async fn test_scale_1m_packets() -> Result<()> {
        require_root!();
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

        let mut mcr = McrInstance::builder().interface("veth0p").core(0).start()?;
        mcr.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:lo"])?;

        // Send at 50k pps for 1M packets = 20 seconds send + 5 seconds drain
        crate::common::traffic::send_packets_with_options(
            "10.0.0.1",
            "239.1.1.1",
            5001,
            1000000,
            1400,
            50000,
        )?;

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
}
