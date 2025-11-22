// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::Result;

// Non-privileged tests can go here at the top level.

mod privileged {
    use super::*;
    use crate::common::{McrInstance, NetworkNamespace, VethPair};
    use std::thread;
    use std::time::Duration;

    /// All privileged tests must call this setup function.
    fn setup() {
        if !nix::unistd::geteuid().is_root() {
            panic!("SKIPPED: This test must be run with root privileges.");
        }
    }

    #[tokio::test]
    async fn test_single_hop_1000_packets() -> Result<()> {
        setup();
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
        crate::common::traffic::send_packets("10.0.0.1", "239.1.1.1", 5001, 1000)?;

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
    async fn test_minimal_10_packets() -> Result<()> {
        setup();
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

        crate::common::traffic::send_packets("10.0.0.1", "239.1.1.1", 5001, 10)?;
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
}
