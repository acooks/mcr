// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::Result;

// Non-privileged tests can go here at the top level.

mod privileged {
    use super::*;
    use crate::common::{McrInstance, NetworkNamespace, VethPair};
    use std::thread;
    use std::time::Duration;

    #[tokio::test]
    async fn test_single_hop_1000_packets() -> Result<()> {
        require_root!();
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
        let mut mcr = McrInstance::builder().interface("veth0p").core(0).start()?;
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

        // Validate packet matching - should receive close to 1000 packets
        // (some OS-level packet loss is acceptable under load, but not orders of magnitude)
        assert!(
            stats.ingress.matched >= 900,
            "Should match at least 90% of 1000 packets, got {}",
            stats.ingress.matched
        );

        // Validate 1:1 forwarding through the pipeline
        assert_eq!(
            stats.ingress.matched, stats.ingress.egr_sent,
            "Ingress matched ({}) should equal egr_sent ({})",
            stats.ingress.matched, stats.ingress.egr_sent
        );

        assert_eq!(
            stats.egress.ch_recv, stats.ingress.egr_sent,
            "Egress ch_recv ({}) should equal ingress egr_sent ({})",
            stats.egress.ch_recv, stats.ingress.egr_sent
        );

        assert_eq!(
            stats.egress.sent, stats.egress.ch_recv,
            "Egress sent ({}) should equal ch_recv ({})",
            stats.egress.sent, stats.egress.ch_recv
        );

        assert_eq!(
            stats.egress.sent, stats.egress.submitted,
            "Egress sent ({}) should equal submitted ({})",
            stats.egress.sent, stats.egress.submitted
        );

        // Validate no errors
        assert_eq!(
            stats.ingress.buf_exhaust, 0,
            "Should have no buffer exhaustion"
        );
        assert_eq!(stats.egress.errors, 0, "Should have no egress errors");

        println!("\n=== ✅ Test passed ===\n");

        Ok(())
    }

    /// Test: Single packet forwarding (edge case - minimum traffic)
    ///
    /// Verifies that even a single packet is correctly forwarded through
    /// the entire pipeline without loss.
    #[tokio::test]
    async fn test_single_packet_forwarding() -> Result<()> {
        require_root!();
        println!("\n=== Test: Single packet forwarding ===\n");

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

        // Send exactly 1 packet
        crate::common::traffic::send_packets_with_options(
            "10.0.0.1",
            "239.1.1.1",
            5001,
            1,
            100,
            1,
        )?;

        thread::sleep(Duration::from_secs(2));

        let stats = mcr.shutdown_and_get_stats()?;

        println!(
            "Ingress: matched={} egr_sent={}",
            stats.ingress.matched, stats.ingress.egr_sent
        );
        println!(
            "Egress: sent={} ch_recv={}",
            stats.egress.sent, stats.egress.ch_recv
        );

        // Must match exactly 1 packet
        assert_eq!(
            stats.ingress.matched, 1,
            "Should match exactly 1 packet, got {}",
            stats.ingress.matched
        );

        // Validate 1:1 forwarding
        assert_eq!(stats.ingress.matched, stats.ingress.egr_sent);
        assert_eq!(stats.egress.ch_recv, stats.ingress.egr_sent);
        assert_eq!(stats.egress.sent, stats.egress.ch_recv);

        // No errors
        assert_eq!(stats.ingress.buf_exhaust, 0);
        assert_eq!(stats.egress.errors, 0);

        println!("\n=== ✅ Test passed ===\n");
        Ok(())
    }

    /// Test: Large packet forwarding (near MTU size)
    ///
    /// Verifies that packets close to the MTU size (1500 bytes for Ethernet)
    /// are correctly forwarded without fragmentation issues.
    #[tokio::test]
    async fn test_large_packet_forwarding() -> Result<()> {
        require_root!();
        println!("\n=== Test: Large packet forwarding (1400 byte payload) ===\n");

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

        // Send 100 large packets (1400 byte payload, close to MTU)
        crate::common::traffic::send_packets_with_options(
            "10.0.0.1",
            "239.1.1.1",
            5001,
            100,
            1400,
            100,
        )?;

        thread::sleep(Duration::from_secs(2));

        let stats = mcr.shutdown_and_get_stats()?;

        println!(
            "Ingress: matched={} egr_sent={} bytes={}",
            stats.ingress.matched, stats.ingress.egr_sent, stats.egress.bytes
        );

        // Should match all 100 packets
        assert!(
            stats.ingress.matched >= 95,
            "Should match at least 95 of 100 large packets, got {}",
            stats.ingress.matched
        );

        // Validate 1:1 forwarding
        assert_eq!(stats.ingress.matched, stats.ingress.egr_sent);
        assert_eq!(stats.egress.ch_recv, stats.ingress.egr_sent);
        assert_eq!(stats.egress.sent, stats.egress.ch_recv);

        // Verify byte count (each packet should be ~1400 bytes payload)
        let expected_bytes = stats.egress.sent * 1400;
        assert!(
            stats.egress.bytes >= expected_bytes * 9 / 10,
            "Byte count should be close to {} (got {})",
            expected_bytes,
            stats.egress.bytes
        );

        // No errors
        assert_eq!(stats.ingress.buf_exhaust, 0);
        assert_eq!(stats.egress.errors, 0);

        println!("\n=== ✅ Test passed ===\n");
        Ok(())
    }
}
