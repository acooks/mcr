// SPDX-License-Identifier: Apache-2.0 OR MIT
// Topology tests - multi-hop chains and fanout patterns
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

    /// All privileged tests must call this setup function.
    fn setup() {
        if !nix::unistd::geteuid().is_root() {
            panic!("SKIPPED: This test must be run with root privileges.");
        }
    }

    /// Helper to send multicast packets using traffic_generator with explicit rate
    fn send_packets(
        source_ip: &str,
        dest_group: &str,
        dest_port: u16,
        count: u32,
        rate: u32,
    ) -> Result<()> {
        crate::common::traffic::send_packets_with_options(
            source_ip, dest_group, dest_port, count, 1400, rate,
        )
    }

    #[tokio::test]
    async fn test_baseline_2hop_100k_packets() -> Result<()> {
        setup();
        println!("\n=== Baseline: 2-hop forwarding with 100k packets ===\n");

        let _ns = NetworkNamespace::enter()?;
        _ns.enable_loopback().await?;

        // Create veth pairs for 2-hop chain
        // Traffic Gen → veth0 → veth0p (MCR-1 ingress)
        // MCR-1 egress → veth1a → veth1b (MCR-2 ingress)
        let _veth0 = VethPair::create("veth0", "veth0p")
            .await?
            .set_addr("veth0", "10.0.0.1/24")
            .await?
            .set_addr("veth0p", "10.0.0.2/24")
            .await?
            .up()
            .await?;

        let _veth1 = VethPair::create("veth1a", "veth1b")
            .await?
            .set_addr("veth1a", "10.0.1.1/24")
            .await?
            .set_addr("veth1b", "10.0.1.2/24")
            .await?
            .up()
            .await?;

        println!("Network setup complete");

        // Start MCR instances on separate cores
        let mut mcr1 = McrInstance::start("veth0p", Some(0))?;
        let mut mcr2 = McrInstance::start("veth1b", Some(1))?;
        println!("MCR instances started");

        // Configure forwarding rules
        // MCR-1: Forward 239.1.1.1:5001 → 239.2.2.2:5002 via veth1a
        mcr1.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:veth1a"])?;

        // MCR-2: Receive 239.2.2.2:5002 → forward to loopback (sink)
        mcr2.add_rule("239.2.2.2:5002", vec!["239.9.9.9:5099:lo"])?;

        println!("Rules configured");

        // Send 100k packets at 50k pps
        println!("Sending 100k packets at 50k pps...");
        send_packets("10.0.0.1", "239.1.1.1", 5001, 100000, 50000)?;

        println!("Waiting for pipeline to drain...");
        thread::sleep(Duration::from_secs(5));

        // Shutdown and get stats
        println!("Shutting down MCR instances...");
        let stats1 = mcr1.shutdown_and_get_stats()?;
        let stats2 = mcr2.shutdown_and_get_stats()?;

        // Print results
        println!("\n=== MCR-1 Results ===");
        println!(
            "Ingress: recv={} matched={} egr_sent={} filtered={} no_match={} buf_exhaust={}",
            stats1.ingress.recv,
            stats1.ingress.matched,
            stats1.ingress.egr_sent,
            stats1.ingress.filtered,
            stats1.ingress.no_match,
            stats1.ingress.buf_exhaust
        );
        println!(
            "Egress: sent={} submitted={} ch_recv={} errors={} bytes={}",
            stats1.egress.sent,
            stats1.egress.submitted,
            stats1.egress.ch_recv,
            stats1.egress.errors,
            stats1.egress.bytes
        );

        println!("\n=== MCR-2 Results ===");
        println!(
            "Ingress: recv={} matched={} egr_sent={} filtered={} no_match={} buf_exhaust={}",
            stats2.ingress.recv,
            stats2.ingress.matched,
            stats2.ingress.egr_sent,
            stats2.ingress.filtered,
            stats2.ingress.no_match,
            stats2.ingress.buf_exhaust
        );
        println!(
            "Egress: sent={} submitted={} ch_recv={} errors={} bytes={}",
            stats2.egress.sent,
            stats2.egress.submitted,
            stats2.egress.ch_recv,
            stats2.egress.errors,
            stats2.egress.bytes
        );

        // Validate MCR-1 forwarding
        assert!(stats1.ingress.matched > 0, "MCR-1 should match packets");
        assert_eq!(
            stats1.ingress.matched, stats1.ingress.egr_sent,
            "MCR-1: ingress matched should equal egr_sent"
        );
        assert_eq!(
            stats1.egress.ch_recv, stats1.ingress.egr_sent,
            "MCR-1: egress ch_recv should equal ingress egr_sent"
        );
        assert_eq!(
            stats1.egress.sent, stats1.egress.ch_recv,
            "MCR-1: egress sent should equal ch_recv"
        );

        // Validate MCR-2 forwarding
        assert!(stats2.ingress.matched > 0, "MCR-2 should match packets");
        assert_eq!(
            stats2.ingress.matched, stats2.ingress.egr_sent,
            "MCR-2: ingress matched should equal egr_sent"
        );
        assert_eq!(
            stats2.egress.ch_recv, stats2.ingress.egr_sent,
            "MCR-2: egress ch_recv should equal ingress egr_sent"
        );
        assert_eq!(
            stats2.egress.sent, stats2.egress.ch_recv,
            "MCR-2: egress sent should equal ch_recv"
        );

        // Allow small amount of filtered packets (stray multicast traffic like ARP, IPv6)
        // Note: AF_PACKET sockets see all link-layer traffic
        assert!(
            stats1.ingress.filtered < 100,
            "Too many filtered packets on MCR-1: {}",
            stats1.ingress.filtered
        );
        assert_eq!(
            stats1.egress.errors, 0,
            "MCR-1 should have no egress errors"
        );
        assert!(
            stats2.ingress.filtered < 100,
            "Too many filtered packets on MCR-2: {}",
            stats2.ingress.filtered
        );
        assert_eq!(
            stats2.egress.errors, 0,
            "MCR-2 should have no egress errors"
        );

        println!("\n=== ✅ Test passed ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_chain_3hop() -> Result<()> {
        setup();
        println!("\n=== 3-Hop Chain Topology Test ===\n");

        let _ns = NetworkNamespace::enter()?;
        _ns.enable_loopback().await?;

        // Create veth pairs for 3-hop chain
        // Traffic Gen → veth0 → veth0p (MCR-1 ingress)
        // MCR-1 egress → veth1a → veth1b (MCR-2 ingress)
        // MCR-2 egress → veth2a → veth2b (MCR-3 ingress)
        let _veth0 = VethPair::create("veth0", "veth0p")
            .await?
            .set_addr("veth0", "10.0.0.1/24")
            .await?
            .set_addr("veth0p", "10.0.0.2/24")
            .await?
            .up()
            .await?;

        let _veth1 = VethPair::create("veth1a", "veth1b")
            .await?
            .set_addr("veth1a", "10.0.1.1/24")
            .await?
            .set_addr("veth1b", "10.0.1.2/24")
            .await?
            .up()
            .await?;

        let _veth2 = VethPair::create("veth2a", "veth2b")
            .await?
            .set_addr("veth2a", "10.0.2.1/24")
            .await?
            .set_addr("veth2b", "10.0.2.2/24")
            .await?
            .up()
            .await?;

        println!("Network setup complete");

        // Start 3 MCR instances on separate cores
        let mut mcr1 = McrInstance::start("veth0p", Some(0))?;
        let mut mcr2 = McrInstance::start("veth1b", Some(1))?;
        let mut mcr3 = McrInstance::start("veth2b", Some(2))?;
        println!("MCR instances started");

        // Configure forwarding rules
        // MCR-1: Receive on veth0p (239.1.1.1:5001) → Forward to veth1a (239.2.2.2:5002)
        mcr1.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:veth1a"])?;

        // MCR-2: Receive on veth1b (239.2.2.2:5002) → Forward to veth2a (239.3.3.3:5003)
        mcr2.add_rule("239.2.2.2:5002", vec!["239.3.3.3:5003:veth2a"])?;

        // MCR-3: Receive on veth2b (239.3.3.3:5003) → sink to loopback
        mcr3.add_rule("239.3.3.3:5003", vec!["239.9.9.9:5099:lo"])?;

        println!("Rules configured");

        // Send 10k packets at 10k pps for faster test
        println!("Sending 10k packets at 10k pps...");
        send_packets("10.0.0.1", "239.1.1.1", 5001, 10000, 10000)?;

        println!("Waiting for pipeline to drain...");
        thread::sleep(Duration::from_secs(5));

        // Shutdown and get stats
        println!("Shutting down MCR instances...");
        let stats1 = mcr1.shutdown_and_get_stats()?;
        let stats2 = mcr2.shutdown_and_get_stats()?;
        let stats3 = mcr3.shutdown_and_get_stats()?;

        // Print results
        println!("\n=== MCR-1 Results ===");
        println!(
            "Ingress: matched={} egr_sent={}",
            stats1.ingress.matched, stats1.ingress.egr_sent
        );
        println!(
            "Egress: sent={} ch_recv={}",
            stats1.egress.sent, stats1.egress.ch_recv
        );

        println!("\n=== MCR-2 Results ===");
        println!(
            "Ingress: matched={} egr_sent={}",
            stats2.ingress.matched, stats2.ingress.egr_sent
        );
        println!(
            "Egress: sent={} ch_recv={}",
            stats2.egress.sent, stats2.egress.ch_recv
        );

        println!("\n=== MCR-3 Results ===");
        println!(
            "Ingress: matched={} egr_sent={}",
            stats3.ingress.matched, stats3.ingress.egr_sent
        );
        println!(
            "Egress: sent={} ch_recv={}",
            stats3.egress.sent, stats3.egress.ch_recv
        );

        // Validate each hop has 1:1 forwarding
        assert!(stats1.ingress.matched > 0, "MCR-1 should match packets");
        assert_eq!(
            stats1.ingress.matched, stats1.ingress.egr_sent,
            "MCR-1: 1:1 forwarding"
        );
        assert_eq!(
            stats1.egress.ch_recv, stats1.ingress.egr_sent,
            "MCR-1: channel delivery"
        );

        assert!(stats2.ingress.matched > 0, "MCR-2 should match packets");
        assert_eq!(
            stats2.ingress.matched, stats2.ingress.egr_sent,
            "MCR-2: 1:1 forwarding"
        );
        assert_eq!(
            stats2.egress.ch_recv, stats2.ingress.egr_sent,
            "MCR-2: channel delivery"
        );

        assert!(stats3.ingress.matched > 0, "MCR-3 should match packets");
        assert_eq!(
            stats3.ingress.matched, stats3.ingress.egr_sent,
            "MCR-3: 1:1 forwarding"
        );
        assert_eq!(
            stats3.egress.ch_recv, stats3.ingress.egr_sent,
            "MCR-3: channel delivery"
        );

        // Allow small amount of filtered packets (stray multicast traffic like ARP, IPv6)
        // Note: AF_PACKET sockets see all link-layer traffic
        assert!(
            stats1.ingress.filtered < 100,
            "Too many filtered packets on MCR-1: {}",
            stats1.ingress.filtered
        );
        assert!(
            stats2.ingress.filtered < 100,
            "Too many filtered packets on MCR-2: {}",
            stats2.ingress.filtered
        );
        assert!(
            stats3.ingress.filtered < 100,
            "Too many filtered packets on MCR-3: {}",
            stats3.ingress.filtered
        );

        println!("\n=== ✅ Test passed: 3-hop chain with perfect forwarding ===\n");
        Ok(())
    }

    #[tokio::test]
    async fn test_tree_fanout_1_to_3() -> Result<()> {
        setup();
        println!("\n=== Tree Topology: 1:3 Fanout (Head-End Replication) ===\n");

        let _ns = NetworkNamespace::enter()?;
        _ns.enable_loopback().await?;

        // Create veth pairs for tree topology
        // Traffic Gen → veth0 → veth0p (MCR-1 ingress)
        // MCR-1 egress → veth1a → veth1b (MCR-2 ingress)
        // MCR-1 egress → veth2a → veth2b (MCR-3 ingress)
        // MCR-1 egress → veth3a → veth3b (MCR-4 ingress)
        let _veth0 = VethPair::create("veth0", "veth0p")
            .await?
            .set_addr("veth0", "10.0.0.1/24")
            .await?
            .set_addr("veth0p", "10.0.0.2/24")
            .await?
            .up()
            .await?;

        let _veth1 = VethPair::create("veth1a", "veth1b")
            .await?
            .set_addr("veth1a", "10.0.1.1/24")
            .await?
            .set_addr("veth1b", "10.0.1.2/24")
            .await?
            .up()
            .await?;

        let _veth2 = VethPair::create("veth2a", "veth2b")
            .await?
            .set_addr("veth2a", "10.0.2.1/24")
            .await?
            .set_addr("veth2b", "10.0.2.2/24")
            .await?
            .up()
            .await?;

        let _veth3 = VethPair::create("veth3a", "veth3b")
            .await?
            .set_addr("veth3a", "10.0.3.1/24")
            .await?
            .set_addr("veth3b", "10.0.3.2/24")
            .await?
            .up()
            .await?;

        println!("Network setup complete");

        // Start MCR instances on separate cores
        let mut mcr1 = McrInstance::start("veth0p", Some(0))?;
        let mut mcr2 = McrInstance::start("veth1b", Some(1))?;
        let mut mcr3 = McrInstance::start("veth2b", Some(2))?;
        let mut mcr4 = McrInstance::start("veth3b", Some(3))?;
        println!("MCR instances started");

        // Configure forwarding rules
        // MCR-1: Head-end replication - 1 input → 3 outputs
        println!("Configuring 1:3 head-end replication on MCR-1...");
        mcr1.add_rule(
            "239.1.1.1:5001",
            vec![
                "239.2.2.2:5002:veth1a",
                "239.3.3.3:5003:veth2a",
                "239.4.4.4:5004:veth3a",
            ],
        )?;

        // MCR-2, MCR-3, MCR-4: Sink nodes
        mcr2.add_rule("239.2.2.2:5002", vec!["239.9.9.9:5099:lo"])?;
        mcr3.add_rule("239.3.3.3:5003", vec!["239.9.9.9:5099:lo"])?;
        mcr4.add_rule("239.4.4.4:5004", vec!["239.9.9.9:5099:lo"])?;

        println!("Rules configured");

        // Send 10k packets at 10k pps
        println!("Sending 10k packets at 10k pps...");
        send_packets("10.0.0.1", "239.1.1.1", 5001, 10000, 10000)?;

        println!("Waiting for pipeline to drain...");
        thread::sleep(Duration::from_secs(5));

        // Shutdown and get stats
        println!("Shutting down MCR instances...");
        let stats1 = mcr1.shutdown_and_get_stats()?;
        let stats2 = mcr2.shutdown_and_get_stats()?;
        let stats3 = mcr3.shutdown_and_get_stats()?;
        let stats4 = mcr4.shutdown_and_get_stats()?;

        // Print results
        println!("\n=== MCR-1 Results (Head-End Replicator) ===");
        println!(
            "Ingress: recv={} matched={} egr_sent={} filtered={} no_match={}",
            stats1.ingress.recv,
            stats1.ingress.matched,
            stats1.ingress.egr_sent,
            stats1.ingress.filtered,
            stats1.ingress.no_match
        );
        println!(
            "Egress: sent={} ch_recv={}",
            stats1.egress.sent, stats1.egress.ch_recv
        );

        println!("\n=== MCR-2 Results (Leaf 1) ===");
        println!(
            "Ingress: matched={} egr_sent={}",
            stats2.ingress.matched, stats2.ingress.egr_sent
        );

        println!("\n=== MCR-3 Results (Leaf 2) ===");
        println!(
            "Ingress: matched={} egr_sent={}",
            stats3.ingress.matched, stats3.ingress.egr_sent
        );

        println!("\n=== MCR-4 Results (Leaf 3) ===");
        println!(
            "Ingress: matched={} egr_sent={}",
            stats4.ingress.matched, stats4.ingress.egr_sent
        );

        // Validate MCR-1: Should replicate 1 → 3 (3x egress)
        assert!(stats1.ingress.matched > 0, "MCR-1 should match packets");

        // Critical assertion: egress should be ~3x ingress due to replication
        let expected_egress = stats1.ingress.matched * 3;
        let egress_tolerance = expected_egress / 10; // 10% tolerance
        assert!(
            stats1.egress.sent >= expected_egress - egress_tolerance
                && stats1.egress.sent <= expected_egress + egress_tolerance,
            "MCR-1 should send ~3x packets (matched={}, sent={}, expected={})",
            stats1.ingress.matched,
            stats1.egress.sent,
            expected_egress
        );

        // Each leaf should receive roughly equal share
        assert!(stats2.ingress.matched > 0, "MCR-2 should receive packets");
        assert!(stats3.ingress.matched > 0, "MCR-3 should receive packets");
        assert!(stats4.ingress.matched > 0, "MCR-4 should receive packets");

        // Allow small amount of filtered packets (stray multicast traffic)
        assert!(
            stats1.ingress.filtered < 100,
            "Too many filtered packets: {}",
            stats1.ingress.filtered
        );
        assert_eq!(stats1.egress.errors, 0);

        println!("\n=== ✅ Test passed: 1:3 fanout with head-end replication ===\n");
        Ok(())
    }
}
