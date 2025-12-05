// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Scaling tests - verify 1:1 forwarding at multiple packet counts
//!
//! Run with: sudo -E cargo test --release --test integration -- --test-threads=1
//!
//! Tests require:
//! - Root privileges (for network namespaces) - enforced by require_root!
//! - Release binaries built: cargo build --release --bins
//! - Single-threaded execution (network namespaces can conflict)

use anyhow::Result;

mod privileged {
    use super::*;
    use crate::common::{McrInstance, NetworkNamespace, VethPair};
    use std::thread;
    use std::time::Duration;

    /// Configuration for a scaling test
    struct ScalingTestConfig {
        name: &'static str,
        packet_count: u32,
        rate_pps: u32,
        drain_secs: u64,
    }

    /// Run a scaling test with the given configuration
    async fn run_scaling_test(config: ScalingTestConfig) -> Result<()> {
        println!("\n=== Scaling Test: {} ===\n", config.name);

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

        crate::common::traffic::send_packets_with_options(
            "10.0.0.1",
            "239.1.1.1",
            5001,
            config.packet_count,
            1400,
            config.rate_pps,
        )?;

        println!("Waiting for pipeline to drain...");
        thread::sleep(Duration::from_secs(config.drain_secs));

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
        assert!(
            stats.ingress.matched > 0,
            "Should forward some packets (got 0 matched)"
        );
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
    async fn test_scale_1000_packets() -> Result<()> {
        require_root!();
        run_scaling_test(ScalingTestConfig {
            name: "1,000 packets",
            packet_count: 1_000,
            rate_pps: 1_000,
            drain_secs: 3,
        })
        .await
    }

    #[tokio::test]
    async fn test_scale_10000_packets() -> Result<()> {
        require_root!();
        run_scaling_test(ScalingTestConfig {
            name: "10,000 packets",
            packet_count: 10_000,
            rate_pps: 10_000,
            drain_secs: 4,
        })
        .await
    }

    #[tokio::test]
    async fn test_scale_1m_packets() -> Result<()> {
        require_root!();
        run_scaling_test(ScalingTestConfig {
            name: "1,000,000 packets",
            packet_count: 1_000_000,
            rate_pps: 50_000,
            drain_secs: 25,
        })
        .await
    }
}
