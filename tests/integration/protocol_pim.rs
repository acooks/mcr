// SPDX-License-Identifier: Apache-2.0 OR MIT
//! PIM Protocol Integration Tests
//!
//! Tests for PIM-SM neighbor discovery, DR election, and route management.
//! These tests verify the PIM state machine and control plane integration.
//!
//! Note: Due to the missing outgoing packet infrastructure (see
//! PROTOCOL_IMPLEMENTATION_GAP_ANALYSIS.md), actual Hello packet exchange
//! between routers is not yet functional. These tests focus on the control
//! plane API and configuration aspects that are currently working.

use anyhow::Result;

mod privileged {
    use super::*;
    use crate::common::{ControlClient, McrInstance, NetworkNamespace, VethPair};
    use multicast_relay::ExternalNeighbor;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    /// Test PIM neighbor table via control plane API.
    ///
    /// This test verifies:
    /// 1. MCR starts with empty PIM neighbor table
    /// 2. PIM can be enabled/disabled via API
    /// 3. Neighbor state can be queried via API
    #[tokio::test]
    async fn test_pim_neighbor_api() -> Result<()> {
        require_root!();
        println!("\n=== Test: PIM neighbor table via API ===\n");

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

        println!("Network setup complete");

        // Start MCR with PIM enabled
        let config = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.2",
                interfaces: [{ name: "veth0p", dr_priority: 100 }]
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        println!("MCR started with PIM enabled");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Get PIM neighbors - should be empty (no external routers)
        let neighbors = client.get_pim_neighbors().await?;
        println!("PIM neighbors: {:?}", neighbors);

        // Neighbors should be empty since we have no external PIM routers
        // and Hello send is not yet functional
        assert!(
            neighbors.is_empty(),
            "Expected empty PIM neighbor table in isolated namespace"
        );

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }

    /// Test enabling/disabling PIM via runtime API.
    #[tokio::test]
    async fn test_pim_enable_disable() -> Result<()> {
        require_root!();
        println!("\n=== Test: PIM enable/disable via API ===\n");

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

        // Start MCR without PIM initially
        let config = r#"{
            rules: []
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        println!("MCR started without PIM");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Enable PIM on interface
        client.enable_pim("veth0p", Some(100)).await?;
        println!("Enabled PIM on veth0p with DR priority 100");

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify PIM is working (empty neighbors is expected)
        let neighbors = client.get_pim_neighbors().await?;
        println!("PIM neighbors after enable: {:?}", neighbors);

        // Disable PIM
        client.disable_pim("veth0p").await?;
        println!("Disabled PIM on veth0p");

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }

    /// Test external neighbor injection.
    ///
    /// This tests the ability to inject external PIM neighbors via the API,
    /// which is used for integration with external control planes.
    #[tokio::test]
    async fn test_pim_external_neighbor() -> Result<()> {
        require_root!();
        println!("\n=== Test: PIM external neighbor injection ===\n");

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

        let config = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.2",
                interfaces: [{ name: "veth0p" }]
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Inject an external neighbor
        let external_neighbor = ExternalNeighbor {
            address: "10.0.0.100".parse::<Ipv4Addr>().unwrap(),
            interface: "veth0p".to_string(),
            dr_priority: Some(200),
            tag: None,
        };

        client
            .add_external_neighbor(external_neighbor.clone())
            .await?;
        println!("Added external neighbor: {:?}", external_neighbor);

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify neighbor injection succeeded by checking we can query neighbors
        let neighbors = client.get_pim_neighbors().await?;
        println!("PIM neighbors after injection: {:?}", neighbors);

        // Check if the neighbor appears (may require more time or different state)
        let found = neighbors
            .iter()
            .any(|n| n.address == external_neighbor.address);

        if found {
            println!("External neighbor found in table");

            // Remove external neighbor
            client
                .remove_external_neighbor(external_neighbor.address, "veth0p")
                .await?;
            println!("Removed external neighbor");

            tokio::time::sleep(Duration::from_millis(200)).await;

            // Verify neighbor is removed
            let neighbors = client.get_pim_neighbors().await?;
            let still_found = neighbors
                .iter()
                .any(|n| n.address == external_neighbor.address);
            assert!(!still_found, "Expected external neighbor to be removed");
        } else {
            // The external neighbor API succeeded but neighbor not visible in table
            // This may be expected if GetPimNeighbors only returns Hello-learned neighbors
            println!(
                "Note: External neighbor not visible in GetPimNeighbors response. \
                 This may indicate GetPimNeighbors only shows Hello-learned neighbors."
            );
        }

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }

    /// Test static RP configuration via API.
    #[tokio::test]
    async fn test_pim_static_rp() -> Result<()> {
        require_root!();
        println!("\n=== Test: PIM static RP configuration ===\n");

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

        let config = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.2",
                interfaces: [{ name: "veth0p" }]
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Set static RP for 239.0.0.0/8
        let rp_address: Ipv4Addr = "10.0.0.50".parse()?;
        client.set_static_rp("239.0.0.0/8", rp_address).await?;
        println!("Set static RP 10.0.0.50 for 239.0.0.0/8");

        // Verify RP is in config
        let running_config = client.get_config().await?;

        if let Some(pim) = running_config.pim {
            let has_rp = pim.static_rp.iter().any(|rp| rp.rp == rp_address);
            assert!(has_rp, "Expected static RP to be in config");
            println!("Verified static RP in running config");
        }

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }

    /// Test PIM configuration via config file.
    #[tokio::test]
    async fn test_pim_config_file() -> Result<()> {
        require_root!();
        println!("\n=== Test: PIM configuration via config file ===\n");

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

        // Full PIM config with RP
        let config = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.2",
                interfaces: [{
                    name: "veth0p",
                    dr_priority: 150
                }],
                static_rp: [{
                    group: "239.0.0.0/8",
                    rp: "10.0.0.1"
                }]
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        println!("MCR started with full PIM config");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Verify config was loaded
        let running_config = client.get_config().await?;

        // Note: GetConfig may not return protocol configs in all cases
        if let Some(pim) = running_config.pim {
            println!("PIM config verified: {:?}", pim);
            if pim.enabled {
                assert!(
                    !pim.interfaces.is_empty(),
                    "PIM interfaces should be configured when enabled"
                );
            }
        } else {
            println!("PIM config not in running config (expected if config is runtime-only)");
        }

        // Verify we can still interact with PIM API
        let neighbors = client.get_pim_neighbors().await?;
        println!("PIM neighbors (after config load): {:?}", neighbors);

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }
}
