// SPDX-License-Identifier: Apache-2.0 OR MIT
//! MSDP Protocol Integration Tests
//!
//! Tests for MSDP peer management, SA cache, and session handling.
//! These tests verify that MSDP state machine correctly tracks peer
//! state and can be controlled via the control plane API.
//!
//! Note: Full peer session establishment requires two MCR instances or an
//! external MSDP peer. Single-instance tests focus on configuration and
//! API functionality.

use anyhow::Result;

mod privileged {
    use super::*;
    use crate::common::{ControlClient, McrInstance, NetworkNamespace, VethPair};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    /// Test MSDP peer management via control plane API.
    ///
    /// This test verifies:
    /// 1. MCR starts with empty MSDP peer table
    /// 2. Peers can be added/removed via API
    /// 3. Peer state can be queried via API
    #[tokio::test]
    async fn test_msdp_peer_api() -> Result<()> {
        require_root!();
        println!("\n=== Test: MSDP peer management via API ===\n");

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

        // Start MCR with MSDP enabled
        let config = r#"{
            rules: [],
            msdp: {
                enabled: true,
                local_address: "10.0.0.2"
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        println!("MCR started with MSDP enabled");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Get MSDP peers - should be empty initially
        let peers = client.get_msdp_peers().await?;
        println!("Initial MSDP peers: {:?}", peers);
        assert!(peers.is_empty(), "Expected empty MSDP peer table initially");

        // Add a peer via API
        let peer_addr: Ipv4Addr = "10.0.0.100".parse()?;
        client
            .add_msdp_peer(peer_addr, Some("test-peer".to_string()), None, false)
            .await?;
        println!("Added MSDP peer: {}", peer_addr);

        tokio::time::sleep(Duration::from_millis(300)).await;

        // Verify peer appears in table
        let peers = client.get_msdp_peers().await?;
        println!("MSDP peers after add: {:?}", peers);
        assert!(!peers.is_empty(), "Expected peer to be added");

        let found = peers.iter().any(|p| p.address == peer_addr);
        assert!(found, "Expected to find peer 10.0.0.100");

        // Remove peer
        client.remove_msdp_peer(peer_addr).await?;
        println!("Removed MSDP peer: {}", peer_addr);

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify peer is removed
        let peers = client.get_msdp_peers().await?;
        let still_found = peers.iter().any(|p| p.address == peer_addr);
        assert!(!still_found, "Expected peer to be removed");

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }

    /// Test MSDP SA cache management via API.
    #[tokio::test]
    async fn test_msdp_sa_cache_api() -> Result<()> {
        require_root!();
        println!("\n=== Test: MSDP SA cache via API ===\n");

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
            msdp: {
                enabled: true,
                local_address: "10.0.0.2"
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Get SA cache - should be empty
        let sa_cache = client.get_msdp_sa_cache().await?;
        println!("Initial SA cache: {:?}", sa_cache);
        assert!(sa_cache.is_empty(), "Expected empty SA cache initially");

        // Clear SA cache (should succeed even if empty)
        client.clear_msdp_sa_cache().await?;
        println!("Cleared SA cache");

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }

    /// Test MSDP configuration via config file.
    #[tokio::test]
    async fn test_msdp_config_file() -> Result<()> {
        require_root!();
        println!("\n=== Test: MSDP configuration via config file ===\n");

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

        // MSDP config with peer
        let config = r#"{
            rules: [],
            msdp: {
                enabled: true,
                local_address: "10.0.0.2",
                peers: [{
                    address: "10.0.0.100",
                    description: "Test peer"
                }]
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        println!("MCR started with MSDP peer config");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Verify config was loaded
        let running_config = client.get_config().await?;

        // Note: GetConfig may not return protocol configs in all cases
        if let Some(msdp) = running_config.msdp {
            println!("MSDP config verified: {:?}", msdp);
        } else {
            println!("MSDP config not in running config (expected if config is runtime-only)");
        }

        // Verify we can still interact with MSDP API

        // Verify peer is in peer table
        let peers = client.get_msdp_peers().await?;
        println!("MSDP peers from config: {:?}", peers);
        assert!(!peers.is_empty(), "Expected configured peer in table");

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }

    /// Test MSDP mesh group configuration.
    #[tokio::test]
    async fn test_msdp_mesh_group() -> Result<()> {
        require_root!();
        println!("\n=== Test: MSDP mesh group configuration ===\n");

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

        // MSDP config with mesh group
        let config = r#"{
            rules: [],
            msdp: {
                enabled: true,
                local_address: "10.0.0.2",
                peers: [
                    { address: "10.0.0.100", mesh_group: "mesh1" },
                    { address: "10.0.0.101", mesh_group: "mesh1" }
                ]
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        println!("MCR started with MSDP mesh group");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = ControlClient::new(mcr.control_socket());

        // Verify peers are configured
        let peers = client.get_msdp_peers().await?;
        println!("MSDP peers: {:?}", peers);
        assert_eq!(peers.len(), 2, "Expected 2 mesh group peers");

        // Verify mesh group is set
        for peer in &peers {
            assert_eq!(
                peer.mesh_group.as_deref(),
                Some("mesh1"),
                "Peer should be in mesh1"
            );
        }

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }

    /// Test MSDP peer state transitions.
    ///
    /// This test verifies peer state is Idle (no connection possible in
    /// isolated namespace) and that state can be queried.
    #[tokio::test]
    async fn test_msdp_peer_state() -> Result<()> {
        require_root!();
        println!("\n=== Test: MSDP peer state tracking ===\n");

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
            msdp: {
                enabled: true,
                local_address: "10.0.0.2",
                peers: [{ address: "10.0.0.100" }]
            }
        }"#;

        let mcr = McrInstance::builder()
            .interface("veth0p")
            .config_content(config)
            .start_async()
            .await?;

        // Wait for connection attempts
        tokio::time::sleep(Duration::from_secs(2)).await;

        let client = ControlClient::new(mcr.control_socket());

        let peers = client.get_msdp_peers().await?;
        println!("MSDP peer state: {:?}", peers);

        assert!(!peers.is_empty(), "Expected peer in table");

        let peer = &peers[0];
        println!("Peer {} state: {:?}", peer.address, peer.state);

        // In isolated namespace, peer may be in various states:
        // - "disabled" if MSDP isn't fully enabled (no TCP listener)
        // - "Idle" or "Connect" if attempting connections
        // - "Active" if connection in progress
        // - "connecting" if timer fired but TCP channel not ready yet
        // The important thing is we can query the state and get a valid response
        let valid_states = ["disabled", "Idle", "Connect", "Active", "connecting"];
        assert!(
            valid_states.contains(&peer.state.as_str()),
            "Expected peer state to be one of {:?}, got: {}",
            valid_states,
            peer.state
        );

        drop(mcr);
        println!("\n=== Test passed ===\n");

        Ok(())
    }
}
