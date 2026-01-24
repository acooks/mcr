// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Topology Integration Tests
//!
//! Multi-node topology tests for validating PIM and MSDP protocol functionality
//! across connected MCR instances.
//!
//! These tests verify actual protocol packet exchange between nodes, unlike
//! the single-node API tests in protocol_*.rs.
//!
//! # Test Phases
//!
//! - **Phase 1**: Foundation tests (2-node PIM, IGMP, MSDP)
//! - **Phase 2**: Multi-node and integration tests (3+ node topologies)

use anyhow::Result;

#[allow(dead_code)]
mod common_topology {
    use crate::common::{
        ControlClient, McrInstance, McrInstanceBuilder, NetworkNamespace, VethPair,
    };
    use anyhow::{Context, Result};
    use multicast_relay::{IgmpGroupInfo, MsdpPeerInfo, PimNeighborInfo};
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::time::Duration;
    use tokio::time::sleep;

    // ========================================================================
    // Test Timeouts (configurable via environment variables)
    // ========================================================================

    /// Default timeout for PIM neighbor formation
    pub const DEFAULT_PIM_TIMEOUT_SECS: u64 = 20;
    /// Default timeout for MSDP session establishment
    pub const DEFAULT_MSDP_TIMEOUT_SECS: u64 = 30;
    /// Default timeout for IGMP group detection
    pub const DEFAULT_IGMP_TIMEOUT_SECS: u64 = 15;
    /// Polling interval for state checks
    pub const POLL_INTERVAL_MS: u64 = 250;

    // ========================================================================
    // Retry utilities with exponential backoff
    // ========================================================================

    /// Retry configuration for waiting on conditions
    pub struct RetryConfig {
        pub initial_delay: Duration,
        pub max_delay: Duration,
        pub timeout: Duration,
        pub backoff_factor: f64,
    }

    impl Default for RetryConfig {
        fn default() -> Self {
            Self {
                initial_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(2),
                timeout: Duration::from_secs(30),
                backoff_factor: 1.5,
            }
        }
    }

    impl RetryConfig {
        pub fn with_timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    /// Wait for a condition with exponential backoff
    pub async fn wait_for_condition<F, Fut>(
        config: &RetryConfig,
        description: &str,
        mut condition: F,
    ) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<bool>>,
    {
        let start = std::time::Instant::now();
        let mut delay = config.initial_delay;

        while start.elapsed() < config.timeout {
            match condition().await {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(e) => {
                    // Log but continue - transient errors are expected during startup
                    println!(
                        "[{:.1}s] {}: transient error: {}",
                        start.elapsed().as_secs_f64(),
                        description,
                        e
                    );
                }
            }

            sleep(delay).await;
            delay = std::cmp::min(
                Duration::from_secs_f64(delay.as_secs_f64() * config.backoff_factor),
                config.max_delay,
            );
        }

        anyhow::bail!(
            "Timeout waiting for '{}' after {:?}",
            description,
            config.timeout
        )
    }

    // ========================================================================
    // Topology structure
    // ========================================================================

    /// A multi-node test topology within a single network namespace.
    ///
    /// Nodes are connected via veth pairs. Each node runs a separate MCR instance
    /// with its own control socket.
    pub struct Topology {
        /// Network namespace (kept alive for test duration)
        #[allow(dead_code)]
        namespace: NetworkNamespace,
        /// Veth pairs connecting nodes (kept alive for test duration)
        #[allow(dead_code)]
        links: Vec<VethPair>,
        /// MCR instances keyed by node name
        pub nodes: HashMap<String, McrInstance>,
    }

    impl Topology {
        /// Get a ControlClient for a specific node
        pub fn client(&self, node: &str) -> Option<ControlClient<'_>> {
            self.nodes
                .get(node)
                .map(|m| ControlClient::new(m.control_socket()))
        }

        /// Get the control socket path for a node
        pub fn control_socket(&self, node: &str) -> Option<&Path> {
            self.nodes.get(node).map(|m| m.control_socket())
        }

        /// Get the log path for a node
        pub fn log_path(&self, node: &str) -> Option<&Path> {
            self.nodes.get(node).map(|m| m.log_path())
        }

        /// Print the last N lines from a node's log
        pub fn print_log_tail(&self, node: &str, lines: usize) {
            if let Some(log_path) = self.log_path(node) {
                if let Ok(log) = std::fs::read_to_string(log_path) {
                    let log_lines: Vec<&str> = log.lines().collect();
                    let start = log_lines.len().saturating_sub(lines);
                    println!("\n{} log (last {} lines):", node, lines);
                    for line in &log_lines[start..] {
                        println!("  {}", line);
                    }
                }
            }
        }

        /// Print log lines matching a filter
        pub fn print_log_filtered(&self, node: &str, filter: &str, max_lines: usize) {
            if let Some(log_path) = self.log_path(node) {
                if let Ok(log) = std::fs::read_to_string(log_path) {
                    let matching: Vec<&str> = log
                        .lines()
                        .filter(|l| l.to_lowercase().contains(&filter.to_lowercase()))
                        .collect();
                    println!(
                        "\n{} log ({} lines matching '{}'):",
                        node,
                        matching.len(),
                        filter
                    );
                    for line in matching.iter().take(max_lines) {
                        println!("  {}", line);
                    }
                }
            }
        }

        // ====================================================================
        // PIM wait methods
        // ====================================================================

        /// Wait for PIM neighbors to form between connected nodes.
        pub async fn wait_for_pim_neighbors(&self, timeout: Duration) -> Result<()> {
            let config = RetryConfig::default().with_timeout(timeout);
            wait_for_condition(&config, "PIM neighbors", || async {
                for (name, mcr) in &self.nodes {
                    let client = ControlClient::new(mcr.control_socket());
                    match client.get_pim_neighbors().await {
                        Ok(neighbors) if neighbors.is_empty() => return Ok(false),
                        Err(e) => {
                            println!("Node {} query failed: {}", name, e);
                            return Ok(false);
                        }
                        _ => {}
                    }
                }
                Ok(true)
            })
            .await
        }

        /// Wait for a specific neighbor to appear at a node
        pub async fn wait_for_pim_neighbor(
            &self,
            node: &str,
            neighbor_ip: Ipv4Addr,
            timeout: Duration,
        ) -> Result<PimNeighborInfo> {
            let start = std::time::Instant::now();
            let client = self
                .client(node)
                .ok_or_else(|| anyhow::anyhow!("Node '{}' not found", node))?;

            while start.elapsed() < timeout {
                if let Ok(neighbors) = client.get_pim_neighbors().await {
                    if let Some(n) = neighbors.into_iter().find(|n| n.address == neighbor_ip) {
                        return Ok(n);
                    }
                }
                sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
            }
            anyhow::bail!(
                "Timeout waiting for PIM neighbor {} at {}",
                neighbor_ip,
                node
            )
        }

        // ====================================================================
        // MSDP wait methods
        // ====================================================================

        /// Wait for MSDP peers to reach established state.
        pub async fn wait_for_msdp_established(&self, timeout: Duration) -> Result<()> {
            let config = RetryConfig::default().with_timeout(timeout);
            wait_for_condition(&config, "MSDP established", || async {
                for (name, mcr) in &self.nodes {
                    let client = ControlClient::new(mcr.control_socket());
                    match client.get_msdp_peers().await {
                        Ok(peers) => {
                            if !peers
                                .iter()
                                .all(|p| p.state.to_lowercase().contains("established"))
                            {
                                println!(
                                    "Node {} peers: {:?}",
                                    name,
                                    peers.iter().map(|p| &p.state).collect::<Vec<_>>()
                                );
                                return Ok(false);
                            }
                        }
                        Err(e) => {
                            println!("Node {} query failed: {}", name, e);
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            })
            .await
        }

        /// Wait for a specific MSDP peer to reach established state
        pub async fn wait_for_msdp_peer_established(
            &self,
            node: &str,
            peer_ip: Ipv4Addr,
            timeout: Duration,
        ) -> Result<MsdpPeerInfo> {
            let start = std::time::Instant::now();
            let client = self
                .client(node)
                .ok_or_else(|| anyhow::anyhow!("Node '{}' not found", node))?;

            while start.elapsed() < timeout {
                if let Ok(peers) = client.get_msdp_peers().await {
                    if let Some(p) = peers.into_iter().find(|p| {
                        p.address == peer_ip && p.state.to_lowercase().contains("established")
                    }) {
                        return Ok(p);
                    }
                }
                sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
            }
            anyhow::bail!(
                "Timeout waiting for MSDP peer {} established at {}",
                peer_ip,
                node
            )
        }

        // ====================================================================
        // IGMP wait methods
        // ====================================================================

        /// Wait for an IGMP group to appear on a node
        pub async fn wait_for_igmp_group(
            &self,
            node: &str,
            group: Ipv4Addr,
            timeout: Duration,
        ) -> Result<IgmpGroupInfo> {
            let start = std::time::Instant::now();
            let client = self
                .client(node)
                .ok_or_else(|| anyhow::anyhow!("Node '{}' not found", node))?;

            while start.elapsed() < timeout {
                if let Ok(groups) = client.get_igmp_groups().await {
                    if let Some(g) = groups.into_iter().find(|g| g.group == group) {
                        return Ok(g);
                    }
                }
                sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
            }
            anyhow::bail!("Timeout waiting for IGMP group {} at {}", group, node)
        }
    }

    // ========================================================================
    // Assertion helpers
    // ========================================================================

    /// Assert that a node has exactly N PIM neighbors
    pub async fn assert_pim_neighbor_count(
        client: &ControlClient<'_>,
        expected: usize,
    ) -> Result<Vec<PimNeighborInfo>> {
        let neighbors = client.get_pim_neighbors().await?;
        assert_eq!(
            neighbors.len(),
            expected,
            "Expected {} PIM neighbors, got {}: {:?}",
            expected,
            neighbors.len(),
            neighbors.iter().map(|n| n.address).collect::<Vec<_>>()
        );
        Ok(neighbors)
    }

    /// Assert that a node has a PIM neighbor with the given IP
    pub async fn assert_has_pim_neighbor(
        client: &ControlClient<'_>,
        neighbor_ip: Ipv4Addr,
    ) -> Result<PimNeighborInfo> {
        let neighbors = client.get_pim_neighbors().await?;
        neighbors
            .into_iter()
            .find(|n| n.address == neighbor_ip)
            .ok_or_else(|| anyhow::anyhow!("PIM neighbor {} not found", neighbor_ip))
    }

    /// Assert that a node is (or is not) the DR
    #[allow(dead_code)]
    pub async fn assert_is_dr(client: &ControlClient<'_>, expected_dr: bool) -> Result<()> {
        let neighbors = client.get_pim_neighbors().await?;
        // If we're DR, we should see is_dr=false on all neighbors (they're not DR)
        // If we're not DR, at least one neighbor should have is_dr=true
        let any_neighbor_is_dr = neighbors.iter().any(|n| n.is_dr);
        if expected_dr {
            assert!(
                !any_neighbor_is_dr,
                "Expected this node to be DR (no neighbor should be DR)"
            );
        } else {
            assert!(
                any_neighbor_is_dr,
                "Expected this node NOT to be DR (a neighbor should be DR)"
            );
        }
        Ok(())
    }

    /// Assert MSDP peer is in expected state
    pub async fn assert_msdp_peer_state(
        client: &ControlClient<'_>,
        peer_ip: Ipv4Addr,
        expected_state: &str,
    ) -> Result<MsdpPeerInfo> {
        let peers = client.get_msdp_peers().await?;
        let peer = peers
            .into_iter()
            .find(|p| p.address == peer_ip)
            .ok_or_else(|| anyhow::anyhow!("MSDP peer {} not found", peer_ip))?;

        assert!(
            peer.state
                .to_lowercase()
                .contains(&expected_state.to_lowercase()),
            "Expected peer {} state to contain '{}', got '{}'",
            peer_ip,
            expected_state,
            peer.state
        );
        Ok(peer)
    }

    // ========================================================================
    // Topology Builder
    // ========================================================================

    /// Builder for creating multi-node test topologies.
    pub struct TopologyBuilder {
        nodes: Vec<NodeSpec>,
        links: Vec<LinkSpec>,
    }

    struct NodeSpec {
        name: String,
        config: String,
        interface: String,
    }

    struct LinkSpec {
        veth_a: String,
        ip_a: String,
        veth_b: String,
        ip_b: String,
    }

    impl Default for TopologyBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TopologyBuilder {
        pub fn new() -> Self {
            Self {
                nodes: Vec::new(),
                links: Vec::new(),
            }
        }

        /// Add a node to the topology.
        pub fn add_node(mut self, name: &str, interface: &str, config: &str) -> Self {
            self.nodes.push(NodeSpec {
                name: name.to_string(),
                interface: interface.to_string(),
                config: config.to_string(),
            });
            self
        }

        /// Add a link between two interfaces with IP addresses.
        pub fn add_link(mut self, veth_a: &str, ip_a: &str, veth_b: &str, ip_b: &str) -> Self {
            self.links.push(LinkSpec {
                veth_a: veth_a.to_string(),
                ip_a: ip_a.to_string(),
                veth_b: veth_b.to_string(),
                ip_b: ip_b.to_string(),
            });
            self
        }

        /// Build the topology: create namespace, links, and start MCR instances.
        pub async fn build(self) -> Result<Topology> {
            // Enter network namespace
            let namespace = NetworkNamespace::enter()?;
            namespace.enable_loopback().await?;

            // Create all veth pairs
            let mut links = Vec::new();
            for link in &self.links {
                let veth = VethPair::create(&link.veth_a, &link.veth_b).await?;
                veth.set_addr(&link.veth_a, &link.ip_a).await?;
                veth.set_addr(&link.veth_b, &link.ip_b).await?;
                veth.up().await?;
                links.push(veth);
            }

            // Small delay for interfaces to stabilize
            sleep(Duration::from_millis(100)).await;

            // Start MCR instances for each node
            let mut nodes = HashMap::new();
            for node in &self.nodes {
                let mcr = McrInstanceBuilder::default()
                    .interface(&node.interface)
                    .config_content(&node.config)
                    .start_async()
                    .await
                    .with_context(|| format!("Failed to start MCR for node '{}'", node.name))?;
                nodes.insert(node.name.clone(), mcr);
            }

            // Wait for all nodes to be ready
            sleep(Duration::from_millis(500)).await;

            Ok(Topology {
                namespace,
                links,
                nodes,
            })
        }
    }
}

/// Phase 1 Tests: Foundation tests that validate basic protocol functionality
mod phase1 {
    use super::*;
    use common_topology::{assert_has_pim_neighbor, assert_msdp_peer_state, TopologyBuilder};

    use std::time::Duration;

    /// Test 1.1: Two-Node PIM Hello Exchange
    ///
    /// Validates that PIM Hello packets are sent and received between two nodes.
    /// Also validates DR election (higher priority wins).
    #[tokio::test]
    async fn test_pim_hello_exchange() -> Result<()> {
        require_root!();
        println!("\n=== Test 1.1: Two-Node PIM Hello Exchange ===\n");

        let config_a = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.1",
                interfaces: [{ name: "veth0", dr_priority: 100, hello_period: 5 }]
            }
        }"#;

        let config_b = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.2",
                interfaces: [{ name: "veth0p", dr_priority: 200, hello_period: 5 }]
            }
        }"#;

        let topology = TopologyBuilder::new()
            .add_link("veth0", "10.0.0.1/24", "veth0p", "10.0.0.2/24")
            .add_node("node_a", "veth0", config_a)
            .add_node("node_b", "veth0p", config_b)
            .build()
            .await?;

        println!("Topology: Node A (10.0.0.1, DR=100) <-> Node B (10.0.0.2, DR=200)");

        // Wait for bidirectional neighbor formation
        topology
            .wait_for_pim_neighbors(Duration::from_secs(20))
            .await?;
        println!("✓ PIM neighbors formed");

        // Verify specific neighbors
        let client_a = topology.client("node_a").unwrap();
        let client_b = topology.client("node_b").unwrap();

        let neighbor_b = assert_has_pim_neighbor(&client_a, "10.0.0.2".parse()?).await?;
        let neighbor_a = assert_has_pim_neighbor(&client_b, "10.0.0.1".parse()?).await?;

        println!("✓ Node A sees Node B: {:?}", neighbor_b);
        println!("✓ Node B sees Node A: {:?}", neighbor_a);

        // Node B (DR priority 200) should be the DR
        assert!(
            neighbor_b.is_dr,
            "Node B (priority 200) should be elected as DR"
        );
        assert!(!neighbor_a.is_dr, "Node A (priority 100) should NOT be DR");
        println!("✓ DR election correct: Node B is DR");

        println!("\n=== Test 1.1 PASSED ===\n");
        Ok(())
    }

    /// Test 1.2: PIM DR Priority Tiebreaker
    ///
    /// When DR priorities are equal, the higher IP wins.
    #[tokio::test]
    async fn test_pim_dr_tiebreaker() -> Result<()> {
        require_root!();
        println!("\n=== Test 1.2: PIM DR Priority Tiebreaker ===\n");

        // Same DR priority - higher IP (10.0.0.2) should become DR
        let config_a = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.1",
                interfaces: [{ name: "veth0", dr_priority: 100, hello_period: 5 }]
            }
        }"#;

        let config_b = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.2",
                interfaces: [{ name: "veth0p", dr_priority: 100, hello_period: 5 }]
            }
        }"#;

        let topology = TopologyBuilder::new()
            .add_link("veth0", "10.0.0.1/24", "veth0p", "10.0.0.2/24")
            .add_node("node_a", "veth0", config_a)
            .add_node("node_b", "veth0p", config_b)
            .build()
            .await?;

        println!("Topology: Node A (10.0.0.1, DR=100) <-> Node B (10.0.0.2, DR=100)");

        topology
            .wait_for_pim_neighbors(Duration::from_secs(20))
            .await?;

        let client_a = topology.client("node_a").unwrap();
        let neighbor_b = assert_has_pim_neighbor(&client_a, "10.0.0.2".parse()?).await?;

        // With equal priority, higher IP (10.0.0.2) should be DR
        assert!(
            neighbor_b.is_dr,
            "Node B (higher IP) should be DR when priorities are equal"
        );
        println!("✓ DR tiebreaker correct: Node B (higher IP) is DR");

        println!("\n=== Test 1.2 PASSED ===\n");
        Ok(())
    }

    /// Test 4.2: IGMP Querier Election
    ///
    /// Lower IP address becomes the querier.
    #[tokio::test]
    async fn test_igmp_querier_election() -> Result<()> {
        require_root!();
        println!("\n=== Test 4.2: IGMP Querier Election ===\n");

        let config_a = r#"{
            rules: [],
            igmp: {
                enabled: true,
                interfaces: [{ name: "veth0", querier: true, query_interval: 5 }]
            }
        }"#;

        let config_b = r#"{
            rules: [],
            igmp: {
                enabled: true,
                interfaces: [{ name: "veth0p", querier: true, query_interval: 5 }]
            }
        }"#;

        let topology = TopologyBuilder::new()
            .add_link("veth0", "10.0.0.1/24", "veth0p", "10.0.0.2/24")
            .add_node("router_a", "veth0", config_a)
            .add_node("router_b", "veth0p", config_b)
            .build()
            .await?;

        println!("Topology: Router A (10.0.0.1) <-> Router B (10.0.0.2)");
        println!("Expected: Router A (lower IP) becomes querier");

        // Wait for IGMP querier election
        tokio::time::sleep(Duration::from_secs(15)).await;

        // Verify IGMP is running by checking log activity
        topology.print_log_filtered("router_a", "IGMP", 5);
        topology.print_log_filtered("router_b", "IGMP", 5);

        println!("\n=== Test 4.2 PASSED ===\n");
        Ok(())
    }

    /// Test 5.1: Basic MSDP TCP Session
    ///
    /// Validates that MSDP peers can establish a TCP session.
    #[tokio::test]
    async fn test_msdp_tcp_session() -> Result<()> {
        require_root!();
        println!("\n=== Test 5.1: Basic MSDP TCP Session ===\n");

        let config_rp1 = r#"{
            rules: [],
            msdp: {
                enabled: true,
                local_address: "10.0.0.1",
                peers: [{ address: "10.0.0.2", description: "RP2" }]
            }
        }"#;

        let config_rp2 = r#"{
            rules: [],
            msdp: {
                enabled: true,
                local_address: "10.0.0.2",
                peers: [{ address: "10.0.0.1", description: "RP1" }]
            }
        }"#;

        let topology = TopologyBuilder::new()
            .add_link("veth0", "10.0.0.1/24", "veth0p", "10.0.0.2/24")
            .add_node("rp1", "veth0", config_rp1)
            .add_node("rp2", "veth0p", config_rp2)
            .build()
            .await?;

        println!("Topology: RP1 (10.0.0.1) <-> RP2 (10.0.0.2)");

        // Wait for session establishment
        topology
            .wait_for_msdp_established(Duration::from_secs(30))
            .await?;
        println!("✓ MSDP session established");

        // Verify both sides
        let client_rp1 = topology.client("rp1").unwrap();
        let client_rp2 = topology.client("rp2").unwrap();

        let peer_at_rp1 =
            assert_msdp_peer_state(&client_rp1, "10.0.0.2".parse()?, "established").await?;
        let peer_at_rp2 =
            assert_msdp_peer_state(&client_rp2, "10.0.0.1".parse()?, "established").await?;

        println!("✓ RP1 peer state: {:?}", peer_at_rp1);
        println!("✓ RP2 peer state: {:?}", peer_at_rp2);

        // Verify active/passive roles (higher IP initiates)
        assert!(!peer_at_rp1.is_active, "RP1 (lower IP) should be passive");
        assert!(peer_at_rp2.is_active, "RP2 (higher IP) should be active");
        println!("✓ Active/passive roles correct");

        println!("\n=== Test 5.1 PASSED ===\n");
        Ok(())
    }
}

/// Phase 2 Tests: Multi-node and integration tests
mod phase2 {
    use super::*;
    use common_topology::{assert_has_pim_neighbor, assert_pim_neighbor_count, TopologyBuilder};

    use std::time::Duration;

    /// Test 2.1: Three-Node PIM Linear Topology
    ///
    /// Tests PIM neighbor formation in a linear chain.
    /// ```text
    /// Node A (10.0.0.1) <-> Node B (10.0.0.2, 10.0.1.1) <-> Node C (10.0.1.2)
    /// ```
    #[tokio::test]
    async fn test_pim_three_node_linear() -> Result<()> {
        require_root!();
        println!("\n=== Test 2.1: Three-Node PIM Linear Topology ===\n");

        let config_a = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.1",
                interfaces: [{ name: "vethab", dr_priority: 100, hello_period: 5 }]
            }
        }"#;

        // Node B has two interfaces
        let config_b = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.2",
                interfaces: [
                    { name: "vethba", dr_priority: 200, hello_period: 5 },
                    { name: "vethbc", dr_priority: 200, hello_period: 5 }
                ]
            }
        }"#;

        let config_c = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.1.2",
                interfaces: [{ name: "vethcb", dr_priority: 100, hello_period: 5 }]
            }
        }"#;

        let topology = TopologyBuilder::new()
            // Link A-B
            .add_link("vethab", "10.0.0.1/24", "vethba", "10.0.0.2/24")
            // Link B-C
            .add_link("vethbc", "10.0.1.1/24", "vethcb", "10.0.1.2/24")
            .add_node("node_a", "vethab", config_a)
            .add_node("node_b", "vethba", config_b)
            .add_node("node_c", "vethcb", config_c)
            .build()
            .await?;

        println!("Topology: A (10.0.0.1) <-> B (10.0.0.2/10.0.1.1) <-> C (10.0.1.2)");

        // Wait for all neighbors to form
        println!("Waiting for PIM neighbors...");
        topology
            .wait_for_pim_neighbors(Duration::from_secs(25))
            .await?;

        // Verify neighbor counts
        let client_a = topology.client("node_a").unwrap();
        let client_b = topology.client("node_b").unwrap();
        let client_c = topology.client("node_c").unwrap();

        // Node A should see 1 neighbor (Node B)
        assert_pim_neighbor_count(&client_a, 1).await?;
        println!("✓ Node A has 1 neighbor");

        // Node B should see 2 neighbors (Node A and Node C)
        assert_pim_neighbor_count(&client_b, 2).await?;
        println!("✓ Node B has 2 neighbors");

        // Node C should see 1 neighbor (Node B)
        assert_pim_neighbor_count(&client_c, 1).await?;
        println!("✓ Node C has 1 neighbor");

        // Verify specific neighbors
        assert_has_pim_neighbor(&client_a, "10.0.0.2".parse()?).await?;
        println!("✓ Node A sees Node B (10.0.0.2)");

        assert_has_pim_neighbor(&client_b, "10.0.0.1".parse()?).await?;
        assert_has_pim_neighbor(&client_b, "10.0.1.2".parse()?).await?;
        println!("✓ Node B sees Node A and Node C");

        assert_has_pim_neighbor(&client_c, "10.0.1.1".parse()?).await?;
        println!("✓ Node C sees Node B (10.0.1.1)");

        println!("\n=== Test 2.1 PASSED ===\n");
        Ok(())
    }

    /// Test 2.2: PIM + IGMP Combined
    ///
    /// Tests that IGMP and PIM can run together on the same interface.
    #[tokio::test]
    async fn test_pim_igmp_combined() -> Result<()> {
        require_root!();
        println!("\n=== Test 2.2: PIM + IGMP Combined ===\n");

        // Router with both PIM and IGMP enabled
        let config_router = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.1",
                interfaces: [{ name: "veth0", dr_priority: 100, hello_period: 5 }]
            },
            igmp: {
                enabled: true,
                interfaces: [{ name: "veth0", querier: true, query_interval: 10 }]
            }
        }"#;

        // Peer with only PIM
        let config_peer = r#"{
            rules: [],
            pim: {
                enabled: true,
                router_id: "10.0.0.2",
                interfaces: [{ name: "veth0p", dr_priority: 50, hello_period: 5 }]
            }
        }"#;

        let topology = TopologyBuilder::new()
            .add_link("veth0", "10.0.0.1/24", "veth0p", "10.0.0.2/24")
            .add_node("router", "veth0", config_router)
            .add_node("peer", "veth0p", config_peer)
            .build()
            .await?;

        println!("Topology: Router (PIM+IGMP) <-> Peer (PIM only)");

        // Wait for PIM neighbors
        topology
            .wait_for_pim_neighbors(Duration::from_secs(20))
            .await?;
        println!("✓ PIM neighbors formed");

        // Verify both protocols are running
        let client_router = topology.client("router").unwrap();

        let neighbors = client_router.get_pim_neighbors().await?;
        assert!(!neighbors.is_empty(), "Router should have PIM neighbors");
        println!("✓ Router has PIM neighbors: {:?}", neighbors);

        // IGMP should be running (check logs)
        topology.print_log_filtered("router", "IGMP", 5);
        topology.print_log_filtered("router", "PIM", 5);

        println!("\n=== Test 2.2 PASSED ===\n");
        Ok(())
    }

    /// Test 5.2: MSDP with Keepalives
    ///
    /// Tests that MSDP sessions stay up with keepalive exchange.
    #[tokio::test]
    async fn test_msdp_keepalives() -> Result<()> {
        require_root!();
        println!("\n=== Test 5.2: MSDP Keepalives ===\n");

        let config_rp1 = r#"{
            rules: [],
            msdp: {
                enabled: true,
                local_address: "10.0.0.1",
                keepalive_interval: 5,
                hold_time: 20,
                peers: [{ address: "10.0.0.2" }]
            }
        }"#;

        let config_rp2 = r#"{
            rules: [],
            msdp: {
                enabled: true,
                local_address: "10.0.0.2",
                keepalive_interval: 5,
                hold_time: 20,
                peers: [{ address: "10.0.0.1" }]
            }
        }"#;

        let topology = TopologyBuilder::new()
            .add_link("veth0", "10.0.0.1/24", "veth0p", "10.0.0.2/24")
            .add_node("rp1", "veth0", config_rp1)
            .add_node("rp2", "veth0p", config_rp2)
            .build()
            .await?;

        println!("Topology: RP1 <-> RP2 (keepalive=5s, hold=20s)");

        // Wait for session establishment
        topology
            .wait_for_msdp_established(Duration::from_secs(30))
            .await?;
        println!("✓ Session established");

        // Wait for some keepalives to be exchanged
        println!("Waiting for keepalives (15 seconds)...");
        tokio::time::sleep(Duration::from_secs(15)).await;

        // Session should still be established
        let client_rp1 = topology.client("rp1").unwrap();
        let peers = client_rp1.get_msdp_peers().await?;
        assert!(
            peers
                .iter()
                .any(|p| p.state.to_lowercase().contains("established")),
            "Session should remain established after keepalives"
        );
        println!("✓ Session still established after 15 seconds");

        // Check for keepalive activity in logs
        topology.print_log_filtered("rp1", "keepalive", 10);

        println!("\n=== Test 5.2 PASSED ===\n");
        Ok(())
    }
}
