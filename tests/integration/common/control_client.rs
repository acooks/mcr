// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control client for communicating with the MCR supervisor in tests.

use anyhow::Result;
use multicast_relay::config::Config;
use multicast_relay::{
    ExternalNeighbor, FlowStats, ForwardingRule, IgmpGroupInfo, MrouteEntry, MsdpPeerInfo,
    MsdpSaCacheInfo, OutputDestination, PimNeighborInfo, Response, SupervisorCommand, WorkerInfo,
};
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// A client for interacting with the supervisor's control socket in tests.
pub struct ControlClient<'a> {
    socket_path: &'a Path,
}

impl<'a> ControlClient<'a> {
    /// Create a new control client connected to the given socket path
    pub fn new(socket_path: &'a Path) -> Self {
        Self { socket_path }
    }

    /// Send a command to the supervisor and get the response
    pub async fn send_command(&self, command: SupervisorCommand) -> Result<Response> {
        let mut stream = UnixStream::connect(self.socket_path).await?;
        let command_bytes = serde_json::to_vec(&command)?;
        stream.write_all(&command_bytes).await?;
        stream.shutdown().await?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await?;

        let response: Response = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    /// List all workers
    pub async fn list_workers(&self) -> Result<Vec<WorkerInfo>> {
        match self.send_command(SupervisorCommand::ListWorkers).await? {
            Response::Workers(workers) => Ok(workers),
            Response::Error(e) => anyhow::bail!("Failed to list workers: {}", e),
            other => anyhow::bail!("Unexpected response for ListWorkers: {:?}", other),
        }
    }

    /// List all rules
    pub async fn list_rules(&self) -> Result<Vec<ForwardingRule>> {
        match self.send_command(SupervisorCommand::ListRules).await? {
            Response::Rules(rules) => Ok(rules),
            Response::Error(e) => anyhow::bail!("Failed to list rules: {}", e),
            other => anyhow::bail!("Unexpected response for ListRules: {:?}", other),
        }
    }

    /// Add a rule with optional name
    pub async fn add_rule_with_name(
        &self,
        rule_id: String,
        name: Option<String>,
        input_interface: String,
        input_group: Ipv4Addr,
        input_port: u16,
        outputs: Vec<OutputDestination>,
    ) -> Result<String> {
        match self
            .send_command(SupervisorCommand::AddRule {
                rule_id: rule_id.clone(),
                name,
                input_interface,
                input_group,
                input_port,
                outputs,
            })
            .await?
        {
            Response::Success(_) => Ok(rule_id),
            Response::Error(e) => anyhow::bail!("Failed to add rule: {}", e),
            other => anyhow::bail!("Unexpected response for AddRule: {:?}", other),
        }
    }

    /// Add a rule from a ForwardingRule struct (without name)
    pub async fn add_rule(&self, rule: ForwardingRule) -> Result<String> {
        self.add_rule_with_name(
            rule.rule_id.clone(),
            None,
            rule.input_interface,
            rule.input_group,
            rule.input_port,
            rule.outputs,
        )
        .await
    }

    /// Remove a rule by ID
    pub async fn remove_rule(&self, rule_id: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::RemoveRule {
                rule_id: rule_id.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to remove rule: {}", e),
            other => anyhow::bail!("Unexpected response for RemoveRule: {:?}", other),
        }
    }

    /// Remove a rule by name
    pub async fn remove_rule_by_name(&self, name: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::RemoveRuleByName {
                name: name.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to remove rule by name: {}", e),
            other => anyhow::bail!("Unexpected response for RemoveRuleByName: {:?}", other),
        }
    }

    /// Get stats for all flows
    pub async fn get_stats(&self) -> Result<Vec<FlowStats>> {
        match self.send_command(SupervisorCommand::GetStats).await? {
            Response::Stats(stats) => Ok(stats),
            Response::Error(e) => anyhow::bail!("Failed to get stats: {}", e),
            other => anyhow::bail!("Unexpected response for GetStats: {:?}", other),
        }
    }

    /// Get the current config
    pub async fn get_config(&self) -> Result<Config> {
        match self.send_command(SupervisorCommand::GetConfig).await? {
            Response::Config(config) => Ok(config),
            Response::Error(e) => anyhow::bail!("Failed to get config: {}", e),
            other => anyhow::bail!("Unexpected response for GetConfig: {:?}", other),
        }
    }

    // --- IGMP Methods ---

    /// Get IGMP group membership
    pub async fn get_igmp_groups(&self) -> Result<Vec<IgmpGroupInfo>> {
        match self.send_command(SupervisorCommand::GetIgmpGroups).await? {
            Response::IgmpGroups(groups) => Ok(groups),
            Response::Error(e) => anyhow::bail!("Failed to get IGMP groups: {}", e),
            other => anyhow::bail!("Unexpected response for GetIgmpGroups: {:?}", other),
        }
    }

    /// Enable IGMP querier on an interface
    pub async fn enable_igmp_querier(&self, interface: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::EnableIgmpQuerier {
                interface: interface.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to enable IGMP querier: {}", e),
            other => anyhow::bail!("Unexpected response for EnableIgmpQuerier: {:?}", other),
        }
    }

    /// Disable IGMP querier on an interface
    pub async fn disable_igmp_querier(&self, interface: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::DisableIgmpQuerier {
                interface: interface.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to disable IGMP querier: {}", e),
            other => anyhow::bail!("Unexpected response for DisableIgmpQuerier: {:?}", other),
        }
    }

    // --- PIM Methods ---

    /// Get PIM neighbors
    pub async fn get_pim_neighbors(&self) -> Result<Vec<PimNeighborInfo>> {
        match self
            .send_command(SupervisorCommand::GetPimNeighbors)
            .await?
        {
            Response::PimNeighbors(neighbors) => Ok(neighbors),
            Response::Error(e) => anyhow::bail!("Failed to get PIM neighbors: {}", e),
            other => anyhow::bail!("Unexpected response for GetPimNeighbors: {:?}", other),
        }
    }

    /// Enable PIM on an interface
    pub async fn enable_pim(&self, interface: &str, dr_priority: Option<u32>) -> Result<()> {
        match self
            .send_command(SupervisorCommand::EnablePim {
                interface: interface.to_string(),
                dr_priority,
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to enable PIM: {}", e),
            other => anyhow::bail!("Unexpected response for EnablePim: {:?}", other),
        }
    }

    /// Disable PIM on an interface
    pub async fn disable_pim(&self, interface: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::DisablePim {
                interface: interface.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to disable PIM: {}", e),
            other => anyhow::bail!("Unexpected response for DisablePim: {:?}", other),
        }
    }

    /// Set a static RP mapping
    pub async fn set_static_rp(&self, group_prefix: &str, rp_address: Ipv4Addr) -> Result<()> {
        match self
            .send_command(SupervisorCommand::SetStaticRp {
                group_prefix: group_prefix.to_string(),
                rp_address,
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to set static RP: {}", e),
            other => anyhow::bail!("Unexpected response for SetStaticRp: {:?}", other),
        }
    }

    /// Add an external PIM neighbor
    pub async fn add_external_neighbor(&self, neighbor: ExternalNeighbor) -> Result<()> {
        match self
            .send_command(SupervisorCommand::AddExternalNeighbor { neighbor })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to add external neighbor: {}", e),
            other => anyhow::bail!("Unexpected response for AddExternalNeighbor: {:?}", other),
        }
    }

    /// Remove an external PIM neighbor
    pub async fn remove_external_neighbor(&self, address: Ipv4Addr, interface: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::RemoveExternalNeighbor {
                address,
                interface: interface.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to remove external neighbor: {}", e),
            other => anyhow::bail!(
                "Unexpected response for RemoveExternalNeighbor: {:?}",
                other
            ),
        }
    }

    // --- MSDP Methods ---

    /// Get MSDP peers
    pub async fn get_msdp_peers(&self) -> Result<Vec<MsdpPeerInfo>> {
        match self.send_command(SupervisorCommand::GetMsdpPeers).await? {
            Response::MsdpPeers(peers) => Ok(peers),
            Response::Error(e) => anyhow::bail!("Failed to get MSDP peers: {}", e),
            other => anyhow::bail!("Unexpected response for GetMsdpPeers: {:?}", other),
        }
    }

    /// Get MSDP SA cache
    pub async fn get_msdp_sa_cache(&self) -> Result<Vec<MsdpSaCacheInfo>> {
        match self.send_command(SupervisorCommand::GetMsdpSaCache).await? {
            Response::MsdpSaCache(cache) => Ok(cache),
            Response::Error(e) => anyhow::bail!("Failed to get MSDP SA cache: {}", e),
            other => anyhow::bail!("Unexpected response for GetMsdpSaCache: {:?}", other),
        }
    }

    /// Add an MSDP peer
    pub async fn add_msdp_peer(
        &self,
        address: Ipv4Addr,
        description: Option<String>,
        mesh_group: Option<String>,
        default_peer: bool,
    ) -> Result<()> {
        match self
            .send_command(SupervisorCommand::AddMsdpPeer {
                address,
                description,
                mesh_group,
                default_peer,
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to add MSDP peer: {}", e),
            other => anyhow::bail!("Unexpected response for AddMsdpPeer: {:?}", other),
        }
    }

    /// Remove an MSDP peer
    pub async fn remove_msdp_peer(&self, address: Ipv4Addr) -> Result<()> {
        match self
            .send_command(SupervisorCommand::RemoveMsdpPeer { address })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to remove MSDP peer: {}", e),
            other => anyhow::bail!("Unexpected response for RemoveMsdpPeer: {:?}", other),
        }
    }

    /// Clear MSDP SA cache
    pub async fn clear_msdp_sa_cache(&self) -> Result<()> {
        match self
            .send_command(SupervisorCommand::ClearMsdpSaCache)
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to clear MSDP SA cache: {}", e),
            other => anyhow::bail!("Unexpected response for ClearMsdpSaCache: {:?}", other),
        }
    }

    /// Get multicast routing table entries
    pub async fn get_mroute(&self) -> Result<Vec<MrouteEntry>> {
        match self.send_command(SupervisorCommand::GetMroute).await? {
            Response::Mroute(entries) => Ok(entries),
            Response::Error(e) => anyhow::bail!("Failed to get mroute: {}", e),
            other => anyhow::bail!("Unexpected response for GetMroute: {:?}", other),
        }
    }
}
