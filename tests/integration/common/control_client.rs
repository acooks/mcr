// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control client for communicating with the MCR supervisor in tests.

use anyhow::Result;
use multicast_relay::config::Config;
use multicast_relay::{
    FlowStats, ForwardingRule, OutputDestination, Response, SupervisorCommand, WorkerInfo,
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
}
