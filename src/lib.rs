// SPDX-License-Identifier: Apache-2.0 OR MIT
use clap::Parser;
pub mod logging;

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use uuid::Uuid;

/// Protocol version for supervisor-client communication.
/// Increment when making breaking changes to SupervisorCommand or Response.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct WorkerInfo {
    pub pid: u32,
    pub worker_type: String,
    pub core_id: Option<u32>,
}

pub mod supervisor;
pub mod worker;

#[derive(Parser, Debug, PartialEq, serde::Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Parser, Debug, PartialEq, serde::Deserialize)]
pub enum Command {
    /// Run the supervisor process
    Supervisor {
        /// Path to the Unix socket for worker command and control.
        #[clap(long, default_value = "/tmp/mcr_relay_commands.sock")]
        relay_command_socket_path: PathBuf,

        /// Path to the Unix socket for client command and control.
        #[clap(long, default_value = "/tmp/multicast_relay_control.sock")]
        control_socket_path: PathBuf,

        /// Network interface for data plane workers to listen on.
        /// This is required for PACKET_FANOUT_CPU: all workers must bind to the same interface
        /// with a shared fanout_group_id, allowing the kernel to distribute packets to the
        /// worker running on the CPU that received the packet (for optimal cache locality).
        /// Note: ForwardingRule.input_interface serves a different purpose - it will be used
        /// for rule filtering in multi-interface scenarios. See MULTI_INTERFACE_ARCHITECTURE.md.
        #[clap(long, default_value = "lo")]
        interface: String,

        /// Number of data plane workers to spawn. Defaults to number of CPU cores.
        #[arg(long)]
        num_workers: Option<usize>,
    },
    /// Run the worker process (intended to be called by the supervisor)
    Worker {
        #[arg(long)]
        relay_command_socket_path: PathBuf,
        #[arg(long)]
        data_plane: bool,
        #[arg(long)]
        core_id: Option<u32>,
        #[arg(long)]
        input_interface_name: Option<String>,
        #[arg(long)]
        input_group: Option<Ipv4Addr>,
        #[arg(long)]
        input_port: Option<u16>,
        #[arg(long)]
        output_group: Option<Ipv4Addr>,
        #[arg(long)]
        output_port: Option<u16>,
        #[arg(long)]
        output_interface: Option<String>,
        #[arg(long)]
        reporting_interval: Option<u64>,
        #[arg(long)]
        fanout_group_id: Option<u16>,
    },
}

pub struct DataPlaneConfig {
    pub supervisor_pid: u32, // PID of the supervisor process (for shared memory paths)
    pub core_id: Option<u32>,
    pub input_interface_name: Option<String>,
    pub input_group: Option<Ipv4Addr>,
    pub input_port: Option<u16>,
    pub output_group: Option<Ipv4Addr>,
    pub output_port: Option<u16>,
    pub output_interface: Option<String>,
    pub reporting_interval: u64,
    pub fanout_group_id: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct OutputDestination {
    pub group: Ipv4Addr,
    pub port: u16,
    pub interface: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum SupervisorCommand {
    AddRule {
        #[serde(default = "default_rule_id")]
        rule_id: String,
        input_interface: String,
        input_group: Ipv4Addr,
        input_port: u16,
        outputs: Vec<OutputDestination>,
    },
    RemoveRule {
        rule_id: String,
    },
    ListRules,
    GetStats,
    ListWorkers,
    /// Health check - returns OK if supervisor is ready to process traffic
    Ping,
    /// Set the global minimum log level
    SetGlobalLogLevel {
        level: logging::Severity,
    },
    /// Set the minimum log level for a specific facility
    SetFacilityLogLevel {
        facility: logging::Facility,
        level: logging::Severity,
    },
    /// Get all configured log levels (global + per-facility overrides)
    GetLogLevels,
    /// Get protocol version for compatibility checking
    GetVersion,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Response {
    Success(String),
    Error(String),
    Rules(Vec<ForwardingRule>),
    Stats(Vec<FlowStats>),
    Workers(Vec<WorkerInfo>),
    LogLevels {
        global: logging::Severity,
        facility_overrides: std::collections::HashMap<logging::Facility, logging::Severity>,
    },
    Version {
        protocol_version: u32,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ForwardingRule {
    pub rule_id: String,
    pub input_interface: String,
    pub input_group: Ipv4Addr,
    pub input_port: u16,
    pub outputs: Vec<OutputDestination>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct FlowStats {
    pub input_group: Ipv4Addr,
    pub input_port: u16,
    pub packets_relayed: u64,
    pub bytes_relayed: u64,
    pub packets_per_second: f64,
    pub bits_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RelayCommand {
    AddRule(ForwardingRule),
    RemoveRule {
        rule_id: String,
    },
    /// Synchronize the complete ruleset - used when workers start to ensure they have all existing rules
    SyncRules(Vec<ForwardingRule>),
    Shutdown,
    /// Ping command for readiness check - workers should respond when fully initialized
    Ping,
}

impl RelayCommand {
    pub fn rule_id(&self) -> Option<String> {
        match self {
            RelayCommand::AddRule(rule) => Some(rule.rule_id.clone()),
            RelayCommand::RemoveRule { rule_id } => Some(rule_id.clone()),
            RelayCommand::SyncRules(_) => None,
            RelayCommand::Shutdown => None,
            RelayCommand::Ping => None,
        }
    }
}

fn default_rule_id() -> String {
    Uuid::new_v4().to_string()
}

/// Compute a deterministic hash of a ruleset for drift detection.
/// Returns a hash of the sorted rule IDs to detect when worker rules don't match supervisor's master_rules.
pub fn compute_ruleset_hash<'a, I>(rules: I) -> u64
where
    I: Iterator<Item = &'a ForwardingRule>,
{
    use std::collections::BTreeSet;
    use std::hash::{Hash, Hasher};

    // Collect and sort rule_ids for deterministic ordering
    let rule_ids: BTreeSet<&str> = rules.map(|r| r.rule_id.as_str()).collect();

    // Compute hash
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for rule_id in rule_ids {
        rule_id.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_command_serialization() {
        let add_command = SupervisorCommand::AddRule {
            rule_id: "test-uuid".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![OutputDestination {
                group: "224.0.0.2".parse().unwrap(),
                port: 5001,
                interface: "127.0.0.1".to_string(),
            }],
        };
        let json = serde_json::to_string(&add_command).unwrap();
        let deserialized: SupervisorCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(add_command, deserialized);

        let remove_command = SupervisorCommand::RemoveRule {
            rule_id: "test-uuid".to_string(),
        };
        let json = serde_json::to_string(&remove_command).unwrap();
        let deserialized: SupervisorCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(remove_command, deserialized);

        let list_command = SupervisorCommand::ListRules;
        let json = serde_json::to_string(&list_command).unwrap();
        let deserialized: SupervisorCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(list_command, deserialized);

        let stats_command = SupervisorCommand::GetStats;
        let json = serde_json::to_string(&stats_command).unwrap();
        let deserialized: SupervisorCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(stats_command, deserialized);
    }

    #[test]
    fn test_response_serialization() {
        let success_response = Response::Success("OK".to_string());
        let json = serde_json::to_string(&success_response).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(success_response, deserialized);

        let error_response = Response::Error("Something went wrong".to_string());
        let json = serde_json::to_string(&error_response).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(error_response, deserialized);

        let rule = ForwardingRule {
            rule_id: "test-uuid".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![],
        };
        let rules_response = Response::Rules(vec![rule]);
        let json = serde_json::to_string(&rules_response).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(rules_response, deserialized);

        let stats = FlowStats {
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            packets_relayed: 100,
            bytes_relayed: 12345,
            packets_per_second: 10.0,
            bits_per_second: 12345.0 * 8.0,
        };
        let stats_response = Response::Stats(vec![stats]);
        let json = serde_json::to_string(&stats_response).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(stats_response, deserialized);
    }

    #[test]
    fn test_forwarding_rule_serialization() {
        let rule = ForwardingRule {
            rule_id: "test-uuid".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![OutputDestination {
                group: "224.0.0.2".parse().unwrap(),
                port: 5001,
                interface: "127.0.0.1".to_string(),
            }],
        };
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: ForwardingRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, deserialized);
    }

    #[test]
    fn test_flow_stats_serialization() {
        let stats = FlowStats {
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            packets_relayed: 100,
            bytes_relayed: 12345,
            packets_per_second: 10.0,
            bits_per_second: 12345.0 * 8.0,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: FlowStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, deserialized);
    }

    #[test]
    fn test_default_rule_id_is_valid_uuid() {
        let rule_id = default_rule_id();
        assert!(
            Uuid::parse_str(&rule_id).is_ok(),
            "Generated rule_id should be a valid UUID"
        );
    }
}
