// SPDX-License-Identifier: Apache-2.0 OR MIT
use clap::Parser;
pub mod config;
pub mod logging;

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::path::PathBuf;

pub use config::{Config, ConfigRule, InputSpec, OutputSpec};

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
        /// Path to JSON5 configuration file.
        /// If provided, loads startup config from this file.
        #[arg(long)]
        config: Option<PathBuf>,

        /// Path to the Unix socket for worker command and control.
        #[clap(long, default_value = "/tmp/mcr_relay_commands.sock")]
        relay_command_socket_path: PathBuf,

        /// Path to the Unix socket for client command and control.
        #[clap(long, default_value = "/tmp/mcrd_control.sock")]
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
        /// Optional human-friendly name for the rule
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        input_interface: String,
        input_group: Ipv4Addr,
        input_port: u16,
        outputs: Vec<OutputDestination>,
    },
    RemoveRule {
        rule_id: String,
    },
    /// Remove a rule by its human-friendly name
    RemoveRuleByName {
        name: String,
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
    /// Get the full running configuration (for `mcrctl show`)
    GetConfig,
    /// Load configuration from provided config (for `mcrctl load`)
    LoadConfig {
        config: Config,
        /// If true, replace all existing rules; if false, merge with existing
        replace: bool,
    },
    /// Save running configuration to a file (for `mcrctl save`)
    SaveConfig {
        /// Path to save to; None means use startup config path
        path: Option<PathBuf>,
    },
    /// Validate a configuration without loading it (for `mcrctl check`)
    CheckConfig {
        config: Config,
    },
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
    /// Running configuration response (for `mcrctl show`)
    Config(Config),
    /// Configuration validation result
    ConfigValidation {
        valid: bool,
        errors: Vec<String>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ForwardingRule {
    pub rule_id: String,
    /// Optional human-friendly name for display/logging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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

/// Default rule_id for serde deserialization.
/// Returns empty string, signaling that the supervisor should generate a hash-based ID.
fn default_rule_id() -> String {
    String::new()
}

/// Generate a stable rule ID from the input tuple (interface, group, port).
/// This produces a deterministic 16-character hex string that is stable across reloads.
pub fn generate_rule_id(interface: &str, group: Ipv4Addr, port: u16) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    interface.hash(&mut hasher);
    group.hash(&mut hasher);
    port.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
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
            name: None,
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
            name: None,
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
            name: None,
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
    fn test_default_rule_id_is_empty() {
        let rule_id = default_rule_id();
        assert!(
            rule_id.is_empty(),
            "default_rule_id() should return empty string (supervisor generates hash-based ID)"
        );
    }

    #[test]
    fn test_generate_rule_id_is_stable() {
        // Same inputs should produce same ID
        let id1 = generate_rule_id("eth0", "224.0.0.1".parse().unwrap(), 5000);
        let id2 = generate_rule_id("eth0", "224.0.0.1".parse().unwrap(), 5000);
        assert_eq!(id1, id2, "Same inputs should generate same ID");

        // ID should be 16 hex characters
        assert_eq!(id1.len(), 16, "Rule ID should be 16 hex characters");
        assert!(
            id1.chars().all(|c| c.is_ascii_hexdigit()),
            "Rule ID should contain only hex digits"
        );

        // Different inputs should produce different IDs
        let id3 = generate_rule_id("eth0", "224.0.0.1".parse().unwrap(), 5001);
        assert_ne!(id1, id3, "Different port should generate different ID");

        let id4 = generate_rule_id("eth1", "224.0.0.1".parse().unwrap(), 5000);
        assert_ne!(id1, id4, "Different interface should generate different ID");

        let id5 = generate_rule_id("eth0", "224.0.0.2".parse().unwrap(), 5000);
        assert_ne!(id1, id5, "Different group should generate different ID");
    }
}
