use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use uuid::Uuid;

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

        /// User to run worker processes as.
        #[clap(long, default_value = "nobody")]
        user: String,
        #[arg(long, default_value = "daemon")]
        group: String,
        #[arg(long)]
        prometheus_addr: Option<std::net::SocketAddr>,
    },
    /// Run the worker process (intended to be called by the supervisor)
    Worker {
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        gid: u32,
        #[arg(long)]
        relay_command_socket_path: PathBuf,
        #[arg(long)]
        data_plane: bool,
        #[arg(long)]
        core_id: Option<u32>,
        #[arg(long)]
        prometheus_addr: Option<std::net::SocketAddr>,
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
        socket_fd: Option<i32>,
    },
}

pub struct ControlPlaneConfig {
    pub uid: u32,
    pub gid: u32,
    pub relay_command_socket_path: PathBuf,
    pub prometheus_addr: Option<std::net::SocketAddr>,
    pub reporting_interval: u64,
    pub socket_fd: Option<i32>,
}

pub struct DataPlaneConfig {
    pub uid: u32,
    pub gid: u32,
    pub core_id: Option<u32>,
    pub prometheus_addr: std::net::SocketAddr,
    pub input_interface_name: Option<String>,
    pub input_group: Option<Ipv4Addr>,
    pub input_port: Option<u16>,
    pub output_group: Option<Ipv4Addr>,
    pub output_port: Option<u16>,
    pub output_interface: Option<String>,
    pub reporting_interval: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct OutputDestination {
    pub group: Ipv4Addr,
    pub port: u16,
    pub interface: String,
    pub dtls_enabled: bool,
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
        #[serde(default)]
        dtls_enabled: bool,
    },
    RemoveRule {
        rule_id: String,
    },
    ListRules,
    GetStats,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Response {
    Success(String),
    Error(String),
    Rules(Vec<ForwardingRule>),
    Stats(Vec<FlowStats>),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ForwardingRule {
    pub rule_id: String,
    pub input_interface: String,
    pub input_group: Ipv4Addr,
    pub input_port: u16,
    pub outputs: Vec<OutputDestination>,
    pub dtls_enabled: bool,
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
    RemoveRule { rule_id: String },
}

fn default_rule_id() -> String {
    Uuid::new_v4().to_string()
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
                dtls_enabled: true,
            }],
            dtls_enabled: false,
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
            dtls_enabled: false,
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
                dtls_enabled: true,
            }],
            dtls_enabled: false,
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
