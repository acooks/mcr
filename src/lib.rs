use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub mod supervisor;
pub mod worker;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct OutputDestination {
    pub group: Ipv4Addr,
    pub port: u16,
    pub interface: String,
    pub dtls_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Command {
    AddRule {
        input_interface: String,
        input_group: Ipv4Addr,
        input_port: u16,
        outputs: Vec<OutputDestination>,
        #[serde(default)]
        dtls_enabled: bool,
    },
    RemoveRule {
        input_group: Ipv4Addr,
        input_port: u16,
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

#[derive(Debug, Clone)]
pub enum RelayCommand {
    AddRule(ForwardingRule),
    RemoveRule {
        input_group: Ipv4Addr,
        input_port: u16,
    },
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serialization() {
        let command = Command::AddRule {
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![OutputDestination {
                group: "224.0.0.2".parse().unwrap(),
                port: 5001,
                interface: "127.0.0.1".parse().unwrap(),
                dtls_enabled: true,
            }],
            dtls_enabled: false,
        };
        let json = serde_json::to_string(&command).unwrap();
        let deserialized: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(command, deserialized);
    }

    #[test]
    fn test_response_serialization() {
        let response = Response::Success("OK".to_string());
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(response, deserialized);

        let stats = FlowStats {
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            packets_relayed: 100,
            bytes_relayed: 12345,
            packets_per_second: 10.0,
            bits_per_second: 12345.0 * 8.0,
        };
        let response = Response::Stats(vec![stats]);
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(response, deserialized);
    }
}
