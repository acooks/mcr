// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Configuration file types and parsing for mcrd.
//!
//! JSON5 configuration format supporting:
//! - Core pinning per interface
//! - Forwarding rules with optional human-friendly names
//! - Comments and trailing commas

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::{ForwardingRule, OutputDestination};

/// Startup/running configuration (JSON5 file format)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Config {
    /// Optional core pinning per interface.
    /// Interfaces not listed get 1 worker on auto-assigned core.
    #[serde(default)]
    pub pinning: HashMap<String, Vec<u32>>,

    /// Forwarding rules
    #[serde(default)]
    pub rules: Vec<ConfigRule>,
}

/// Rule as stored in config file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigRule {
    /// Optional human-friendly name for display/logging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Input specification (interface, multicast group, port)
    pub input: InputSpec,

    /// Output destinations
    pub outputs: Vec<OutputSpec>,
}

/// Input specification for a rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputSpec {
    /// Network interface name
    pub interface: String,

    /// Multicast group address
    pub group: Ipv4Addr,

    /// UDP port
    pub port: u16,
}

/// Output specification for a rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutputSpec {
    /// Multicast group address
    pub group: Ipv4Addr,

    /// UDP port
    pub port: u16,

    /// Network interface name
    pub interface: String,
}

impl Config {
    /// Load configuration from a JSON5 file
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(path.to_path_buf(), e.to_string()))?;
        Self::parse(&content)
    }

    /// Parse configuration from a JSON5 string
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        json5::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Serialize configuration to JSON5 string (with pretty formatting)
    pub fn to_json5(&self) -> String {
        // json5 crate doesn't have pretty printing, so we use serde_json for output
        // and rely on json5 for input (which handles comments and trailing commas)
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Save configuration to a file
    pub fn save_to_file(&self, path: &Path) -> Result<(), ConfigError> {
        let content = self.to_json5();
        std::fs::write(path, content)
            .map_err(|e| ConfigError::IoError(path.to_path_buf(), e.to_string()))
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Check for duplicate rules (same input tuple)
        let mut seen_inputs: HashMap<(String, Ipv4Addr, u16), usize> = HashMap::new();
        for (idx, rule) in self.rules.iter().enumerate() {
            let key = (
                rule.input.interface.clone(),
                rule.input.group,
                rule.input.port,
            );
            if let Some(prev_idx) = seen_inputs.get(&key) {
                return Err(ConfigError::DuplicateRule {
                    interface: key.0,
                    group: key.1,
                    port: key.2,
                    rule_indices: (*prev_idx, idx),
                });
            }
            seen_inputs.insert(key, idx);

            // Validate interface names
            validate_interface_name(&rule.input.interface)?;
            for output in &rule.outputs {
                validate_interface_name(&output.interface)?;
            }

            // Validate ports
            if rule.input.port == 0 {
                return Err(ConfigError::InvalidPort {
                    port: 0,
                    context: format!("rule {}", idx),
                });
            }
            for output in &rule.outputs {
                if output.port == 0 {
                    return Err(ConfigError::InvalidPort {
                        port: 0,
                        context: format!("rule {} output", idx),
                    });
                }
            }

            // Validate multicast addresses
            if !rule.input.group.is_multicast() {
                return Err(ConfigError::InvalidMulticastAddress {
                    address: rule.input.group,
                    context: format!("rule {} input", idx),
                });
            }
            for output in &rule.outputs {
                if !output.group.is_multicast() {
                    return Err(ConfigError::InvalidMulticastAddress {
                        address: output.group,
                        context: format!("rule {} output", idx),
                    });
                }
            }
        }

        // Validate pinning configuration
        for (interface, cores) in &self.pinning {
            validate_interface_name(interface)?;
            if cores.is_empty() {
                return Err(ConfigError::EmptyPinning {
                    interface: interface.clone(),
                });
            }
        }

        Ok(())
    }

    /// Get all unique interfaces referenced in the configuration
    pub fn get_interfaces(&self) -> Vec<String> {
        let mut interfaces: Vec<String> = self
            .rules
            .iter()
            .flat_map(|r| {
                std::iter::once(r.input.interface.clone())
                    .chain(r.outputs.iter().map(|o| o.interface.clone()))
            })
            .chain(self.pinning.keys().cloned())
            .collect();
        interfaces.sort();
        interfaces.dedup();
        interfaces
    }

    /// Convert config rules to ForwardingRules with generated IDs
    pub fn to_forwarding_rules(&self) -> Vec<ForwardingRule> {
        self.rules
            .iter()
            .map(|rule| rule.to_forwarding_rule())
            .collect()
    }

    /// Create a Config from existing ForwardingRules
    pub fn from_forwarding_rules(rules: &[ForwardingRule]) -> Self {
        Config {
            pinning: HashMap::new(),
            rules: rules.iter().map(ConfigRule::from_forwarding_rule).collect(),
        }
    }
}

impl ConfigRule {
    /// Convert to a ForwardingRule with a generated ID (hash of input tuple)
    pub fn to_forwarding_rule(&self) -> ForwardingRule {
        ForwardingRule {
            rule_id: self.generate_rule_id(),
            name: self.name.clone(),
            input_interface: self.input.interface.clone(),
            input_group: self.input.group,
            input_port: self.input.port,
            outputs: self
                .outputs
                .iter()
                .map(|o| OutputDestination {
                    group: o.group,
                    port: o.port,
                    interface: o.interface.clone(),
                })
                .collect(),
        }
    }

    /// Create from an existing ForwardingRule
    pub fn from_forwarding_rule(rule: &ForwardingRule) -> Self {
        ConfigRule {
            name: rule.name.clone(),
            input: InputSpec {
                interface: rule.input_interface.clone(),
                group: rule.input_group,
                port: rule.input_port,
            },
            outputs: rule
                .outputs
                .iter()
                .map(|o| OutputSpec {
                    group: o.group,
                    port: o.port,
                    interface: o.interface.clone(),
                })
                .collect(),
        }
    }

    /// Generate a stable rule ID from the input tuple (hash-based)
    fn generate_rule_id(&self) -> String {
        crate::generate_rule_id(&self.input.interface, self.input.group, self.input.port)
    }
}

/// Validate an interface name
fn validate_interface_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "interface name cannot be empty".to_string(),
        });
    }
    if name.len() > 15 {
        // Linux IFNAMSIZ limit
        return Err(ConfigError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "interface name too long (max 15 chars)".to_string(),
        });
    }
    // Check for invalid characters
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ConfigError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "interface name contains invalid characters".to_string(),
        });
    }
    // Interface names shouldn't start with a number
    if name.chars().next().map(|c| c.is_ascii_digit()) == Some(true) {
        return Err(ConfigError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "interface name cannot start with a digit".to_string(),
        });
    }
    Ok(())
}

/// Configuration errors
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    IoError(std::path::PathBuf, String),
    ParseError(String),
    DuplicateRule {
        interface: String,
        group: Ipv4Addr,
        port: u16,
        rule_indices: (usize, usize),
    },
    InvalidInterfaceName {
        name: String,
        reason: String,
    },
    InvalidPort {
        port: u16,
        context: String,
    },
    InvalidMulticastAddress {
        address: Ipv4Addr,
        context: String,
    },
    EmptyPinning {
        interface: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError(path, msg) => {
                write!(
                    f,
                    "failed to read config file '{}': {}",
                    path.display(),
                    msg
                )
            }
            ConfigError::ParseError(msg) => write!(f, "failed to parse config: {}", msg),
            ConfigError::DuplicateRule {
                interface,
                group,
                port,
                rule_indices,
            } => write!(
                f,
                "duplicate rule for input {}:{}:{} (rules {} and {})",
                interface, group, port, rule_indices.0, rule_indices.1
            ),
            ConfigError::InvalidInterfaceName { name, reason } => {
                write!(f, "invalid interface name '{}': {}", name, reason)
            }
            ConfigError::InvalidPort { port, context } => {
                write!(f, "invalid port {} in {}", port, context)
            }
            ConfigError::InvalidMulticastAddress { address, context } => {
                write!(f, "invalid multicast address {} in {}", address, context)
            }
            ConfigError::EmptyPinning { interface } => {
                write!(f, "empty core list for pinned interface '{}'", interface)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let config: Config = Config::parse("{}").unwrap();
        assert!(config.rules.is_empty());
        assert!(config.pinning.is_empty());
    }

    #[test]
    fn test_parse_config_with_rules() {
        let json5 = r#"{
            rules: [
                {
                    name: "test-rule",
                    input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
                    outputs: [
                        { group: "239.2.2.2", port: 5001, interface: "eth1" },
                    ],
                },
            ],
        }"#;

        let config = Config::parse(json5).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, Some("test-rule".to_string()));
        assert_eq!(config.rules[0].input.interface, "eth0");
        assert_eq!(
            config.rules[0].input.group,
            "239.1.1.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(config.rules[0].input.port, 5000);
        assert_eq!(config.rules[0].outputs.len(), 1);
    }

    #[test]
    fn test_parse_config_with_comments() {
        let json5 = r#"{
            // This is a comment
            rules: [
                {
                    // Rule comment
                    input: { interface: "lo", group: "239.0.0.1", port: 1234 },
                    outputs: [],
                },
            ],
        }"#;

        let config = Config::parse(json5).unwrap();
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn test_parse_config_with_pinning() {
        let json5 = r#"{
            pinning: {
                eth1: [4, 5, 6, 7],
                eth2: [0, 1],
            },
            rules: [],
        }"#;

        let config = Config::parse(json5).unwrap();
        assert_eq!(config.pinning.len(), 2);
        assert_eq!(config.pinning.get("eth1"), Some(&vec![4, 5, 6, 7]));
        assert_eq!(config.pinning.get("eth2"), Some(&vec![0, 1]));
    }

    #[test]
    fn test_validate_duplicate_rules() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![
                ConfigRule {
                    name: Some("rule1".to_string()),
                    input: InputSpec {
                        interface: "eth0".to_string(),
                        group: "239.1.1.1".parse().unwrap(),
                        port: 5000,
                    },
                    outputs: vec![],
                },
                ConfigRule {
                    name: Some("rule2".to_string()),
                    input: InputSpec {
                        interface: "eth0".to_string(),
                        group: "239.1.1.1".parse().unwrap(),
                        port: 5000,
                    },
                    outputs: vec![],
                },
            ],
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::DuplicateRule { .. })));
    }

    #[test]
    fn test_validate_invalid_interface_name() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "".to_string(),
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                },
                outputs: vec![],
            }],
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidInterfaceName { .. })
        ));
    }

    #[test]
    fn test_validate_invalid_port() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "eth0".to_string(),
                    group: "239.1.1.1".parse().unwrap(),
                    port: 0,
                },
                outputs: vec![],
            }],
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidPort { .. })));
    }

    #[test]
    fn test_validate_non_multicast_address() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "eth0".to_string(),
                    group: "192.168.1.1".parse().unwrap(), // Not multicast
                    port: 5000,
                },
                outputs: vec![],
            }],
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidMulticastAddress { .. })
        ));
    }

    #[test]
    fn test_config_rule_to_forwarding_rule() {
        let rule = ConfigRule {
            name: Some("test".to_string()),
            input: InputSpec {
                interface: "eth0".to_string(),
                group: "239.1.1.1".parse().unwrap(),
                port: 5000,
            },
            outputs: vec![OutputSpec {
                group: "239.2.2.2".parse().unwrap(),
                port: 5001,
                interface: "eth1".to_string(),
            }],
        };

        let forwarding_rule = rule.to_forwarding_rule();
        assert!(!forwarding_rule.rule_id.is_empty());
        assert_eq!(forwarding_rule.input_interface, "eth0");
        assert_eq!(
            forwarding_rule.input_group,
            "239.1.1.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(forwarding_rule.input_port, 5000);
        assert_eq!(forwarding_rule.outputs.len(), 1);
    }

    #[test]
    fn test_rule_id_is_stable() {
        let rule1 = ConfigRule {
            name: None,
            input: InputSpec {
                interface: "eth0".to_string(),
                group: "239.1.1.1".parse().unwrap(),
                port: 5000,
            },
            outputs: vec![],
        };

        let rule2 = ConfigRule {
            name: Some("different-name".to_string()), // Name shouldn't affect ID
            input: InputSpec {
                interface: "eth0".to_string(),
                group: "239.1.1.1".parse().unwrap(),
                port: 5000,
            },
            outputs: vec![],
        };

        // Same input tuple should generate same ID
        assert_eq!(rule1.generate_rule_id(), rule2.generate_rule_id());

        // Different input should generate different ID
        let rule3 = ConfigRule {
            name: None,
            input: InputSpec {
                interface: "eth0".to_string(),
                group: "239.1.1.1".parse().unwrap(),
                port: 5001, // Different port
            },
            outputs: vec![],
        };
        assert_ne!(rule1.generate_rule_id(), rule3.generate_rule_id());
    }

    #[test]
    fn test_get_interfaces() {
        let config = Config {
            pinning: [("eth2".to_string(), vec![0, 1])].into_iter().collect(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "eth0".to_string(),
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                },
                outputs: vec![OutputSpec {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(),
                }],
            }],
        };

        let interfaces = config.get_interfaces();
        assert_eq!(interfaces, vec!["eth0", "eth1", "eth2"]);
    }

    #[test]
    fn test_config_roundtrip() {
        let config = Config {
            pinning: [("eth1".to_string(), vec![4, 5])].into_iter().collect(),
            rules: vec![ConfigRule {
                name: Some("test-rule".to_string()),
                input: InputSpec {
                    interface: "eth0".to_string(),
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                },
                outputs: vec![OutputSpec {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(),
                }],
            }],
        };

        // Serialize to JSON5 and parse back
        let json5 = config.to_json5();
        let parsed = Config::parse(&json5).unwrap();
        assert_eq!(config, parsed);
    }
}
