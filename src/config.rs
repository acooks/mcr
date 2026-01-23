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

use crate::{ForwardingRule, OutputDestination, RuleSource};

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

    /// PIM-SM configuration (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pim: Option<PimConfig>,

    /// IGMP configuration (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub igmp: Option<IgmpConfig>,

    /// MSDP configuration (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msdp: Option<MsdpConfig>,

    /// Control plane integration configuration (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane: Option<ControlPlaneConfig>,
}

/// PIM-SM configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PimConfig {
    /// Enable PIM-SM
    #[serde(default)]
    pub enabled: bool,

    /// Router ID (typically highest loopback IP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router_id: Option<Ipv4Addr>,

    /// Per-interface PIM configuration
    #[serde(default)]
    pub interfaces: Vec<PimInterfaceConfig>,

    /// Static RP mappings (group prefix -> RP address)
    #[serde(default)]
    pub static_rp: Vec<StaticRpConfig>,

    /// Our RP address (if we are an RP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_address: Option<Ipv4Addr>,
}

/// Per-interface PIM configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PimInterfaceConfig {
    /// Interface name
    pub name: String,

    /// DR priority (higher wins, default 1)
    #[serde(default = "default_dr_priority")]
    pub dr_priority: u32,
}

fn default_dr_priority() -> u32 {
    1
}

/// Static RP configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticRpConfig {
    /// Multicast group or prefix (e.g., "239.0.0.0/8" or "239.1.1.1")
    pub group: String,

    /// RP address for this group
    pub rp: Ipv4Addr,
}

/// IGMP configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct IgmpConfig {
    /// Interfaces to act as IGMP querier on
    #[serde(default)]
    pub querier_interfaces: Vec<String>,

    /// Query interval in seconds (default 125)
    #[serde(default = "default_query_interval")]
    pub query_interval: u32,

    /// Robustness variable (default 2)
    #[serde(default = "default_robustness")]
    pub robustness: u8,

    /// Query response interval in seconds (default 10)
    #[serde(default = "default_query_response_interval")]
    pub query_response_interval: u32,
}

fn default_query_interval() -> u32 {
    125
}

fn default_robustness() -> u8 {
    2
}

fn default_query_response_interval() -> u32 {
    10
}

/// MSDP (Multicast Source Discovery Protocol) configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MsdpConfig {
    /// Enable MSDP
    #[serde(default)]
    pub enabled: bool,

    /// Local address for MSDP connections (source IP for outbound TCP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_address: Option<Ipv4Addr>,

    /// MSDP peer configurations
    #[serde(default)]
    pub peers: Vec<MsdpPeerConfig>,

    /// Keepalive interval in seconds (default 60)
    #[serde(default = "default_msdp_keepalive_interval")]
    pub keepalive_interval: u32,

    /// Hold time in seconds (default 75)
    #[serde(default = "default_msdp_hold_time")]
    pub hold_time: u32,
}

/// Per-peer MSDP configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MsdpPeerConfig {
    /// Peer's IP address
    pub address: Ipv4Addr,

    /// Optional description for this peer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Mesh group name (peers in the same mesh group don't flood SA to each other)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_group: Option<String>,

    /// Whether this is a default peer (used when no other peer available)
    #[serde(default)]
    pub default_peer: bool,
}

fn default_msdp_keepalive_interval() -> u32 {
    60
}

fn default_msdp_hold_time() -> u32 {
    75
}

/// Control plane integration configuration
///
/// Settings for external control plane integration including RPF providers,
/// external neighbor injection, and event subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlPlaneConfig {
    /// RPF provider configuration: "disabled", "static", or socket path for external
    #[serde(default = "default_rpf_provider")]
    pub rpf_provider: String,

    /// Allow external neighbor injection via control socket
    #[serde(default = "default_external_neighbors_enabled")]
    pub external_neighbors_enabled: bool,

    /// Event subscription buffer size (number of events to buffer)
    #[serde(default = "default_event_buffer_size")]
    pub event_buffer_size: usize,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            rpf_provider: "disabled".to_string(),
            external_neighbors_enabled: true,
            event_buffer_size: default_event_buffer_size(),
        }
    }
}

fn default_rpf_provider() -> String {
    "disabled".to_string()
}

fn default_external_neighbors_enabled() -> bool {
    true
}

fn default_event_buffer_size() -> usize {
    256
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

            // Both input and output addresses can be unicast or multicast.
            // This enables flexible forwarding scenarios:
            // - Multicast → Multicast (standard relay)
            // - Multicast → Unicast (conversion for legacy/cloud systems)
            // - Unicast → Multicast (injection from unicast tunnel)
            // - Unicast → Unicast (general packet forwarding)
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

        // Validate PIM configuration
        if let Some(pim) = &self.pim {
            validate_pim_config(pim)?;
        }

        // Validate IGMP configuration
        if let Some(igmp) = &self.igmp {
            validate_igmp_config(igmp)?;
        }

        // Validate MSDP configuration
        if let Some(msdp) = &self.msdp {
            validate_msdp_config(msdp)?;
        }

        // Validate control plane configuration
        if let Some(control_plane) = &self.control_plane {
            validate_control_plane_config(control_plane)?;
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
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
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
            input_source: None, // Static rules from config don't have source filtering
            outputs: self
                .outputs
                .iter()
                .map(|o| OutputDestination {
                    group: o.group,
                    port: o.port,
                    interface: o.interface.clone(),
                })
                .collect(),
            source: RuleSource::Static, // Config file rules are static
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

/// Validate PIM configuration
fn validate_pim_config(pim: &PimConfig) -> Result<(), ConfigError> {
    // Validate router_id if provided (must be unicast)
    if let Some(router_id) = pim.router_id {
        if router_id.is_multicast() || router_id.is_broadcast() || router_id.is_unspecified() {
            return Err(ConfigError::InvalidPimConfig {
                reason: format!(
                    "router_id must be a valid unicast address, got {}",
                    router_id
                ),
            });
        }
    }

    // Validate rp_address if provided (must be unicast)
    if let Some(rp_address) = pim.rp_address {
        if rp_address.is_multicast() || rp_address.is_broadcast() || rp_address.is_unspecified() {
            return Err(ConfigError::InvalidPimConfig {
                reason: format!(
                    "rp_address must be a valid unicast address, got {}",
                    rp_address
                ),
            });
        }
    }

    // Validate interface configurations
    let mut seen_interfaces = std::collections::HashSet::new();
    for iface_config in &pim.interfaces {
        validate_interface_name(&iface_config.name)?;

        // Check for duplicate interface entries
        if !seen_interfaces.insert(&iface_config.name) {
            return Err(ConfigError::InvalidPimConfig {
                reason: format!(
                    "duplicate interface '{}' in PIM configuration",
                    iface_config.name
                ),
            });
        }
    }

    // Validate static RP configurations
    for rp_config in &pim.static_rp {
        validate_group_prefix(&rp_config.group)?;

        // RP address must be unicast
        if rp_config.rp.is_multicast()
            || rp_config.rp.is_broadcast()
            || rp_config.rp.is_unspecified()
        {
            return Err(ConfigError::InvalidPimConfig {
                reason: format!(
                    "static RP address must be unicast, got {} for group {}",
                    rp_config.rp, rp_config.group
                ),
            });
        }
    }

    Ok(())
}

/// Validate IGMP configuration
fn validate_igmp_config(igmp: &IgmpConfig) -> Result<(), ConfigError> {
    // Validate all querier interface names
    let mut seen_interfaces = std::collections::HashSet::new();
    for iface in &igmp.querier_interfaces {
        validate_interface_name(iface)?;

        // Check for duplicate interface entries
        if !seen_interfaces.insert(iface) {
            return Err(ConfigError::InvalidIgmpConfig {
                reason: format!("duplicate interface '{}' in IGMP querier_interfaces", iface),
            });
        }
    }

    // Validate query_interval (must be > 0)
    if igmp.query_interval == 0 {
        return Err(ConfigError::InvalidIgmpConfig {
            reason: "query_interval must be greater than 0".to_string(),
        });
    }

    // Validate robustness (must be > 0)
    if igmp.robustness == 0 {
        return Err(ConfigError::InvalidIgmpConfig {
            reason: "robustness must be greater than 0".to_string(),
        });
    }

    // Validate query_response_interval (should be less than query_interval)
    if igmp.query_response_interval >= igmp.query_interval {
        return Err(ConfigError::InvalidIgmpConfig {
            reason: format!(
                "query_response_interval ({}) must be less than query_interval ({})",
                igmp.query_response_interval, igmp.query_interval
            ),
        });
    }

    Ok(())
}

/// Validate MSDP configuration
fn validate_msdp_config(msdp: &MsdpConfig) -> Result<(), ConfigError> {
    // Validate local_address if provided (must be unicast)
    if let Some(local_addr) = msdp.local_address {
        if local_addr.is_multicast() || local_addr.is_broadcast() || local_addr.is_unspecified() {
            return Err(ConfigError::InvalidMsdpConfig {
                reason: format!(
                    "local_address must be a valid unicast address, got {}",
                    local_addr
                ),
            });
        }
    }

    // Validate keepalive_interval (must be > 0)
    if msdp.keepalive_interval == 0 {
        return Err(ConfigError::InvalidMsdpConfig {
            reason: "keepalive_interval must be greater than 0".to_string(),
        });
    }

    // Validate hold_time (must be > keepalive_interval)
    if msdp.hold_time <= msdp.keepalive_interval {
        return Err(ConfigError::InvalidMsdpConfig {
            reason: format!(
                "hold_time ({}) must be greater than keepalive_interval ({})",
                msdp.hold_time, msdp.keepalive_interval
            ),
        });
    }

    // Validate peer configurations
    let mut seen_peers = std::collections::HashSet::new();
    for peer_config in &msdp.peers {
        // Peer address must be unicast
        if peer_config.address.is_multicast()
            || peer_config.address.is_broadcast()
            || peer_config.address.is_unspecified()
        {
            return Err(ConfigError::InvalidMsdpConfig {
                reason: format!("peer address must be unicast, got {}", peer_config.address),
            });
        }

        // Check for duplicate peers
        if !seen_peers.insert(peer_config.address) {
            return Err(ConfigError::InvalidMsdpConfig {
                reason: format!("duplicate peer address: {}", peer_config.address),
            });
        }

        // Validate mesh_group name if provided
        if let Some(ref mesh_group) = peer_config.mesh_group {
            if mesh_group.is_empty() {
                return Err(ConfigError::InvalidMsdpConfig {
                    reason: "mesh_group name cannot be empty".to_string(),
                });
            }
            if mesh_group.len() > 64 {
                return Err(ConfigError::InvalidMsdpConfig {
                    reason: "mesh_group name too long (max 64 chars)".to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Validate control plane integration configuration
fn validate_control_plane_config(config: &ControlPlaneConfig) -> Result<(), ConfigError> {
    // Validate RPF provider value
    let rpf = config.rpf_provider.as_str();
    if rpf != "disabled" && rpf != "static" && !rpf.starts_with('/') {
        return Err(ConfigError::InvalidControlPlane {
            reason: format!(
                "rpf_provider must be 'disabled', 'static', or an absolute socket path (got '{}')",
                rpf
            ),
        });
    }

    // Validate event buffer size
    if config.event_buffer_size == 0 {
        return Err(ConfigError::InvalidControlPlane {
            reason: "event_buffer_size must be greater than 0".to_string(),
        });
    }

    if config.event_buffer_size > 65536 {
        return Err(ConfigError::InvalidControlPlane {
            reason: "event_buffer_size must be <= 65536".to_string(),
        });
    }

    Ok(())
}

/// Validate a multicast group prefix (e.g., "239.0.0.0/8" or "239.1.1.1")
fn validate_group_prefix(prefix: &str) -> Result<(), ConfigError> {
    // Check if it's a CIDR prefix or single address
    if let Some((addr_str, prefix_len_str)) = prefix.split_once('/') {
        // CIDR format: addr/prefix_len
        let addr: Ipv4Addr = addr_str
            .parse()
            .map_err(|_| ConfigError::InvalidGroupPrefix {
                prefix: prefix.to_string(),
                reason: "invalid IPv4 address".to_string(),
            })?;

        let prefix_len: u8 =
            prefix_len_str
                .parse()
                .map_err(|_| ConfigError::InvalidGroupPrefix {
                    prefix: prefix.to_string(),
                    reason: "invalid prefix length".to_string(),
                })?;

        if prefix_len > 32 {
            return Err(ConfigError::InvalidGroupPrefix {
                prefix: prefix.to_string(),
                reason: "prefix length must be <= 32".to_string(),
            });
        }

        // For PIM, the base address should be a multicast address
        if !addr.is_multicast() {
            return Err(ConfigError::InvalidGroupPrefix {
                prefix: prefix.to_string(),
                reason: "group prefix must be a multicast address (224.0.0.0/4)".to_string(),
            });
        }
    } else {
        // Single address format
        let addr: Ipv4Addr = prefix
            .parse()
            .map_err(|_| ConfigError::InvalidGroupPrefix {
                prefix: prefix.to_string(),
                reason: "invalid IPv4 address".to_string(),
            })?;

        if !addr.is_multicast() {
            return Err(ConfigError::InvalidGroupPrefix {
                prefix: prefix.to_string(),
                reason: "group address must be a multicast address (224.0.0.0/4)".to_string(),
            });
        }
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
    EmptyPinning {
        interface: String,
    },
    InvalidPimConfig {
        reason: String,
    },
    InvalidIgmpConfig {
        reason: String,
    },
    InvalidGroupPrefix {
        prefix: String,
        reason: String,
    },
    InvalidMsdpConfig {
        reason: String,
    },
    InvalidControlPlane {
        reason: String,
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
            ConfigError::EmptyPinning { interface } => {
                write!(f, "empty core list for pinned interface '{}'", interface)
            }
            ConfigError::InvalidPimConfig { reason } => {
                write!(f, "invalid PIM configuration: {}", reason)
            }
            ConfigError::InvalidIgmpConfig { reason } => {
                write!(f, "invalid IGMP configuration: {}", reason)
            }
            ConfigError::InvalidGroupPrefix { prefix, reason } => {
                write!(f, "invalid group prefix '{}': {}", prefix, reason)
            }
            ConfigError::InvalidMsdpConfig { reason } => {
                write!(f, "invalid MSDP configuration: {}", reason)
            }
            ConfigError::InvalidControlPlane { reason } => {
                write!(f, "invalid control plane configuration: {}", reason)
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
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::DuplicateRule { .. })));
    }

    #[test]
    fn test_validate_invalid_interface_name_empty() {
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
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidInterfaceName { .. })
        ));
    }

    #[test]
    fn test_validate_invalid_interface_name_too_long() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "thisinterfaceistoolong".to_string(), // > 15 chars
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                },
                outputs: vec![],
            }],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        match result {
            Err(ConfigError::InvalidInterfaceName { reason, .. }) => {
                assert!(reason.contains("too long"));
            }
            _ => panic!("Expected InvalidInterfaceName error for too long name"),
        }
    }

    #[test]
    fn test_validate_invalid_interface_name_invalid_chars() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "eth0/bad".to_string(), // contains '/'
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                },
                outputs: vec![],
            }],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        match result {
            Err(ConfigError::InvalidInterfaceName { reason, .. }) => {
                assert!(reason.contains("invalid characters"));
            }
            _ => panic!("Expected InvalidInterfaceName error for invalid chars"),
        }
    }

    #[test]
    fn test_validate_invalid_interface_name_starts_with_digit() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "0eth".to_string(), // starts with digit
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                },
                outputs: vec![],
            }],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        match result {
            Err(ConfigError::InvalidInterfaceName { reason, .. }) => {
                assert!(reason.contains("cannot start with a digit"));
            }
            _ => panic!("Expected InvalidInterfaceName error for digit start"),
        }
    }

    #[test]
    fn test_validate_invalid_output_interface() {
        let config = Config {
            pinning: HashMap::new(),
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
                    interface: "".to_string(), // Invalid empty output interface
                }],
            }],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidInterfaceName { .. })
        ));
    }

    #[test]
    fn test_validate_invalid_input_port() {
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
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidPort { .. })));
    }

    #[test]
    fn test_validate_invalid_output_port() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "eth0".to_string(),
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                },
                outputs: vec![OutputSpec {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 0, // Invalid port
                    interface: "eth1".to_string(),
                }],
            }],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        match result {
            Err(ConfigError::InvalidPort { port, context }) => {
                assert_eq!(port, 0);
                assert!(context.contains("output"));
            }
            _ => panic!("Expected InvalidPort error for output"),
        }
    }

    #[test]
    fn test_unicast_input_address_allowed() {
        // Unicast input addresses are allowed for unicast-to-multicast conversion
        // (e.g., receiving from a unicast tunnel and forwarding to multicast)
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "eth0".to_string(),
                    group: "192.168.1.1".parse().unwrap(), // Unicast input is allowed
                    port: 5000,
                },
                outputs: vec![OutputSpec {
                    group: "239.1.1.1".parse().unwrap(), // Multicast output
                    port: 5001,
                    interface: "eth1".to_string(),
                }],
            }],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(result.is_ok(), "Unicast input addresses should be allowed");
    }

    #[test]
    fn test_unicast_output_address_allowed() {
        // Unicast output addresses are allowed for multicast-to-unicast conversion
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![ConfigRule {
                name: None,
                input: InputSpec {
                    interface: "eth0".to_string(),
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                },
                outputs: vec![OutputSpec {
                    group: "10.0.0.1".parse().unwrap(), // Unicast is allowed
                    port: 5001,
                    interface: "eth1".to_string(),
                }],
            }],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(result.is_ok(), "Unicast output addresses should be allowed");
    }

    #[test]
    fn test_validate_empty_pinning() {
        let config = Config {
            pinning: [("eth0".to_string(), vec![])].into_iter().collect(), // Empty cores
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        match result {
            Err(ConfigError::EmptyPinning { interface }) => {
                assert_eq!(interface, "eth0");
            }
            _ => panic!("Expected EmptyPinning error"),
        }
    }

    #[test]
    fn test_validate_invalid_pinning_interface() {
        let config = Config {
            pinning: [("".to_string(), vec![0, 1])].into_iter().collect(), // Empty interface name
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidInterfaceName { .. })
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
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
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
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        // Serialize to JSON5 and parse back
        let json5 = config.to_json5();
        let parsed = Config::parse(&json5).unwrap();
        assert_eq!(config, parsed);
    }

    // PIM configuration validation tests
    #[test]
    fn test_pim_config_valid() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: Some(PimConfig {
                enabled: true,
                router_id: Some("10.0.0.1".parse().unwrap()),
                interfaces: vec![PimInterfaceConfig {
                    name: "eth0".to_string(),
                    dr_priority: 100,
                }],
                static_rp: vec![StaticRpConfig {
                    group: "239.0.0.0/8".to_string(),
                    rp: "10.0.0.1".parse().unwrap(),
                }],
                rp_address: Some("10.0.0.1".parse().unwrap()),
            }),
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_pim_config_invalid_router_id_multicast() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: Some(PimConfig {
                enabled: true,
                router_id: Some("224.0.0.1".parse().unwrap()), // Multicast address
                interfaces: vec![],
                static_rp: vec![],
                rp_address: None,
            }),
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidPimConfig { .. })));
    }

    #[test]
    fn test_pim_config_invalid_rp_address_multicast() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: Some(PimConfig {
                enabled: true,
                router_id: Some("10.0.0.1".parse().unwrap()),
                interfaces: vec![],
                static_rp: vec![],
                rp_address: Some("224.0.0.1".parse().unwrap()), // Multicast address
            }),
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidPimConfig { .. })));
    }

    #[test]
    fn test_pim_config_duplicate_interface() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: Some(PimConfig {
                enabled: true,
                router_id: None,
                interfaces: vec![
                    PimInterfaceConfig {
                        name: "eth0".to_string(),
                        dr_priority: 100,
                    },
                    PimInterfaceConfig {
                        name: "eth0".to_string(), // Duplicate
                        dr_priority: 50,
                    },
                ],
                static_rp: vec![],
                rp_address: None,
            }),
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidPimConfig { .. })));
    }

    #[test]
    fn test_pim_config_invalid_interface_name() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: Some(PimConfig {
                enabled: true,
                router_id: None,
                interfaces: vec![PimInterfaceConfig {
                    name: "".to_string(), // Empty name
                    dr_priority: 100,
                }],
                static_rp: vec![],
                rp_address: None,
            }),
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidInterfaceName { .. })
        ));
    }

    #[test]
    fn test_pim_config_invalid_static_rp_unicast_group() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: Some(PimConfig {
                enabled: true,
                router_id: None,
                interfaces: vec![],
                static_rp: vec![StaticRpConfig {
                    group: "192.168.1.0/24".to_string(), // Unicast prefix
                    rp: "10.0.0.1".parse().unwrap(),
                }],
                rp_address: None,
            }),
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidGroupPrefix { .. })
        ));
    }

    #[test]
    fn test_pim_config_invalid_static_rp_multicast_rp() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: Some(PimConfig {
                enabled: true,
                router_id: None,
                interfaces: vec![],
                static_rp: vec![StaticRpConfig {
                    group: "239.0.0.0/8".to_string(),
                    rp: "224.0.0.1".parse().unwrap(), // RP is multicast (invalid)
                }],
                rp_address: None,
            }),
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidPimConfig { .. })));
    }

    // IGMP configuration validation tests
    #[test]
    fn test_igmp_config_valid() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: Some(IgmpConfig {
                querier_interfaces: vec!["eth0".to_string(), "eth1".to_string()],
                query_interval: 125,
                robustness: 2,
                query_response_interval: 10,
            }),
            msdp: None,
            control_plane: None,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_igmp_config_invalid_interface_name() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: Some(IgmpConfig {
                querier_interfaces: vec!["".to_string()], // Empty name
                query_interval: 125,
                robustness: 2,
                query_response_interval: 10,
            }),
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidInterfaceName { .. })
        ));
    }

    #[test]
    fn test_igmp_config_duplicate_interface() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: Some(IgmpConfig {
                querier_interfaces: vec!["eth0".to_string(), "eth0".to_string()], // Duplicate
                query_interval: 125,
                robustness: 2,
                query_response_interval: 10,
            }),
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidIgmpConfig { .. })));
    }

    #[test]
    fn test_igmp_config_invalid_query_interval() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: Some(IgmpConfig {
                querier_interfaces: vec![],
                query_interval: 0, // Invalid
                robustness: 2,
                query_response_interval: 0,
            }),
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidIgmpConfig { .. })));
    }

    #[test]
    fn test_igmp_config_invalid_robustness() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: Some(IgmpConfig {
                querier_interfaces: vec![],
                query_interval: 125,
                robustness: 0, // Invalid
                query_response_interval: 10,
            }),
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidIgmpConfig { .. })));
    }

    #[test]
    fn test_igmp_config_response_interval_too_large() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: Some(IgmpConfig {
                querier_interfaces: vec![],
                query_interval: 125,
                robustness: 2,
                query_response_interval: 125, // Must be < query_interval
            }),
            msdp: None,
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidIgmpConfig { .. })));
    }

    // Group prefix validation tests
    #[test]
    fn test_group_prefix_cidr_valid() {
        let result = validate_group_prefix("239.0.0.0/8");
        assert!(result.is_ok());
    }

    #[test]
    fn test_group_prefix_single_address_valid() {
        let result = validate_group_prefix("239.1.1.1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_group_prefix_invalid_address() {
        let result = validate_group_prefix("not.an.ip");
        assert!(matches!(
            result,
            Err(ConfigError::InvalidGroupPrefix { .. })
        ));
    }

    #[test]
    fn test_group_prefix_invalid_prefix_len() {
        let result = validate_group_prefix("239.0.0.0/33");
        assert!(matches!(
            result,
            Err(ConfigError::InvalidGroupPrefix { .. })
        ));
    }

    #[test]
    fn test_parse_pim_igmp_config() {
        let json5 = r#"{
            pim: {
                enabled: true,
                router_id: "10.0.0.1",
                interfaces: [
                    { name: "eth0", dr_priority: 100 },
                ],
                static_rp: [
                    { group: "239.0.0.0/8", rp: "10.0.0.1" },
                ],
                rp_address: "10.0.0.1",
            },
            igmp: {
                querier_interfaces: ["eth0", "eth1"],
                query_interval: 125,
                robustness: 2,
                query_response_interval: 10,
            },
        }"#;

        let config = Config::parse(json5).unwrap();
        assert!(config.pim.is_some());
        assert!(config.igmp.is_some());

        let pim = config.pim.unwrap();
        assert!(pim.enabled);
        assert_eq!(pim.router_id, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(pim.interfaces.len(), 1);
        assert_eq!(pim.interfaces[0].name, "eth0");
        assert_eq!(pim.interfaces[0].dr_priority, 100);

        let igmp = config.igmp.unwrap();
        assert_eq!(igmp.querier_interfaces.len(), 2);
        assert_eq!(igmp.query_interval, 125);
        assert_eq!(igmp.robustness, 2);
    }

    // MSDP configuration validation tests
    #[test]
    fn test_msdp_config_valid() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: Some(MsdpConfig {
                enabled: true,
                local_address: Some("10.0.0.1".parse().unwrap()),
                peers: vec![MsdpPeerConfig {
                    address: "10.1.0.1".parse().unwrap(),
                    description: Some("Remote RP".to_string()),
                    mesh_group: None,
                    default_peer: false,
                }],
                keepalive_interval: 60,
                hold_time: 75,
            }),
            control_plane: None,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_msdp_config_invalid_local_address_multicast() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: Some(MsdpConfig {
                enabled: true,
                local_address: Some("224.0.0.1".parse().unwrap()), // Multicast address
                peers: vec![],
                keepalive_interval: 60,
                hold_time: 75,
            }),
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidMsdpConfig { .. })));
    }

    #[test]
    fn test_msdp_config_invalid_peer_address_multicast() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: Some(MsdpConfig {
                enabled: true,
                local_address: Some("10.0.0.1".parse().unwrap()),
                peers: vec![MsdpPeerConfig {
                    address: "239.1.1.1".parse().unwrap(), // Multicast address
                    description: None,
                    mesh_group: None,
                    default_peer: false,
                }],
                keepalive_interval: 60,
                hold_time: 75,
            }),
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidMsdpConfig { .. })));
    }

    #[test]
    fn test_msdp_config_invalid_keepalive_zero() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: Some(MsdpConfig {
                enabled: true,
                local_address: None,
                peers: vec![],
                keepalive_interval: 0, // Invalid
                hold_time: 75,
            }),
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidMsdpConfig { .. })));
    }

    #[test]
    fn test_msdp_config_invalid_hold_time_less_than_keepalive() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: Some(MsdpConfig {
                enabled: true,
                local_address: None,
                peers: vec![],
                keepalive_interval: 60,
                hold_time: 50, // Must be > keepalive_interval
            }),
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidMsdpConfig { .. })));
    }

    #[test]
    fn test_msdp_config_duplicate_peers() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: Some(MsdpConfig {
                enabled: true,
                local_address: None,
                peers: vec![
                    MsdpPeerConfig {
                        address: "10.0.0.1".parse().unwrap(),
                        description: None,
                        mesh_group: None,
                        default_peer: false,
                    },
                    MsdpPeerConfig {
                        address: "10.0.0.1".parse().unwrap(), // Duplicate
                        description: None,
                        mesh_group: None,
                        default_peer: false,
                    },
                ],
                keepalive_interval: 60,
                hold_time: 75,
            }),
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidMsdpConfig { .. })));
    }

    #[test]
    fn test_msdp_config_invalid_mesh_group_empty() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: Some(MsdpConfig {
                enabled: true,
                local_address: None,
                peers: vec![MsdpPeerConfig {
                    address: "10.0.0.1".parse().unwrap(),
                    description: None,
                    mesh_group: Some("".to_string()), // Empty mesh group
                    default_peer: false,
                }],
                keepalive_interval: 60,
                hold_time: 75,
            }),
            control_plane: None,
        };

        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::InvalidMsdpConfig { .. })));
    }

    #[test]
    fn test_parse_msdp_config() {
        let json5 = r#"{
            msdp: {
                enabled: true,
                local_address: "10.0.0.1",
                keepalive_interval: 60,
                hold_time: 75,
                peers: [
                    { address: "10.1.0.1", description: "Remote RP" },
                    { address: "10.2.0.1", mesh_group: "anycast-rp" },
                ],
            },
        }"#;

        let config = Config::parse(json5).unwrap();
        assert!(config.msdp.is_some());

        let msdp = config.msdp.unwrap();
        assert!(msdp.enabled);
        assert_eq!(msdp.local_address, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(msdp.keepalive_interval, 60);
        assert_eq!(msdp.hold_time, 75);
        assert_eq!(msdp.peers.len(), 2);
        assert_eq!(
            msdp.peers[0].address,
            "10.1.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(msdp.peers[0].description, Some("Remote RP".to_string()));
        assert_eq!(msdp.peers[1].mesh_group, Some("anycast-rp".to_string()));
    }

    #[test]
    fn test_control_plane_config_valid_disabled() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: Some(ControlPlaneConfig {
                rpf_provider: "disabled".to_string(),
                external_neighbors_enabled: true,
                event_buffer_size: 256,
            }),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_control_plane_config_valid_static() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: Some(ControlPlaneConfig {
                rpf_provider: "static".to_string(),
                external_neighbors_enabled: false,
                event_buffer_size: 1024,
            }),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_control_plane_config_valid_external() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: Some(ControlPlaneConfig {
                rpf_provider: "/var/run/babel-rpf.sock".to_string(),
                external_neighbors_enabled: true,
                event_buffer_size: 512,
            }),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_control_plane_config_invalid_rpf_provider() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: Some(ControlPlaneConfig {
                rpf_provider: "invalid".to_string(), // Not disabled, static, or absolute path
                external_neighbors_enabled: true,
                event_buffer_size: 256,
            }),
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidControlPlane { .. })
        ));
    }

    #[test]
    fn test_control_plane_config_invalid_buffer_size_zero() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: Some(ControlPlaneConfig {
                rpf_provider: "disabled".to_string(),
                external_neighbors_enabled: true,
                event_buffer_size: 0, // Invalid
            }),
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidControlPlane { .. })
        ));
    }

    #[test]
    fn test_control_plane_config_invalid_buffer_size_too_large() {
        let config = Config {
            pinning: HashMap::new(),
            rules: vec![],
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: Some(ControlPlaneConfig {
                rpf_provider: "disabled".to_string(),
                external_neighbors_enabled: true,
                event_buffer_size: 100000, // Too large
            }),
        };

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidControlPlane { .. })
        ));
    }

    #[test]
    fn test_parse_control_plane_config() {
        let json5 = r#"{
            control_plane: {
                rpf_provider: "static",
                external_neighbors_enabled: false,
                event_buffer_size: 512,
            },
        }"#;

        let config = Config::parse(json5).unwrap();
        assert!(config.control_plane.is_some());

        let cp = config.control_plane.unwrap();
        assert_eq!(cp.rpf_provider, "static");
        assert!(!cp.external_neighbors_enabled);
        assert_eq!(cp.event_buffer_size, 512);
    }

    #[test]
    fn test_control_plane_config_defaults() {
        let json5 = r#"{
            control_plane: {},
        }"#;

        let config = Config::parse(json5).unwrap();
        assert!(config.control_plane.is_some());

        let cp = config.control_plane.unwrap();
        assert_eq!(cp.rpf_provider, "disabled");
        assert!(cp.external_neighbors_enabled);
        assert_eq!(cp.event_buffer_size, 256);
    }
}
