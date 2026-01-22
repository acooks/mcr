// SPDX-License-Identifier: Apache-2.0 OR MIT
//! PIM-SM State Machine Implementation (RFC 7761 subset)
//!
//! This module implements PIM-SM (Protocol Independent Multicast - Sparse Mode)
//! for building multicast distribution trees.
//!
//! ## Scope
//!
//! This implementation focuses on the RP (Rendezvous Point) functionality:
//! - Neighbor discovery and Hello exchange
//! - DR (Designated Router) election
//! - (*,G) and (S,G) state management
//! - Join/Prune handling
//! - Register message handling (RP role)
//!
//! ## Out of Scope (Future Work)
//!
//! - BSR (Bootstrap Router) / Auto-RP
//! - PIM-DM / Bidir-PIM
//! - Assert handling
//! - SPT switchover logic
//!
//! ## Key Addresses
//!
//! | Address | Purpose |
//! |---------|---------|
//! | 224.0.0.13 | ALL-PIM-ROUTERS |
//! | IP Protocol 103 | PIM packets |
//!
//! ## Message Types
//!
//! | Type | Value | Description |
//! |------|-------|-------------|
//! | Hello | 0 | Neighbor discovery |
//! | Register | 1 | First-hop to RP |
//! | Register-Stop | 2 | RP to first-hop |
//! | Join/Prune | 3 | Tree maintenance |
//! | Bootstrap | 4 | BSR election (not implemented) |
//! | Assert | 5 | Forwarder election (not implemented) |

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::{PacketBuilder, TimerRequest, TimerType};

// PIM message types
pub const PIM_HELLO: u8 = 0;
pub const PIM_REGISTER: u8 = 1;
pub const PIM_REGISTER_STOP: u8 = 2;
pub const PIM_JOIN_PRUNE: u8 = 3;
pub const PIM_BOOTSTRAP: u8 = 4;
pub const PIM_ASSERT: u8 = 5;
pub const PIM_GRAFT: u8 = 6;
pub const PIM_GRAFT_ACK: u8 = 7;
pub const PIM_CANDIDATE_RP: u8 = 8;

// Hello option types
pub const PIM_HELLO_HOLDTIME: u16 = 1;
pub const PIM_HELLO_LAN_PRUNE_DELAY: u16 = 2;
pub const PIM_HELLO_DR_PRIORITY: u16 = 19;
pub const PIM_HELLO_GENERATION_ID: u16 = 20;
pub const PIM_HELLO_ADDRESS_LIST: u16 = 24;

// Default timer values (RFC 7761)
pub const DEFAULT_HELLO_PERIOD: Duration = Duration::from_secs(30);
pub const DEFAULT_HELLO_HOLDTIME: Duration = Duration::from_secs(105); // 3.5 * Hello Period
pub const DEFAULT_JOIN_PRUNE_PERIOD: Duration = Duration::from_secs(60);
pub const DEFAULT_JOIN_PRUNE_HOLDTIME: Duration = Duration::from_secs(210); // 3.5 * JP Period
pub const DEFAULT_DR_PRIORITY: u32 = 1;
pub const DEFAULT_REGISTER_SUPPRESS_TIME: Duration = Duration::from_secs(60);

/// All PIM routers multicast address (224.0.0.13)
pub const ALL_PIM_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

/// Configuration for PIM on an interface
#[derive(Debug, Clone)]
pub struct PimInterfaceConfig {
    /// Period between Hello messages
    pub hello_period: Duration,
    /// Holdtime advertised in Hello (neighbor expiry)
    pub hello_holdtime: Duration,
    /// DR priority for this interface
    pub dr_priority: u32,
}

impl Default for PimInterfaceConfig {
    fn default() -> Self {
        Self {
            hello_period: DEFAULT_HELLO_PERIOD,
            hello_holdtime: DEFAULT_HELLO_HOLDTIME,
            dr_priority: DEFAULT_DR_PRIORITY,
        }
    }
}

/// Global PIM configuration
#[derive(Debug, Clone, Default)]
pub struct PimConfig {
    /// Router ID (typically highest loopback IP)
    pub router_id: Option<Ipv4Addr>,
    /// Per-interface configuration
    pub interfaces: HashMap<String, PimInterfaceConfig>,
    /// Static RP mappings (group prefix -> RP address)
    pub static_rp: HashMap<Ipv4Addr, Ipv4Addr>,
    /// Our RP address (if we are an RP)
    pub rp_address: Option<Ipv4Addr>,
    /// Join/Prune period
    pub join_prune_period: Duration,
    /// Join/Prune holdtime
    pub join_prune_holdtime: Duration,
}

impl PimConfig {
    /// Get the RP for a group (from static configuration)
    pub fn get_rp_for_group(&self, group: Ipv4Addr) -> Option<Ipv4Addr> {
        // Simple longest-prefix match on group address
        // In practice, this would use a proper prefix trie
        self.static_rp
            .iter()
            .filter(|(prefix, _)| {
                // Check if group matches prefix (simplified - just exact match for now)
                // A real implementation would check prefix length
                **prefix == group || group.octets()[0] == prefix.octets()[0] // Same first octet
            })
            .map(|(_, rp)| *rp)
            .next()
    }

    /// Check if we are the RP for this group
    pub fn is_rp_for_group(&self, group: Ipv4Addr) -> bool {
        if let Some(our_rp) = self.rp_address {
            self.get_rp_for_group(group) == Some(our_rp)
        } else {
            false
        }
    }
}

/// Events that can occur in the PIM state machine
#[derive(Debug, Clone)]
pub enum PimEvent {
    /// Enable PIM on an interface
    EnableInterface {
        interface: String,
        interface_ip: Ipv4Addr,
        dr_priority: Option<u32>,
    },
    /// Disable PIM on an interface
    DisableInterface { interface: String },
    /// Received a PIM packet
    PacketReceived {
        interface: String,
        src_ip: Ipv4Addr,
        msg_type: u8,
        payload: Vec<u8>,
    },
    /// Hello timer expired - send Hello
    HelloTimerExpired { interface: String },
    /// Neighbor expired - remove from table
    NeighborExpired {
        interface: String,
        neighbor: Ipv4Addr,
    },
    /// (*,G) or (S,G) state expired
    RouteExpired {
        source: Option<Ipv4Addr>,
        group: Ipv4Addr,
    },
    /// Configure static RP
    SetStaticRp { group: Ipv4Addr, rp: Ipv4Addr },
    /// Set our RP address
    SetRpAddress { rp: Ipv4Addr },
}

/// PIM neighbor state
#[derive(Debug, Clone)]
pub struct PimNeighbor {
    /// Neighbor's IP address
    pub address: Ipv4Addr,
    /// Interface the neighbor is reachable on
    pub interface: String,
    /// When the neighbor expires (based on Holdtime)
    pub expires_at: Instant,
    /// DR priority from Hello
    pub dr_priority: u32,
    /// Generation ID from Hello
    pub generation_id: u32,
}

impl PimNeighbor {
    /// Create a new neighbor entry
    pub fn new(
        address: Ipv4Addr,
        interface: String,
        expires_at: Instant,
        dr_priority: u32,
        generation_id: u32,
    ) -> Self {
        Self {
            address,
            interface,
            expires_at,
            dr_priority,
            generation_id,
        }
    }

    /// Check if the neighbor has expired
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Refresh the neighbor's expiry time
    pub fn refresh(&mut self, expires_at: Instant, dr_priority: u32, generation_id: u32) {
        self.expires_at = expires_at;
        self.dr_priority = dr_priority;
        // If generation ID changed, neighbor rebooted
        if self.generation_id != generation_id {
            self.generation_id = generation_id;
        }
    }
}

/// Per-interface PIM state
#[derive(Debug)]
pub struct PimInterfaceState {
    /// Interface name
    pub interface: String,
    /// Our IP address on this interface
    pub address: Ipv4Addr,
    /// Configuration
    pub config: PimInterfaceConfig,
    /// PIM neighbors on this interface
    pub neighbors: HashMap<Ipv4Addr, PimNeighbor>,
    /// Current Designated Router (DR)
    pub designated_router: Option<Ipv4Addr>,
    /// Our generation ID (random, changes on restart)
    pub generation_id: u32,
    /// When to send next Hello
    pub next_hello_time: Option<Instant>,
}

impl PimInterfaceState {
    /// Create new PIM interface state
    pub fn new(interface: String, address: Ipv4Addr, config: PimInterfaceConfig) -> Self {
        Self {
            interface,
            address,
            config,
            neighbors: HashMap::new(),
            designated_router: None,
            generation_id: rand::random(),
            next_hello_time: None,
        }
    }

    /// Check if we are the DR on this interface
    pub fn is_dr(&self) -> bool {
        self.designated_router == Some(self.address)
    }

    /// Run DR election and return true if DR changed
    pub fn elect_dr(&mut self) -> bool {
        let old_dr = self.designated_router;

        // Collect all candidates: neighbors + ourselves
        let mut candidates: Vec<(u32, Ipv4Addr)> = self
            .neighbors
            .values()
            .map(|n| (n.dr_priority, n.address))
            .collect();
        candidates.push((self.config.dr_priority, self.address));

        // Sort by (priority DESC, IP DESC) - highest wins
        candidates.sort_by(|a, b| {
            b.0.cmp(&a.0) // Higher priority first
                .then_with(|| b.1.cmp(&a.1)) // Then higher IP
        });

        self.designated_router = candidates.first().map(|(_, ip)| *ip);
        self.designated_router != old_dr
    }

    /// Process received Hello from a neighbor
    pub fn received_hello(
        &mut self,
        src_ip: Ipv4Addr,
        holdtime: Duration,
        dr_priority: u32,
        generation_id: u32,
        now: Instant,
    ) -> Vec<TimerRequest> {
        let mut timers = Vec::new();
        let expires_at = now + holdtime;

        if let Some(neighbor) = self.neighbors.get_mut(&src_ip) {
            // Existing neighbor - refresh
            neighbor.refresh(expires_at, dr_priority, generation_id);
        } else {
            // New neighbor
            let neighbor = PimNeighbor::new(
                src_ip,
                self.interface.clone(),
                expires_at,
                dr_priority,
                generation_id,
            );
            self.neighbors.insert(src_ip, neighbor);
        }

        // Schedule neighbor expiry timer
        timers.push(TimerRequest {
            timer_type: TimerType::PimNeighborExpiry {
                interface: self.interface.clone(),
                neighbor: src_ip,
            },
            fire_at: expires_at,
            replace_existing: true,
        });

        // Re-run DR election
        self.elect_dr();

        timers
    }

    /// Remove an expired neighbor
    pub fn neighbor_expired(&mut self, neighbor_ip: Ipv4Addr) -> bool {
        if self.neighbors.remove(&neighbor_ip).is_some() {
            // Re-run DR election
            self.elect_dr();
            true
        } else {
            false
        }
    }

    /// Get timers for Hello transmission
    pub fn hello_timer_expired(&mut self, now: Instant) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        // Schedule next Hello
        let next_hello = now + self.config.hello_period;
        self.next_hello_time = Some(next_hello);

        timers.push(TimerRequest {
            timer_type: TimerType::PimHello {
                interface: self.interface.clone(),
            },
            fire_at: next_hello,
            replace_existing: true,
        });

        timers
    }
}

/// Global PIM state
#[derive(Debug, Default)]
pub struct PimState {
    /// Global configuration
    pub config: PimConfig,
    /// Per-interface state
    pub interfaces: HashMap<String, PimInterfaceState>,
    /// (*,G) entries
    pub star_g: HashMap<Ipv4Addr, StarGState>,
    /// (S,G) entries
    pub sg: HashMap<(Ipv4Addr, Ipv4Addr), SGState>,
}

/// (*,G) shared tree state
#[derive(Debug, Clone)]
pub struct StarGState {
    /// Multicast group
    pub group: Ipv4Addr,
    /// RP for this group
    pub rp: Ipv4Addr,
    /// Upstream interface (toward RP)
    pub upstream_interface: Option<String>,
    /// Downstream interfaces with Join state
    pub downstream_interfaces: HashSet<String>,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry expires
    pub expires_at: Option<Instant>,
}

impl StarGState {
    /// Create new (*,G) state
    pub fn new(group: Ipv4Addr, rp: Ipv4Addr) -> Self {
        Self {
            group,
            rp,
            upstream_interface: None,
            downstream_interfaces: HashSet::new(),
            created_at: Instant::now(),
            expires_at: None,
        }
    }

    /// Add a downstream interface
    pub fn add_downstream(&mut self, interface: &str, holdtime: Duration) {
        self.downstream_interfaces.insert(interface.to_string());
        self.expires_at = Some(Instant::now() + holdtime);
    }

    /// Remove a downstream interface
    pub fn remove_downstream(&mut self, interface: &str) {
        self.downstream_interfaces.remove(interface);
    }

    /// Check if there are any downstream interfaces
    pub fn has_downstream(&self) -> bool {
        !self.downstream_interfaces.is_empty()
    }
}

/// (S,G) shortest-path tree state
#[derive(Debug, Clone)]
pub struct SGState {
    /// Source address
    pub source: Ipv4Addr,
    /// Multicast group
    pub group: Ipv4Addr,
    /// Upstream interface (toward source)
    pub upstream_interface: Option<String>,
    /// Downstream interfaces with Join state
    pub downstream_interfaces: HashSet<String>,
    /// Whether SPT bit is set
    pub spt_bit: bool,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry expires
    pub expires_at: Option<Instant>,
}

impl SGState {
    /// Create new (S,G) state
    pub fn new(source: Ipv4Addr, group: Ipv4Addr) -> Self {
        Self {
            source,
            group,
            upstream_interface: None,
            downstream_interfaces: HashSet::new(),
            spt_bit: false,
            created_at: Instant::now(),
            expires_at: None,
        }
    }

    /// Add a downstream interface
    pub fn add_downstream(&mut self, interface: &str, holdtime: Duration) {
        self.downstream_interfaces.insert(interface.to_string());
        self.expires_at = Some(Instant::now() + holdtime);
    }

    /// Remove a downstream interface
    pub fn remove_downstream(&mut self, interface: &str) {
        self.downstream_interfaces.remove(interface);
    }

    /// Check if there are any downstream interfaces
    pub fn has_downstream(&self) -> bool {
        !self.downstream_interfaces.is_empty()
    }
}

impl PimState {
    /// Create new global PIM state
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable PIM on an interface
    pub fn enable_interface(
        &mut self,
        interface: &str,
        address: Ipv4Addr,
        config: PimInterfaceConfig,
    ) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        let state = PimInterfaceState::new(interface.to_string(), address, config.clone());

        // Schedule first Hello
        let hello_time = Instant::now();
        timers.push(TimerRequest {
            timer_type: TimerType::PimHello {
                interface: interface.to_string(),
            },
            fire_at: hello_time,
            replace_existing: true,
        });

        self.interfaces.insert(interface.to_string(), state);
        timers
    }

    /// Disable PIM on an interface
    pub fn disable_interface(&mut self, interface: &str) {
        self.interfaces.remove(interface);

        // Clean up (*,G) and (S,G) entries that use this interface
        self.star_g.retain(|_, state| {
            state.downstream_interfaces.remove(interface);
            state.upstream_interface.as_ref() != Some(&interface.to_string())
                && !state.downstream_interfaces.is_empty()
        });

        self.sg.retain(|_, state| {
            state.downstream_interfaces.remove(interface);
            state.upstream_interface.as_ref() != Some(&interface.to_string())
                && !state.downstream_interfaces.is_empty()
        });
    }

    /// Get interface state
    pub fn get_interface(&self, interface: &str) -> Option<&PimInterfaceState> {
        self.interfaces.get(interface)
    }

    /// Get mutable interface state
    pub fn get_interface_mut(&mut self, interface: &str) -> Option<&mut PimInterfaceState> {
        self.interfaces.get_mut(interface)
    }

    /// Process a received Join/Prune message
    pub fn process_join_prune(
        &mut self,
        interface: &str,
        _upstream_neighbor: Ipv4Addr,
        joins: &[(Option<Ipv4Addr>, Ipv4Addr)], // (source, group) - None source = (*,G)
        prunes: &[(Option<Ipv4Addr>, Ipv4Addr)],
        holdtime: Duration,
    ) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        // Process Joins
        for (source, group) in joins {
            match source {
                None => {
                    // (*,G) Join
                    let rp = self.config.get_rp_for_group(*group);
                    if let Some(rp) = rp {
                        let state = self
                            .star_g
                            .entry(*group)
                            .or_insert_with(|| StarGState::new(*group, rp));
                        state.add_downstream(interface, holdtime);

                        timers.push(TimerRequest {
                            timer_type: TimerType::PimStarGExpiry { group: *group },
                            fire_at: Instant::now() + holdtime,
                            replace_existing: true,
                        });
                    }
                }
                Some(src) => {
                    // (S,G) Join
                    let state = self
                        .sg
                        .entry((*src, *group))
                        .or_insert_with(|| SGState::new(*src, *group));
                    state.add_downstream(interface, holdtime);

                    timers.push(TimerRequest {
                        timer_type: TimerType::PimSGExpiry {
                            source: *src,
                            group: *group,
                        },
                        fire_at: Instant::now() + holdtime,
                        replace_existing: true,
                    });
                }
            }
        }

        // Process Prunes
        for (source, group) in prunes {
            match source {
                None => {
                    // (*,G) Prune
                    if let Some(state) = self.star_g.get_mut(group) {
                        state.remove_downstream(interface);
                    }
                }
                Some(src) => {
                    // (S,G) Prune
                    if let Some(state) = self.sg.get_mut(&(*src, *group)) {
                        state.remove_downstream(interface);
                    }
                }
            }
        }

        // Clean up empty entries
        self.star_g.retain(|_, state| state.has_downstream());
        self.sg.retain(|_, state| state.has_downstream());

        timers
    }

    /// Process a received Register message (RP function)
    pub fn process_register(
        &mut self,
        source: Ipv4Addr,
        group: Ipv4Addr,
        _null_register: bool,
    ) -> (bool, Option<SGState>) {
        // Check if we're the RP for this group
        if !self.config.is_rp_for_group(group) {
            return (false, None);
        }

        // Create (S,G) state if it doesn't exist
        let state = self
            .sg
            .entry((source, group))
            .or_insert_with(|| SGState::new(source, group));

        // The RP should forward data to (*,G) downstream interfaces
        // For now, just return the state
        (true, Some(state.clone()))
    }

    /// Get all neighbors across all interfaces
    pub fn all_neighbors(&self) -> Vec<&PimNeighbor> {
        self.interfaces
            .values()
            .flat_map(|iface| iface.neighbors.values())
            .collect()
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&mut self, now: Instant) {
        // Clean up (*,G)
        self.star_g
            .retain(|_, state| state.expires_at.is_none_or(|expires| expires > now));

        // Clean up (S,G)
        self.sg
            .retain(|_, state| state.expires_at.is_none_or(|expires| expires > now));
    }
}

/// Parsed PIM header (common header for all PIM messages)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimHeader {
    /// PIM version (must be 2)
    pub version: u8,
    /// Message type
    pub msg_type: u8,
    /// Reserved field
    pub reserved: u8,
    /// Checksum
    pub checksum: u16,
}

impl PimHeader {
    /// Parse a PIM header from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let ver_type = data[0];
        let version = (ver_type >> 4) & 0x0F;
        let msg_type = ver_type & 0x0F;

        if version != 2 {
            return None;
        }

        Some(Self {
            version,
            msg_type,
            reserved: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
        })
    }

    /// Get the message type as a string
    pub fn type_name(&self) -> &'static str {
        match self.msg_type {
            PIM_HELLO => "Hello",
            PIM_REGISTER => "Register",
            PIM_REGISTER_STOP => "Register-Stop",
            PIM_JOIN_PRUNE => "Join/Prune",
            PIM_BOOTSTRAP => "Bootstrap",
            PIM_ASSERT => "Assert",
            PIM_GRAFT => "Graft",
            PIM_GRAFT_ACK => "Graft-Ack",
            PIM_CANDIDATE_RP => "Candidate-RP",
            _ => "Unknown",
        }
    }
}

/// Parsed PIM Hello option
#[derive(Debug, Clone)]
pub enum PimHelloOption {
    /// Holdtime in seconds
    Holdtime(u16),
    /// DR Priority
    DrPriority(u32),
    /// Generation ID
    GenerationId(u32),
    /// Unknown option
    Unknown { option_type: u16, data: Vec<u8> },
}

impl PimHelloOption {
    /// Parse Hello options from payload
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut options = Vec::new();
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let option_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let option_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + option_len > data.len() {
                break;
            }

            let option_data = &data[offset..offset + option_len];
            offset += option_len;

            let option = match option_type {
                PIM_HELLO_HOLDTIME if option_len >= 2 => {
                    PimHelloOption::Holdtime(u16::from_be_bytes([option_data[0], option_data[1]]))
                }
                PIM_HELLO_DR_PRIORITY if option_len >= 4 => {
                    PimHelloOption::DrPriority(u32::from_be_bytes([
                        option_data[0],
                        option_data[1],
                        option_data[2],
                        option_data[3],
                    ]))
                }
                PIM_HELLO_GENERATION_ID if option_len >= 4 => {
                    PimHelloOption::GenerationId(u32::from_be_bytes([
                        option_data[0],
                        option_data[1],
                        option_data[2],
                        option_data[3],
                    ]))
                }
                _ => PimHelloOption::Unknown {
                    option_type,
                    data: option_data.to_vec(),
                },
            };

            options.push(option);
        }

        options
    }
}

/// Builder for PIM Hello packets
#[derive(Debug)]
pub struct PimHelloBuilder {
    /// Holdtime in seconds
    pub holdtime: u16,
    /// DR Priority
    pub dr_priority: u32,
    /// Generation ID
    pub generation_id: u32,
}

impl PimHelloBuilder {
    /// Create a new Hello builder
    pub fn new(holdtime_secs: u16, dr_priority: u32, generation_id: u32) -> Self {
        Self {
            holdtime: holdtime_secs,
            dr_priority,
            generation_id,
        }
    }
}

impl PacketBuilder for PimHelloBuilder {
    fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(24);

        // PIM header: Version 2, Type 0 (Hello)
        packet.push((2 << 4) | PIM_HELLO);
        packet.push(0); // Reserved
        packet.push(0); // Checksum placeholder
        packet.push(0);

        // Holdtime option (type 1)
        packet.extend_from_slice(&PIM_HELLO_HOLDTIME.to_be_bytes());
        packet.extend_from_slice(&2u16.to_be_bytes()); // Length
        packet.extend_from_slice(&self.holdtime.to_be_bytes());

        // DR Priority option (type 19)
        packet.extend_from_slice(&PIM_HELLO_DR_PRIORITY.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes()); // Length
        packet.extend_from_slice(&self.dr_priority.to_be_bytes());

        // Generation ID option (type 20)
        packet.extend_from_slice(&PIM_HELLO_GENERATION_ID.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes()); // Length
        packet.extend_from_slice(&self.generation_id.to_be_bytes());

        // Calculate and insert checksum
        let checksum = self.calculate_checksum(&packet);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = (checksum & 0xFF) as u8;

        packet
    }
}

/// Helper to generate random u32 for generation ID
mod rand {
    use std::time::SystemTime;

    /// Generate a pseudo-random u32 for generation ID
    pub fn random() -> u32 {
        let duration = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        // Mix nanoseconds to get pseudo-randomness
        (duration.as_nanos() as u32) ^ (duration.as_secs() as u32).wrapping_mul(2654435769)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pim_interface_config_default() {
        let config = PimInterfaceConfig::default();
        assert_eq!(config.hello_period, Duration::from_secs(30));
        assert_eq!(config.hello_holdtime, Duration::from_secs(105));
        assert_eq!(config.dr_priority, 1);
    }

    #[test]
    fn test_pim_interface_state_new() {
        let state = PimInterfaceState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        assert_eq!(state.interface, "eth0");
        assert!(state.neighbors.is_empty());
        assert!(state.designated_router.is_none());
    }

    #[test]
    fn test_dr_election() {
        let mut state = PimInterfaceState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig {
                dr_priority: 100,
                ..Default::default()
            },
        );

        // Initially we're DR (no neighbors)
        state.elect_dr();
        assert!(state.is_dr());

        // Add neighbor with higher priority
        let now = Instant::now();
        state.received_hello(
            "192.168.1.2".parse().unwrap(),
            Duration::from_secs(105),
            200, // Higher priority
            12345,
            now,
        );

        // Neighbor should be DR now
        assert!(!state.is_dr());
        assert_eq!(
            state.designated_router,
            Some("192.168.1.2".parse().unwrap())
        );
    }

    #[test]
    fn test_dr_election_ip_tiebreaker() {
        let mut state = PimInterfaceState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig {
                dr_priority: 100,
                ..Default::default()
            },
        );

        // Add neighbor with same priority but higher IP
        let now = Instant::now();
        state.received_hello(
            "192.168.1.10".parse().unwrap(),
            Duration::from_secs(105),
            100, // Same priority
            12345,
            now,
        );

        // Higher IP wins, so neighbor should be DR
        assert!(!state.is_dr());
        assert_eq!(
            state.designated_router,
            Some("192.168.1.10".parse().unwrap())
        );
    }

    #[test]
    fn test_pim_header_parse() {
        // PIM Hello: version 2, type 0
        let data = [0x20, 0x00, 0x00, 0x00];
        let header = PimHeader::parse(&data).unwrap();

        assert_eq!(header.version, 2);
        assert_eq!(header.msg_type, PIM_HELLO);
        assert_eq!(header.type_name(), "Hello");
    }

    #[test]
    fn test_pim_header_parse_invalid_version() {
        // PIM with version 1 (invalid)
        let data = [0x10, 0x00, 0x00, 0x00];
        let header = PimHeader::parse(&data);
        assert!(header.is_none());
    }

    #[test]
    fn test_pim_hello_options_parse() {
        // Build a Hello option payload
        let mut payload = Vec::new();

        // Holdtime option: type=1, len=2, value=105
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        payload.extend_from_slice(&105u16.to_be_bytes());

        // DR Priority option: type=19, len=4, value=100
        payload.extend_from_slice(&19u16.to_be_bytes());
        payload.extend_from_slice(&4u16.to_be_bytes());
        payload.extend_from_slice(&100u32.to_be_bytes());

        let options = PimHelloOption::parse_all(&payload);
        assert_eq!(options.len(), 2);

        match &options[0] {
            PimHelloOption::Holdtime(h) => assert_eq!(*h, 105),
            _ => panic!("Expected Holdtime option"),
        }

        match &options[1] {
            PimHelloOption::DrPriority(p) => assert_eq!(*p, 100),
            _ => panic!("Expected DrPriority option"),
        }
    }

    #[test]
    fn test_pim_hello_builder() {
        let builder = PimHelloBuilder::new(105, 100, 12345);
        let packet = builder.build();

        // Parse the header
        let header = PimHeader::parse(&packet).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.msg_type, PIM_HELLO);

        // Parse options (skip 4-byte header)
        let options = PimHelloOption::parse_all(&packet[4..]);
        assert_eq!(options.len(), 3); // Holdtime, DR Priority, Generation ID
    }

    #[test]
    fn test_pim_state_enable_interface() {
        let mut state = PimState::new();

        let timers = state.enable_interface(
            "eth0",
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        assert!(state.interfaces.contains_key("eth0"));
        assert!(!timers.is_empty()); // Should have Hello timer
    }

    #[test]
    fn test_star_g_state() {
        let mut state = StarGState::new("239.1.1.1".parse().unwrap(), "10.0.0.1".parse().unwrap());

        assert!(!state.has_downstream());

        state.add_downstream("eth1", Duration::from_secs(210));
        assert!(state.has_downstream());

        state.remove_downstream("eth1");
        assert!(!state.has_downstream());
    }

    #[test]
    fn test_sg_state() {
        let mut state = SGState::new("10.0.0.5".parse().unwrap(), "239.2.2.2".parse().unwrap());

        assert!(!state.has_downstream());
        assert!(!state.spt_bit);

        state.add_downstream("eth1", Duration::from_secs(210));
        assert!(state.has_downstream());
    }

    #[test]
    fn test_process_join_prune() {
        let mut state = PimState::new();
        state
            .config
            .static_rp
            .insert("239.0.0.0".parse().unwrap(), "10.0.0.1".parse().unwrap());

        // Process a (*,G) Join
        let joins = vec![(None, "239.1.1.1".parse().unwrap())];
        let prunes = vec![];

        let timers = state.process_join_prune(
            "eth0",
            "192.168.1.2".parse().unwrap(),
            &joins,
            &prunes,
            Duration::from_secs(210),
        );

        assert!(!timers.is_empty());
        assert!(state.star_g.contains_key(&"239.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_neighbor_expiry() {
        let mut state = PimInterfaceState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        let now = Instant::now();
        state.received_hello(
            "192.168.1.2".parse().unwrap(),
            Duration::from_secs(105),
            100,
            12345,
            now,
        );

        assert_eq!(state.neighbors.len(), 1);

        let removed = state.neighbor_expired("192.168.1.2".parse().unwrap());
        assert!(removed);
        assert!(state.neighbors.is_empty());
    }
}
