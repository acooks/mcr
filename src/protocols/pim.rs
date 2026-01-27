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
use crate::{ExternalNeighbor, NeighborSource, RpfInfo, RpfProvider};

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
    /// RPF provider configuration
    pub rpf_provider: RpfProvider,
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
    /// Direct-connect source detected (multicast traffic from source on DR interface)
    /// This is used when the RP is also the DR for the source's subnet
    DirectSourceDetected {
        interface: String,
        source: Ipv4Addr,
        group: Ipv4Addr,
    },
}

/// PIM neighbor state
#[derive(Debug, Clone)]
pub struct PimNeighbor {
    /// Neighbor's IP address
    pub address: Ipv4Addr,
    /// Interface the neighbor is reachable on
    pub interface: String,
    /// When the neighbor expires (based on Holdtime) - None for external neighbors
    pub expires_at: Option<Instant>,
    /// DR priority from Hello or external config
    pub dr_priority: u32,
    /// Generation ID from Hello - None for external neighbors
    pub generation_id: Option<u32>,
    /// Source of this neighbor (Hello-learned or external)
    pub source: NeighborSource,
}

impl PimNeighbor {
    /// Create a new Hello-learned neighbor entry
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
            expires_at: Some(expires_at),
            dr_priority,
            generation_id: Some(generation_id),
            source: NeighborSource::PimHello,
        }
    }

    /// Create an external neighbor entry (no expiry, managed externally)
    pub fn new_external(
        address: Ipv4Addr,
        interface: String,
        dr_priority: u32,
        tag: Option<String>,
    ) -> Self {
        Self {
            address,
            interface,
            expires_at: None,
            dr_priority,
            generation_id: None,
            source: NeighborSource::External { tag },
        }
    }

    /// Check if this is an external neighbor
    pub fn is_external(&self) -> bool {
        matches!(self.source, NeighborSource::External { .. })
    }

    /// Check if the neighbor has expired (external neighbors never expire)
    pub fn is_expired(&self, now: Instant) -> bool {
        match self.expires_at {
            Some(expires_at) => now >= expires_at,
            None => false, // External neighbors don't expire
        }
    }

    /// Refresh the neighbor's expiry time (Hello-learned neighbors only)
    pub fn refresh(&mut self, expires_at: Instant, dr_priority: u32, generation_id: u32) {
        // If this was an external neighbor and we receive a Hello, transition to Hello-learned
        if self.is_external() {
            self.source = NeighborSource::PimHello;
        }
        self.expires_at = Some(expires_at);
        self.dr_priority = dr_priority;
        // If generation ID changed, neighbor rebooted
        if self.generation_id != Some(generation_id) {
            self.generation_id = Some(generation_id);
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

    /// Check if a neighbor exists on this interface
    pub fn has_neighbor(&self, addr: Ipv4Addr) -> bool {
        self.neighbors.contains_key(&addr)
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
    /// Static RPF entries (source -> RPF info)
    pub static_rpf: HashMap<Ipv4Addr, RpfInfo>,
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

        let mut state = PimInterfaceState::new(interface.to_string(), address, config.clone());

        // Run initial DR election - with no neighbors, we become DR
        state.elect_dr();

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

    /// Find the PIM-enabled interface that's in the same subnet as the given neighbor IP.
    ///
    /// This is used to handle cases where IP_PKTINFO reports the wrong interface,
    /// such as in shared namespace test setups.
    pub fn find_interface_for_neighbor(&self, neighbor_ip: Ipv4Addr) -> Option<String> {
        use pnet::datalink::interfaces;

        // Get all system interfaces and their IP configurations
        let system_ifaces = interfaces();

        for iface_name in self.interfaces.keys() {
            // Find the system interface with this name
            if let Some(sys_iface) = system_ifaces.iter().find(|i| &i.name == iface_name) {
                // Check if neighbor_ip is in the same subnet as any of the interface's IPs
                for ip_net in &sys_iface.ips {
                    if ip_net.ip().is_ipv4() {
                        // Check if neighbor IP is in this subnet
                        if ip_net.contains(std::net::IpAddr::V4(neighbor_ip)) {
                            return Some(iface_name.clone());
                        }
                    }
                }
            }
        }
        None
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

    /// Add an external neighbor (injected by external control plane)
    /// Returns true if neighbor was added, false if interface doesn't exist
    pub fn add_external_neighbor(&mut self, neighbor: &ExternalNeighbor) -> bool {
        if let Some(iface_state) = self.interfaces.get_mut(&neighbor.interface) {
            let pim_neighbor = PimNeighbor::new_external(
                neighbor.address,
                neighbor.interface.clone(),
                neighbor.dr_priority.unwrap_or(DEFAULT_DR_PRIORITY),
                neighbor.tag.clone(),
            );
            iface_state.neighbors.insert(neighbor.address, pim_neighbor);
            // Re-run DR election with new neighbor
            iface_state.elect_dr();
            true
        } else {
            false
        }
    }

    /// Remove an external neighbor
    /// Returns true if neighbor was removed, false if not found or not external
    pub fn remove_external_neighbor(&mut self, address: Ipv4Addr, interface: &str) -> bool {
        if let Some(iface_state) = self.interfaces.get_mut(interface) {
            // Only remove if it's an external neighbor
            if let Some(neighbor) = iface_state.neighbors.get(&address) {
                if neighbor.is_external() {
                    iface_state.neighbors.remove(&address);
                    // Re-run DR election
                    iface_state.elect_dr();
                    return true;
                }
            }
        }
        false
    }

    /// List all external neighbors
    pub fn list_external_neighbors(&self) -> Vec<&PimNeighbor> {
        self.interfaces
            .values()
            .flat_map(|iface| iface.neighbors.values())
            .filter(|n| n.is_external())
            .collect()
    }

    /// Clear all external neighbors, optionally filtered by interface
    /// Returns the number of neighbors removed
    pub fn clear_external_neighbors(&mut self, interface: Option<&str>) -> usize {
        let mut removed = 0;

        let interfaces_to_clear: Vec<String> = match interface {
            Some(iface) => vec![iface.to_string()],
            None => self.interfaces.keys().cloned().collect(),
        };

        for iface_name in interfaces_to_clear {
            if let Some(iface_state) = self.interfaces.get_mut(&iface_name) {
                let before = iface_state.neighbors.len();
                iface_state.neighbors.retain(|_, n| !n.is_external());
                let after = iface_state.neighbors.len();
                removed += before - after;

                if before != after {
                    // Re-run DR election if we removed any
                    iface_state.elect_dr();
                }
            }
        }

        removed
    }

    /// Check if a neighbor is valid (either Hello-learned and not expired, or external)
    pub fn is_valid_neighbor(&self, address: Ipv4Addr, interface: &str, now: Instant) -> bool {
        if let Some(iface_state) = self.interfaces.get(interface) {
            if let Some(neighbor) = iface_state.neighbors.get(&address) {
                return !neighbor.is_expired(now);
            }
        }
        false
    }

    // --- RPF Management Methods ---

    /// Set the RPF provider
    pub fn set_rpf_provider(&mut self, provider: RpfProvider) {
        self.config.rpf_provider = provider;
    }

    /// Get the current RPF provider
    pub fn get_rpf_provider(&self) -> &RpfProvider {
        &self.config.rpf_provider
    }

    /// Add a static RPF entry
    pub fn add_rpf_route(&mut self, source: Ipv4Addr, rpf: RpfInfo) {
        self.static_rpf.insert(source, rpf);
    }

    /// Remove a static RPF entry
    /// Returns true if entry was found and removed
    pub fn remove_rpf_route(&mut self, source: Ipv4Addr) -> bool {
        self.static_rpf.remove(&source).is_some()
    }

    /// Get all static RPF entries
    pub fn get_rpf_routes(&self) -> Vec<(Ipv4Addr, &RpfInfo)> {
        self.static_rpf.iter().map(|(s, r)| (*s, r)).collect()
    }

    /// Clear all static RPF entries
    /// Returns the number of entries removed
    pub fn clear_rpf_routes(&mut self) -> usize {
        let count = self.static_rpf.len();
        self.static_rpf.clear();
        count
    }

    /// Lookup RPF information for a source address
    /// Returns RPF info if found based on current provider configuration
    pub fn lookup_rpf(&self, source: Ipv4Addr) -> Option<&RpfInfo> {
        match &self.config.rpf_provider {
            RpfProvider::Disabled => None,
            RpfProvider::Static => self.static_rpf.get(&source),
            RpfProvider::External { .. } => {
                // For external provider, we only check static entries here
                // External lookups are handled asynchronously by the supervisor
                self.static_rpf.get(&source)
            }
        }
    }

    /// Check if the RPF interface for a source matches the expected interface
    /// Returns true if RPF check passes or RPF is disabled
    pub fn check_rpf(&self, source: Ipv4Addr, interface: &str) -> bool {
        match &self.config.rpf_provider {
            RpfProvider::Disabled => true, // No RPF check
            RpfProvider::Static | RpfProvider::External { .. } => {
                match self.static_rpf.get(&source) {
                    Some(rpf) => rpf.upstream_interface == interface,
                    None => {
                        // No RPF entry found - behavior depends on provider
                        // For static: fail (must have explicit entry)
                        // For external: could be pending lookup, allow for now
                        matches!(self.config.rpf_provider, RpfProvider::External { .. })
                    }
                }
            }
        }
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

/// A join or prune entry for a specific group
#[derive(Debug, Clone)]
pub struct JoinPruneGroup {
    /// The multicast group address
    pub group: Ipv4Addr,
    /// Joined sources: None = (*,G), Some(source) = (S,G)
    pub joins: Vec<Option<Ipv4Addr>>,
    /// Pruned sources: None = (*,G), Some(source) = (S,G)
    pub prunes: Vec<Option<Ipv4Addr>>,
    /// RP address (used for (*,G) joins where "source" field contains RP)
    pub rp: Option<Ipv4Addr>,
}

impl JoinPruneGroup {
    /// Create a (*,G) Join entry
    pub fn star_g_join(group: Ipv4Addr, rp: Ipv4Addr) -> Self {
        Self {
            group,
            joins: vec![None], // None indicates (*,G)
            prunes: vec![],
            rp: Some(rp),
        }
    }

    /// Create an (S,G) Join entry
    pub fn sg_join(group: Ipv4Addr, source: Ipv4Addr) -> Self {
        Self {
            group,
            joins: vec![Some(source)],
            prunes: vec![],
            rp: None,
        }
    }

    /// Create a (*,G) Prune entry
    pub fn star_g_prune(group: Ipv4Addr, rp: Ipv4Addr) -> Self {
        Self {
            group,
            joins: vec![],
            prunes: vec![None],
            rp: Some(rp),
        }
    }

    /// Create an (S,G) Prune entry
    pub fn sg_prune(group: Ipv4Addr, source: Ipv4Addr) -> Self {
        Self {
            group,
            joins: vec![],
            prunes: vec![Some(source)],
            rp: None,
        }
    }
}

/// Builder for PIM Join/Prune packets (RFC 7761 Section 4.9.5)
///
/// Join/Prune packet format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |PIM Ver| Type  |   Reserved    |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Upstream Neighbor Address (Encoded-Unicast format)     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Reserved     | Num groups    |          Holdtime             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Multicast Group Address 1 (Encoded-Group format)      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Number of Joined Sources    |   Number of Pruned Sources    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Joined Source Address 1 (Encoded-Source format)        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             .                                 |
/// |                             .                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Pruned Source Address 1 (Encoded-Source format)        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct PimJoinPruneBuilder {
    /// Upstream neighbor address (next hop towards RP)
    pub upstream_neighbor: Ipv4Addr,
    /// Holdtime in seconds (default 210 = 3.5 * 60s JP period)
    pub holdtime: u16,
    /// Groups with their join/prune entries
    pub groups: Vec<JoinPruneGroup>,
}

impl PimJoinPruneBuilder {
    /// Create a new Join/Prune builder
    pub fn new(upstream_neighbor: Ipv4Addr, holdtime: u16) -> Self {
        Self {
            upstream_neighbor,
            holdtime,
            groups: Vec::new(),
        }
    }

    /// Add a group entry to the message
    pub fn add_group(&mut self, group: JoinPruneGroup) {
        self.groups.push(group);
    }

    /// Create a (*,G) Join message
    pub fn star_g_join(upstream_neighbor: Ipv4Addr, group: Ipv4Addr, rp: Ipv4Addr) -> Self {
        let mut builder = Self::new(
            upstream_neighbor,
            DEFAULT_JOIN_PRUNE_HOLDTIME.as_secs() as u16,
        );
        builder.add_group(JoinPruneGroup::star_g_join(group, rp));
        builder
    }

    /// Create an (S,G) Join message
    pub fn sg_join(upstream_neighbor: Ipv4Addr, group: Ipv4Addr, source: Ipv4Addr) -> Self {
        let mut builder = Self::new(
            upstream_neighbor,
            DEFAULT_JOIN_PRUNE_HOLDTIME.as_secs() as u16,
        );
        builder.add_group(JoinPruneGroup::sg_join(group, source));
        builder
    }

    /// Encode a unicast address (IPv4)
    /// Format: addr_family(1) + encoding_type(1) + address(4)
    fn encode_unicast(addr: Ipv4Addr) -> [u8; 6] {
        let octets = addr.octets();
        [
            1, // Address family: IPv4
            0, // Encoding type: native
            octets[0], octets[1], octets[2], octets[3],
        ]
    }

    /// Encode a group address (IPv4)
    /// Format: addr_family(1) + encoding_type(1) + reserved(1) + mask_len(1) + group(4)
    fn encode_group(group: Ipv4Addr) -> [u8; 8] {
        let octets = group.octets();
        [
            1,  // Address family: IPv4
            0,  // Encoding type: native
            0,  // Reserved (B=0, reserved=0, Z=0)
            32, // Mask length: /32 for specific group
            octets[0], octets[1], octets[2], octets[3],
        ]
    }

    /// Encode a source address (IPv4)
    /// Format: addr_family(1) + encoding_type(1) + flags(1) + mask_len(1) + source(4)
    /// Flags: S=Sparse(0x04), W=WildCard(0x02), R=RPT(0x01)
    fn encode_source(source: Option<Ipv4Addr>, rp: Option<Ipv4Addr>) -> [u8; 8] {
        let (addr, flags) = match source {
            Some(s) => {
                // (S,G) entry: use actual source, S bit set
                (s, 0x04) // S=1, W=0, R=0
            }
            None => {
                // (*,G) entry: use RP address, W and R bits set
                let rp_addr = rp.unwrap_or(Ipv4Addr::UNSPECIFIED);
                (rp_addr, 0x06) // S=0, W=1, R=1 (0x04 | 0x02)
            }
        };
        let octets = addr.octets();
        [
            1, // Address family: IPv4
            0, // Encoding type: native
            flags, 32, // Mask length: /32
            octets[0], octets[1], octets[2], octets[3],
        ]
    }
}

impl PacketBuilder for PimJoinPruneBuilder {
    fn build(&self) -> Vec<u8> {
        // Estimate size: header(4) + upstream(6) + header2(4) + groups*(group(8) + counts(4) + sources*8)
        let estimated_size = 4 + 6 + 4 + self.groups.len() * 20;
        let mut packet = Vec::with_capacity(estimated_size);

        // PIM header: Version 2, Type 3 (Join/Prune)
        packet.push((2 << 4) | PIM_JOIN_PRUNE);
        packet.push(0); // Reserved
        packet.push(0); // Checksum placeholder
        packet.push(0);

        // Encoded unicast upstream neighbor address
        packet.extend_from_slice(&Self::encode_unicast(self.upstream_neighbor));

        // Reserved (1 byte) + Number of groups (1 byte)
        packet.push(0); // Reserved
        packet.push(self.groups.len() as u8);

        // Holdtime (2 bytes)
        packet.extend_from_slice(&self.holdtime.to_be_bytes());

        // Encode each group
        for group in &self.groups {
            // Encoded group address
            packet.extend_from_slice(&Self::encode_group(group.group));

            // Number of joined sources (2 bytes)
            packet.extend_from_slice(&(group.joins.len() as u16).to_be_bytes());
            // Number of pruned sources (2 bytes)
            packet.extend_from_slice(&(group.prunes.len() as u16).to_be_bytes());

            // Encode joined sources
            for source in &group.joins {
                packet.extend_from_slice(&Self::encode_source(*source, group.rp));
            }

            // Encode pruned sources
            for source in &group.prunes {
                packet.extend_from_slice(&Self::encode_source(*source, group.rp));
            }
        }

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
    fn test_pim_join_prune_builder_star_g() {
        let upstream: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let group: Ipv4Addr = "239.1.1.1".parse().unwrap();
        let rp: Ipv4Addr = "10.0.0.1".parse().unwrap();

        let builder = PimJoinPruneBuilder::star_g_join(upstream, group, rp);
        let packet = builder.build();

        // Parse the header
        let header = PimHeader::parse(&packet).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.msg_type, PIM_JOIN_PRUNE);

        // Verify structure: header(4) + upstream(6) + reserved(1) + num_groups(1) + holdtime(2) = 14 bytes
        // + group(8) + num_joined(2) + num_pruned(2) + joined_source(8) = 20 bytes
        // Total minimum: 34 bytes
        assert!(packet.len() >= 34);

        // Check upstream neighbor (after 4-byte header)
        assert_eq!(packet[4], 1); // IPv4 family
        assert_eq!(packet[5], 0); // Encoding type
        assert_eq!(&packet[6..10], upstream.octets());

        // Check number of groups
        assert_eq!(packet[11], 1); // 1 group

        // Check holdtime (210 seconds = 0x00D2)
        let holdtime = u16::from_be_bytes([packet[12], packet[13]]);
        assert_eq!(holdtime, 210);

        // Check group address (starts at offset 14)
        assert_eq!(packet[14], 1); // IPv4 family
        assert_eq!(&packet[18..22], group.octets());

        // Check num joined (1) and num pruned (0)
        let num_joined = u16::from_be_bytes([packet[22], packet[23]]);
        let num_pruned = u16::from_be_bytes([packet[24], packet[25]]);
        assert_eq!(num_joined, 1);
        assert_eq!(num_pruned, 0);

        // Check joined source flags (WC=1, RPT=1 means flags=0x06)
        assert_eq!(packet[28], 0x06); // W=1, R=1
    }

    #[test]
    fn test_pim_join_prune_builder_sg() {
        let upstream: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let group: Ipv4Addr = "239.2.2.2".parse().unwrap();
        let source: Ipv4Addr = "192.168.1.100".parse().unwrap();

        let builder = PimJoinPruneBuilder::sg_join(upstream, group, source);
        let packet = builder.build();

        // Parse the header
        let header = PimHeader::parse(&packet).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.msg_type, PIM_JOIN_PRUNE);

        // Check source flags (S=1 means flags=0x04)
        // Source is at offset 26 (flags at offset 28)
        assert_eq!(packet[28], 0x04); // S=1, W=0, R=0

        // Check source address
        assert_eq!(&packet[30..34], source.octets());
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

    #[test]
    fn test_external_neighbor_creation() {
        let neighbor = PimNeighbor::new_external(
            "192.168.1.5".parse().unwrap(),
            "eth0".to_string(),
            100,
            Some("babel".to_string()),
        );

        assert_eq!(neighbor.address, "192.168.1.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(neighbor.interface, "eth0");
        assert_eq!(neighbor.dr_priority, 100);
        assert!(neighbor.expires_at.is_none());
        assert!(neighbor.generation_id.is_none());
        assert!(neighbor.is_external());
        assert!(matches!(
            neighbor.source,
            NeighborSource::External {
                tag: Some(ref t)
            } if t == "babel"
        ));
    }

    #[test]
    fn test_external_neighbor_never_expires() {
        let neighbor = PimNeighbor::new_external(
            "192.168.1.5".parse().unwrap(),
            "eth0".to_string(),
            100,
            None,
        );

        let now = Instant::now();
        let future = now + Duration::from_secs(100000);

        // External neighbors should never expire
        assert!(!neighbor.is_expired(now));
        assert!(!neighbor.is_expired(future));
    }

    #[test]
    fn test_external_neighbor_transitions_on_hello() {
        let mut neighbor = PimNeighbor::new_external(
            "192.168.1.5".parse().unwrap(),
            "eth0".to_string(),
            100,
            Some("babel".to_string()),
        );

        assert!(neighbor.is_external());

        // Receiving a Hello should transition to PimHello source
        let now = Instant::now();
        neighbor.refresh(now + Duration::from_secs(105), 200, 54321);

        assert!(!neighbor.is_external());
        assert!(matches!(neighbor.source, NeighborSource::PimHello));
        assert_eq!(neighbor.dr_priority, 200);
        assert_eq!(neighbor.generation_id, Some(54321));
        assert!(neighbor.expires_at.is_some());
    }

    #[test]
    fn test_add_external_neighbor_to_pim_state() {
        let mut state = PimState::new();

        // Enable interface first
        state.enable_interface(
            "eth0",
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        let external = ExternalNeighbor {
            address: "192.168.1.5".parse().unwrap(),
            interface: "eth0".to_string(),
            dr_priority: Some(200),
            tag: Some("test".to_string()),
        };

        assert!(state.add_external_neighbor(&external));
        assert_eq!(state.interfaces["eth0"].neighbors.len(), 1);

        let neighbor = state.interfaces["eth0"]
            .neighbors
            .get(&"192.168.1.5".parse().unwrap())
            .unwrap();
        assert!(neighbor.is_external());
        assert_eq!(neighbor.dr_priority, 200);
    }

    #[test]
    fn test_add_external_neighbor_nonexistent_interface() {
        let mut state = PimState::new();

        let external = ExternalNeighbor {
            address: "192.168.1.5".parse().unwrap(),
            interface: "eth99".to_string(), // Not enabled
            dr_priority: None,
            tag: None,
        };

        // Should return false because interface doesn't exist
        assert!(!state.add_external_neighbor(&external));
    }

    #[test]
    fn test_remove_external_neighbor() {
        let mut state = PimState::new();

        state.enable_interface(
            "eth0",
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        let external = ExternalNeighbor {
            address: "192.168.1.5".parse().unwrap(),
            interface: "eth0".to_string(),
            dr_priority: None,
            tag: None,
        };

        state.add_external_neighbor(&external);
        assert_eq!(state.interfaces["eth0"].neighbors.len(), 1);

        // Remove the external neighbor
        assert!(state.remove_external_neighbor("192.168.1.5".parse().unwrap(), "eth0"));
        assert_eq!(state.interfaces["eth0"].neighbors.len(), 0);

        // Removing again should return false
        assert!(!state.remove_external_neighbor("192.168.1.5".parse().unwrap(), "eth0"));
    }

    #[test]
    fn test_remove_external_neighbor_does_not_remove_hello_learned() {
        let mut state = PimState::new();

        state.enable_interface(
            "eth0",
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        // Add a Hello-learned neighbor
        let iface = state.interfaces.get_mut("eth0").unwrap();
        let now = Instant::now();
        iface.received_hello(
            "192.168.1.5".parse().unwrap(),
            Duration::from_secs(105),
            100,
            12345,
            now,
        );
        assert_eq!(iface.neighbors.len(), 1);

        // Trying to remove as external should fail
        assert!(!state.remove_external_neighbor("192.168.1.5".parse().unwrap(), "eth0"));
        assert_eq!(state.interfaces["eth0"].neighbors.len(), 1);
    }

    #[test]
    fn test_list_external_neighbors() {
        let mut state = PimState::new();

        state.enable_interface(
            "eth0",
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        // Add one external neighbor
        let external = ExternalNeighbor {
            address: "192.168.1.5".parse().unwrap(),
            interface: "eth0".to_string(),
            dr_priority: None,
            tag: Some("babel".to_string()),
        };
        state.add_external_neighbor(&external);

        // Add one Hello-learned neighbor
        let iface = state.interfaces.get_mut("eth0").unwrap();
        let now = Instant::now();
        iface.received_hello(
            "192.168.1.6".parse().unwrap(),
            Duration::from_secs(105),
            100,
            12345,
            now,
        );

        // Total neighbors should be 2
        assert_eq!(state.all_neighbors().len(), 2);

        // External neighbors should be 1
        let external_list = state.list_external_neighbors();
        assert_eq!(external_list.len(), 1);
        assert_eq!(
            external_list[0].address,
            "192.168.1.5".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn test_clear_external_neighbors() {
        let mut state = PimState::new();

        state.enable_interface(
            "eth0",
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );
        state.enable_interface(
            "eth1",
            "192.168.2.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        // Add external neighbors on both interfaces
        state.add_external_neighbor(&ExternalNeighbor {
            address: "192.168.1.5".parse().unwrap(),
            interface: "eth0".to_string(),
            dr_priority: None,
            tag: None,
        });
        state.add_external_neighbor(&ExternalNeighbor {
            address: "192.168.2.5".parse().unwrap(),
            interface: "eth1".to_string(),
            dr_priority: None,
            tag: None,
        });

        // Clear only eth0
        let removed = state.clear_external_neighbors(Some("eth0"));
        assert_eq!(removed, 1);
        assert_eq!(state.interfaces["eth0"].neighbors.len(), 0);
        assert_eq!(state.interfaces["eth1"].neighbors.len(), 1);

        // Clear all remaining
        let removed = state.clear_external_neighbors(None);
        assert_eq!(removed, 1);
        assert_eq!(state.interfaces["eth1"].neighbors.len(), 0);
    }

    #[test]
    fn test_external_neighbor_participates_in_dr_election() {
        let mut state = PimState::new();

        state.enable_interface(
            "eth0",
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig {
                dr_priority: 100,
                ..Default::default()
            },
        );

        // Run initial DR election (with no neighbors, we should be DR)
        let iface = state.interfaces.get_mut("eth0").unwrap();
        iface.elect_dr();
        assert!(iface.is_dr());

        // Add external neighbor with higher priority
        let external = ExternalNeighbor {
            address: "192.168.1.5".parse().unwrap(),
            interface: "eth0".to_string(),
            dr_priority: Some(200), // Higher priority
            tag: None,
        };
        state.add_external_neighbor(&external);

        // External neighbor should be DR now (election runs in add_external_neighbor)
        let iface = state.interfaces.get("eth0").unwrap();
        assert!(!iface.is_dr());
        assert_eq!(
            iface.designated_router,
            Some("192.168.1.5".parse().unwrap())
        );
    }

    #[test]
    fn test_is_valid_neighbor() {
        let mut state = PimState::new();

        state.enable_interface(
            "eth0",
            "192.168.1.1".parse().unwrap(),
            PimInterfaceConfig::default(),
        );

        // Add external neighbor (never expires)
        state.add_external_neighbor(&ExternalNeighbor {
            address: "192.168.1.5".parse().unwrap(),
            interface: "eth0".to_string(),
            dr_priority: None,
            tag: None,
        });

        let now = Instant::now();

        // External neighbor should always be valid
        assert!(state.is_valid_neighbor("192.168.1.5".parse().unwrap(), "eth0", now));
        assert!(state.is_valid_neighbor(
            "192.168.1.5".parse().unwrap(),
            "eth0",
            now + Duration::from_secs(100000)
        ));

        // Unknown neighbor should not be valid
        assert!(!state.is_valid_neighbor("192.168.1.99".parse().unwrap(), "eth0", now));

        // Wrong interface should not be valid
        assert!(!state.is_valid_neighbor("192.168.1.5".parse().unwrap(), "eth1", now));
    }

    #[test]
    fn test_neighbor_source_display() {
        assert_eq!(NeighborSource::PimHello.to_string(), "pim-hello");
        assert_eq!(
            NeighborSource::External { tag: None }.to_string(),
            "external"
        );
        assert_eq!(
            NeighborSource::External {
                tag: Some("babel".to_string())
            }
            .to_string(),
            "external:babel"
        );
    }

    // --- RPF Tests ---

    #[test]
    fn test_rpf_provider_default() {
        let state = PimState::new();
        assert!(matches!(state.config.rpf_provider, RpfProvider::Disabled));
    }

    #[test]
    fn test_set_rpf_provider() {
        let mut state = PimState::new();

        state.set_rpf_provider(RpfProvider::Static);
        assert!(matches!(state.config.rpf_provider, RpfProvider::Static));

        state.set_rpf_provider(RpfProvider::External {
            socket_path: "/tmp/rpf.sock".to_string(),
        });
        assert!(matches!(
            state.config.rpf_provider,
            RpfProvider::External { .. }
        ));
    }

    #[test]
    fn test_add_rpf_route() {
        let mut state = PimState::new();

        let rpf = RpfInfo {
            upstream_interface: "eth0".to_string(),
            upstream_neighbor: Some("10.0.0.1".parse().unwrap()),
            metric: Some(100),
        };

        state.add_rpf_route("192.168.1.1".parse().unwrap(), rpf.clone());

        assert_eq!(state.static_rpf.len(), 1);
        let stored = state
            .static_rpf
            .get(&"192.168.1.1".parse().unwrap())
            .unwrap();
        assert_eq!(stored.upstream_interface, "eth0");
        assert_eq!(stored.upstream_neighbor, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(stored.metric, Some(100));
    }

    #[test]
    fn test_remove_rpf_route() {
        let mut state = PimState::new();

        let rpf = RpfInfo {
            upstream_interface: "eth0".to_string(),
            upstream_neighbor: None,
            metric: None,
        };

        state.add_rpf_route("192.168.1.1".parse().unwrap(), rpf);
        assert_eq!(state.static_rpf.len(), 1);

        // Remove existing route
        assert!(state.remove_rpf_route("192.168.1.1".parse().unwrap()));
        assert_eq!(state.static_rpf.len(), 0);

        // Remove non-existent route
        assert!(!state.remove_rpf_route("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_get_rpf_routes() {
        let mut state = PimState::new();

        state.add_rpf_route(
            "10.1.0.1".parse().unwrap(),
            RpfInfo {
                upstream_interface: "eth0".to_string(),
                upstream_neighbor: None,
                metric: None,
            },
        );
        state.add_rpf_route(
            "10.2.0.1".parse().unwrap(),
            RpfInfo {
                upstream_interface: "eth1".to_string(),
                upstream_neighbor: None,
                metric: None,
            },
        );

        let routes = state.get_rpf_routes();
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn test_clear_rpf_routes() {
        let mut state = PimState::new();

        state.add_rpf_route(
            "10.1.0.1".parse().unwrap(),
            RpfInfo {
                upstream_interface: "eth0".to_string(),
                upstream_neighbor: None,
                metric: None,
            },
        );
        state.add_rpf_route(
            "10.2.0.1".parse().unwrap(),
            RpfInfo {
                upstream_interface: "eth1".to_string(),
                upstream_neighbor: None,
                metric: None,
            },
        );

        let cleared = state.clear_rpf_routes();
        assert_eq!(cleared, 2);
        assert_eq!(state.static_rpf.len(), 0);
    }

    #[test]
    fn test_lookup_rpf_disabled() {
        let state = PimState::new();
        // With disabled provider, lookup always returns None
        assert!(state.lookup_rpf("10.1.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn test_lookup_rpf_static() {
        let mut state = PimState::new();
        state.set_rpf_provider(RpfProvider::Static);

        // No entry yet
        assert!(state.lookup_rpf("10.1.0.1".parse().unwrap()).is_none());

        // Add entry
        state.add_rpf_route(
            "10.1.0.1".parse().unwrap(),
            RpfInfo {
                upstream_interface: "eth0".to_string(),
                upstream_neighbor: None,
                metric: None,
            },
        );

        // Now lookup succeeds
        let rpf = state.lookup_rpf("10.1.0.1".parse().unwrap());
        assert!(rpf.is_some());
        assert_eq!(rpf.unwrap().upstream_interface, "eth0");
    }

    #[test]
    fn test_check_rpf_disabled() {
        let state = PimState::new();
        // With disabled provider, RPF check always passes
        assert!(state.check_rpf("10.1.0.1".parse().unwrap(), "eth0"));
        assert!(state.check_rpf("10.1.0.1".parse().unwrap(), "eth1"));
    }

    #[test]
    fn test_check_rpf_static() {
        let mut state = PimState::new();
        state.set_rpf_provider(RpfProvider::Static);

        state.add_rpf_route(
            "10.1.0.1".parse().unwrap(),
            RpfInfo {
                upstream_interface: "eth0".to_string(),
                upstream_neighbor: None,
                metric: None,
            },
        );

        // Correct interface passes
        assert!(state.check_rpf("10.1.0.1".parse().unwrap(), "eth0"));

        // Wrong interface fails
        assert!(!state.check_rpf("10.1.0.1".parse().unwrap(), "eth1"));

        // No entry for source - static mode fails
        assert!(!state.check_rpf("10.2.0.1".parse().unwrap(), "eth0"));
    }

    #[test]
    fn test_check_rpf_external_no_entry() {
        let mut state = PimState::new();
        state.set_rpf_provider(RpfProvider::External {
            socket_path: "/tmp/rpf.sock".to_string(),
        });

        // With external provider and no cached entry, allow (pending lookup)
        assert!(state.check_rpf("10.1.0.1".parse().unwrap(), "eth0"));
    }

    #[test]
    fn test_rpf_provider_display() {
        assert_eq!(RpfProvider::Disabled.to_string(), "disabled");
        assert_eq!(RpfProvider::Static.to_string(), "static");
        assert_eq!(
            RpfProvider::External {
                socket_path: "/tmp/rpf.sock".to_string()
            }
            .to_string(),
            "external:/tmp/rpf.sock"
        );
    }
}
