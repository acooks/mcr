// SPDX-License-Identifier: Apache-2.0 OR MIT
//! MSDP (Multicast Source Discovery Protocol) Implementation (RFC 3618)
//!
//! This module implements MSDP for sharing active multicast source information
//! between PIM-SM domains via TCP connections between MSDP peers.
//!
//! ## Purpose
//!
//! MSDP enables receivers in one PIM domain to learn about sources in other
//! domains, enabling inter-domain multicast without requiring a common RP.
//!
//! ## Key Concepts
//!
//! - **SA (Source-Active)**: Messages announcing (source, group) pairs
//! - **Peer**: An MSDP router with which we maintain a TCP connection
//! - **Mesh Group**: A set of peers that share full SA state
//! - **RPF Check**: Reverse Path Forwarding check to prevent SA loops
//!
//! ## Message Types
//!
//! | Type | Value | Description |
//! |------|-------|-------------|
//! | Source-Active | 1 | Announces (source, group) pairs |
//! | SA-Request | 2 | Request SA for specific group |
//! | SA-Response | 3 | Response with SA data |
//! | Keepalive | 4 | Maintain peer session |
//!
//! ## Timers
//!
//! | Timer | Default | Purpose |
//! |-------|---------|---------|
//! | Connect Retry | 30s | Retry failed connections |
//! | Keepalive | 60s | Send if no other message |
//! | Hold | 75s | Peer dead if no message received |
//! | SA Cache | ~60s | Entry expiry |

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::{PacketBuilder, TimerRequest, TimerType};

// MSDP message types (RFC 3618)
pub const MSDP_SA: u8 = 1;
pub const MSDP_SA_REQUEST: u8 = 2;
pub const MSDP_SA_RESPONSE: u8 = 3;
pub const MSDP_KEEPALIVE: u8 = 4;

// Default timer values (RFC 3618)
pub const DEFAULT_CONNECT_RETRY_PERIOD: Duration = Duration::from_secs(30);
pub const DEFAULT_KEEPALIVE_PERIOD: Duration = Duration::from_secs(60);
pub const DEFAULT_HOLD_TIME: Duration = Duration::from_secs(75);
pub const DEFAULT_SA_CACHE_TIMEOUT: Duration = Duration::from_secs(60);

/// MSDP well-known port
pub const MSDP_PORT: u16 = 639;

/// SA flood request - returned by state machine methods when SA needs to be flooded
#[derive(Debug, Clone)]
pub struct SaFloodRequest {
    /// RP address that originated this SA
    pub rp_address: Ipv4Addr,
    /// Source/group pairs to flood
    pub entries: Vec<(Ipv4Addr, Ipv4Addr)>,
    /// Peer to exclude from flooding (the peer we learned from, if any)
    pub exclude_peer: Option<Ipv4Addr>,
}

/// Result of MSDP state machine operations
#[derive(Debug, Default)]
pub struct MsdpActionResult {
    /// Timer requests to schedule
    pub timers: Vec<TimerRequest>,
    /// SA flood requests to send
    pub floods: Vec<SaFloodRequest>,
    /// Newly learned (source, group) pairs that should be checked for local receivers
    /// If local receivers exist, the supervisor should create (S,G) routing state
    pub learned_sources: Vec<(Ipv4Addr, Ipv4Addr)>,
}

impl MsdpActionResult {
    /// Create an empty result
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a result with only timers
    pub fn with_timers(timers: Vec<TimerRequest>) -> Self {
        Self {
            timers,
            floods: Vec::new(),
            learned_sources: Vec::new(),
        }
    }

    /// Add a flood request
    pub fn add_flood(&mut self, flood: SaFloodRequest) {
        self.floods.push(flood);
    }

    /// Add a learned source
    pub fn add_learned_source(&mut self, source: Ipv4Addr, group: Ipv4Addr) {
        self.learned_sources.push((source, group));
    }
}

/// MSDP peer state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsdpPeerState {
    /// Not connected, will attempt to connect
    Disabled,
    /// Attempting to establish TCP connection
    Connecting,
    /// TCP connection established, waiting for first message
    Established,
    /// Peer is active and exchanging messages
    Active,
}

impl std::fmt::Display for MsdpPeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MsdpPeerState::Disabled => write!(f, "disabled"),
            MsdpPeerState::Connecting => write!(f, "connecting"),
            MsdpPeerState::Established => write!(f, "established"),
            MsdpPeerState::Active => write!(f, "active"),
        }
    }
}

/// Configuration for an MSDP peer
#[derive(Debug, Clone)]
pub struct MsdpPeerConfig {
    /// Peer's IP address
    pub address: Ipv4Addr,
    /// Optional description
    pub description: Option<String>,
    /// Mesh group name (if in a mesh group)
    pub mesh_group: Option<String>,
    /// Whether this is a default peer
    pub default_peer: bool,
    /// Keepalive interval (default: 60s)
    pub keepalive_interval: Duration,
    /// Hold time (default: 75s)
    pub hold_time: Duration,
}

impl MsdpPeerConfig {
    /// Create a new peer config with defaults
    pub fn new(address: Ipv4Addr) -> Self {
        Self {
            address,
            description: None,
            mesh_group: None,
            default_peer: false,
            keepalive_interval: DEFAULT_KEEPALIVE_PERIOD,
            hold_time: DEFAULT_HOLD_TIME,
        }
    }
}

/// State for an MSDP peer connection
#[derive(Debug)]
pub struct MsdpPeer {
    /// Peer configuration
    pub config: MsdpPeerConfig,
    /// Current peer state
    pub state: MsdpPeerState,
    /// When we last received a message from this peer
    pub last_received: Option<Instant>,
    /// When we last sent a message to this peer
    pub last_sent: Option<Instant>,
    /// When the peer session was established
    pub established_at: Option<Instant>,
    /// Number of SA messages received from this peer
    pub sa_received: u64,
    /// Number of SA messages sent to this peer
    pub sa_sent: u64,
    /// Number of keepalives received
    pub keepalives_received: u64,
    /// Number of keepalives sent
    pub keepalives_sent: u64,
    /// Number of connection attempts
    pub connect_attempts: u32,
    /// Whether we initiated the connection (active) or received it (passive)
    pub is_active: bool,
}

impl MsdpPeer {
    /// Create a new peer in disabled state
    pub fn new(config: MsdpPeerConfig) -> Self {
        Self {
            config,
            state: MsdpPeerState::Disabled,
            last_received: None,
            last_sent: None,
            established_at: None,
            sa_received: 0,
            sa_sent: 0,
            keepalives_received: 0,
            keepalives_sent: 0,
            connect_attempts: 0,
            is_active: false,
        }
    }

    /// Check if the peer has timed out (no message received within hold time)
    pub fn is_timed_out(&self, now: Instant) -> bool {
        if let Some(last) = self.last_received {
            now.duration_since(last) > self.config.hold_time
        } else {
            // No message received yet - check if we've been established too long
            if let Some(established) = self.established_at {
                now.duration_since(established) > self.config.hold_time
            } else {
                false
            }
        }
    }

    /// Check if we need to send a keepalive
    pub fn needs_keepalive(&self, now: Instant) -> bool {
        if self.state != MsdpPeerState::Active && self.state != MsdpPeerState::Established {
            return false;
        }

        if let Some(last) = self.last_sent {
            now.duration_since(last) >= self.config.keepalive_interval
        } else {
            // Never sent anything - send keepalive
            true
        }
    }

    /// Record that we received a message
    pub fn record_received(&mut self, now: Instant) {
        self.last_received = Some(now);
    }

    /// Record that we sent a message
    pub fn record_sent(&mut self, now: Instant) {
        self.last_sent = Some(now);
    }

    /// Transition to connected state
    pub fn connected(&mut self, now: Instant, is_active: bool) {
        self.state = MsdpPeerState::Established;
        self.established_at = Some(now);
        self.is_active = is_active;
        self.last_received = Some(now);
    }

    /// Transition to active state (after first message exchange)
    pub fn activate(&mut self) {
        self.state = MsdpPeerState::Active;
    }

    /// Disconnect the peer
    pub fn disconnect(&mut self) {
        self.state = MsdpPeerState::Disabled;
        self.last_received = None;
        self.last_sent = None;
        self.established_at = None;
    }

    /// Get uptime in seconds (if connected)
    pub fn uptime_secs(&self) -> Option<u64> {
        self.established_at.map(|t| t.elapsed().as_secs())
    }
}

/// SA (Source-Active) cache entry
#[derive(Debug, Clone)]
pub struct SaCacheEntry {
    /// Source IP address
    pub source: Ipv4Addr,
    /// Multicast group address
    pub group: Ipv4Addr,
    /// RP that originated this SA
    pub origin_rp: Ipv4Addr,
    /// Peer from which we learned this SA (None if local)
    pub learned_from: Option<Ipv4Addr>,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry expires
    pub expires_at: Instant,
    /// Whether this is a local source (we originated it)
    pub is_local: bool,
}

impl SaCacheEntry {
    /// Create a new SA cache entry learned from a peer
    pub fn new_learned(
        source: Ipv4Addr,
        group: Ipv4Addr,
        origin_rp: Ipv4Addr,
        learned_from: Ipv4Addr,
        timeout: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            source,
            group,
            origin_rp,
            learned_from: Some(learned_from),
            created_at: now,
            expires_at: now + timeout,
            is_local: false,
        }
    }

    /// Create a new SA cache entry for a local source
    pub fn new_local(source: Ipv4Addr, group: Ipv4Addr, origin_rp: Ipv4Addr) -> Self {
        let now = Instant::now();
        Self {
            source,
            group,
            origin_rp,
            learned_from: None,
            created_at: now,
            expires_at: now + DEFAULT_SA_CACHE_TIMEOUT,
            is_local: true,
        }
    }

    /// Refresh the entry (extend expiry)
    pub fn refresh(&mut self, timeout: Duration) {
        self.expires_at = Instant::now() + timeout;
    }

    /// Check if the entry has expired
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Get the age of this entry in seconds
    pub fn age_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
    }

    /// Get seconds until expiry
    pub fn expires_in_secs(&self, now: Instant) -> u64 {
        self.expires_at.saturating_duration_since(now).as_secs()
    }
}

/// Events that can occur in the MSDP state machine
#[derive(Debug, Clone)]
pub enum MsdpEvent {
    /// TCP connection established with a peer
    TcpConnectionEstablished {
        peer: Ipv4Addr,
        /// Whether we initiated (true) or received (false) the connection
        is_active: bool,
    },
    /// TCP connection attempt failed
    TcpConnectionFailed { peer: Ipv4Addr, reason: String },
    /// TCP connection closed
    TcpConnectionClosed { peer: Ipv4Addr, reason: String },
    /// Received an MSDP message from a peer
    MessageReceived {
        peer: Ipv4Addr,
        msg_type: u8,
        payload: Vec<u8>,
    },
    /// Local source became active (from PIM)
    LocalSourceActive { source: Ipv4Addr, group: Ipv4Addr },
    /// Local source became inactive (from PIM)
    LocalSourceInactive { source: Ipv4Addr, group: Ipv4Addr },
    /// Connect retry timer expired
    ConnectRetryExpired { peer: Ipv4Addr },
    /// Keepalive timer expired
    KeepaliveTimerExpired { peer: Ipv4Addr },
    /// Hold timer expired (peer timed out)
    HoldTimerExpired { peer: Ipv4Addr },
    /// SA cache entry expired
    SaCacheExpired {
        source: Ipv4Addr,
        group: Ipv4Addr,
        origin_rp: Ipv4Addr,
    },
    /// Add a new peer
    AddPeer { config: MsdpPeerConfig },
    /// Remove a peer
    RemovePeer { peer: Ipv4Addr },
    /// Enable MSDP (start connecting to peers)
    Enable,
    /// Disable MSDP (disconnect all peers)
    Disable,
}

/// Global MSDP configuration
#[derive(Debug, Clone)]
pub struct MsdpGlobalConfig {
    /// Whether MSDP is enabled
    pub enabled: bool,
    /// Our local address for MSDP connections
    pub local_address: Option<Ipv4Addr>,
    /// Default keepalive interval
    pub keepalive_interval: Duration,
    /// Default hold time
    pub hold_time: Duration,
    /// Connect retry period
    pub connect_retry_period: Duration,
    /// SA cache timeout
    pub sa_cache_timeout: Duration,
}

impl Default for MsdpGlobalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            local_address: None,
            keepalive_interval: DEFAULT_KEEPALIVE_PERIOD,
            hold_time: DEFAULT_HOLD_TIME,
            connect_retry_period: DEFAULT_CONNECT_RETRY_PERIOD,
            sa_cache_timeout: DEFAULT_SA_CACHE_TIMEOUT,
        }
    }
}

/// Global MSDP state
#[derive(Debug)]
pub struct MsdpState {
    /// Global configuration
    pub config: MsdpGlobalConfig,
    /// Peer state, keyed by peer IP address
    pub peers: HashMap<Ipv4Addr, MsdpPeer>,
    /// SA cache, keyed by (source, group, origin_rp)
    pub sa_cache: HashMap<(Ipv4Addr, Ipv4Addr, Ipv4Addr), SaCacheEntry>,
    /// Mesh groups, keyed by group name
    pub mesh_groups: HashMap<String, Vec<Ipv4Addr>>,
}

impl Default for MsdpState {
    fn default() -> Self {
        Self::new()
    }
}

impl MsdpState {
    /// Create new MSDP state
    pub fn new() -> Self {
        Self {
            config: MsdpGlobalConfig::default(),
            peers: HashMap::new(),
            sa_cache: HashMap::new(),
            mesh_groups: HashMap::new(),
        }
    }

    /// Add a peer
    pub fn add_peer(&mut self, config: MsdpPeerConfig) -> Vec<TimerRequest> {
        let mut timers = Vec::new();
        let peer_addr = config.address;

        // Track mesh group membership
        if let Some(ref group_name) = config.mesh_group {
            self.mesh_groups
                .entry(group_name.clone())
                .or_default()
                .push(peer_addr);
        }

        let peer = MsdpPeer::new(config);
        self.peers.insert(peer_addr, peer);

        // If MSDP is enabled, schedule connection attempt
        if self.config.enabled {
            timers.push(TimerRequest {
                timer_type: TimerType::MsdpConnectRetry { peer: peer_addr },
                fire_at: Instant::now(), // Connect immediately
                replace_existing: true,
            });
        }

        timers
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_addr: Ipv4Addr) {
        if let Some(peer) = self.peers.remove(&peer_addr) {
            // Remove from mesh group
            if let Some(ref group_name) = peer.config.mesh_group {
                if let Some(members) = self.mesh_groups.get_mut(group_name) {
                    members.retain(|&addr| addr != peer_addr);
                    if members.is_empty() {
                        self.mesh_groups.remove(group_name);
                    }
                }
            }
        }

        // Remove SA entries learned from this peer
        self.sa_cache
            .retain(|_, entry| entry.learned_from != Some(peer_addr));
    }

    /// Get a peer by address
    pub fn get_peer(&self, peer_addr: Ipv4Addr) -> Option<&MsdpPeer> {
        self.peers.get(&peer_addr)
    }

    /// Get a mutable peer by address
    pub fn get_peer_mut(&mut self, peer_addr: Ipv4Addr) -> Option<&mut MsdpPeer> {
        self.peers.get_mut(&peer_addr)
    }

    /// Process a TCP connection established event
    pub fn connection_established(
        &mut self,
        peer_addr: Ipv4Addr,
        is_active: bool,
        now: Instant,
    ) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        if let Some(peer) = self.peers.get_mut(&peer_addr) {
            peer.connected(now, is_active);

            // Schedule hold timer
            timers.push(TimerRequest {
                timer_type: TimerType::MsdpHold { peer: peer_addr },
                fire_at: now + peer.config.hold_time,
                replace_existing: true,
            });

            // Schedule keepalive timer
            timers.push(TimerRequest {
                timer_type: TimerType::MsdpKeepalive { peer: peer_addr },
                fire_at: now + peer.config.keepalive_interval,
                replace_existing: true,
            });
        }

        timers
    }

    /// Process a TCP connection failed event
    pub fn connection_failed(&mut self, peer_addr: Ipv4Addr, now: Instant) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        if let Some(peer) = self.peers.get_mut(&peer_addr) {
            peer.disconnect();
            peer.connect_attempts += 1;

            // Schedule reconnection attempt
            timers.push(TimerRequest {
                timer_type: TimerType::MsdpConnectRetry { peer: peer_addr },
                fire_at: now + self.config.connect_retry_period,
                replace_existing: true,
            });
        }

        timers
    }

    /// Process a TCP connection closed event
    pub fn connection_closed(&mut self, peer_addr: Ipv4Addr, now: Instant) -> Vec<TimerRequest> {
        // Same handling as connection_failed for now
        self.connection_failed(peer_addr, now)
    }

    /// Process a received SA message
    pub fn process_sa_message(
        &mut self,
        peer_addr: Ipv4Addr,
        entries: Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr)>, // (source, group, origin_rp)
        now: Instant,
    ) -> MsdpActionResult {
        let mut result = MsdpActionResult::new();

        // Track new entries for flooding, grouped by origin_rp
        let mut new_entries_by_rp: HashMap<Ipv4Addr, Vec<(Ipv4Addr, Ipv4Addr)>> = HashMap::new();

        // Update peer's last received time
        if let Some(peer) = self.peers.get_mut(&peer_addr) {
            peer.record_received(now);
            peer.sa_received += entries.len() as u64;

            // Transition to active state
            if peer.state == MsdpPeerState::Established {
                peer.activate();
            }

            // Reset hold timer
            result.timers.push(TimerRequest {
                timer_type: TimerType::MsdpHold { peer: peer_addr },
                fire_at: now + peer.config.hold_time,
                replace_existing: true,
            });
        }

        // Process each SA entry
        for (source, group, origin_rp) in entries {
            // RPF check: only accept SA if peer is the RPF neighbor toward origin_rp
            // TODO: Implement proper RPF check (for now, accept all SAs)

            let key = (source, group, origin_rp);

            if let Some(entry) = self.sa_cache.get_mut(&key) {
                // Refresh existing entry
                entry.refresh(self.config.sa_cache_timeout);
            } else {
                // Create new entry
                let entry = SaCacheEntry::new_learned(
                    source,
                    group,
                    origin_rp,
                    peer_addr,
                    self.config.sa_cache_timeout,
                );
                let expires_at = entry.expires_at;
                self.sa_cache.insert(key, entry);

                // Schedule expiry timer
                result.timers.push(TimerRequest {
                    timer_type: TimerType::MsdpSaCacheExpiry {
                        source,
                        group,
                        origin_rp,
                    },
                    fire_at: expires_at,
                    replace_existing: false,
                });

                // Track for flooding
                new_entries_by_rp
                    .entry(origin_rp)
                    .or_default()
                    .push((source, group));

                // Track as learned source for MSDP-to-PIM notification
                result.add_learned_source(source, group);
            }
        }

        // Create flood requests for new entries (grouped by origin_rp)
        for (rp_address, entries) in new_entries_by_rp {
            result.add_flood(SaFloodRequest {
                rp_address,
                entries,
                exclude_peer: Some(peer_addr), // Don't flood back to sender
            });
        }

        result
    }

    /// Process a received keepalive message
    pub fn process_keepalive(&mut self, peer_addr: Ipv4Addr, now: Instant) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        if let Some(peer) = self.peers.get_mut(&peer_addr) {
            peer.record_received(now);
            peer.keepalives_received += 1;

            // Transition to active state
            if peer.state == MsdpPeerState::Established {
                peer.activate();
            }

            // Reset hold timer
            timers.push(TimerRequest {
                timer_type: TimerType::MsdpHold { peer: peer_addr },
                fire_at: now + peer.config.hold_time,
                replace_existing: true,
            });
        }

        timers
    }

    /// Register a local source (from PIM)
    pub fn local_source_active(
        &mut self,
        source: Ipv4Addr,
        group: Ipv4Addr,
        origin_rp: Ipv4Addr,
        _now: Instant,
    ) -> MsdpActionResult {
        let mut result = MsdpActionResult::new();

        use std::collections::hash_map::Entry;

        let key = (source, group, origin_rp);

        if let Entry::Vacant(e) = self.sa_cache.entry(key) {
            let entry = SaCacheEntry::new_local(source, group, origin_rp);
            let expires_at = entry.expires_at;
            e.insert(entry);

            // Schedule expiry timer
            result.timers.push(TimerRequest {
                timer_type: TimerType::MsdpSaCacheExpiry {
                    source,
                    group,
                    origin_rp,
                },
                fire_at: expires_at,
                replace_existing: false,
            });

            // Request SA flood to all peers (local source, so no peer to exclude)
            result.add_flood(SaFloodRequest {
                rp_address: origin_rp,
                entries: vec![(source, group)],
                exclude_peer: None,
            });
        }

        result
    }

    /// Remove a local source (from PIM)
    pub fn local_source_inactive(&mut self, source: Ipv4Addr, group: Ipv4Addr) {
        // Remove entries for this source/group that are local
        self.sa_cache
            .retain(|&(s, g, _), entry| !(s == source && g == group && entry.is_local));
    }

    /// Process SA cache expiry
    pub fn sa_cache_expired(&mut self, source: Ipv4Addr, group: Ipv4Addr, origin_rp: Ipv4Addr) {
        let key = (source, group, origin_rp);
        self.sa_cache.remove(&key);
    }

    /// Get peers that should receive an SA (flood decision)
    ///
    /// Flooding rules:
    /// - Don't flood back to the peer we learned from
    /// - For mesh groups: don't flood within the same mesh group
    /// - For default peers: only use if no other peer available
    pub fn get_flood_peers(&self, learned_from: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
        let learned_mesh_group = learned_from
            .and_then(|peer| self.peers.get(&peer))
            .and_then(|p| p.config.mesh_group.clone());

        self.peers
            .iter()
            .filter(|(&addr, peer)| {
                // Must be active
                if peer.state != MsdpPeerState::Active {
                    return false;
                }

                // Don't flood back to source
                if Some(addr) == learned_from {
                    return false;
                }

                // If source was in a mesh group, don't flood to same mesh group
                if let Some(ref learned_group) = learned_mesh_group {
                    if peer.config.mesh_group.as_ref() == Some(learned_group) {
                        return false;
                    }
                }

                true
            })
            .map(|(&addr, _)| addr)
            .collect()
    }

    /// Enable MSDP - start connecting to peers
    pub fn enable(&mut self) -> Vec<TimerRequest> {
        let mut timers = Vec::new();
        self.config.enabled = true;

        // Schedule connection attempts for all peers
        let now = Instant::now();
        for peer_addr in self.peers.keys().copied().collect::<Vec<_>>() {
            timers.push(TimerRequest {
                timer_type: TimerType::MsdpConnectRetry { peer: peer_addr },
                fire_at: now,
                replace_existing: true,
            });
        }

        timers
    }

    /// Disable MSDP - disconnect all peers
    pub fn disable(&mut self) {
        self.config.enabled = false;

        // Disconnect all peers
        for peer in self.peers.values_mut() {
            peer.disconnect();
        }

        // Clear SA cache
        self.sa_cache.clear();
    }

    /// Cleanup expired entries
    pub fn cleanup_expired(&mut self, now: Instant) {
        self.sa_cache.retain(|_, entry| !entry.is_expired(now));
    }

    /// Get all SA entries for a specific group
    pub fn get_sa_for_group(&self, group: Ipv4Addr) -> Vec<&SaCacheEntry> {
        self.sa_cache
            .values()
            .filter(|entry| entry.group == group)
            .collect()
    }

    /// Get all active peers
    pub fn get_active_peers(&self) -> Vec<Ipv4Addr> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.state == MsdpPeerState::Active)
            .map(|(&addr, _)| addr)
            .collect()
    }

    /// Get statistics summary
    pub fn stats(&self) -> MsdpStats {
        let active_peers = self
            .peers
            .values()
            .filter(|p| p.state == MsdpPeerState::Active)
            .count();
        let local_entries = self.sa_cache.values().filter(|e| e.is_local).count();
        let learned_entries = self.sa_cache.len() - local_entries;

        MsdpStats {
            total_peers: self.peers.len(),
            active_peers,
            sa_cache_size: self.sa_cache.len(),
            local_entries,
            learned_entries,
        }
    }
}

/// MSDP statistics
#[derive(Debug, Clone, Default)]
pub struct MsdpStats {
    /// Total number of configured peers
    pub total_peers: usize,
    /// Number of active (connected) peers
    pub active_peers: usize,
    /// Total SA cache entries
    pub sa_cache_size: usize,
    /// Number of local (originated) SA entries
    pub local_entries: usize,
    /// Number of learned SA entries
    pub learned_entries: usize,
}

/// Parsed MSDP message header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsdpHeader {
    /// Message type
    pub msg_type: u8,
    /// Message length (including header)
    pub length: u16,
}

impl MsdpHeader {
    /// Header size in bytes
    pub const SIZE: usize = 3;

    /// Parse an MSDP header from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        Some(Self {
            msg_type: data[0],
            length: u16::from_be_bytes([data[1], data[2]]),
        })
    }

    /// Get the message type name
    pub fn type_name(&self) -> &'static str {
        match self.msg_type {
            MSDP_SA => "SA",
            MSDP_SA_REQUEST => "SA-Request",
            MSDP_SA_RESPONSE => "SA-Response",
            MSDP_KEEPALIVE => "Keepalive",
            _ => "Unknown",
        }
    }
}

/// Parsed SA (Source-Active) message
#[derive(Debug, Clone)]
pub struct MsdpSaMessage {
    /// Number of (source, group) entries
    pub entry_count: u8,
    /// RP address that originated this SA
    pub rp_address: Ipv4Addr,
    /// List of (source, group) pairs
    pub entries: Vec<(Ipv4Addr, Ipv4Addr)>,
}

impl MsdpSaMessage {
    /// Minimum SA message size (1 byte count + 4 bytes RP)
    pub const MIN_SIZE: usize = 5;
    /// Size of each SA entry (4 bytes reserved + 1 byte prefix len + 1 byte group prefix len + 4 bytes group + 4 bytes source)
    /// Simplified: 8 bytes per entry (group + source)
    pub const ENTRY_SIZE: usize = 12;

    /// Parse an SA message from bytes (after header)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_SIZE {
            return None;
        }

        let entry_count = data[0];
        let rp_address = Ipv4Addr::new(data[1], data[2], data[3], data[4]);

        let mut entries = Vec::new();
        let mut offset = 5;

        for _ in 0..entry_count {
            // RFC 3618 format:
            // 3 reserved bytes, 1 byte spread prefix len, 1 byte group prefix len
            // Then encoded group address, then encoded source address
            // Simplified parsing assuming /32 addresses
            if offset + Self::ENTRY_SIZE > data.len() {
                break;
            }

            // Skip reserved (3) + sprefix (1) + group prefix len (1)
            offset += 3;

            // Group prefix length (should be 32 for single group)
            let _group_prefix_len = data[offset];
            offset += 1;

            // Group address
            if offset + 4 > data.len() {
                break;
            }
            let group = Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            offset += 4;

            // Source address
            if offset + 4 > data.len() {
                break;
            }
            let source = Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            offset += 4;

            entries.push((source, group));
        }

        Some(Self {
            entry_count,
            rp_address,
            entries,
        })
    }
}

/// Builder for MSDP SA messages
#[derive(Debug)]
pub struct MsdpSaBuilder {
    /// RP address
    pub rp_address: Ipv4Addr,
    /// (source, group) entries
    pub entries: Vec<(Ipv4Addr, Ipv4Addr)>,
}

impl MsdpSaBuilder {
    /// Create a new SA builder
    pub fn new(rp_address: Ipv4Addr) -> Self {
        Self {
            rp_address,
            entries: Vec::new(),
        }
    }

    /// Add a (source, group) entry
    pub fn add_entry(&mut self, source: Ipv4Addr, group: Ipv4Addr) {
        self.entries.push((source, group));
    }
}

impl PacketBuilder for MsdpSaBuilder {
    fn build(&self) -> Vec<u8> {
        // Calculate total length
        // Header (3) + entry_count (1) + RP (4) + entries (12 each)
        let payload_len = 1 + 4 + (self.entries.len() * 12);
        let total_len = 3 + payload_len;

        let mut packet = Vec::with_capacity(total_len);

        // Header
        packet.push(MSDP_SA);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());

        // Entry count
        packet.push(self.entries.len() as u8);

        // RP address
        packet.extend_from_slice(&self.rp_address.octets());

        // Entries
        for (source, group) in &self.entries {
            // Reserved (3 bytes)
            packet.extend_from_slice(&[0u8; 3]);
            // Spread prefix length (not used, set to 0)
            // Group prefix length (32 for single address)
            packet.push(32);
            // Group address
            packet.extend_from_slice(&group.octets());
            // Source address
            packet.extend_from_slice(&source.octets());
        }

        packet
    }
}

/// Builder for MSDP Keepalive messages
#[derive(Debug)]
pub struct MsdpKeepaliveBuilder;

impl MsdpKeepaliveBuilder {
    /// Create a new keepalive builder
    pub fn new() -> Self {
        Self
    }
}

impl Default for MsdpKeepaliveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuilder for MsdpKeepaliveBuilder {
    fn build(&self) -> Vec<u8> {
        // Keepalive is just header (3 bytes)
        vec![MSDP_KEEPALIVE, 0, 3]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msdp_peer_config_new() {
        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        assert_eq!(config.address, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert!(config.description.is_none());
        assert!(config.mesh_group.is_none());
        assert!(!config.default_peer);
        assert_eq!(config.keepalive_interval, DEFAULT_KEEPALIVE_PERIOD);
        assert_eq!(config.hold_time, DEFAULT_HOLD_TIME);
    }

    #[test]
    fn test_msdp_peer_new() {
        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        let peer = MsdpPeer::new(config);
        assert_eq!(peer.state, MsdpPeerState::Disabled);
        assert!(peer.last_received.is_none());
        assert!(peer.last_sent.is_none());
        assert_eq!(peer.sa_received, 0);
        assert_eq!(peer.sa_sent, 0);
    }

    #[test]
    fn test_msdp_peer_state_transitions() {
        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        let mut peer = MsdpPeer::new(config);
        let now = Instant::now();

        // Connect
        peer.connected(now, true);
        assert_eq!(peer.state, MsdpPeerState::Established);
        assert!(peer.is_active);

        // Activate
        peer.activate();
        assert_eq!(peer.state, MsdpPeerState::Active);

        // Disconnect
        peer.disconnect();
        assert_eq!(peer.state, MsdpPeerState::Disabled);
    }

    #[test]
    fn test_msdp_peer_timeout_check() {
        let mut config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        config.hold_time = Duration::from_millis(100);
        let mut peer = MsdpPeer::new(config);
        let now = Instant::now();

        // Not timed out before connection
        assert!(!peer.is_timed_out(now));

        // Connect
        peer.connected(now, true);
        assert!(!peer.is_timed_out(now));

        // After hold time
        std::thread::sleep(Duration::from_millis(150));
        assert!(peer.is_timed_out(Instant::now()));
    }

    #[test]
    fn test_sa_cache_entry_learned() {
        let entry = SaCacheEntry::new_learned(
            "10.0.0.5".parse().unwrap(),
            "239.1.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            Duration::from_secs(60),
        );

        assert_eq!(entry.source, "10.0.0.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(entry.group, "239.1.1.1".parse::<Ipv4Addr>().unwrap());
        assert!(!entry.is_local);
        assert_eq!(
            entry.learned_from,
            Some("192.168.1.1".parse::<Ipv4Addr>().unwrap())
        );
    }

    #[test]
    fn test_sa_cache_entry_local() {
        let entry = SaCacheEntry::new_local(
            "10.0.0.5".parse().unwrap(),
            "239.1.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        );

        assert!(entry.is_local);
        assert!(entry.learned_from.is_none());
    }

    #[test]
    fn test_msdp_state_add_peer() {
        let mut state = MsdpState::new();
        state.config.enabled = true;

        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        let timers = state.add_peer(config);

        assert!(state.peers.contains_key(&"10.0.0.1".parse().unwrap()));
        assert!(!timers.is_empty()); // Should have connect retry timer
    }

    #[test]
    fn test_msdp_state_remove_peer() {
        let mut state = MsdpState::new();

        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        state.add_peer(config);

        // Add SA learned from this peer
        let entry = SaCacheEntry::new_learned(
            "10.0.0.5".parse().unwrap(),
            "239.1.1.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            Duration::from_secs(60),
        );
        state.sa_cache.insert(
            (
                "10.0.0.5".parse().unwrap(),
                "239.1.1.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ),
            entry,
        );

        state.remove_peer("10.0.0.1".parse().unwrap());

        assert!(!state.peers.contains_key(&"10.0.0.1".parse().unwrap()));
        assert!(state.sa_cache.is_empty()); // SA should be removed
    }

    #[test]
    fn test_msdp_state_mesh_groups() {
        let mut state = MsdpState::new();

        let mut config1 = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        config1.mesh_group = Some("anycast-rp".to_string());
        state.add_peer(config1);

        let mut config2 = MsdpPeerConfig::new("10.0.0.2".parse().unwrap());
        config2.mesh_group = Some("anycast-rp".to_string());
        state.add_peer(config2);

        assert_eq!(state.mesh_groups.len(), 1);
        assert_eq!(state.mesh_groups.get("anycast-rp").unwrap().len(), 2);

        state.remove_peer("10.0.0.1".parse().unwrap());
        assert_eq!(state.mesh_groups.get("anycast-rp").unwrap().len(), 1);

        state.remove_peer("10.0.0.2".parse().unwrap());
        assert!(!state.mesh_groups.contains_key("anycast-rp"));
    }

    #[test]
    fn test_msdp_header_parse() {
        // SA message header
        let data = [MSDP_SA, 0, 15]; // type=1, length=15
        let header = MsdpHeader::parse(&data).unwrap();
        assert_eq!(header.msg_type, MSDP_SA);
        assert_eq!(header.length, 15);
        assert_eq!(header.type_name(), "SA");
    }

    #[test]
    fn test_msdp_keepalive_builder() {
        let builder = MsdpKeepaliveBuilder::new();
        let packet = builder.build();

        assert_eq!(packet.len(), 3);
        assert_eq!(packet[0], MSDP_KEEPALIVE);
        assert_eq!(u16::from_be_bytes([packet[1], packet[2]]), 3);
    }

    #[test]
    fn test_msdp_sa_builder() {
        let mut builder = MsdpSaBuilder::new("10.0.0.1".parse().unwrap());
        builder.add_entry("10.0.0.5".parse().unwrap(), "239.1.1.1".parse().unwrap());

        let packet = builder.build();

        // Verify header
        assert_eq!(packet[0], MSDP_SA);

        // Parse it back
        let header = MsdpHeader::parse(&packet).unwrap();
        assert_eq!(header.msg_type, MSDP_SA);

        // Parse SA message
        let sa_msg = MsdpSaMessage::parse(&packet[3..]).unwrap();
        assert_eq!(sa_msg.entry_count, 1);
        assert_eq!(sa_msg.rp_address, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_msdp_state_get_flood_peers() {
        let mut state = MsdpState::new();

        // Add three peers: two in mesh group, one standalone
        let mut config1 = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        config1.mesh_group = Some("mesh1".to_string());
        state.add_peer(config1);

        let mut config2 = MsdpPeerConfig::new("10.0.0.2".parse().unwrap());
        config2.mesh_group = Some("mesh1".to_string());
        state.add_peer(config2);

        let config3 = MsdpPeerConfig::new("10.0.0.3".parse().unwrap());
        state.add_peer(config3);

        // Activate all peers
        let now = Instant::now();
        for peer in state.peers.values_mut() {
            peer.connected(now, true);
            peer.activate();
        }

        // Flood from peer1 (in mesh1) - should not go to peer2 (same mesh)
        let flood_peers = state.get_flood_peers(Some("10.0.0.1".parse().unwrap()));
        assert_eq!(flood_peers.len(), 1);
        assert!(flood_peers.contains(&"10.0.0.3".parse().unwrap()));

        // Flood from peer3 (standalone) - should go to peer1 and peer2
        let flood_peers = state.get_flood_peers(Some("10.0.0.3".parse().unwrap()));
        assert_eq!(flood_peers.len(), 2);
    }

    #[test]
    fn test_msdp_state_enable_disable() {
        let mut state = MsdpState::new();

        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        state.add_peer(config);

        let timers = state.enable();
        assert!(state.config.enabled);
        assert!(!timers.is_empty());

        state.disable();
        assert!(!state.config.enabled);
        assert!(state.sa_cache.is_empty());
        assert_eq!(
            state.peers.values().next().unwrap().state,
            MsdpPeerState::Disabled
        );
    }

    #[test]
    fn test_msdp_stats() {
        let mut state = MsdpState::new();

        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        state.add_peer(config);

        // Add SA entries
        let entry1 = SaCacheEntry::new_local(
            "10.0.0.5".parse().unwrap(),
            "239.1.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        );
        state.sa_cache.insert(
            (
                "10.0.0.5".parse().unwrap(),
                "239.1.1.1".parse().unwrap(),
                "10.0.0.1".parse().unwrap(),
            ),
            entry1,
        );

        let entry2 = SaCacheEntry::new_learned(
            "10.0.0.6".parse().unwrap(),
            "239.2.2.2".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            Duration::from_secs(60),
        );
        state.sa_cache.insert(
            (
                "10.0.0.6".parse().unwrap(),
                "239.2.2.2".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ),
            entry2,
        );

        let stats = state.stats();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.active_peers, 0);
        assert_eq!(stats.sa_cache_size, 2);
        assert_eq!(stats.local_entries, 1);
        assert_eq!(stats.learned_entries, 1);
    }

    #[test]
    fn test_local_source_active_creates_flood_request() {
        let mut state = MsdpState::new();
        state.config.enabled = true;

        let source: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let group: Ipv4Addr = "239.1.1.1".parse().unwrap();
        let rp: Ipv4Addr = "10.0.0.1".parse().unwrap();

        let result = state.local_source_active(source, group, rp, Instant::now());

        // Should have timer for SA expiry
        assert!(!result.timers.is_empty());

        // Should have flood request
        assert_eq!(result.floods.len(), 1);
        assert_eq!(result.floods[0].rp_address, rp);
        assert_eq!(result.floods[0].entries.len(), 1);
        assert_eq!(result.floods[0].entries[0], (source, group));
        assert!(result.floods[0].exclude_peer.is_none()); // Local source, no peer to exclude

        // SA should be in cache
        assert!(state.sa_cache.contains_key(&(source, group, rp)));
    }

    #[test]
    fn test_local_source_active_no_duplicate_flood() {
        let mut state = MsdpState::new();
        state.config.enabled = true;

        let source: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let group: Ipv4Addr = "239.1.1.1".parse().unwrap();
        let rp: Ipv4Addr = "10.0.0.1".parse().unwrap();

        // First call should create flood
        let result1 = state.local_source_active(source, group, rp, Instant::now());
        assert_eq!(result1.floods.len(), 1);

        // Second call should NOT create flood (already in cache)
        let result2 = state.local_source_active(source, group, rp, Instant::now());
        assert!(result2.floods.is_empty());
    }

    #[test]
    fn test_process_sa_message_creates_flood_and_learned_sources() {
        let mut state = MsdpState::new();
        state.config.enabled = true;

        // Add a peer first
        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        state.add_peer(config);

        // Activate the peer
        let now = Instant::now();
        state.connection_established("10.0.0.1".parse().unwrap(), true, now);
        if let Some(peer) = state.peers.get_mut(&"10.0.0.1".parse().unwrap()) {
            peer.activate();
        }

        let peer: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let entries = vec![
            (
                "10.0.0.5".parse().unwrap(),
                "239.1.1.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ),
            (
                "10.0.0.6".parse().unwrap(),
                "239.2.2.2".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ),
        ];

        let result = state.process_sa_message(peer, entries, now);

        // Should have flood requests (grouped by RP)
        assert_eq!(result.floods.len(), 1);
        assert_eq!(result.floods[0].entries.len(), 2);
        assert_eq!(result.floods[0].exclude_peer, Some(peer)); // Exclude sender

        // Should track learned sources for MSDP-to-PIM
        assert_eq!(result.learned_sources.len(), 2);

        // SA entries should be in cache
        assert_eq!(state.sa_cache.len(), 2);
    }

    #[test]
    fn test_process_sa_message_no_flood_for_existing() {
        let mut state = MsdpState::new();
        state.config.enabled = true;

        // Add a peer
        let config = MsdpPeerConfig::new("10.0.0.1".parse().unwrap());
        state.add_peer(config);
        let now = Instant::now();
        state.connection_established("10.0.0.1".parse().unwrap(), true, now);
        if let Some(peer) = state.peers.get_mut(&"10.0.0.1".parse().unwrap()) {
            peer.activate();
        }

        let peer: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let entries = vec![(
            "10.0.0.5".parse().unwrap(),
            "239.1.1.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        )];

        // First message should create flood
        let result1 = state.process_sa_message(peer, entries.clone(), now);
        assert_eq!(result1.floods.len(), 1);
        assert_eq!(result1.learned_sources.len(), 1);

        // Second message with same entries should just refresh, no flood
        let result2 = state.process_sa_message(peer, entries, now);
        assert!(result2.floods.is_empty());
        assert!(result2.learned_sources.is_empty());
    }

    #[test]
    fn test_sa_flood_request_struct() {
        let flood = SaFloodRequest {
            rp_address: "10.0.0.1".parse().unwrap(),
            entries: vec![
                ("10.0.0.5".parse().unwrap(), "239.1.1.1".parse().unwrap()),
                ("10.0.0.6".parse().unwrap(), "239.2.2.2".parse().unwrap()),
            ],
            exclude_peer: Some("10.0.0.3".parse().unwrap()),
        };

        assert_eq!(flood.rp_address, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(flood.entries.len(), 2);
        assert_eq!(flood.exclude_peer, Some("10.0.0.3".parse().unwrap()));
    }

    #[test]
    fn test_msdp_action_result() {
        let mut result = MsdpActionResult::new();
        assert!(result.timers.is_empty());
        assert!(result.floods.is_empty());
        assert!(result.learned_sources.is_empty());

        result.add_flood(SaFloodRequest {
            rp_address: "10.0.0.1".parse().unwrap(),
            entries: vec![("10.0.0.5".parse().unwrap(), "239.1.1.1".parse().unwrap())],
            exclude_peer: None,
        });
        assert_eq!(result.floods.len(), 1);

        result.add_learned_source("10.0.0.5".parse().unwrap(), "239.1.1.1".parse().unwrap());
        assert_eq!(result.learned_sources.len(), 1);
    }

    #[test]
    fn test_local_source_inactive_removes_from_cache() {
        let mut state = MsdpState::new();
        state.config.enabled = true;

        let source: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let group: Ipv4Addr = "239.1.1.1".parse().unwrap();
        let rp: Ipv4Addr = "10.0.0.1".parse().unwrap();

        // Add local source
        state.local_source_active(source, group, rp, Instant::now());
        assert!(state.sa_cache.contains_key(&(source, group, rp)));

        // Remove it
        state.local_source_inactive(source, group);
        assert!(!state.sa_cache.contains_key(&(source, group, rp)));
    }
}
