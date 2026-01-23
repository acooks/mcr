// SPDX-License-Identifier: Apache-2.0 OR MIT
use clap::Parser;
pub mod config;
pub mod logging;

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::path::PathBuf;

pub use config::{Config, ConfigRule, InputSpec, OutputSpec};

pub mod mroute;
pub mod protocols;

/// Protocol version for supervisor-client communication.
/// Increment when making breaking changes to SupervisorCommand or Response.
pub const PROTOCOL_VERSION: u32 = 1;

/// IP protocol numbers for PIM and IGMP
pub const IP_PROTO_IGMP: u8 = 2;
pub const IP_PROTO_PIM: u8 = 103;

/// PIM tree type for (S,G) vs (*,G) routing
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PimTreeType {
    /// (*,G) shared tree rooted at RP
    StarG,
    /// (S,G) shortest-path tree rooted at source
    SG,
}

impl std::fmt::Display for PimTreeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PimTreeType::StarG => write!(f, "(*,G)"),
            PimTreeType::SG => write!(f, "(S,G)"),
        }
    }
}

/// Source of a forwarding rule - distinguishes static from protocol-learned routes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum RuleSource {
    /// Rule loaded from config file at startup
    #[default]
    Static,
    /// Rule added dynamically via CLI at runtime
    Dynamic,
    /// Rule created by PIM state machine
    Pim {
        tree_type: PimTreeType,
        /// Unix timestamp when the route was created
        created_at: u64,
    },
    /// Rule created by IGMP membership
    Igmp {
        /// Unix timestamp when the membership was learned
        created_at: u64,
    },
}

impl std::fmt::Display for RuleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSource::Static => write!(f, "static"),
            RuleSource::Dynamic => write!(f, "dynamic"),
            RuleSource::Pim { tree_type, .. } => write!(f, "pim-{}", tree_type),
            RuleSource::Igmp { .. } => write!(f, "igmp"),
        }
    }
}

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
    // --- PIM Commands ---
    /// Get PIM neighbor table
    GetPimNeighbors,
    /// Enable PIM on an interface
    EnablePim {
        interface: String,
        dr_priority: Option<u32>,
    },
    /// Disable PIM on an interface
    DisablePim {
        interface: String,
    },
    /// Set a static RP mapping
    SetStaticRp {
        group_prefix: String,
        rp_address: Ipv4Addr,
    },
    /// Add an external PIM neighbor (injected by external control plane)
    AddExternalNeighbor {
        neighbor: ExternalNeighbor,
    },
    /// Remove an external PIM neighbor
    RemoveExternalNeighbor {
        address: Ipv4Addr,
        interface: String,
    },
    /// List external PIM neighbors
    ListExternalNeighbors,
    /// Clear all external PIM neighbors (optionally filtered by interface)
    ClearExternalNeighbors {
        interface: Option<String>,
    },
    // --- RPF Commands ---
    /// Set the RPF provider (disabled, static, or external socket)
    SetRpfProvider {
        provider: RpfProvider,
    },
    /// Get current RPF provider configuration
    GetRpfProvider,
    /// Query RPF for a specific source (for debugging)
    QueryRpf {
        source: Ipv4Addr,
    },
    /// Add a static RPF entry
    AddRpfRoute {
        source: Ipv4Addr,
        rpf: RpfInfo,
    },
    /// Remove a static RPF entry
    RemoveRpfRoute {
        source: Ipv4Addr,
    },
    /// List all static RPF entries
    ListRpfRoutes,
    /// Clear all static RPF entries
    ClearRpfRoutes,
    // --- IGMP Commands ---
    /// Get IGMP group membership table
    GetIgmpGroups,
    /// Enable IGMP querier on an interface
    EnableIgmpQuerier {
        interface: String,
    },
    /// Disable IGMP querier on an interface
    DisableIgmpQuerier {
        interface: String,
    },
    // --- Multicast Routing Table ---
    /// Get the multicast routing table (merged static + dynamic)
    GetMroute,
    // --- MSDP Commands ---
    /// Get MSDP peer status
    GetMsdpPeers,
    /// Get MSDP SA cache
    GetMsdpSaCache,
    /// Add an MSDP peer
    AddMsdpPeer {
        address: Ipv4Addr,
        description: Option<String>,
        mesh_group: Option<String>,
        default_peer: bool,
    },
    /// Remove an MSDP peer
    RemoveMsdpPeer {
        address: Ipv4Addr,
    },
    /// Clear MSDP SA cache
    ClearMsdpSaCache,
    // --- Event Subscription Commands ---
    /// Subscribe to protocol events (returns subscription ID)
    Subscribe {
        /// Event types to subscribe to
        events: Vec<EventType>,
    },
    /// Unsubscribe from events (by subscription ID)
    Unsubscribe {
        /// Subscription ID to cancel
        subscription_id: SubscriptionId,
    },
    /// List active subscriptions for this connection
    ListSubscriptions,
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
    /// PIM neighbor table response
    PimNeighbors(Vec<PimNeighborInfo>),
    /// External PIM neighbors response
    ExternalNeighbors(Vec<PimNeighborInfo>),
    /// IGMP group membership response
    IgmpGroups(Vec<IgmpGroupInfo>),
    /// Multicast routing table response
    Mroute(Vec<MrouteEntry>),
    /// MSDP peer table response
    MsdpPeers(Vec<MsdpPeerInfo>),
    /// MSDP SA cache response
    MsdpSaCache(Vec<MsdpSaCacheInfo>),
    /// RPF provider configuration response
    RpfProvider(RpfProviderInfo),
    /// RPF query result response
    RpfResult(Option<RpfInfo>),
    /// Static RPF routes response
    RpfRoutes(Vec<RpfRouteEntry>),
    /// Subscription created successfully
    Subscribed {
        /// Unique subscription ID for managing this subscription
        subscription_id: SubscriptionId,
        /// Event types subscribed to
        events: Vec<EventType>,
    },
    /// List of active subscriptions
    Subscriptions(Vec<SubscriptionInfo>),
    /// Protocol event notification (pushed to subscribers)
    Event(ProtocolEventNotification),
}

/// Source of a PIM neighbor - distinguishes Hello-learned from externally-injected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum NeighborSource {
    /// Discovered via PIM Hello exchange (default)
    #[default]
    PimHello,
    /// Injected by external control plane
    External {
        /// Optional tag for tracking the source (e.g., "babel", "ospf")
        tag: Option<String>,
    },
}

impl std::fmt::Display for NeighborSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NeighborSource::PimHello => write!(f, "pim-hello"),
            NeighborSource::External { tag: Some(t) } => write!(f, "external:{}", t),
            NeighborSource::External { tag: None } => write!(f, "external"),
        }
    }
}

/// External neighbor injection request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalNeighbor {
    /// Neighbor's IP address
    pub address: Ipv4Addr,
    /// Interface where neighbor is reachable
    pub interface: String,
    /// Optional DR priority (defaults to 1)
    pub dr_priority: Option<u32>,
    /// Optional tag for tracking source (e.g., "babel", "ospf")
    pub tag: Option<String>,
}

/// RPF (Reverse Path Forwarding) lookup result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpfInfo {
    /// Interface toward the source (RPF interface)
    pub upstream_interface: String,
    /// Next-hop neighbor toward the source (optional, for Join targeting)
    pub upstream_neighbor: Option<Ipv4Addr>,
    /// Metric/preference (lower is better, for choosing between multiple paths)
    pub metric: Option<u32>,
}

/// RPF provider configuration - determines how RPF lookups are performed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum RpfProvider {
    /// No RPF check (accept from any interface) - default for backwards compatibility
    #[default]
    Disabled,
    /// Use static RPF entries only
    Static,
    /// Query external Unix socket for RPF information
    External {
        /// Path to the external RPF provider socket
        socket_path: String,
    },
}

impl std::fmt::Display for RpfProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpfProvider::Disabled => write!(f, "disabled"),
            RpfProvider::Static => write!(f, "static"),
            RpfProvider::External { socket_path } => write!(f, "external:{}", socket_path),
        }
    }
}

/// Information about the current RPF provider configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpfProviderInfo {
    /// Current RPF provider type
    pub provider: RpfProvider,
    /// Number of static RPF entries
    pub static_entries: usize,
    /// Number of cached external RPF lookups
    pub cached_entries: usize,
}

/// Entry in the static RPF table
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpfRouteEntry {
    /// Source IP address this RPF entry applies to
    pub source: Ipv4Addr,
    /// RPF information (upstream interface and neighbor)
    pub rpf: RpfInfo,
}

/// Information about a PIM neighbor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PimNeighborInfo {
    /// Interface where neighbor was discovered
    pub interface: String,
    /// Neighbor's IP address
    pub address: Ipv4Addr,
    /// Neighbor's DR priority
    pub dr_priority: u32,
    /// Whether this neighbor is the DR on this interface
    pub is_dr: bool,
    /// Seconds until neighbor expires (None for external neighbors)
    pub expires_in_secs: Option<u64>,
    /// Neighbor's generation ID (None for external neighbors)
    pub generation_id: Option<u32>,
    /// Source of this neighbor (Hello-learned or external)
    pub source: NeighborSource,
}

/// Information about an IGMP group membership
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IgmpGroupInfo {
    /// Interface where membership was learned
    pub interface: String,
    /// Multicast group address
    pub group: Ipv4Addr,
    /// Seconds until membership expires
    pub expires_in_secs: u64,
    /// IP address of the last host that reported membership
    pub last_reporter: Option<Ipv4Addr>,
    /// Whether we are the querier on this interface
    pub is_querier: bool,
}

/// Entry in the multicast routing table
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MrouteEntry {
    /// Source IP (None = (*,G) entry)
    pub source: Option<Ipv4Addr>,
    /// Multicast group address
    pub group: Ipv4Addr,
    /// Input interface
    pub input_interface: String,
    /// Output interfaces
    pub output_interfaces: Vec<String>,
    /// Type of entry (static, (*,G), (S,G), igmp)
    pub entry_type: MrouteEntryType,
    /// Age in seconds (how long ago was this entry created)
    pub age_secs: u64,
}

/// Type of multicast route entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MrouteEntryType {
    /// Static rule from config/CLI
    Static,
    /// PIM (*,G) shared tree
    StarG,
    /// PIM (S,G) shortest-path tree
    SG,
    /// IGMP membership (local receivers)
    Igmp,
}

/// Information about an MSDP peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MsdpPeerInfo {
    /// Peer's IP address
    pub address: Ipv4Addr,
    /// Peer state (disabled, connecting, established, active)
    pub state: String,
    /// Optional description
    pub description: Option<String>,
    /// Mesh group name (if configured)
    pub mesh_group: Option<String>,
    /// Whether this peer is a default peer
    pub default_peer: bool,
    /// Uptime in seconds (if connected)
    pub uptime_secs: Option<u64>,
    /// Number of SA messages received
    pub sa_received: u64,
    /// Number of SA messages sent
    pub sa_sent: u64,
    /// Whether we initiated (active) or received (passive) the connection
    pub is_active: bool,
}

/// Information about an MSDP SA cache entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MsdpSaCacheInfo {
    /// Source IP address
    pub source: Ipv4Addr,
    /// Multicast group address
    pub group: Ipv4Addr,
    /// RP that originated this SA
    pub origin_rp: Ipv4Addr,
    /// Peer from which we learned this SA (None if local)
    pub learned_from: Option<Ipv4Addr>,
    /// Age in seconds
    pub age_secs: u64,
    /// Seconds until expiry
    pub expires_in_secs: u64,
    /// Whether this is a local source
    pub is_local: bool,
}

// ============================================================================
// Event Subscription Types (Phase 3: Control Plane Integration)
// ============================================================================

/// Event types that can be subscribed to for push notifications
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    /// IGMP membership changes (join/leave)
    IgmpMembership,
    /// PIM neighbor changes (up/down)
    PimNeighbor,
    /// PIM route changes (add/remove/update)
    PimRoute,
    /// MSDP SA cache changes (add/remove/refresh)
    MsdpSaCache,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::IgmpMembership => write!(f, "igmp-membership"),
            EventType::PimNeighbor => write!(f, "pim-neighbor"),
            EventType::PimRoute => write!(f, "pim-route"),
            EventType::MsdpSaCache => write!(f, "msdp-sa-cache"),
        }
    }
}

/// Protocol event notification payload - sent to subscribers
///
/// This is the external event notification type for control plane integration.
/// It differs from `protocols::ProtocolEvent` which is used internally for
/// state machine communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProtocolEventNotification {
    /// IGMP membership change on an interface
    IgmpMembershipChange {
        /// Interface where membership changed
        interface: String,
        /// Multicast group address
        group: Ipv4Addr,
        /// Join or leave action
        action: MembershipAction,
        /// IP address of the reporting host (if available)
        reporter: Option<Ipv4Addr>,
        /// Unix timestamp (seconds since epoch)
        timestamp: u64,
    },
    /// PIM neighbor state change
    PimNeighborChange {
        /// Interface where neighbor changed
        interface: String,
        /// Neighbor IP address
        neighbor: Ipv4Addr,
        /// Up or down action
        action: NeighborAction,
        /// Source of the neighbor (Hello-learned or external)
        source: NeighborSource,
        /// Unix timestamp (seconds since epoch)
        timestamp: u64,
    },
    /// PIM route state change
    PimRouteChange {
        /// Type of route ((*,G) or (S,G))
        route_type: PimTreeType,
        /// Multicast group address
        group: Ipv4Addr,
        /// Source address (None for (*,G))
        source: Option<Ipv4Addr>,
        /// Add, remove, or update action
        action: RouteAction,
        /// Unix timestamp (seconds since epoch)
        timestamp: u64,
    },
    /// MSDP SA cache change
    MsdpSaCacheChange {
        /// Source IP address
        source: Ipv4Addr,
        /// Multicast group address
        group: Ipv4Addr,
        /// RP that originated this SA
        rp: Ipv4Addr,
        /// Add, remove, or refresh action
        action: SaCacheAction,
        /// Unix timestamp (seconds since epoch)
        timestamp: u64,
    },
}

impl ProtocolEventNotification {
    /// Get the event type for this notification
    pub fn event_type(&self) -> EventType {
        match self {
            ProtocolEventNotification::IgmpMembershipChange { .. } => EventType::IgmpMembership,
            ProtocolEventNotification::PimNeighborChange { .. } => EventType::PimNeighbor,
            ProtocolEventNotification::PimRouteChange { .. } => EventType::PimRoute,
            ProtocolEventNotification::MsdpSaCacheChange { .. } => EventType::MsdpSaCache,
        }
    }

    /// Get the timestamp for this event
    pub fn timestamp(&self) -> u64 {
        match self {
            ProtocolEventNotification::IgmpMembershipChange { timestamp, .. } => *timestamp,
            ProtocolEventNotification::PimNeighborChange { timestamp, .. } => *timestamp,
            ProtocolEventNotification::PimRouteChange { timestamp, .. } => *timestamp,
            ProtocolEventNotification::MsdpSaCacheChange { timestamp, .. } => *timestamp,
        }
    }
}

/// IGMP membership action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MembershipAction {
    /// Host joined the group
    Join,
    /// Host left the group (or membership expired)
    Leave,
}

impl std::fmt::Display for MembershipAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MembershipAction::Join => write!(f, "join"),
            MembershipAction::Leave => write!(f, "leave"),
        }
    }
}

/// PIM neighbor action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NeighborAction {
    /// Neighbor came up (Hello received or externally injected)
    Up,
    /// Neighbor went down (timeout or externally removed)
    Down,
}

impl std::fmt::Display for NeighborAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NeighborAction::Up => write!(f, "up"),
            NeighborAction::Down => write!(f, "down"),
        }
    }
}

/// PIM route action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RouteAction {
    /// Route was added
    Add,
    /// Route was removed
    Remove,
    /// Route was updated (e.g., OIL changed)
    Update,
}

impl std::fmt::Display for RouteAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteAction::Add => write!(f, "add"),
            RouteAction::Remove => write!(f, "remove"),
            RouteAction::Update => write!(f, "update"),
        }
    }
}

/// MSDP SA cache action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SaCacheAction {
    /// SA entry was added
    Add,
    /// SA entry was removed (expired or withdrawn)
    Remove,
    /// SA entry was refreshed
    Refresh,
}

impl std::fmt::Display for SaCacheAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaCacheAction::Add => write!(f, "add"),
            SaCacheAction::Remove => write!(f, "remove"),
            SaCacheAction::Refresh => write!(f, "refresh"),
        }
    }
}

/// Subscription identifier for tracking active subscriptions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub String);

impl SubscriptionId {
    /// Generate a new unique subscription ID
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        SubscriptionId(format!("sub-{:x}", ts))
    }
}

impl Default for SubscriptionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information about an active subscription
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubscriptionInfo {
    /// Unique subscription ID
    pub id: SubscriptionId,
    /// Event types subscribed to
    pub events: Vec<EventType>,
    /// Unix timestamp when subscription was created
    pub created_at: u64,
    /// Number of events delivered on this subscription
    pub events_delivered: u64,
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
    /// Optional source IP filter for PIM (S,G) matching.
    /// If Some, only packets from this source are matched.
    /// If None, packets from any source are matched ((*,G) or static rules).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_source: Option<Ipv4Addr>,
    pub outputs: Vec<OutputDestination>,
    /// Source of this rule (static, dynamic, PIM, IGMP)
    #[serde(default)]
    pub source: RuleSource,
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
    /// Set log level for workers - sent from supervisor when log levels are changed
    SetLogLevel {
        /// If None, set global level. If Some(facility), set facility-specific level.
        facility: Option<logging::Facility>,
        level: logging::Severity,
    },
}

impl RelayCommand {
    pub fn rule_id(&self) -> Option<String> {
        match self {
            RelayCommand::AddRule(rule) => Some(rule.rule_id.clone()),
            RelayCommand::RemoveRule { rule_id } => Some(rule_id.clone()),
            RelayCommand::SyncRules(_) => None,
            RelayCommand::Shutdown => None,
            RelayCommand::Ping => None,
            RelayCommand::SetLogLevel { .. } => None,
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
            input_source: None,
            outputs: vec![],
            source: RuleSource::Static,
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
            input_source: None,
            outputs: vec![OutputDestination {
                group: "224.0.0.2".parse().unwrap(),
                port: 5001,
                interface: "127.0.0.1".to_string(),
            }],
            source: RuleSource::Static,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: ForwardingRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, deserialized);
    }

    #[test]
    fn test_forwarding_rule_with_source_filter() {
        let rule = ForwardingRule {
            rule_id: "sg-rule".to_string(),
            name: Some("S,G rule".to_string()),
            input_interface: "eth0".to_string(),
            input_group: "239.1.1.1".parse().unwrap(),
            input_port: 5000,
            input_source: Some("10.0.0.5".parse().unwrap()),
            outputs: vec![OutputDestination {
                group: "239.1.1.1".parse().unwrap(),
                port: 5000,
                interface: "eth1".to_string(),
            }],
            source: RuleSource::Pim {
                tree_type: PimTreeType::SG,
                created_at: 1234567890,
            },
        };
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: ForwardingRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, deserialized);
        assert_eq!(rule.input_source, Some("10.0.0.5".parse().unwrap()));
        assert!(matches!(
            rule.source,
            RuleSource::Pim {
                tree_type: PimTreeType::SG,
                ..
            }
        ));
    }

    #[test]
    fn test_rule_source_display() {
        assert_eq!(RuleSource::Static.to_string(), "static");
        assert_eq!(RuleSource::Dynamic.to_string(), "dynamic");
        assert_eq!(
            RuleSource::Pim {
                tree_type: PimTreeType::StarG,
                created_at: 0
            }
            .to_string(),
            "pim-(*,G)"
        );
        assert_eq!(
            RuleSource::Pim {
                tree_type: PimTreeType::SG,
                created_at: 0
            }
            .to_string(),
            "pim-(S,G)"
        );
        assert_eq!(RuleSource::Igmp { created_at: 0 }.to_string(), "igmp");
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

    #[test]
    fn test_event_type_display() {
        assert_eq!(EventType::IgmpMembership.to_string(), "igmp-membership");
        assert_eq!(EventType::PimNeighbor.to_string(), "pim-neighbor");
        assert_eq!(EventType::PimRoute.to_string(), "pim-route");
        assert_eq!(EventType::MsdpSaCache.to_string(), "msdp-sa-cache");
    }

    #[test]
    fn test_event_type_serialization() {
        let events = vec![
            EventType::IgmpMembership,
            EventType::PimNeighbor,
            EventType::PimRoute,
            EventType::MsdpSaCache,
        ];
        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            let deserialized: EventType = serde_json::from_str(&json).unwrap();
            assert_eq!(event, deserialized);
        }
    }

    #[test]
    fn test_protocol_event_notification_igmp() {
        let event = ProtocolEventNotification::IgmpMembershipChange {
            interface: "eth0".to_string(),
            group: "239.1.1.1".parse().unwrap(),
            action: MembershipAction::Join,
            reporter: Some("10.0.0.5".parse().unwrap()),
            timestamp: 1706012345,
        };
        assert_eq!(event.event_type(), EventType::IgmpMembership);
        assert_eq!(event.timestamp(), 1706012345);

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ProtocolEventNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_protocol_event_notification_pim_neighbor() {
        let event = ProtocolEventNotification::PimNeighborChange {
            interface: "eth0".to_string(),
            neighbor: "10.0.0.1".parse().unwrap(),
            action: NeighborAction::Up,
            source: NeighborSource::PimHello,
            timestamp: 1706012345,
        };
        assert_eq!(event.event_type(), EventType::PimNeighbor);

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ProtocolEventNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_protocol_event_notification_pim_route() {
        let event = ProtocolEventNotification::PimRouteChange {
            route_type: PimTreeType::SG,
            group: "239.1.1.1".parse().unwrap(),
            source: Some("10.0.0.5".parse().unwrap()),
            action: RouteAction::Add,
            timestamp: 1706012345,
        };
        assert_eq!(event.event_type(), EventType::PimRoute);

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ProtocolEventNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_protocol_event_notification_msdp() {
        let event = ProtocolEventNotification::MsdpSaCacheChange {
            source: "10.0.0.5".parse().unwrap(),
            group: "239.1.1.1".parse().unwrap(),
            rp: "10.0.0.1".parse().unwrap(),
            action: SaCacheAction::Add,
            timestamp: 1706012345,
        };
        assert_eq!(event.event_type(), EventType::MsdpSaCache);

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ProtocolEventNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_action_enum_display() {
        assert_eq!(MembershipAction::Join.to_string(), "join");
        assert_eq!(MembershipAction::Leave.to_string(), "leave");
        assert_eq!(NeighborAction::Up.to_string(), "up");
        assert_eq!(NeighborAction::Down.to_string(), "down");
        assert_eq!(RouteAction::Add.to_string(), "add");
        assert_eq!(RouteAction::Remove.to_string(), "remove");
        assert_eq!(RouteAction::Update.to_string(), "update");
        assert_eq!(SaCacheAction::Add.to_string(), "add");
        assert_eq!(SaCacheAction::Remove.to_string(), "remove");
        assert_eq!(SaCacheAction::Refresh.to_string(), "refresh");
    }

    #[test]
    fn test_subscription_id_unique() {
        let id1 = SubscriptionId::new();
        let id2 = SubscriptionId::new();
        // IDs should be unique (different nanosecond timestamps)
        assert_ne!(id1.0, id2.0);
        assert!(id1.0.starts_with("sub-"));
        assert!(id2.0.starts_with("sub-"));
    }

    #[test]
    fn test_subscribe_command_serialization() {
        let cmd = SupervisorCommand::Subscribe {
            events: vec![EventType::IgmpMembership, EventType::PimNeighbor],
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let deserialized: SupervisorCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, deserialized);
    }

    #[test]
    fn test_subscribed_response_serialization() {
        let resp = Response::Subscribed {
            subscription_id: SubscriptionId("sub-12345".to_string()),
            events: vec![EventType::IgmpMembership],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn test_event_response_serialization() {
        let event = ProtocolEventNotification::IgmpMembershipChange {
            interface: "eth0".to_string(),
            group: "239.1.1.1".parse().unwrap(),
            action: MembershipAction::Join,
            reporter: None,
            timestamp: 1706012345,
        };
        let resp = Response::Event(event.clone());
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, deserialized);
    }
}
