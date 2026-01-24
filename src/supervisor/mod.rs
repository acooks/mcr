// SPDX-License-Identifier: Apache-2.0 OR MIT
// Allow await_holding_lock for std::sync::Mutex - these are intentional short-lived locks
#![allow(clippy::await_holding_lock)]

// Submodules
mod actions;
mod command_handler;
mod event_subscription;
mod socket_helpers;
mod timer_manager;
mod worker_manager;

// Re-exports
pub use actions::{MribAction, OutgoingPacket, ProtocolHandlerResult, ProtocolType};
pub use command_handler::{handle_supervisor_command, CommandAction};
pub use event_subscription::EventSubscriptionManager;
pub use timer_manager::ProtocolTimerManager;

// Internal imports from submodules
use worker_manager::WorkerManager;

use anyhow::Result;
use futures::SinkExt;
use log::error;
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;

use crate::config::Config;
use crate::logging::{AsyncConsumer, Facility, Logger, MPSCRingBuffer};
use crate::mroute::MulticastRib;
use crate::protocols::igmp::InterfaceIgmpState;
use crate::protocols::msdp::MsdpState;
use crate::protocols::pim::PimState;
use crate::protocols::{ProtocolEvent, TimerRequest, TimerType};
use crate::{log_debug, log_error, log_info, log_warning, ForwardingRule, RelayCommand};
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const SHUTDOWN_TIMEOUT_SECS: u64 = 10; // Timeout for graceful worker shutdown
const PERIODIC_SYNC_INTERVAL_SECS: u64 = 300; // 5 minutes - periodic full ruleset sync to all workers

// Protocol constants
#[allow(dead_code)]
const ALL_PIM_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

/// Get current Unix timestamp in seconds
fn unix_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Protocol state management for IGMP, PIM, and MSDP
///
/// This struct holds all protocol state machines and raw sockets needed
/// for multicast routing protocol support. It runs in the supervisor
/// process to maintain centralized state.
pub struct ProtocolState {
    /// IGMP state per interface (querier election, group membership)
    pub igmp_state: HashMap<String, InterfaceIgmpState>,

    /// Global PIM-SM state (neighbors, (*,G) and (S,G) entries)
    pub pim_state: PimState,

    /// Global MSDP state (peers, SA cache)
    pub msdp_state: MsdpState,

    /// Multicast Routing Information Base - merges static + dynamic routes
    pub mrib: MulticastRib,

    /// Raw socket for IGMP packets (protocol 2)
    pub igmp_socket: Option<OwnedFd>,

    /// Raw socket for PIM packets (protocol 103)
    pub pim_socket: Option<OwnedFd>,

    /// Channel to send timer requests
    pub timer_tx: Option<mpsc::Sender<TimerRequest>>,

    /// Channel to send MSDP TCP commands
    pub msdp_tcp_tx: Option<mpsc::Sender<crate::protocols::msdp_tcp::MsdpTcpCommand>>,

    /// Channel to send protocol events (for spawning receiver loop)
    pub event_tx: Option<mpsc::Sender<ProtocolEvent>>,

    /// Whether the protocol receiver loop has been started
    pub receiver_loop_running: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// Whether protocols are enabled
    pub igmp_enabled: bool,
    pub pim_enabled: bool,
    pub msdp_enabled: bool,

    /// Logger for protocol events
    logger: Logger,

    /// Event subscription manager for push notifications
    pub event_manager: Option<EventSubscriptionManager>,

    /// Event buffer size for subscription manager
    event_buffer_size: usize,

    /// Pending timers from protocol init (processed after timer_tx is available)
    pending_igmp_timers: Vec<TimerRequest>,
}

impl ProtocolState {
    /// Create a new ProtocolState with protocols disabled
    pub fn new(logger: Logger) -> Self {
        Self {
            igmp_state: HashMap::new(),
            pim_state: PimState::new(),
            msdp_state: MsdpState::new(),
            mrib: MulticastRib::new(),
            igmp_socket: None,
            pim_socket: None,
            timer_tx: None,
            msdp_tcp_tx: None,
            event_tx: None,
            receiver_loop_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            igmp_enabled: false,
            pim_enabled: false,
            msdp_enabled: false,
            logger,
            event_manager: None,
            event_buffer_size: 256, // Default
            pending_igmp_timers: Vec::new(),
        }
    }

    /// Enable event subscription manager for external control plane integration
    pub fn enable_event_subscriptions(&mut self, buffer_size: usize) {
        self.event_buffer_size = buffer_size;
        self.event_manager = Some(EventSubscriptionManager::new(buffer_size));
    }

    /// Get the configured event buffer size
    pub fn event_buffer_size(&self) -> usize {
        self.event_buffer_size
    }

    /// Emit an event to all subscribers (if event manager is enabled)
    pub fn emit_event(&self, event: crate::ProtocolEventNotification) {
        if let Some(ref manager) = self.event_manager {
            manager.send(event);
        }
    }

    /// Apply MRIB actions returned by a protocol handler
    pub fn apply_mrib_actions(&mut self, actions: Vec<MribAction>) {
        for action in actions {
            match action {
                MribAction::AddIgmpMembership {
                    interface,
                    group,
                    membership,
                } => {
                    self.mrib.add_igmp_membership(&interface, group, membership);
                }
                MribAction::RemoveIgmpMembership { interface, group } => {
                    self.mrib.remove_igmp_membership(&interface, group);
                }
                MribAction::AddStarGRoute(route) => {
                    self.mrib.add_star_g_route(route);
                }
                MribAction::RemoveStarGRoute { group } => {
                    self.mrib.remove_star_g_route(group);
                }
                MribAction::AddSgRoute(route) => {
                    self.mrib.add_sg_route(route);
                }
                MribAction::RemoveSgRoute { source, group } => {
                    self.mrib.remove_sg_route(source, group);
                }
            }
        }
    }

    /// Emit notifications returned by a protocol handler
    pub fn emit_notifications(&self, notifications: Vec<crate::ProtocolEventNotification>) {
        for notification in notifications {
            self.emit_event(notification);
        }
    }

    /// Initialize IGMP on specified interfaces
    pub fn enable_igmp(&mut self, interfaces: &[String], config: &crate::config::IgmpConfig) {
        use crate::protocols::igmp::IgmpConfig as ProtocolIgmpConfig;

        let igmp_config = ProtocolIgmpConfig {
            query_interval: std::time::Duration::from_secs(config.query_interval as u64),
            query_response_interval: std::time::Duration::from_secs(
                config.query_response_interval as u64,
            ),
            robustness_variable: config.robustness,
            ..ProtocolIgmpConfig::default()
        };

        for iface in interfaces {
            // Get interface IP address
            if let Some(ip) = get_interface_ipv4(iface) {
                let state = InterfaceIgmpState::new(iface.clone(), ip, igmp_config.clone());
                self.igmp_state.insert(iface.clone(), state);

                // Schedule initial General Query for this interface
                // The query will trigger hosts to send Membership Reports
                self.pending_igmp_timers.push(TimerRequest {
                    timer_type: TimerType::IgmpGeneralQuery {
                        interface: iface.clone(),
                    },
                    fire_at: Instant::now(), // Send immediately
                    replace_existing: true,
                });

                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("IGMP enabled on interface {} (IP: {})", iface, ip)
                );
            } else {
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("Cannot enable IGMP on {}: no IPv4 address found", iface)
                );
            }
        }
        self.igmp_enabled = !self.igmp_state.is_empty();
    }

    /// Initialize PIM-SM with the given configuration
    pub fn enable_pim(&mut self, config: &crate::config::PimConfig) {
        use crate::protocols::pim::PimInterfaceConfig;

        // Determine router ID
        let router_id = config.router_id.unwrap_or_else(|| {
            // Use highest interface IP as default router ID
            config
                .interfaces
                .iter()
                .filter_map(|iface| get_interface_ipv4(&iface.name))
                .max()
                .unwrap_or(Ipv4Addr::new(0, 0, 0, 1))
        });

        // Create new PIM state
        self.pim_state = PimState::new();
        self.pim_state.config.router_id = Some(router_id);

        // Configure RP if we are one
        if let Some(rp_addr) = config.rp_address {
            self.pim_state.config.rp_address = Some(rp_addr);
        }

        // Add static RP mappings
        for rp_config in &config.static_rp {
            if let Ok(group) = parse_group_prefix(&rp_config.group) {
                self.pim_state.config.static_rp.insert(group, rp_config.rp);
            }
        }

        // Initialize per-interface PIM state
        for iface_config in &config.interfaces {
            if let Some(ip) = get_interface_ipv4(&iface_config.name) {
                let pim_iface_config = PimInterfaceConfig {
                    dr_priority: iface_config.dr_priority,
                    hello_period: std::time::Duration::from_secs(iface_config.hello_period),
                    ..PimInterfaceConfig::default()
                };
                let timers =
                    self.pim_state
                        .enable_interface(&iface_config.name, ip, pim_iface_config);

                // Schedule PIM Hello timer (if timer channel is available)
                if let Some(ref timer_tx) = self.timer_tx {
                    for timer in timers {
                        if let Err(e) = timer_tx.try_send(timer) {
                            log_warning!(
                                self.logger,
                                Facility::Supervisor,
                                &format!("Failed to schedule PIM Hello timer: {}", e)
                            );
                        }
                    }
                }

                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "PIM enabled on interface {} (IP: {}, DR priority: {})",
                        iface_config.name, ip, iface_config.dr_priority
                    )
                );
            }
        }

        self.pim_enabled = !config.interfaces.is_empty();
        if self.pim_enabled {
            log_info!(
                self.logger,
                Facility::Supervisor,
                &format!("PIM-SM initialized with router_id={}", router_id)
            );
        }
    }

    /// Process a protocol event and return any timer requests
    pub fn process_event(&mut self, event: ProtocolEvent) -> Vec<TimerRequest> {
        let result = match event {
            ProtocolEvent::Igmp(igmp_event) => self.handle_igmp_event(igmp_event),
            ProtocolEvent::Pim(pim_event) => self.handle_pim_event(pim_event),
            ProtocolEvent::Msdp(msdp_event) => self.handle_msdp_event(msdp_event),
            ProtocolEvent::TimerExpired(timer_type) => self.handle_timer_expired(timer_type),
        };

        // Apply MRIB actions, emit notifications, and send packets
        self.apply_mrib_actions(result.mrib_actions);
        self.emit_notifications(result.notifications);
        self.send_outgoing_packets(result.packets);

        result.timers
    }

    fn handle_igmp_event(
        &mut self,
        event: crate::protocols::igmp::IgmpEvent,
    ) -> ProtocolHandlerResult {
        use crate::protocols::igmp::IgmpEvent;
        let now = Instant::now();
        let mut result = ProtocolHandlerResult::new();

        match event {
            IgmpEvent::EnableQuerier {
                interface,
                interface_ip,
            } => {
                let igmp_config = crate::protocols::igmp::IgmpConfig::default();
                let state = InterfaceIgmpState::new(interface.clone(), interface_ip, igmp_config);
                self.igmp_state.insert(interface, state);
            }
            IgmpEvent::DisableQuerier { interface } => {
                self.igmp_state.remove(&interface);
            }
            IgmpEvent::PacketReceived {
                interface,
                src_ip,
                msg_type,
                max_resp_time: _,
                group,
            } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    match msg_type {
                        0x11 => {
                            // Query - handle querier election
                            result.add_timers(igmp_state.received_query(src_ip, now));
                        }
                        0x16 => {
                            // V2 Membership Report
                            let timers = igmp_state.received_report(src_ip, group, now);
                            result.add_timers(timers);
                            // Add to MRIB if this is a new group (read access is kept)
                            let is_new = !self
                                .mrib
                                .get_igmp_interfaces_for_group(group)
                                .contains(&interface);
                            if is_new {
                                let membership = crate::mroute::IgmpMembership {
                                    group,
                                    expires_at: now + igmp_state.config.group_membership_interval(),
                                    last_reporter: Some(src_ip),
                                };
                                result.add_action(MribAction::AddIgmpMembership {
                                    interface: interface.clone(),
                                    group,
                                    membership,
                                });
                                result.notify(
                                    crate::ProtocolEventNotification::IgmpMembershipChange {
                                        interface: interface.clone(),
                                        group,
                                        action: crate::MembershipAction::Join,
                                        reporter: Some(src_ip),
                                        timestamp: unix_timestamp(),
                                    },
                                );
                            }
                        }
                        0x17 => {
                            // Leave Group
                            result.add_timers(igmp_state.received_leave(group, now));
                        }
                        _ => {}
                    }
                } else {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!(
                            "Received IGMP {} from {} for group {} on interface '{}' which is not IGMP-enabled",
                            match msg_type {
                                0x11 => "Query",
                                0x16 => "V2 Report",
                                0x17 => "Leave",
                                _ => "Unknown",
                            },
                            src_ip, group, interface
                        )
                    );
                }
            }
            IgmpEvent::QueryTimerExpired { interface } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    result.add_timers(igmp_state.query_timer_expired(now));
                }
            }
            IgmpEvent::OtherQuerierExpired { interface } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    result.add_timers(igmp_state.other_querier_expired(now));
                }
            }
            IgmpEvent::GroupExpired { interface, group } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    igmp_state.group_expired(group, now);
                    result.add_action(MribAction::RemoveIgmpMembership {
                        interface: interface.clone(),
                        group,
                    });
                    result.notify(crate::ProtocolEventNotification::IgmpMembershipChange {
                        interface: interface.clone(),
                        group,
                        action: crate::MembershipAction::Leave,
                        reporter: None,
                        timestamp: unix_timestamp(),
                    });
                }
            }
            IgmpEvent::GroupQueryExpired { interface, group } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    let (timers, expired) = igmp_state.group_query_expired(group, now);
                    result.add_timers(timers);
                    if expired {
                        result.add_action(MribAction::RemoveIgmpMembership {
                            interface: interface.clone(),
                            group,
                        });
                        result.notify(crate::ProtocolEventNotification::IgmpMembershipChange {
                            interface: interface.clone(),
                            group,
                            action: crate::MembershipAction::Leave,
                            reporter: None,
                            timestamp: unix_timestamp(),
                        });
                    }
                }
            }
        }
        result
    }

    fn handle_pim_event(
        &mut self,
        event: crate::protocols::pim::PimEvent,
    ) -> ProtocolHandlerResult {
        use crate::protocols::pim::PimEvent;
        let mut result = ProtocolHandlerResult::new();

        match event {
            PimEvent::EnableInterface {
                interface,
                interface_ip,
                dr_priority,
            } => {
                let config = if let Some(priority) = dr_priority {
                    crate::protocols::pim::PimInterfaceConfig {
                        dr_priority: priority,
                        ..Default::default()
                    }
                } else {
                    crate::protocols::pim::PimInterfaceConfig::default()
                };
                let timers = self
                    .pim_state
                    .enable_interface(&interface, interface_ip, config);
                result.add_timers(timers);
            }
            PimEvent::DisableInterface { interface } => {
                self.pim_state.disable_interface(&interface);
            }
            PimEvent::PacketReceived {
                interface: reported_interface,
                src_ip,
                msg_type,
                payload,
            } => {
                match msg_type {
                    0 => {
                        // Hello - parse options and process
                        // Find the correct PIM-enabled interface for this source IP.
                        // In shared namespace setups, IP_PKTINFO may report the wrong interface,
                        // so we look for a PIM-enabled interface in the same subnet as src_ip.
                        let interface = self
                            .pim_state
                            .find_interface_for_neighbor(src_ip)
                            .unwrap_or(reported_interface);

                        let (timers, is_new_neighbor, dr_changed, is_dr) =
                            if let Some(iface_state) = self.pim_state.get_interface_mut(&interface)
                            {
                                // Skip self-originated packets (multicast loop)
                                if src_ip == iface_state.address {
                                    log_debug!(
                                        self.logger,
                                        Facility::Supervisor,
                                        &format!(
                                            "PIM: Ignoring self-originated Hello on interface {}",
                                            interface
                                        )
                                    );
                                    return result;
                                }

                                log_info!(
                                    self.logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "PIM: Processing Hello from {} on interface {}",
                                        src_ip, interface
                                    )
                                );
                                use crate::protocols::pim::PimHelloOption;
                                use std::time::Duration;

                                // Parse Hello options from payload
                                let options = PimHelloOption::parse_all(&payload);
                                let mut holdtime = Duration::from_secs(105); // Default holdtime
                                let mut dr_priority = 1u32; // Default DR priority
                                let mut generation_id = 0u32;

                                for option in options {
                                    match option {
                                        PimHelloOption::Holdtime(h) => {
                                            holdtime = Duration::from_secs(h as u64)
                                        }
                                        PimHelloOption::DrPriority(p) => dr_priority = p,
                                        PimHelloOption::GenerationId(g) => generation_id = g,
                                        PimHelloOption::Unknown { .. } => {}
                                    }
                                }

                                // Check if this is a new neighbor before processing
                                let is_new = !iface_state.has_neighbor(src_ip);

                                let timers = iface_state.received_hello(
                                    src_ip,
                                    holdtime,
                                    dr_priority,
                                    generation_id,
                                    Instant::now(),
                                );

                                // Check if DR election changed
                                let dr_changed = iface_state.elect_dr();
                                let is_dr = iface_state.is_dr();

                                (timers, is_new, dr_changed, is_dr)
                            } else {
                                log_warning!(
                                    self.logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "PIM: Ignored Hello from {} - interface {} not PIM-enabled",
                                        src_ip, interface
                                    )
                                );
                                (Vec::new(), false, false, false)
                            };

                        result.add_timers(timers);

                        // Emit event for new neighbor (outside mutable borrow)
                        if is_new_neighbor {
                            log_info!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "PIM: Added neighbor {} on interface {}",
                                    src_ip, interface
                                )
                            );
                            result.notify(crate::ProtocolEventNotification::PimNeighborChange {
                                interface: interface.clone(),
                                neighbor: src_ip,
                                action: crate::NeighborAction::Up,
                                source: crate::NeighborSource::PimHello,
                                timestamp: unix_timestamp(),
                            });
                        }

                        if dr_changed {
                            log_debug!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "DR election on {} - we are {}DR",
                                    interface,
                                    if is_dr { "" } else { "not " }
                                )
                            );
                        }
                    }
                    1 => {
                        // Register - only if we're RP
                        if let Some(rp_address) = self.pim_state.config.rp_address {
                            // Parse Register message
                            // Register format: 4 bytes flags, then encapsulated IP packet
                            if payload.len() >= 24 {
                                // 4 bytes flags + 20 bytes min IP header
                                let flags = u32::from_be_bytes([
                                    payload[0], payload[1], payload[2], payload[3],
                                ]);
                                let null_register = (flags & 0x40000000) != 0;

                                // Extract source and group from encapsulated IP header
                                let ip_header = &payload[4..];
                                if ip_header.len() >= 20 {
                                    let source = Ipv4Addr::new(
                                        ip_header[12],
                                        ip_header[13],
                                        ip_header[14],
                                        ip_header[15],
                                    );
                                    let group = Ipv4Addr::new(
                                        ip_header[16],
                                        ip_header[17],
                                        ip_header[18],
                                        ip_header[19],
                                    );

                                    // Check if this is a new source (not already in our state)
                                    let is_new_source =
                                        !self.pim_state.sg.contains_key(&(source, group));

                                    let _ = self.pim_state.process_register(
                                        source,
                                        group,
                                        null_register,
                                    );

                                    // Notify MSDP of new local source (only for non-null registers)
                                    if is_new_source && !null_register && self.msdp_enabled {
                                        log_debug!(
                                            self.logger,
                                            Facility::Supervisor,
                                            &format!(
                                                "PIM: notifying MSDP of new source ({}, {})",
                                                source, group
                                            )
                                        );
                                        let now = Instant::now();
                                        let msdp_result = self
                                            .msdp_state
                                            .local_source_active(source, group, rp_address, now);

                                        // Process flood requests
                                        if !msdp_result.floods.is_empty() {
                                            self.process_msdp_floods(msdp_result.floods);
                                        }

                                        result.add_timers(msdp_result.timers);
                                    }
                                }
                            }
                        }
                    }
                    3 => {
                        // Join/Prune - parse the message
                        use std::time::Duration;

                        // Parse Join/Prune message
                        // Format: upstream neighbor (encoded), reserved, num_groups, holdtime
                        // Then for each group: encoded group, num_joins, num_prunes, sources
                        if let Some((upstream, joins, prunes, holdtime)) =
                            parse_pim_join_prune(&payload)
                        {
                            log_info!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "PIM: Received Join/Prune from {} on {}: {} joins, {} prunes",
                                    src_ip,
                                    reported_interface,
                                    joins.len(),
                                    prunes.len()
                                )
                            );

                            // Track which routes exist before processing prunes
                            // so we can detect removals
                            let prune_targets: Vec<_> =
                                prunes.iter().map(|(src, grp)| (*src, *grp)).collect();

                            // Process joins and prunes, get timers
                            let timers = self.pim_state.process_join_prune(
                                &reported_interface,
                                upstream,
                                &joins,
                                &prunes,
                                Duration::from_secs(holdtime as u64),
                            );
                            result.add_timers(timers);

                            // Generate MRIB actions for joins
                            for (source, group) in &joins {
                                match source {
                                    None => {
                                        // (*,G) join - look up the resulting state
                                        if let Some(star_g_state) = self.pim_state.star_g.get(group)
                                        {
                                            let route = crate::mroute::StarGRoute {
                                                group: *group,
                                                rp: star_g_state.rp,
                                                upstream_interface: star_g_state
                                                    .upstream_interface
                                                    .clone(),
                                                downstream_interfaces: star_g_state
                                                    .downstream_interfaces
                                                    .clone(),
                                                created_at: star_g_state.created_at,
                                                expires_at: star_g_state.expires_at,
                                            };
                                            result.add_action(MribAction::AddStarGRoute(route));
                                            result.notify(
                                                crate::ProtocolEventNotification::PimRouteChange {
                                                    route_type: crate::PimTreeType::StarG,
                                                    group: *group,
                                                    source: None,
                                                    action: crate::RouteAction::Add,
                                                    timestamp: unix_timestamp(),
                                                },
                                            );
                                        }
                                    }
                                    Some(src) => {
                                        // (S,G) join - look up the resulting state
                                        if let Some(sg_state) =
                                            self.pim_state.sg.get(&(*src, *group))
                                        {
                                            let route = crate::mroute::SGRoute {
                                                source: *src,
                                                group: *group,
                                                upstream_interface: sg_state
                                                    .upstream_interface
                                                    .clone(),
                                                downstream_interfaces: sg_state
                                                    .downstream_interfaces
                                                    .clone(),
                                                spt_bit: sg_state.spt_bit,
                                                created_at: sg_state.created_at,
                                                expires_at: sg_state.expires_at,
                                            };
                                            result.add_action(MribAction::AddSgRoute(route));
                                            result.notify(
                                                crate::ProtocolEventNotification::PimRouteChange {
                                                    route_type: crate::PimTreeType::SG,
                                                    group: *group,
                                                    source: Some(*src),
                                                    action: crate::RouteAction::Add,
                                                    timestamp: unix_timestamp(),
                                                },
                                            );
                                        }
                                    }
                                }
                            }

                            // Check for routes removed by prunes
                            for (source, group) in prune_targets {
                                match source {
                                    None => {
                                        // (*,G) prune - check if route was removed
                                        if !self.pim_state.star_g.contains_key(&group) {
                                            result
                                                .add_action(MribAction::RemoveStarGRoute { group });
                                            result.notify(
                                                crate::ProtocolEventNotification::PimRouteChange {
                                                    route_type: crate::PimTreeType::StarG,
                                                    group,
                                                    source: None,
                                                    action: crate::RouteAction::Remove,
                                                    timestamp: unix_timestamp(),
                                                },
                                            );
                                        }
                                    }
                                    Some(src) => {
                                        // (S,G) prune - check if route was removed
                                        if !self.pim_state.sg.contains_key(&(src, group)) {
                                            result.add_action(MribAction::RemoveSgRoute {
                                                source: src,
                                                group,
                                            });
                                            result.notify(
                                                crate::ProtocolEventNotification::PimRouteChange {
                                                    route_type: crate::PimTreeType::SG,
                                                    group,
                                                    source: Some(src),
                                                    action: crate::RouteAction::Remove,
                                                    timestamp: unix_timestamp(),
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            PimEvent::HelloTimerExpired { interface } => {
                if let Some(iface_state) = self.pim_state.get_interface_mut(&interface) {
                    result.add_timers(iface_state.hello_timer_expired(Instant::now()));
                }
            }
            PimEvent::NeighborExpired {
                interface,
                neighbor,
            } => {
                let neighbor_existed =
                    if let Some(iface_state) = self.pim_state.get_interface_mut(&interface) {
                        iface_state.neighbor_expired(neighbor);
                        // Re-run DR election
                        let _ = iface_state.elect_dr();
                        true
                    } else {
                        false
                    };

                // Emit event for neighbor down (outside mutable borrow)
                if neighbor_existed {
                    result.notify(crate::ProtocolEventNotification::PimNeighborChange {
                        interface: interface.clone(),
                        neighbor,
                        action: crate::NeighborAction::Down,
                        source: crate::NeighborSource::PimHello,
                        timestamp: unix_timestamp(),
                    });
                }
            }
            PimEvent::RouteExpired { source, group } => {
                // Remove the expired route from state
                if let Some(src) = source {
                    // (S,G) expired
                    self.pim_state.sg.remove(&(src, group));
                    result.add_action(MribAction::RemoveSgRoute { source: src, group });
                    result.notify(crate::ProtocolEventNotification::PimRouteChange {
                        route_type: crate::PimTreeType::SG,
                        group,
                        source: Some(src),
                        action: crate::RouteAction::Remove,
                        timestamp: unix_timestamp(),
                    });

                    // Notify MSDP of inactive source (if we're the RP and MSDP is enabled)
                    if self.msdp_enabled && self.pim_state.config.rp_address.is_some() {
                        log_debug!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("PIM: notifying MSDP of expired source ({}, {})", src, group)
                        );
                        self.msdp_state.local_source_inactive(src, group);
                    }
                } else {
                    // (*,G) expired
                    self.pim_state.star_g.remove(&group);
                    result.add_action(MribAction::RemoveStarGRoute { group });
                    result.notify(crate::ProtocolEventNotification::PimRouteChange {
                        route_type: crate::PimTreeType::StarG,
                        group,
                        source: None,
                        action: crate::RouteAction::Remove,
                        timestamp: unix_timestamp(),
                    });
                }
            }
            PimEvent::SetStaticRp { group, rp } => {
                self.pim_state.config.static_rp.insert(group, rp);
            }
            PimEvent::SetRpAddress { rp } => {
                self.pim_state.config.rp_address = Some(rp);
            }
        }
        result
    }

    /// Process MSDP flood requests by sending them via the TCP command channel
    fn process_msdp_floods(&self, floods: Vec<crate::protocols::msdp::SaFloodRequest>) {
        use crate::protocols::msdp_tcp::MsdpTcpCommand;

        if let Some(ref tcp_tx) = self.msdp_tcp_tx {
            for flood in floods {
                let cmd = MsdpTcpCommand::FloodSa {
                    rp_address: flood.rp_address,
                    entries: flood.entries,
                    exclude_peer: flood.exclude_peer,
                };
                // Fire and forget - don't block on channel send
                let _ = tcp_tx.try_send(cmd);
            }
        }
    }

    fn handle_msdp_event(
        &mut self,
        event: crate::protocols::msdp::MsdpEvent,
    ) -> ProtocolHandlerResult {
        use crate::protocols::msdp::MsdpEvent;
        let now = Instant::now();
        let mut result = ProtocolHandlerResult::new();

        match event {
            MsdpEvent::TcpConnectionEstablished { peer, is_active } => {
                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "MSDP peer {} connected ({})",
                        peer,
                        if is_active { "active" } else { "passive" }
                    )
                );
                result.add_timers(self.msdp_state.connection_established(peer, is_active, now));
            }
            MsdpEvent::TcpConnectionFailed { peer, reason } => {
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("MSDP peer {} connection failed: {}", peer, reason)
                );
                result.add_timers(self.msdp_state.connection_failed(peer, now));
            }
            MsdpEvent::TcpConnectionClosed { peer, reason } => {
                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("MSDP peer {} connection closed: {}", peer, reason)
                );
                result.add_timers(self.msdp_state.connection_closed(peer, now));
            }
            MsdpEvent::MessageReceived {
                peer,
                msg_type,
                payload,
            } => {
                use crate::protocols::msdp::{MsdpSaMessage, MSDP_KEEPALIVE, MSDP_SA};

                match msg_type {
                    MSDP_SA => {
                        // Parse SA message
                        if let Some(sa_msg) = MsdpSaMessage::parse(&payload) {
                            let entries: Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> = sa_msg
                                .entries
                                .iter()
                                .map(|&(src, grp)| (src, grp, sa_msg.rp_address))
                                .collect();
                            log_debug!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "MSDP: received SA from {} with {} entries",
                                    peer,
                                    entries.len()
                                )
                            );
                            let msdp_result =
                                self.msdp_state.process_sa_message(peer, entries, now);

                            // Process flood requests
                            if !msdp_result.floods.is_empty() {
                                log_debug!(
                                    self.logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "MSDP: flooding {} SA entries to peers",
                                        msdp_result
                                            .floods
                                            .iter()
                                            .map(|f| f.entries.len())
                                            .sum::<usize>()
                                    )
                                );
                                self.process_msdp_floods(msdp_result.floods);
                            }

                            // Process learned sources - create (S,G) routes for groups with local receivers
                            for (source, group) in &msdp_result.learned_sources {
                                // Emit event for new SA entry
                                result.notify(
                                    crate::ProtocolEventNotification::MsdpSaCacheChange {
                                        source: *source,
                                        group: *group,
                                        rp: sa_msg.rp_address,
                                        action: crate::SaCacheAction::Add,
                                        timestamp: unix_timestamp(),
                                    },
                                );

                                // Read access to MRIB is kept
                                let receivers = self.mrib.get_igmp_interfaces_for_group(*group);
                                if !receivers.is_empty() {
                                    log_info!(
                                        self.logger,
                                        Facility::Supervisor,
                                        &format!(
                                            "MSDP: creating (S,G) route for ({}, {}) - {} local receivers",
                                            source, group, receivers.len()
                                        )
                                    );

                                    // Create (S,G) route in MRIB
                                    use crate::mroute::SGRoute;
                                    let mut route = SGRoute::new(*source, *group);
                                    // Add all receiver interfaces as downstream
                                    for iface in receivers {
                                        route.downstream_interfaces.insert(iface);
                                    }
                                    // Set expiry to match SA cache timeout
                                    route.expires_at =
                                        Some(now + self.msdp_state.config.sa_cache_timeout);
                                    result.add_action(MribAction::AddSgRoute(route));
                                }
                            }

                            result.add_timers(msdp_result.timers);
                        }
                    }
                    MSDP_KEEPALIVE => {
                        log_debug!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("MSDP: received keepalive from {}", peer)
                        );
                        result.add_timers(self.msdp_state.process_keepalive(peer, now));
                    }
                    _ => {
                        log_debug!(
                            self.logger,
                            Facility::Supervisor,
                            &format!(
                                "MSDP: received unknown message type {} from {}",
                                msg_type, peer
                            )
                        );
                    }
                }
            }
            MsdpEvent::LocalSourceActive { source, group } => {
                if let Some(rp) = self.pim_state.config.rp_address {
                    log_debug!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("MSDP: local source active ({}, {})", source, group)
                    );
                    let msdp_result = self.msdp_state.local_source_active(source, group, rp, now);

                    // Process flood requests (originating SA for local source)
                    if !msdp_result.floods.is_empty() {
                        log_debug!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("MSDP: originating SA for ({}, {}) to peers", source, group)
                        );
                        self.process_msdp_floods(msdp_result.floods);
                    }

                    result.add_timers(msdp_result.timers);
                }
            }
            MsdpEvent::LocalSourceInactive { source, group } => {
                self.msdp_state.local_source_inactive(source, group);
            }
            MsdpEvent::ConnectRetryExpired { peer } => {
                // This timer triggers a connection attempt
                // The actual TCP connection logic will be handled elsewhere
                log_debug!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("MSDP: connect retry timer expired for {}", peer)
                );
            }
            MsdpEvent::KeepaliveTimerExpired { peer } => {
                // Need to send keepalive to peer
                log_debug!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("MSDP: keepalive timer expired for {}", peer)
                );
            }
            MsdpEvent::HoldTimerExpired { peer } => {
                // Peer timed out - disconnect
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("MSDP: hold timer expired for {} - disconnecting", peer)
                );
                result.add_timers(self.msdp_state.connection_closed(peer, now));
            }
            MsdpEvent::SaCacheExpired {
                source,
                group,
                origin_rp,
            } => {
                self.msdp_state.sa_cache_expired(source, group, origin_rp);
                result.notify(crate::ProtocolEventNotification::MsdpSaCacheChange {
                    source,
                    group,
                    rp: origin_rp,
                    action: crate::SaCacheAction::Remove,
                    timestamp: unix_timestamp(),
                });
            }
            MsdpEvent::AddPeer { config } => {
                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("MSDP: adding peer {}", config.address)
                );
                result.add_timers(self.msdp_state.add_peer(config));
            }
            MsdpEvent::RemovePeer { peer } => {
                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("MSDP: removing peer {}", peer)
                );
                self.msdp_state.remove_peer(peer);
            }
            MsdpEvent::Enable => {
                log_info!(self.logger, Facility::Supervisor, "MSDP: enabled");
                self.msdp_enabled = true;
                result.add_timers(self.msdp_state.enable());
            }
            MsdpEvent::Disable => {
                log_info!(self.logger, Facility::Supervisor, "MSDP: disabled");
                self.msdp_enabled = false;
                self.msdp_state.disable();
            }
        }
        result
    }

    fn handle_timer_expired(&mut self, timer_type: TimerType) -> ProtocolHandlerResult {
        let now = Instant::now();
        let mut result = ProtocolHandlerResult::new();

        match timer_type {
            TimerType::IgmpGeneralQuery { interface } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    // Schedule next query timer
                    result.add_timers(igmp_state.query_timer_expired(now));

                    // Only send query if we're the elected querier
                    if igmp_state.is_querier {
                        use crate::protocols::igmp::IgmpQueryBuilder;
                        use crate::protocols::PacketBuilder;
                        const IGMP_ALL_HOSTS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

                        // Max response time in tenths of seconds (default 10 seconds = 100)
                        let max_resp_time =
                            (igmp_state.config.query_response_interval.as_millis() / 100) as u8;
                        let builder = IgmpQueryBuilder::general_query(max_resp_time);
                        let packet_data = builder.build();

                        result.send_packet(OutgoingPacket {
                            protocol: ProtocolType::Igmp,
                            interface: interface.clone(),
                            destination: IGMP_ALL_HOSTS,
                            source: Some(igmp_state.interface_ip),
                            data: packet_data,
                        });

                        log_debug!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("IGMP: Sending General Query on {}", interface)
                        );
                    }
                }
            }
            TimerType::IgmpGroupQuery { interface, group } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    let (timers, _expired) = igmp_state.group_query_expired(group, now);
                    result.add_timers(timers);

                    // Only send query if we're the elected querier
                    if igmp_state.is_querier {
                        use crate::protocols::igmp::IgmpQueryBuilder;
                        use crate::protocols::PacketBuilder;

                        // Group-specific query uses last member query interval
                        let max_resp_time =
                            (igmp_state.config.last_member_query_interval.as_millis() / 100) as u8;
                        let builder = IgmpQueryBuilder::group_specific_query(group, max_resp_time);
                        let packet_data = builder.build();

                        result.send_packet(OutgoingPacket {
                            protocol: ProtocolType::Igmp,
                            interface: interface.clone(),
                            destination: group, // Group-specific query goes to the group address
                            source: Some(igmp_state.interface_ip),
                            data: packet_data,
                        });

                        log_debug!(
                            self.logger,
                            Facility::Supervisor,
                            &format!(
                                "IGMP: Sending Group-Specific Query for {} on {}",
                                group, interface
                            )
                        );
                    }
                }
            }
            TimerType::IgmpGroupExpiry { interface, group } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    if igmp_state.group_expired(group, now) {
                        result.add_action(MribAction::RemoveIgmpMembership {
                            interface: interface.clone(),
                            group,
                        });
                    }
                }
            }
            TimerType::IgmpOtherQuerierPresent { interface } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    result.add_timers(igmp_state.other_querier_expired(now));
                }
            }
            TimerType::PimHello { interface } => {
                if let Some(iface_state) = self.pim_state.get_interface_mut(&interface) {
                    // Schedule next Hello timer
                    result.add_timers(iface_state.hello_timer_expired(now));

                    // Build and queue PIM Hello packet
                    use crate::protocols::pim::PimHelloBuilder;
                    use crate::protocols::PacketBuilder;
                    const PIM_ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

                    // Holdtime is typically 3.5x the hello period
                    let holdtime = (iface_state.config.hello_period.as_secs() as f64 * 3.5) as u16;
                    let builder = PimHelloBuilder::new(
                        holdtime,
                        iface_state.config.dr_priority,
                        iface_state.generation_id,
                    );
                    let packet_data = builder.build();

                    result.send_packet(OutgoingPacket {
                        protocol: ProtocolType::Pim,
                        interface: interface.clone(),
                        destination: PIM_ALL_ROUTERS,
                        source: Some(iface_state.address),
                        data: packet_data,
                    });

                    log_info!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("PIM: Sending Hello on {}", interface)
                    );
                }
            }
            TimerType::PimNeighborExpiry {
                interface,
                neighbor,
            } => {
                if let Some(iface_state) = self.pim_state.get_interface_mut(&interface) {
                    if iface_state.neighbor_expired(neighbor) {
                        log_info!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("PIM neighbor {} on {} timed out", neighbor, interface)
                        );
                        iface_state.elect_dr();
                    }
                }
            }
            TimerType::PimJoinPrune {
                interface: _,
                group: _,
            } => {
                // TODO: Send periodic Join/Prune refresh
            }
            TimerType::PimStarGExpiry { group } => {
                result.add_action(MribAction::RemoveStarGRoute { group });
            }
            TimerType::PimSGExpiry { source, group } => {
                result.add_action(MribAction::RemoveSgRoute { source, group });
            }
            // MSDP timer handling
            TimerType::MsdpConnectRetry { peer } => {
                use crate::protocols::msdp_tcp::MsdpTcpCommand;

                log_debug!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("MSDP: connect retry timer expired for {}", peer)
                );

                // Update peer state to Connecting
                if let Some(msdp_peer) = self.msdp_state.get_peer_mut(peer) {
                    // Only transition to Connecting if currently Disabled
                    if msdp_peer.state == crate::protocols::msdp::MsdpPeerState::Disabled {
                        msdp_peer.state = crate::protocols::msdp::MsdpPeerState::Connecting;
                    }
                }

                // Send connect command to TCP runner
                if let Some(ref tcp_tx) = self.msdp_tcp_tx {
                    let _ = tcp_tx.try_send(MsdpTcpCommand::Connect { peer });
                } else {
                    // TCP runner not available - log this only once at debug level
                    log_debug!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("MSDP: TCP runner not available for peer {}", peer)
                    );
                }

                // Reschedule connect retry timer
                result.add_timer(TimerRequest {
                    timer_type: TimerType::MsdpConnectRetry { peer },
                    fire_at: now + self.msdp_state.config.connect_retry_period,
                    replace_existing: true,
                });
            }
            TimerType::MsdpKeepalive { peer } => {
                use crate::protocols::msdp_tcp::MsdpTcpCommand;

                // Check if keepalive is needed and get the interval
                let keepalive_info = self.msdp_state.get_peer(peer).map(|msdp_peer| {
                    (
                        msdp_peer.needs_keepalive(now),
                        msdp_peer.config.keepalive_interval,
                    )
                });

                if let Some((needs_keepalive, keepalive_interval)) = keepalive_info {
                    if needs_keepalive {
                        log_debug!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("MSDP: sending keepalive to {}", peer)
                        );

                        // Send keepalive command to TCP runner
                        if let Some(ref tcp_tx) = self.msdp_tcp_tx {
                            let _ = tcp_tx.try_send(MsdpTcpCommand::SendKeepalive { peer });
                        }

                        // Update last_sent time
                        if let Some(msdp_peer) = self.msdp_state.get_peer_mut(peer) {
                            msdp_peer.record_sent(now);
                            msdp_peer.keepalives_sent += 1;
                        }

                        // Reschedule keepalive timer
                        result.add_timer(TimerRequest {
                            timer_type: TimerType::MsdpKeepalive { peer },
                            fire_at: now + keepalive_interval,
                            replace_existing: true,
                        });
                    }
                }
            }
            TimerType::MsdpHold { peer } => {
                use crate::protocols::msdp_tcp::MsdpTcpCommand;

                let is_timed_out = self
                    .msdp_state
                    .get_peer(peer)
                    .is_some_and(|p| p.is_timed_out(now));

                if is_timed_out {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("MSDP: peer {} hold timer expired - disconnecting", peer)
                    );

                    // Send disconnect command to TCP runner
                    if let Some(ref tcp_tx) = self.msdp_tcp_tx {
                        let _ = tcp_tx.try_send(MsdpTcpCommand::Disconnect { peer });
                    }

                    result.add_timers(self.msdp_state.connection_closed(peer, now));
                }
            }
            TimerType::MsdpSaCacheExpiry {
                source,
                group,
                origin_rp,
            } => {
                self.msdp_state.sa_cache_expired(source, group, origin_rp);
            }
        }
        result
    }

    /// Compile current MRIB state into forwarding rules
    pub fn compile_forwarding_rules(&self) -> Vec<ForwardingRule> {
        self.mrib.compile_forwarding_rules()
    }

    /// Get PIM neighbor information for CLI queries
    pub fn get_pim_neighbors(&self) -> Vec<crate::PimNeighborInfo> {
        let mut neighbors = Vec::new();
        let now = Instant::now();
        for (interface, iface_state) in self.pim_state.interfaces.iter() {
            for (neighbor_ip, neighbor) in iface_state.neighbors.iter() {
                let expires_in_secs = neighbor
                    .expires_at
                    .map(|e| e.saturating_duration_since(now).as_secs());
                neighbors.push(crate::PimNeighborInfo {
                    interface: interface.clone(),
                    address: *neighbor_ip,
                    dr_priority: neighbor.dr_priority,
                    is_dr: iface_state.designated_router == Some(*neighbor_ip),
                    expires_in_secs,
                    generation_id: neighbor.generation_id,
                    source: neighbor.source.clone(),
                });
            }
        }
        neighbors
    }

    /// Get external PIM neighbors for CLI queries
    pub fn get_external_neighbors(&self) -> Vec<crate::PimNeighborInfo> {
        self.get_pim_neighbors()
            .into_iter()
            .filter(|n| matches!(n.source, crate::NeighborSource::External { .. }))
            .collect()
    }

    /// Get IGMP group membership for CLI queries
    pub fn get_igmp_groups(&self) -> Vec<crate::IgmpGroupInfo> {
        let mut groups = Vec::new();
        let now = Instant::now();
        for (interface, iface_state) in self.igmp_state.iter() {
            for (group_addr, membership) in iface_state.groups.iter() {
                let expires_in_secs = membership
                    .expires_at
                    .saturating_duration_since(now)
                    .as_secs();
                groups.push(crate::IgmpGroupInfo {
                    interface: interface.clone(),
                    group: *group_addr,
                    last_reporter: membership.last_reporter,
                    expires_in_secs,
                    is_querier: iface_state.is_querier,
                });
            }
        }
        groups
    }

    /// Get multicast routing table entries for CLI queries
    pub fn get_mroute_entries(&self) -> Vec<crate::MrouteEntry> {
        let mut entries = Vec::new();

        // Add (*,G) entries from PIM state
        for (group, star_g) in self.pim_state.star_g.iter() {
            entries.push(crate::MrouteEntry {
                source: None,
                group: *group,
                input_interface: star_g.upstream_interface.clone().unwrap_or_default(),
                output_interfaces: star_g.downstream_interfaces.iter().cloned().collect(),
                entry_type: crate::MrouteEntryType::StarG,
                age_secs: star_g.created_at.elapsed().as_secs(),
            });
        }

        // Add (S,G) entries from PIM state
        for ((source, group), sg) in self.pim_state.sg.iter() {
            entries.push(crate::MrouteEntry {
                source: Some(*source),
                group: *group,
                input_interface: sg.upstream_interface.clone().unwrap_or_default(),
                output_interfaces: sg.downstream_interfaces.iter().cloned().collect(),
                entry_type: crate::MrouteEntryType::SG,
                age_secs: sg.created_at.elapsed().as_secs(),
            });
        }

        // Add static rules from MRIB
        for rule in self.mrib.static_rules.values() {
            entries.push(crate::MrouteEntry {
                source: rule.input_source,
                group: rule.input_group,
                input_interface: rule.input_interface.clone(),
                output_interfaces: rule.outputs.iter().map(|o| o.interface.clone()).collect(),
                entry_type: crate::MrouteEntryType::Static,
                age_secs: 0, // Static rules don't have uptime tracking
            });
        }

        entries
    }

    /// Get MSDP peer information for CLI queries
    pub fn get_msdp_peers(&self) -> Vec<crate::MsdpPeerInfo> {
        self.msdp_state
            .peers
            .iter()
            .map(|(&addr, peer)| crate::MsdpPeerInfo {
                address: addr,
                state: peer.state.to_string(),
                description: peer.config.description.clone(),
                mesh_group: peer.config.mesh_group.clone(),
                default_peer: peer.config.default_peer,
                uptime_secs: peer.uptime_secs(),
                sa_received: peer.sa_received,
                sa_sent: peer.sa_sent,
                is_active: peer.is_active,
            })
            .collect()
    }

    /// Get MSDP SA cache entries for CLI queries
    pub fn get_msdp_sa_cache(&self) -> Vec<crate::MsdpSaCacheInfo> {
        let now = Instant::now();
        self.msdp_state
            .sa_cache
            .values()
            .map(|entry| crate::MsdpSaCacheInfo {
                source: entry.source,
                group: entry.group,
                origin_rp: entry.origin_rp,
                learned_from: entry.learned_from,
                age_secs: entry.age_secs(),
                expires_in_secs: entry.expires_in_secs(now),
                is_local: entry.is_local,
            })
            .collect()
    }

    /// Check if protocols need initialization from config
    pub fn initialize_from_config(&mut self, config: &Config) {
        if let Some(igmp_config) = &config.igmp {
            if !igmp_config.querier_interfaces.is_empty() {
                self.enable_igmp(&igmp_config.querier_interfaces, igmp_config);
            }
        }

        if let Some(pim_config) = &config.pim {
            if pim_config.enabled {
                self.enable_pim(pim_config);
            }
        }

        if let Some(msdp_config) = &config.msdp {
            if msdp_config.enabled {
                self.enable_msdp(msdp_config);
            }
        }

        // Apply control plane configuration
        if let Some(cp_config) = &config.control_plane {
            self.apply_control_plane_config(cp_config);
        }
    }

    /// Apply control plane integration configuration
    fn apply_control_plane_config(&mut self, config: &crate::config::ControlPlaneConfig) {
        // Set RPF provider
        let rpf_provider = if config.rpf_provider == "disabled" {
            crate::RpfProvider::Disabled
        } else if config.rpf_provider == "static" {
            crate::RpfProvider::Static
        } else {
            // Treat as external socket path
            crate::RpfProvider::External {
                socket_path: config.rpf_provider.clone(),
            }
        };
        self.pim_state.set_rpf_provider(rpf_provider);

        // Event buffer size is set separately during initialization
        // (before this method is called)
    }

    /// Initialize MSDP with the given configuration
    pub fn enable_msdp(&mut self, config: &crate::config::MsdpConfig) {
        use crate::protocols::msdp::MsdpPeerConfig as ProtocolMsdpPeerConfig;
        use std::time::Duration;

        // Configure global MSDP settings
        self.msdp_state.config.enabled = config.enabled;
        self.msdp_state.config.local_address = config.local_address;
        self.msdp_state.config.keepalive_interval =
            Duration::from_secs(config.keepalive_interval as u64);
        self.msdp_state.config.hold_time = Duration::from_secs(config.hold_time as u64);

        // Add configured peers
        for peer_config in &config.peers {
            let protocol_peer_config = ProtocolMsdpPeerConfig {
                address: peer_config.address,
                description: peer_config.description.clone(),
                mesh_group: peer_config.mesh_group.clone(),
                default_peer: peer_config.default_peer,
                keepalive_interval: Duration::from_secs(config.keepalive_interval as u64),
                hold_time: Duration::from_secs(config.hold_time as u64),
            };
            let timers = self.msdp_state.add_peer(protocol_peer_config);

            // Schedule connection timers (if timer channel is available)
            if let Some(ref timer_tx) = self.timer_tx {
                for timer in timers {
                    if let Err(e) = timer_tx.try_send(timer) {
                        log_warning!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("Failed to schedule MSDP timer: {}", e)
                        );
                    }
                }
            }

            log_info!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "MSDP peer {} configured{}",
                    peer_config.address,
                    peer_config
                        .description
                        .as_ref()
                        .map(|d| format!(" ({})", d))
                        .unwrap_or_default()
                )
            );
        }

        self.msdp_enabled = config.enabled;
        if self.msdp_enabled {
            log_info!(
                self.logger,
                Facility::Supervisor,
                &format!("MSDP initialized with {} peer(s)", config.peers.len())
            );
        }
    }

    /// Create a raw socket for IGMP (IP protocol 2)
    ///
    /// This socket is used to:
    /// - Send IGMP queries (General and Group-Specific)
    /// - Receive IGMP reports and leaves from hosts
    pub fn create_igmp_socket(&mut self) -> Result<()> {
        // IGMP is IP protocol 2
        const IPPROTO_IGMP: i32 = 2;

        // Create raw socket for IGMP
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                IPPROTO_IGMP,
            )
        };

        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create IGMP raw socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set IP_HDRINCL so we can craft our own IP headers for IGMP messages
        let hdrincl: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &hdrincl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "Failed to set IP_HDRINCL on IGMP socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set IP_PKTINFO to receive the interface index on incoming packets
        let pktinfo: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &pktinfo as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "Failed to set IP_PKTINFO on IGMP socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set IP_MULTICAST_ALL to receive all multicast packets, not just those
        // for groups we've joined. This is essential for IGMP queriers/routers
        // to receive Membership Reports sent to group addresses.
        // IP_MULTICAST_ALL = 49 (not in libc crate)
        const IP_MULTICAST_ALL: libc::c_int = 49;
        let multicast_all: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                IP_MULTICAST_ALL,
                &multicast_all as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            // Not fatal - may not be supported on all kernels
            log_warning!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Failed to set IP_MULTICAST_ALL on IGMP socket (non-fatal): {}",
                    std::io::Error::last_os_error()
                )
            );
        }

        let sock = unsafe { OwnedFd::from_raw_fd(fd) };

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("Created IGMP raw socket (fd: {})", sock.as_raw_fd())
        );

        self.igmp_socket = Some(sock);
        Ok(())
    }

    /// Create a raw socket for PIM (IP protocol 103)
    ///
    /// This socket is used to:
    /// - Send and receive PIM Hello messages
    /// - Send and receive PIM Join/Prune messages
    /// - Receive PIM Register messages (when we're the RP)
    ///
    /// Note: This creates the socket but does NOT join multicast groups.
    /// Call `join_pim_multicast_on_interface()` for each PIM-enabled interface.
    pub fn create_pim_socket(&mut self) -> Result<()> {
        // PIM is IP protocol 103
        const IPPROTO_PIM: i32 = 103;

        // Create raw socket for PIM
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                IPPROTO_PIM,
            )
        };

        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create PIM raw socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set IP_HDRINCL so we can craft our own IP headers for PIM messages
        let hdrincl: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &hdrincl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "Failed to set IP_HDRINCL on PIM socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set IP_PKTINFO to receive the interface index on incoming packets
        let pktinfo: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &pktinfo as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "Failed to set IP_PKTINFO on PIM socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        let sock = unsafe { OwnedFd::from_raw_fd(fd) };

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("Created PIM raw socket (fd: {})", sock.as_raw_fd())
        );

        self.pim_socket = Some(sock);
        Ok(())
    }

    /// Join the ALL-PIM-ROUTERS multicast group (224.0.0.13) on a specific interface
    ///
    /// This must be called for each interface where PIM is enabled. Link-local
    /// multicast groups like 224.0.0.13 require explicit per-interface joins
    /// because they are not routed.
    pub fn join_pim_multicast_on_interface(&self, interface: &str) -> Result<()> {
        let fd = self
            .pim_socket
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PIM socket not created"))?
            .as_raw_fd();

        // Get interface index
        let iface_index = socket_helpers::get_interface_index(interface)?;

        // ALL-PIM-ROUTERS multicast group (224.0.0.13)
        let all_pim_routers = Ipv4Addr::new(224, 0, 0, 13);

        // Use ip_mreqn to specify the interface by index
        let mreqn = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from(all_pim_routers).to_be(),
            },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: iface_index,
        };

        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_ADD_MEMBERSHIP,
                &mreqn as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(anyhow::anyhow!(
                "Failed to join ALL-PIM-ROUTERS on {}: {}",
                interface,
                std::io::Error::last_os_error()
            ));
        }

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Joined ALL-PIM-ROUTERS ({}) on interface {}",
                all_pim_routers, interface
            )
        );

        Ok(())
    }

    /// Enable ALLMULTI mode on an interface for IGMP querier functionality.
    ///
    /// IGMP queriers need to receive Membership Reports for all multicast groups,
    /// not just those the interface has joined. Reports are sent to the group
    /// address (e.g., 239.1.1.1) and would be filtered at L2 without ALLMULTI.
    pub fn enable_allmulti_on_interface(&self, interface: &str) -> Result<()> {
        use std::ffi::CString;

        let iface_cstr = CString::new(interface)
            .map_err(|_| anyhow::anyhow!("Invalid interface name: {}", interface))?;

        // Create a temporary socket for ioctl
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create socket for ALLMULTI: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Get current flags
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = iface_cstr.as_bytes_with_nul();
        let copy_len = std::cmp::min(name_bytes.len(), ifr.ifr_name.len());
        for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
            ifr.ifr_name[i] = b as i8;
        }

        let result = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) };
        if result < 0 {
            unsafe { libc::close(sock) };
            return Err(anyhow::anyhow!(
                "Failed to get interface flags for {}: {}",
                interface,
                std::io::Error::last_os_error()
            ));
        }

        // Set ALLMULTI flag
        let flags = unsafe { ifr.ifr_ifru.ifru_flags };
        if flags & (libc::IFF_ALLMULTI as i16) != 0 {
            // Already set
            unsafe { libc::close(sock) };
            return Ok(());
        }

        ifr.ifr_ifru.ifru_flags = flags | (libc::IFF_ALLMULTI as i16);
        let result = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
        unsafe { libc::close(sock) };

        if result < 0 {
            return Err(anyhow::anyhow!(
                "Failed to set ALLMULTI on {}: {}",
                interface,
                std::io::Error::last_os_error()
            ));
        }

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("Enabled ALLMULTI on interface {} for IGMP", interface)
        );

        Ok(())
    }

    /// Join the IGMPv3 all-routers multicast group (224.0.0.22) on an interface.
    ///
    /// This is required to receive IGMPv3 Membership Reports, which are sent to
    /// 224.0.0.22 instead of the group address (unlike IGMPv2).
    pub fn join_igmp_v3_all_routers(&self, interface: &str) -> Result<()> {
        let fd = self
            .igmp_socket
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IGMP socket not created"))?
            .as_raw_fd();

        // Get interface index
        let iface_index = socket_helpers::get_interface_index(interface)?;

        // IGMPv3 all-routers multicast group (224.0.0.22)
        let igmp_v3_all_routers = Ipv4Addr::new(224, 0, 0, 22);

        // Use ip_mreqn to specify the interface by index
        let mreqn = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from(igmp_v3_all_routers).to_be(),
            },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: iface_index,
        };

        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_ADD_MEMBERSHIP,
                &mreqn as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(anyhow::anyhow!(
                "Failed to join IGMPv3 all-routers on {}: {}",
                interface,
                std::io::Error::last_os_error()
            ));
        }

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Joined IGMPv3 all-routers ({}) on interface {}",
                igmp_v3_all_routers, interface
            )
        );

        Ok(())
    }

    /// Create both protocol sockets if protocols are enabled
    pub fn create_protocol_sockets(&mut self) -> Result<()> {
        if self.igmp_enabled && self.igmp_socket.is_none() {
            self.create_igmp_socket()?;

            // Enable ALLMULTI and join IGMPv3 all-routers on each IGMP-enabled interface
            let interfaces: Vec<String> = self.igmp_state.keys().cloned().collect();
            for interface in &interfaces {
                // Enable ALLMULTI to receive all multicast at L2
                if let Err(e) = self.enable_allmulti_on_interface(interface) {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("Failed to enable ALLMULTI on {}: {}", interface, e)
                    );
                }

                // Join 224.0.0.22 to receive IGMPv3 Membership Reports
                if let Err(e) = self.join_igmp_v3_all_routers(interface) {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("Failed to join IGMPv3 all-routers on {}: {}", interface, e)
                    );
                }
            }
        }
        if self.pim_enabled && self.pim_socket.is_none() {
            self.create_pim_socket()?;

            // Join ALL-PIM-ROUTERS multicast group on each PIM-enabled interface
            let interfaces: Vec<String> = self.pim_state.interfaces.keys().cloned().collect();
            for interface in interfaces {
                if let Err(e) = self.join_pim_multicast_on_interface(&interface) {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("Failed to join PIM multicast on {}: {}", interface, e)
                    );
                }
            }
        }
        Ok(())
    }

    /// Get the IGMP socket fd for async monitoring
    pub fn igmp_socket_fd(&self) -> Option<RawFd> {
        self.igmp_socket.as_ref().map(|s| s.as_raw_fd())
    }

    /// Get the PIM socket fd for async monitoring
    pub fn pim_socket_fd(&self) -> Option<RawFd> {
        self.pim_socket.as_ref().map(|s| s.as_raw_fd())
    }

    /// Spawn the protocol receiver loop if it's not already running and we have sockets.
    ///
    /// This is used when creating protocol sockets via CLI after startup.
    /// Returns true if a new receiver loop was spawned.
    pub fn spawn_receiver_loop_if_needed(&self) -> bool {
        use std::sync::atomic::Ordering;

        // Check if already running
        if self.receiver_loop_running.load(Ordering::SeqCst) {
            return false;
        }

        // Check if we have any sockets to receive on
        let igmp_fd = self.igmp_socket_fd();
        let pim_fd = self.pim_socket_fd();

        if igmp_fd.is_none() && pim_fd.is_none() {
            return false;
        }

        // Get event_tx for the receiver loop
        let event_tx = match &self.event_tx {
            Some(tx) => tx.clone(),
            None => {
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    "Cannot spawn receiver loop: event_tx not available"
                );
                return false;
            }
        };

        // Mark as running before spawning
        self.receiver_loop_running.store(true, Ordering::SeqCst);

        // Spawn the receiver loop
        let receiver_logger = self.logger.clone();
        tokio::spawn(async move {
            protocol_receiver_loop(igmp_fd, pim_fd, event_tx, receiver_logger).await;
        });

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Spawned protocol receiver loop (IGMP: {}, PIM: {})",
                igmp_fd.is_some(),
                pim_fd.is_some()
            )
        );

        true
    }

    /// Send outgoing packets using the appropriate protocol sockets
    ///
    /// Returns the number of packets successfully sent
    pub fn send_outgoing_packets(&self, packets: Vec<OutgoingPacket>) -> usize {
        let mut sent = 0;

        for packet in packets {
            match self.send_packet(&packet) {
                Ok(()) => {
                    sent += 1;
                    log_info!(
                        self.logger,
                        Facility::Supervisor,
                        &format!(
                            "Sent {:?} packet to {} via {}",
                            packet.protocol, packet.destination, packet.interface
                        )
                    );
                }
                Err(e) => {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!(
                            "Failed to send {:?} packet to {} via {}: {}",
                            packet.protocol, packet.destination, packet.interface, e
                        )
                    );
                }
            }
        }

        sent
    }

    /// Send a single outgoing packet
    fn send_packet(&self, packet: &OutgoingPacket) -> Result<()> {
        // Get the appropriate socket
        let fd = match packet.protocol {
            ProtocolType::Igmp => self
                .igmp_socket
                .as_ref()
                .map(|s| s.as_raw_fd())
                .ok_or_else(|| anyhow::anyhow!("IGMP socket not available"))?,
            ProtocolType::Pim => self
                .pim_socket
                .as_ref()
                .map(|s| s.as_raw_fd())
                .ok_or_else(|| anyhow::anyhow!("PIM socket not available"))?,
        };

        // Get source IP from interface if not specified
        let source_ip = packet.source.unwrap_or_else(|| {
            get_interface_ipv4(&packet.interface).unwrap_or(Ipv4Addr::UNSPECIFIED)
        });

        // For multicast destinations, set the outgoing interface
        if packet.destination.is_multicast() {
            let iface_index = socket_helpers::get_interface_index(&packet.interface)?;

            // Use ip_mreqn to specify outgoing interface by index
            let mreqn = libc::ip_mreqn {
                imr_multiaddr: libc::in_addr { s_addr: 0 },
                imr_address: libc::in_addr { s_addr: 0 },
                imr_ifindex: iface_index,
            };

            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MULTICAST_IF,
                    &mreqn as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
                )
            };

            if result < 0 {
                return Err(anyhow::anyhow!(
                    "Failed to set multicast interface: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // Set TTL to 1 for link-local multicast (224.0.0.x)
            if packet.destination.octets()[0..2] == [224, 0] {
                let ttl: libc::c_int = 1;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        libc::IP_MULTICAST_TTL,
                        &ttl as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        }

        // Build IP header + payload
        let ip_packet = build_ip_packet(
            source_ip,
            packet.destination,
            packet.protocol.protocol_number(),
            &packet.data,
        );

        // Set up destination address
        let dest_addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(packet.destination).to_be(),
            },
            sin_zero: [0; 8],
        };

        // Send the packet
        let result = unsafe {
            libc::sendto(
                fd,
                ip_packet.as_ptr() as *const libc::c_void,
                ip_packet.len(),
                0,
                &dest_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if result < 0 {
            return Err(anyhow::anyhow!(
                "sendto failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }
}

/// Build an IP packet with the given payload
///
/// Creates a complete IP packet with:
/// - 24-byte IP header (with Router Alert option for IGMP/PIM)
/// - Payload data
///
/// The Router Alert option (RFC 2113) is required for IGMP packets.
/// The kernel will fill in some fields (like checksum) when IP_HDRINCL is set.
fn build_ip_packet(source: Ipv4Addr, dest: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    // Use 24-byte IP header with Router Alert option
    let header_len = 24;
    let total_len = header_len + payload.len();

    let mut packet = vec![0u8; total_len];

    // IP header (24 bytes, with Router Alert option)
    packet[0] = 0x46; // Version 4, IHL 6 (24 bytes = 6 * 4)
    packet[1] = 0xc0; // TOS: DSCP=48 (CS6), ECN=0 - used for routing protocols
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes()); // Total length
    packet[4..6].copy_from_slice(&[0x00, 0x00]); // Identification (kernel fills)
    packet[6..8].copy_from_slice(&[0x00, 0x00]); // Flags + Fragment offset
    packet[8] = 1; // TTL = 1 for link-local protocols (IGMP/PIM)
    packet[9] = protocol; // Protocol
    packet[10..12].copy_from_slice(&[0x00, 0x00]); // Header checksum (kernel fills)
    packet[12..16].copy_from_slice(&source.octets()); // Source IP
    packet[16..20].copy_from_slice(&dest.octets()); // Destination IP

    // IP Options: Router Alert (RFC 2113)
    // Option type 0x94 (copied=1, class=0, number=20)
    // Length 4, Value 0x0000 (Router shall examine packet)
    packet[20] = 0x94; // Router Alert option type
    packet[21] = 0x04; // Option length (4 bytes)
    packet[22] = 0x00; // Router Alert value high byte
    packet[23] = 0x00; // Router Alert value low byte

    // Copy payload
    packet[header_len..].copy_from_slice(payload);

    packet
}

/// Async wrapper for raw socket I/O using tokio
///
/// This allows us to use raw sockets in an async context with tokio.
struct AsyncRawSocket {
    fd: RawFd,
}

/// Result of reading a packet with interface information
struct RecvResult {
    /// Number of bytes read
    len: usize,
    /// Interface index from IP_PKTINFO (0 if not available)
    iface_index: i32,
}

/// Convert interface index to interface name
fn interface_name_from_index(index: i32) -> Option<String> {
    if index <= 0 {
        return None;
    }
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let result = unsafe { libc::if_indextoname(index as u32, buf.as_mut_ptr() as *mut i8) };
    if result.is_null() {
        None
    } else {
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const i8) };
        name.to_str().ok().map(|s| s.to_string())
    }
}

impl AsyncRawSocket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Read a packet from the socket with IP_PKTINFO to get interface index
    fn try_read_with_pktinfo(&self, buf: &mut [u8]) -> std::io::Result<RecvResult> {
        // Control message buffer for IP_PKTINFO
        // IP_PKTINFO is struct in_pktinfo (12 bytes) plus cmsg header
        let mut cmsg_buf = [0u8; 64];

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len();

        let n = unsafe { libc::recvmsg(self.fd, &mut msg, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Extract interface index from IP_PKTINFO control message
        let mut iface_index: i32 = 0;

        // Walk through control messages
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let cmsg_ref = unsafe { &*cmsg };
            if cmsg_ref.cmsg_level == libc::IPPROTO_IP && cmsg_ref.cmsg_type == libc::IP_PKTINFO {
                // struct in_pktinfo { int ipi_ifindex; struct in_addr ipi_spec_dst; struct in_addr ipi_addr; }
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                // ipi_ifindex is the first field (4 bytes)
                iface_index = unsafe { *(data as *const i32) };
                break;
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }

        Ok(RecvResult {
            len: n as usize,
            iface_index,
        })
    }
}

impl std::os::unix::io::AsRawFd for AsyncRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Protocol packet receiver loop
///
/// This function monitors the IGMP and PIM raw sockets for incoming packets
/// and dispatches them to the event channel for processing by ProtocolState.
pub async fn protocol_receiver_loop(
    igmp_fd: Option<RawFd>,
    pim_fd: Option<RawFd>,
    event_tx: mpsc::Sender<ProtocolEvent>,
    logger: Logger,
) {
    use tokio::io::unix::AsyncFd;

    let mut buf = vec![0u8; 65536]; // Maximum IP packet size

    // Create async fds for non-blocking socket I/O
    let igmp_async = igmp_fd.and_then(|fd| {
        let sock = AsyncRawSocket::new(fd);
        AsyncFd::new(sock).ok()
    });

    let pim_async = pim_fd.and_then(|fd| {
        let sock = AsyncRawSocket::new(fd);
        AsyncFd::new(sock).ok()
    });

    if igmp_async.is_none() && pim_async.is_none() {
        log_warning!(
            logger,
            Facility::Supervisor,
            "No protocol sockets available, protocol receiver loop exiting"
        );
        return;
    }

    log_info!(
        logger,
        Facility::Supervisor,
        &format!(
            "Protocol receiver loop started (IGMP: {}, PIM: {})",
            igmp_async.is_some(),
            pim_async.is_some()
        )
    );

    loop {
        // Wait for either socket to be readable
        tokio::select! {
            // IGMP socket readable
            result = async {
                if let Some(ref async_fd) = igmp_async {
                    async_fd.readable().await
                } else {
                    // Never completes if no IGMP socket
                    std::future::pending().await
                }
            } => {
                if let Ok(mut guard) = result {
                    match guard.get_inner().try_read_with_pktinfo(&mut buf) {
                        Ok(recv) if recv.len > 0 => {
                            let interface = interface_name_from_index(recv.iface_index);
                            log_info!(
                                logger,
                                Facility::Supervisor,
                                &format!(
                                    "IGMP packet received: {} bytes on iface_index={}, interface={:?}",
                                    recv.len, recv.iface_index, interface
                                )
                            );
                            if let Some(event) = parse_igmp_packet(&buf[..recv.len], interface, &logger) {
                                if event_tx.send(event).await.is_err() {
                                    log_warning!(
                                        logger,
                                        Facility::Supervisor,
                                        "Protocol event channel closed, receiver loop exiting"
                                    );
                                    return;
                                }
                            }
                        }
                        Ok(_) => {} // Empty read
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Socket not ready, this is normal
                        }
                        Err(e) => {
                            log_warning!(
                                logger,
                                Facility::Supervisor,
                                &format!("IGMP socket read error: {}", e)
                            );
                        }
                    }
                    guard.clear_ready();
                }
            }

            // PIM socket readable
            result = async {
                if let Some(ref async_fd) = pim_async {
                    async_fd.readable().await
                } else {
                    std::future::pending().await
                }
            } => {
                if let Ok(mut guard) = result {
                    match guard.get_inner().try_read_with_pktinfo(&mut buf) {
                        Ok(recv) if recv.len > 0 => {
                            let interface = interface_name_from_index(recv.iface_index);
                            if let Some(event) = parse_pim_packet(&buf[..recv.len], interface, &logger) {
                                if event_tx.send(event).await.is_err() {
                                    log_warning!(
                                        logger,
                                        Facility::Supervisor,
                                        "Protocol event channel closed, receiver loop exiting"
                                    );
                                    return;
                                }
                            }
                        }
                        Ok(_) => {} // Empty read
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Socket not ready
                        }
                        Err(e) => {
                            log_warning!(
                                logger,
                                Facility::Supervisor,
                                &format!("PIM socket read error: {}", e)
                            );
                        }
                    }
                    guard.clear_ready();
                }
            }
        }
    }
}

/// Parse a raw IGMP packet into a ProtocolEvent
///
/// The interface parameter should be provided from IP_PKTINFO when available.
/// If None, falls back to subnet-based lookup (which may fail for hosts outside our subnets).
fn parse_igmp_packet(
    packet: &[u8],
    interface: Option<String>,
    logger: &Logger,
) -> Option<ProtocolEvent> {
    use crate::protocols::igmp::IgmpEvent;

    // IP header is at least 20 bytes
    if packet.len() < 28 {
        // 20 IP + 8 IGMP minimum
        return None;
    }

    // Check IP version (first nibble should be 4)
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    // Get IP header length (IHL in 32-bit words)
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 8 {
        return None;
    }

    // Check protocol is IGMP (2)
    if packet[9] != 2 {
        return None;
    }

    // Extract source IP
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

    // Use provided interface from IP_PKTINFO, or fall back to subnet lookup
    let interface = interface
        .unwrap_or_else(|| find_interface_by_ip(src_ip).unwrap_or_else(|| "unknown".to_string()));

    // Parse IGMP header (after IP header)
    let igmp = &packet[ihl..];
    if igmp.len() < 8 {
        return None;
    }

    let msg_type = igmp[0];

    // Handle IGMPv3 Membership Report (type 0x22 = 34)
    if msg_type == 0x22 {
        // IGMPv3 Report format:
        // byte 0: type (0x22)
        // byte 1: reserved
        // bytes 2-3: checksum
        // bytes 4-5: reserved
        // bytes 6-7: number of group records
        // bytes 8+: group records
        if igmp.len() < 8 {
            return None;
        }

        let num_records = u16::from_be_bytes([igmp[6], igmp[7]]) as usize;

        log_info!(
            logger,
            Facility::Supervisor,
            &format!(
                "Received IGMPv3 Report: {} group records from {} on {}",
                num_records, src_ip, interface
            )
        );

        // Parse group records and generate events for each
        let mut offset = 8;
        for _i in 0..num_records {
            if offset + 8 > igmp.len() {
                break;
            }
            let record_type = igmp[offset];
            let aux_data_len = igmp[offset + 1] as usize;
            let num_sources = u16::from_be_bytes([igmp[offset + 2], igmp[offset + 3]]) as usize;
            let group = Ipv4Addr::new(
                igmp[offset + 4],
                igmp[offset + 5],
                igmp[offset + 6],
                igmp[offset + 7],
            );

            // IGMPv3 record types:
            // 1 = MODE_IS_INCLUDE (current state)
            // 2 = MODE_IS_EXCLUDE (current state, i.e., joined)
            // 3 = CHANGE_TO_INCLUDE_MODE
            // 4 = CHANGE_TO_EXCLUDE_MODE (join)
            // 5 = ALLOW_NEW_SOURCES
            // 6 = BLOCK_OLD_SOURCES
            let is_join = record_type == 2 || record_type == 4;

            log_info!(
                logger,
                Facility::Supervisor,
                &format!(
                    "IGMPv3 record: type={}, group={}, sources={}, is_join={}",
                    record_type, group, num_sources, is_join
                )
            );

            // Move to next record
            // Record size = 8 bytes header + (num_sources * 4 bytes) + (aux_data_len * 4 bytes)
            offset += 8 + (num_sources * 4) + (aux_data_len * 4);

            // Only process joins (MODE_IS_EXCLUDE or CHANGE_TO_EXCLUDE_MODE with empty source list)
            // These indicate the host wants to receive all traffic for the group
            if is_join && !group.is_unspecified() {
                // Return event for this group - convert to IGMPv2-style event
                // type 0x16 = IGMPv2 Membership Report
                return Some(ProtocolEvent::Igmp(IgmpEvent::PacketReceived {
                    interface,
                    src_ip,
                    msg_type: 0x16, // Treat as IGMPv2 report for state machine
                    max_resp_time: 0,
                    group,
                }));
            }
        }
        return None;
    }

    // Handle IGMPv1/v2 format
    let max_resp_time = igmp[1];
    let group = Ipv4Addr::new(igmp[4], igmp[5], igmp[6], igmp[7]);

    log_info!(
        logger,
        Facility::Supervisor,
        &format!(
            "Received IGMPv2 packet: type={:#x}, src={}, group={}, interface={}, ihl={}",
            msg_type, src_ip, group, interface, ihl
        )
    );

    Some(ProtocolEvent::Igmp(IgmpEvent::PacketReceived {
        interface,
        src_ip,
        msg_type,
        max_resp_time,
        group,
    }))
}

/// Parse a raw PIM packet into a ProtocolEvent
///
/// The interface parameter should be provided from IP_PKTINFO when available.
/// If None, falls back to subnet-based lookup.
fn parse_pim_packet(
    packet: &[u8],
    interface: Option<String>,
    logger: &Logger,
) -> Option<ProtocolEvent> {
    use crate::protocols::pim::PimEvent;

    // IP header is at least 20 bytes
    if packet.len() < 24 {
        // 20 IP + 4 PIM minimum
        log_warning!(
            logger,
            Facility::Supervisor,
            &format!("PIM parse: packet too short ({} bytes)", packet.len())
        );
        return None;
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != 4 {
        log_warning!(
            logger,
            Facility::Supervisor,
            &format!("PIM parse: wrong IP version ({})", version)
        );
        return None;
    }

    // Get IP header length
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 4 {
        log_warning!(
            logger,
            Facility::Supervisor,
            &format!(
                "PIM parse: packet too short for IHL ({} bytes, IHL={})",
                packet.len(),
                ihl
            )
        );
        return None;
    }

    // Check protocol is PIM (103)
    if packet[9] != 103 {
        log_warning!(
            logger,
            Facility::Supervisor,
            &format!("PIM parse: wrong protocol ({})", packet[9])
        );
        return None;
    }

    // Extract source IP
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

    // Use provided interface from IP_PKTINFO, or fall back to subnet lookup
    let interface = interface
        .unwrap_or_else(|| find_interface_by_ip(src_ip).unwrap_or_else(|| "unknown".to_string()));

    // Parse PIM header (after IP header)
    let pim = &packet[ihl..];
    if pim.len() < 4 {
        return None;
    }

    // PIM header: version/type (1 byte), reserved (1 byte), checksum (2 bytes)
    let pim_version = (pim[0] >> 4) & 0x0F;
    let msg_type = pim[0] & 0x0F;

    // Validate PIM version (should be 2)
    if pim_version != 2 {
        log_warning!(
            logger,
            Facility::Supervisor,
            &format!("PIM parse: wrong PIM version ({})", pim_version)
        );
        return None;
    }

    // Extract payload (after 4-byte PIM header)
    let payload = if pim.len() > 4 {
        pim[4..].to_vec()
    } else {
        Vec::new()
    };

    log_debug!(
        logger,
        Facility::Supervisor,
        &format!(
            "Received PIM packet: type={}, src={}, interface={}, payload_len={}",
            msg_type,
            src_ip,
            interface,
            payload.len()
        )
    );

    Some(ProtocolEvent::Pim(PimEvent::PacketReceived {
        interface,
        src_ip,
        msg_type,
        payload,
    }))
}

/// Find interface name by IP address
///
/// For incoming packets, we want to find the interface where the source IP
/// is a neighbor (in the same subnet but not our own IP). This handles the
/// case where multiple interfaces are in the same network namespace.
fn find_interface_by_ip(ip: Ipv4Addr) -> Option<String> {
    let mut subnet_match = None;

    for iface in pnet::datalink::interfaces() {
        for ip_net in &iface.ips {
            if let std::net::IpAddr::V4(v4) = ip_net.ip() {
                // If source IP matches interface IP exactly, this is our own
                // interface sending - skip it and prefer subnet matches
                if v4 == ip {
                    continue;
                }

                // If source IP is in the interface's subnet, it's a neighbor
                if ip_net.contains(std::net::IpAddr::V4(ip)) {
                    // Prefer first subnet match found
                    if subnet_match.is_none() {
                        subnet_match = Some(iface.name.clone());
                    }
                }
            }
        }
    }

    subnet_match
}

/// Protocol coordinator that manages the integration between
/// protocol state machines and the supervisor's main loop
pub struct ProtocolCoordinator {
    /// Protocol state machines and MRIB
    pub state: ProtocolState,
    /// Channel to receive protocol events
    event_rx: mpsc::Receiver<ProtocolEvent>,
    /// Channel to send protocol events (for MSDP TCP)
    event_tx: mpsc::Sender<ProtocolEvent>,
    /// Channel to send timer requests
    timer_tx: mpsc::Sender<TimerRequest>,
    /// Flag to track if rules need syncing
    rules_dirty: bool,
}

impl ProtocolCoordinator {
    /// Create a new protocol coordinator with channels
    pub fn new(
        state: ProtocolState,
        event_rx: mpsc::Receiver<ProtocolEvent>,
        event_tx: mpsc::Sender<ProtocolEvent>,
        timer_tx: mpsc::Sender<TimerRequest>,
    ) -> Self {
        Self {
            state,
            event_rx,
            event_tx,
            timer_tx,
            rules_dirty: false,
        }
    }

    /// Get a clone of the event sender (for MSDP TCP)
    pub fn event_tx_clone(&self) -> mpsc::Sender<ProtocolEvent> {
        self.event_tx.clone()
    }

    /// Process any pending protocol events (non-blocking)
    ///
    /// Returns true if the MRIB was modified and rules need syncing
    pub async fn process_pending_events(&mut self) -> bool {
        let mut mrib_modified = false;

        // Process all available events without blocking
        loop {
            match self.event_rx.try_recv() {
                Ok(event) => {
                    let timer_requests = self.state.process_event(event);

                    // Schedule any timer requests
                    for req in timer_requests {
                        let _ = self.timer_tx.send(req).await;
                    }

                    // Check if this event modified the MRIB
                    // IGMP membership changes and PIM route changes affect forwarding
                    mrib_modified = true;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        if mrib_modified {
            self.rules_dirty = true;
        }

        mrib_modified
    }

    /// Get compiled forwarding rules from the MRIB
    pub fn compile_rules(&self) -> Vec<ForwardingRule> {
        self.state.compile_forwarding_rules()
    }

    /// Check if rules are dirty (need syncing)
    pub fn rules_dirty(&self) -> bool {
        self.rules_dirty
    }

    /// Clear the dirty flag
    pub fn clear_dirty(&mut self) {
        self.rules_dirty = false;
    }
}

/// Initialize protocol subsystem and return the coordinator and background tasks
///
/// This function creates:
/// - ProtocolState with sockets and state machines
/// - Event channel for protocol events
/// - Timer channel for timer requests
/// - Background tasks for receiver loop and timer manager
///
/// The caller should spawn the returned tasks and process events through the coordinator.
pub fn initialize_protocol_subsystem(
    config: &Config,
    logger: Logger,
) -> Result<(
    ProtocolCoordinator,
    impl std::future::Future<Output = ()>,
    impl std::future::Future<Output = ()>,
)> {
    // Create channels
    let (event_tx, event_rx) = mpsc::channel::<ProtocolEvent>(1024);
    let (timer_tx, timer_rx) = mpsc::channel::<TimerRequest>(256);

    // Create protocol state
    let mut state = ProtocolState::new(logger.clone());
    state.timer_tx = Some(timer_tx.clone());

    // Enable event subscriptions for external control plane integration
    // Use buffer size from config if specified, otherwise use default
    let event_buffer_size = config
        .control_plane
        .as_ref()
        .map(|cp| cp.event_buffer_size)
        .unwrap_or(256);
    state.enable_event_subscriptions(event_buffer_size);

    // Initialize from config
    state.initialize_from_config(config);

    // Create protocol sockets if needed
    if state.igmp_enabled || state.pim_enabled {
        state.create_protocol_sockets()?;
    }

    // Schedule any pending timers from protocol initialization
    // This must happen AFTER socket creation so timers can send packets
    for timer in state.pending_igmp_timers.drain(..) {
        if let Err(e) = timer_tx.try_send(timer) {
            log_warning!(
                logger,
                Facility::Supervisor,
                &format!("Failed to schedule pending IGMP timer: {}", e)
            );
        }
    }

    // Store event_tx in state for later use (e.g., spawning receiver loop via CLI)
    state.event_tx = Some(event_tx.clone());

    // Get socket file descriptors for the receiver loop
    let igmp_fd = state.igmp_socket_fd();
    let pim_fd = state.pim_socket_fd();

    // Mark receiver loop as running if we have sockets
    let receiver_will_run = igmp_fd.is_some() || pim_fd.is_some();
    if receiver_will_run {
        state
            .receiver_loop_running
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // Create background tasks
    let receiver_logger = logger.clone();
    let receiver_event_tx = event_tx.clone();
    let receiver_task = async move {
        protocol_receiver_loop(igmp_fd, pim_fd, receiver_event_tx, receiver_logger).await;
    };

    // Clone event_tx before giving it to timer manager
    let coordinator_event_tx = event_tx.clone();

    let timer_manager = ProtocolTimerManager::new(timer_rx, event_tx, logger.clone());
    let timer_task = async move {
        timer_manager.run().await;
    };

    // Create coordinator
    let coordinator = ProtocolCoordinator::new(state, event_rx, coordinator_event_tx, timer_tx);

    Ok((coordinator, receiver_task, timer_task))
}

/// Sync forwarding rules to all data plane workers
///
/// This function sends the compiled rules to all workers, filtering by interface.
async fn sync_rules_to_workers(
    rules: &[ForwardingRule],
    worker_manager: &Arc<Mutex<WorkerManager>>,
    logger: &Logger,
) {
    if rules.is_empty() {
        return;
    }

    let stream_pairs_with_iface = {
        let manager = worker_manager.lock().unwrap();
        manager.get_all_dp_cmd_streams_with_interface()
    };

    for (interface, ingress_stream, egress_stream) in stream_pairs_with_iface {
        // Filter rules to only include those matching this worker's input interface
        let interface_rules: Vec<ForwardingRule> = rules
            .iter()
            .filter(|r| r.input_interface == interface)
            .cloned()
            .collect();

        if interface_rules.is_empty() {
            continue;
        }

        let sync_cmd = RelayCommand::SyncRules(interface_rules);
        if let Ok(cmd_bytes) = serde_json::to_vec(&sync_cmd) {
            let mut ingress = ingress_stream.lock().await;
            let mut egress = egress_stream.lock().await;

            // Fire-and-forget: ignore errors
            let _ = ingress.write_all(&cmd_bytes).await;
            let _ = egress.write_all(&cmd_bytes).await;
        }
    }

    log_debug!(
        logger,
        Facility::Supervisor,
        &format!("Synced {} rules to workers", rules.len())
    );
}

/// Get IPv4 address for an interface
fn get_interface_ipv4(interface: &str) -> Option<Ipv4Addr> {
    for iface in pnet::datalink::interfaces() {
        if iface.name == interface {
            for ip_net in iface.ips {
                if let std::net::IpAddr::V4(ip) = ip_net.ip() {
                    if !ip.is_loopback() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// Get the local source address that would be used to reach a destination.
///
/// Uses the UDP connect trick: connect a UDP socket to the destination
/// (without sending anything), then getsockname() to see which local
/// address the kernel chose based on the routing table.
fn get_source_addr_for_dest(dest: Ipv4Addr) -> Option<Ipv4Addr> {
    use std::net::{SocketAddr, UdpSocket};

    // Create a UDP socket and "connect" to the destination
    // This doesn't send anything, just sets the route
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket
        .connect(SocketAddr::from((dest, 9))) // Port doesn't matter
        .ok()?;

    // Get the local address the kernel chose
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

/// Parse a group prefix like "239.0.0.0/8" or "239.1.1.1" into a base address
pub(super) fn parse_group_prefix(prefix: &str) -> Result<Ipv4Addr> {
    if let Some((addr_str, _)) = prefix.split_once('/') {
        addr_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid group prefix"))
    } else {
        prefix
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid group address"))
    }
}

/// Parse a PIM Join/Prune message payload
///
/// Returns: (upstream_neighbor, joins, prunes, holdtime_secs)
/// Where joins/prunes are Vec<(Option<source>, group)> - None source means (*,G)
#[allow(clippy::type_complexity)]
fn parse_pim_join_prune(
    payload: &[u8],
) -> Option<(
    Ipv4Addr,
    Vec<(Option<Ipv4Addr>, Ipv4Addr)>,
    Vec<(Option<Ipv4Addr>, Ipv4Addr)>,
    u16,
)> {
    // Minimum length: 8 bytes for header (upstream neighbor encoded + reserved + num_groups + holdtime)
    if payload.len() < 8 {
        return None;
    }

    // Parse encoded unicast upstream neighbor (simplified - assuming IPv4, 6 bytes)
    // Format: addr_family(1) + encoding_type(1) + address(4)
    if payload.len() < 6 || payload[0] != 1 {
        // addr_family 1 = IPv4
        return None;
    }
    let upstream = Ipv4Addr::new(payload[2], payload[3], payload[4], payload[5]);

    // Reserved (1 byte) + num_groups (1 byte) + holdtime (2 bytes)
    if payload.len() < 10 {
        return None;
    }
    let num_groups = payload[7] as usize;
    let holdtime = u16::from_be_bytes([payload[8], payload[9]]);

    let mut joins = Vec::new();
    let mut prunes = Vec::new();
    let mut offset = 10;

    for _ in 0..num_groups {
        // Encoded group: addr_family(1) + encoding_type(1) + reserved(1) + mask_len(1) + group(4)
        if offset + 8 > payload.len() {
            break;
        }
        let group = Ipv4Addr::new(
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        );
        offset += 8;

        // Number of joined sources (2 bytes) + number of pruned sources (2 bytes)
        if offset + 4 > payload.len() {
            break;
        }
        let num_joins = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        let num_prunes = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;

        // Parse joined sources
        for _ in 0..num_joins {
            // Encoded source: addr_family(1) + encoding_type(1) + flags(1) + mask_len(1) + source(4)
            if offset + 8 > payload.len() {
                break;
            }
            let flags = payload[offset + 2];
            let source = Ipv4Addr::new(
                payload[offset + 4],
                payload[offset + 5],
                payload[offset + 6],
                payload[offset + 7],
            );
            offset += 8;

            // WC bit (0x02) indicates (*,G), otherwise (S,G)
            if (flags & 0x02) != 0 {
                joins.push((None, group));
            } else {
                joins.push((Some(source), group));
            }
        }

        // Parse pruned sources
        for _ in 0..num_prunes {
            if offset + 8 > payload.len() {
                break;
            }
            let flags = payload[offset + 2];
            let source = Ipv4Addr::new(
                payload[offset + 4],
                payload[offset + 5],
                payload[offset + 6],
                payload[offset + 7],
            );
            offset += 8;

            if (flags & 0x02) != 0 {
                prunes.push((None, group));
            } else {
                prunes.push((Some(source), group));
            }
        }
    }

    Some((upstream, joins, prunes, holdtime))
}

// --- Client Handling ---

/// Handle a single client connection on the control socket
#[allow(clippy::too_many_arguments)]
async fn handle_client(
    mut client_stream: tokio::net::UnixStream,
    worker_manager: Arc<Mutex<WorkerManager>>,
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
    global_min_level: Arc<std::sync::atomic::AtomicU8>,
    facility_min_levels: Arc<
        std::sync::RwLock<
            std::collections::HashMap<crate::logging::Facility, crate::logging::Severity>,
        >,
    >,
    startup_config_path: Option<PathBuf>,
    startup_config: Arc<Option<Config>>,
    protocol_coordinator: Arc<Mutex<Option<ProtocolCoordinator>>>,
    logger: Logger,
) -> Result<()> {
    use crate::{Response, SupervisorCommand};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = Vec::new();
    client_stream.read_to_end(&mut buffer).await?;

    let command: SupervisorCommand = serde_json::from_slice(&buffer)?;

    // Handle subscription requests specially (they need persistent connections)
    if let SupervisorCommand::Subscribe { events } = &command {
        let subscription_result: Option<(
            crate::SubscriptionId,
            Vec<crate::EventType>,
            tokio::sync::broadcast::Receiver<crate::ProtocolEventNotification>,
        )> = {
            let coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref coordinator) = *coordinator_guard {
                if let Some(ref event_manager) = coordinator.state.event_manager {
                    let id = crate::SubscriptionId::new();
                    let rx = event_manager.subscribe();
                    Some((id, events.clone(), rx))
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some((subscription_id, subscribed_events, mut event_rx)) = subscription_result {
            // Send subscription confirmation
            let response = Response::Subscribed {
                subscription_id: subscription_id.clone(),
                events: subscribed_events.clone(),
            };
            let response_bytes = serde_json::to_vec(&response)?;
            client_stream.write_all(&response_bytes).await?;
            client_stream.write_all(b"\n").await?; // Delimiter for streaming

            // Stream events until connection is closed
            let subscribed_set: std::collections::HashSet<_> =
                subscribed_events.into_iter().collect();
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        // Only send events that match subscription
                        if subscribed_set.contains(&event.event_type()) {
                            let event_response = Response::Event(event);
                            let event_bytes = serde_json::to_vec(&event_response)?;
                            if client_stream.write_all(&event_bytes).await.is_err() {
                                break; // Client disconnected
                            }
                            if client_stream.write_all(b"\n").await.is_err() {
                                break; // Client disconnected
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Log lag but continue - subscriber missed some events
                        log_warning!(
                            logger,
                            Facility::Supervisor,
                            &format!("Event subscriber lagged by {} events", n)
                        );
                    }
                }
            }
            return Ok(());
        } else {
            // Event subscriptions not available
            let response = Response::Error("Event subscriptions not available".to_string());
            let response_bytes = serde_json::to_vec(&response)?;
            client_stream.write_all(&response_bytes).await?;
            return Ok(());
        }
    }

    // Handle protocol-specific queries and mutations directly (need access to ProtocolCoordinator state)
    // These commands need real data from the protocol state machines
    let protocol_response: Option<Response> = {
        let mut coordinator_guard = protocol_coordinator.lock().unwrap();
        if let Some(ref mut coordinator) = *coordinator_guard {
            match &command {
                SupervisorCommand::GetPimNeighbors => {
                    let neighbors = coordinator.state.get_pim_neighbors();
                    Some(Response::PimNeighbors(neighbors))
                }
                SupervisorCommand::GetIgmpGroups => {
                    let groups = coordinator.state.get_igmp_groups();
                    Some(Response::IgmpGroups(groups))
                }
                SupervisorCommand::GetMroute => {
                    let routes = coordinator.state.get_mroute_entries();
                    Some(Response::Mroute(routes))
                }
                SupervisorCommand::GetMsdpPeers => {
                    let peers = coordinator.state.get_msdp_peers();
                    Some(Response::MsdpPeers(peers))
                }
                SupervisorCommand::GetMsdpSaCache => {
                    let sa_cache = coordinator.state.get_msdp_sa_cache();
                    Some(Response::MsdpSaCache(sa_cache))
                }
                SupervisorCommand::ListExternalNeighbors => {
                    let neighbors = coordinator.state.get_external_neighbors();
                    Some(Response::ExternalNeighbors(neighbors))
                }
                SupervisorCommand::GetRpfProvider => {
                    let provider = coordinator.state.pim_state.get_rpf_provider().clone();
                    let static_entries = coordinator.state.pim_state.static_rpf.len();
                    Some(Response::RpfProvider(crate::RpfProviderInfo {
                        provider,
                        static_entries,
                        cached_entries: 0, // No caching implemented yet
                    }))
                }
                SupervisorCommand::QueryRpf { source } => {
                    let rpf = coordinator.state.pim_state.lookup_rpf(*source).cloned();
                    Some(Response::RpfResult(rpf))
                }
                SupervisorCommand::ListRpfRoutes => {
                    let routes: Vec<crate::RpfRouteEntry> = coordinator
                        .state
                        .pim_state
                        .get_rpf_routes()
                        .into_iter()
                        .map(|(source, rpf)| crate::RpfRouteEntry {
                            source,
                            rpf: rpf.clone(),
                        })
                        .collect();
                    Some(Response::RpfRoutes(routes))
                }
                SupervisorCommand::GetControlPlaneConfig => {
                    let rpf_provider_str = match coordinator.state.pim_state.get_rpf_provider() {
                        crate::RpfProvider::Disabled => "disabled".to_string(),
                        crate::RpfProvider::Static => "static".to_string(),
                        crate::RpfProvider::External { socket_path } => socket_path.clone(),
                    };
                    Some(Response::ControlPlaneConfig {
                        rpf_provider: rpf_provider_str,
                        external_neighbors_enabled: true, // External neighbors are always accepted via API
                        event_buffer_size: coordinator.state.event_buffer_size(),
                    })
                }
                SupervisorCommand::AddExternalNeighbor { ref neighbor } => {
                    // Validate and add in one atomic operation
                    if coordinator.state.pim_state.add_external_neighbor(neighbor) {
                        log_info!(
                            logger,
                            Facility::Supervisor,
                            &format!(
                                "External PIM neighbor {} added on {}",
                                neighbor.address, neighbor.interface
                            )
                        );
                        // Emit event for external neighbor up
                        coordinator.state.emit_event(
                            crate::ProtocolEventNotification::PimNeighborChange {
                                interface: neighbor.interface.clone(),
                                neighbor: neighbor.address,
                                action: crate::NeighborAction::Up,
                                source: crate::NeighborSource::External {
                                    tag: neighbor.tag.clone(),
                                },
                                timestamp: unix_timestamp(),
                            },
                        );
                        Some(Response::Success(format!(
                            "External neighbor {} added on {}",
                            neighbor.address, neighbor.interface
                        )))
                    } else {
                        Some(Response::Error(format!(
                            "Interface {} not enabled for PIM. Enable PIM on the interface first.",
                            neighbor.interface
                        )))
                    }
                }
                SupervisorCommand::RemoveExternalNeighbor { address, interface } => {
                    // Remove in one atomic operation
                    if coordinator
                        .state
                        .pim_state
                        .remove_external_neighbor(*address, interface)
                    {
                        log_info!(
                            logger,
                            Facility::Supervisor,
                            &format!(
                                "External PIM neighbor {} removed from {}",
                                address, interface
                            )
                        );
                        // Emit event for external neighbor down
                        coordinator.state.emit_event(
                            crate::ProtocolEventNotification::PimNeighborChange {
                                interface: interface.clone(),
                                neighbor: *address,
                                action: crate::NeighborAction::Down,
                                source: crate::NeighborSource::External { tag: None },
                                timestamp: unix_timestamp(),
                            },
                        );
                        Some(Response::Success(format!(
                            "External neighbor {} removed from {}",
                            address, interface
                        )))
                    } else {
                        Some(Response::Error(format!(
                            "External neighbor {} not found on interface {}",
                            address, interface
                        )))
                    }
                }
                SupervisorCommand::ClearExternalNeighbors { ref interface } => {
                    // Clear in one atomic operation
                    let removed = coordinator
                        .state
                        .pim_state
                        .clear_external_neighbors(interface.as_deref());
                    let msg = match interface {
                        Some(iface) => {
                            format!("Cleared {} external neighbors from {}", removed, iface)
                        }
                        None => {
                            format!("Cleared {} external neighbors from all interfaces", removed)
                        }
                    };
                    log_info!(logger, Facility::Supervisor, &msg);
                    Some(Response::Success(msg))
                }
                SupervisorCommand::EnablePim {
                    ref interface,
                    dr_priority,
                } => {
                    // Look up interface IP
                    match get_interface_ipv4(interface) {
                        None => Some(Response::Error(format!(
                            "Interface {} not found or has no IPv4 address",
                            interface
                        ))),
                        Some(interface_ip) => {
                            // Create PIM interface config
                            let pim_config = if let Some(priority) = *dr_priority {
                                crate::protocols::pim::PimInterfaceConfig {
                                    dr_priority: priority,
                                    ..Default::default()
                                }
                            } else {
                                crate::protocols::pim::PimInterfaceConfig::default()
                            };

                            // Enable PIM on the interface
                            let timers = coordinator.state.pim_state.enable_interface(
                                interface,
                                interface_ip,
                                pim_config,
                            );

                            // Schedule the returned timers (Hello timer)
                            if let Some(ref timer_tx) = coordinator.state.timer_tx {
                                for timer in timers {
                                    if let Err(e) = timer_tx.try_send(timer) {
                                        log_warning!(
                                            logger,
                                            Facility::Supervisor,
                                            &format!("Failed to schedule PIM timer: {}", e)
                                        );
                                    }
                                }
                            }

                            // Ensure PIM socket exists and join multicast on this interface
                            coordinator.state.pim_enabled = true;
                            if coordinator.state.pim_socket.is_none() {
                                if let Err(e) = coordinator.state.create_pim_socket() {
                                    log_error!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!("Failed to create PIM socket: {}", e)
                                    );
                                }
                                // Spawn receiver loop if this is the first socket
                                coordinator.state.spawn_receiver_loop_if_needed();
                            }
                            if let Err(e) =
                                coordinator.state.join_pim_multicast_on_interface(interface)
                            {
                                log_warning!(
                                    logger,
                                    Facility::Supervisor,
                                    &format!("Failed to join PIM multicast on {}: {} (may already be joined)", interface, e)
                                );
                            }

                            log_info!(
                                logger,
                                Facility::Supervisor,
                                &format!(
                                    "PIM enabled on interface {} (IP: {}, DR priority: {:?})",
                                    interface, interface_ip, dr_priority
                                )
                            );
                            Some(Response::Success(format!(
                                "PIM enabled on {} (IP: {}, DR priority: {})",
                                interface,
                                interface_ip,
                                dr_priority.unwrap_or(1)
                            )))
                        }
                    }
                }
                SupervisorCommand::DisablePim { ref interface } => {
                    // Disable PIM on the interface
                    coordinator.state.pim_state.disable_interface(interface);
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!("PIM disabled on interface {}", interface)
                    );
                    Some(Response::Success(format!("PIM disabled on {}", interface)))
                }
                _ => None,
            }
        } else {
            None
        }
    };

    // If we handled a protocol query, return early
    if let Some(resp) = protocol_response {
        let response_bytes = serde_json::to_vec(&resp)?;
        client_stream.write_all(&response_bytes).await?;
        return Ok(());
    }

    // Get worker info and stats from WorkerManager (locked access)
    let (worker_info, worker_stats_arc) = {
        let manager = worker_manager.lock().unwrap();
        (manager.get_worker_info(), manager.worker_stats.clone())
    };

    // Create a temporary HashMap for handle_supervisor_command (to keep it pure)
    let worker_map_temp = Mutex::new(
        worker_info
            .iter()
            .map(|w| (w.pid, w.clone()))
            .collect::<HashMap<u32, crate::WorkerInfo>>(),
    );

    // Use the extracted, testable command handler
    let (response, action) = handle_supervisor_command(
        command,
        &master_rules,
        &worker_map_temp,
        &global_min_level,
        &facility_min_levels,
        &worker_stats_arc,
        startup_config_path.as_ref(),
        startup_config.as_ref().as_ref(),
    );

    // Log ruleset hash for drift detection if rules changed
    if matches!(
        action,
        CommandAction::BroadcastToDataPlane(_) | CommandAction::EnsureWorkersAndBroadcast { .. }
    ) {
        let ruleset_hash = {
            let rules = master_rules.lock().unwrap();
            crate::compute_ruleset_hash(rules.values())
        };
        let rule_count = master_rules.lock().unwrap().len();

        // Get logger from worker_manager
        let logger = {
            let manager = worker_manager.lock().unwrap();
            manager.logger.clone()
        };

        log_info!(
            logger,
            Facility::Supervisor,
            &format!(
                "Ruleset updated: hash={:016x} rule_count={}",
                ruleset_hash, rule_count
            )
        );
    }

    // Handle async actions BEFORE sending response for Ping
    let mut final_response = response;
    match action {
        CommandAction::None => {
            // Nothing to do
        }
        CommandAction::BroadcastToDataPlane(relay_cmd) => {
            let is_ping = matches!(relay_cmd, RelayCommand::Ping);
            let is_sync_rules = matches!(relay_cmd, RelayCommand::SyncRules(_));

            if is_sync_rules {
                // For SyncRules, filter rules by interface before sending to each worker
                // This implements per-interface rule distribution (Phase 1 of the roadmap)
                let all_rules = if let RelayCommand::SyncRules(rules) = &relay_cmd {
                    rules.clone()
                } else {
                    vec![]
                };

                // Get streams with interface info for per-interface filtering
                let stream_pairs_with_iface = {
                    let manager = worker_manager.lock().unwrap();
                    manager.get_all_dp_cmd_streams_with_interface()
                };

                for (interface, ingress_stream, egress_stream) in stream_pairs_with_iface {
                    // Filter rules to only include those matching this worker's input interface
                    let interface_rules: Vec<ForwardingRule> = all_rules
                        .iter()
                        .filter(|r| r.input_interface == interface)
                        .cloned()
                        .collect();

                    // Create interface-specific SyncRules command
                    let interface_cmd = RelayCommand::SyncRules(interface_rules);
                    let cmd_bytes = match serde_json::to_vec(&interface_cmd) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            error!(
                                "Failed to serialize SyncRules for interface {}: {}",
                                interface, e
                            );
                            continue;
                        }
                    };

                    // Send to ingress worker
                    let cmd_bytes_clone = cmd_bytes.clone();
                    tokio::spawn(async move {
                        let mut stream = ingress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        let _ = framed.send(cmd_bytes_clone.into()).await;
                    });

                    // Send to egress worker
                    tokio::spawn(async move {
                        let mut stream = egress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        let _ = framed.send(cmd_bytes.into()).await;
                    });
                }
            } else {
                // For non-SyncRules commands, broadcast same command to all workers
                let cmd_bytes = serde_json::to_vec(&relay_cmd)?;

                // Get cmd stream pairs from WorkerManager
                let stream_pairs = {
                    let manager = worker_manager.lock().unwrap();
                    manager.get_all_dp_cmd_streams()
                };

                if is_ping {
                    // For ping, wait for all sends to complete and verify success
                    let mut send_tasks = Vec::new();

                    for (ingress_stream, egress_stream) in stream_pairs {
                        // Send to ingress
                        let cmd_bytes_clone = cmd_bytes.clone();
                        let task = tokio::spawn(async move {
                            let mut stream = ingress_stream.lock().await;
                            let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                            framed.send(cmd_bytes_clone.into()).await
                        });
                        send_tasks.push(task);

                        // Send to egress
                        let cmd_bytes_clone = cmd_bytes.clone();
                        let task = tokio::spawn(async move {
                            let mut stream = egress_stream.lock().await;
                            let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                            framed.send(cmd_bytes_clone.into()).await
                        });
                        send_tasks.push(task);
                    }

                    // Wait for all sends and check for errors
                    let total_streams = send_tasks.len();
                    let mut ready_count = 0;
                    for task in send_tasks {
                        match task.await {
                            Ok(Ok(_)) => {
                                // Send succeeded - worker stream is ready
                                ready_count += 1;
                            }
                            Ok(Err(e)) => {
                                eprintln!("[PING] Failed to send ping to worker: {}", e);
                            }
                            Err(e) => {
                                eprintln!("[PING] Task join error: {}", e);
                            }
                        }
                    }

                    if ready_count == total_streams {
                        final_response = Response::Success(format!(
                            "pong: {}/{} worker streams ready",
                            ready_count, total_streams
                        ));
                    } else {
                        final_response = Response::Error(format!(
                            "Only {}/{} worker streams ready",
                            ready_count, total_streams
                        ));
                    }
                } else {
                    // For non-ping, non-SyncRules commands, fire and forget
                    for (ingress_stream, egress_stream) in stream_pairs {
                        // Send to ingress
                        let cmd_bytes_clone = cmd_bytes.clone();
                        tokio::spawn(async move {
                            let mut stream = ingress_stream.lock().await;
                            let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                            let _ = framed.send(cmd_bytes_clone.into()).await;
                        });

                        // Send to egress
                        let cmd_bytes_clone = cmd_bytes.clone();
                        tokio::spawn(async move {
                            let mut stream = egress_stream.lock().await;
                            let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                            let _ = framed.send(cmd_bytes_clone.into()).await;
                        });
                    }
                }
            }
        }
        CommandAction::EnsureWorkersAndBroadcast {
            interface,
            is_pinned,
            command,
        } => {
            // First, ensure workers exist for the interface
            {
                let manager = worker_manager.lock().unwrap();
                if !manager.has_workers_for_interface(&interface) {
                    // Drop lock before async operation
                    drop(manager);

                    // Re-acquire lock and spawn workers
                    let mut manager = worker_manager.lock().unwrap();
                    if let Err(e) = manager
                        .ensure_workers_for_interface(&interface, is_pinned)
                        .await
                    {
                        error!(
                            "Failed to spawn workers for interface '{}': {}",
                            interface, e
                        );
                    }
                }
            }

            // Now broadcast the command to all workers
            let cmd_bytes = serde_json::to_vec(&command)?;
            let stream_pairs = {
                let manager = worker_manager.lock().unwrap();
                manager.get_all_dp_cmd_streams()
            };

            for (ingress_stream, egress_stream) in stream_pairs {
                // Send to ingress
                let cmd_bytes_clone = cmd_bytes.clone();
                tokio::spawn(async move {
                    let mut stream = ingress_stream.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    let _ = framed.send(cmd_bytes_clone.into()).await;
                });

                // Send to egress
                let cmd_bytes_clone = cmd_bytes.clone();
                tokio::spawn(async move {
                    let mut stream = egress_stream.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    let _ = framed.send(cmd_bytes_clone.into()).await;
                });
            }
        }
        CommandAction::AddMsdpPeer {
            address,
            description,
            mesh_group,
            default_peer,
        } => {
            // First, check if MSDP TCP needs to be initialized
            let needs_msdp_tcp = {
                let coordinator_guard = protocol_coordinator.lock().unwrap();
                if let Some(ref coordinator) = *coordinator_guard {
                    coordinator.state.msdp_tcp_tx.is_none()
                } else {
                    false
                }
            };

            // Initialize MSDP TCP if needed (must be done outside the lock since it's async)
            if needs_msdp_tcp {
                let event_tx = {
                    let coordinator_guard = protocol_coordinator.lock().unwrap();
                    coordinator_guard
                        .as_ref()
                        .and_then(|c| c.state.event_tx.clone())
                };

                if let Some(event_tx) = event_tx {
                    // Find local address that can reach the peer
                    let local_addr = get_source_addr_for_dest(address)
                        .unwrap_or_else(|| get_interface_ipv4("lo").unwrap_or(Ipv4Addr::LOCALHOST));

                    match crate::protocols::msdp_tcp::start_msdp_tcp(local_addr, event_tx).await {
                        Ok((tcp_cmd_tx, listener_task, runner_task)) => {
                            // Store the command channel
                            {
                                let mut coordinator_guard = protocol_coordinator.lock().unwrap();
                                if let Some(ref mut coordinator) = *coordinator_guard {
                                    coordinator.state.msdp_tcp_tx = Some(tcp_cmd_tx);
                                    coordinator.state.msdp_enabled = true;
                                }
                            }

                            // Spawn MSDP TCP tasks
                            tokio::spawn(async move {
                                listener_task.await;
                            });
                            tokio::spawn(async move {
                                runner_task.await;
                            });

                            log_info!(
                                logger,
                                Facility::Supervisor,
                                &format!("MSDP TCP subsystem initialized on {}:639", local_addr)
                            );
                        }
                        Err(e) => {
                            log_warning!(
                                logger,
                                Facility::Supervisor,
                                &format!("Failed to initialize MSDP TCP: {}", e)
                            );
                        }
                    }
                } else {
                    log_warning!(
                        logger,
                        Facility::Supervisor,
                        "Cannot initialize MSDP TCP: event_tx not available"
                    );
                }
            }

            // Now add the peer
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                use crate::protocols::msdp::MsdpPeerConfig;

                // Enable MSDP in the state config (required for add_peer to schedule timers)
                coordinator.state.msdp_state.config.enabled = true;

                let peer_config = MsdpPeerConfig {
                    address,
                    description: description.clone(),
                    mesh_group,
                    default_peer,
                    keepalive_interval: coordinator.state.msdp_state.config.keepalive_interval,
                    hold_time: coordinator.state.msdp_state.config.hold_time,
                };
                let timers = coordinator.state.msdp_state.add_peer(peer_config);

                // Schedule connection timers
                for timer in timers {
                    if let Err(e) = coordinator.timer_tx.try_send(timer) {
                        log_warning!(
                            logger,
                            Facility::Supervisor,
                            &format!("Failed to schedule MSDP timer: {}", e)
                        );
                    }
                }

                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!(
                        "MSDP peer {} added{}",
                        address,
                        description
                            .as_ref()
                            .map(|d| format!(" ({})", d))
                            .unwrap_or_default()
                    )
                );
            }
        }
        CommandAction::RemoveMsdpPeer { address } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                coordinator.state.msdp_state.remove_peer(address);
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!("MSDP peer {} removed", address)
                );
            }
        }
        CommandAction::ClearMsdpSaCache => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                coordinator.state.msdp_state.sa_cache.clear();
                log_info!(logger, Facility::Supervisor, "MSDP SA cache cleared");
            }
        }
        CommandAction::AddExternalNeighbor { neighbor } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                if coordinator.state.pim_state.add_external_neighbor(&neighbor) {
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!(
                            "External PIM neighbor {} added on {}",
                            neighbor.address, neighbor.interface
                        )
                    );
                    // Emit event for external neighbor up
                    coordinator.state.emit_event(
                        crate::ProtocolEventNotification::PimNeighborChange {
                            interface: neighbor.interface.clone(),
                            neighbor: neighbor.address,
                            action: crate::NeighborAction::Up,
                            source: crate::NeighborSource::External {
                                tag: neighbor.tag.clone(),
                            },
                            timestamp: unix_timestamp(),
                        },
                    );
                } else {
                    log_warning!(
                        logger,
                        Facility::Supervisor,
                        &format!(
                            "Failed to add external neighbor {}: interface {} not enabled for PIM",
                            neighbor.address, neighbor.interface
                        )
                    );
                    final_response = Response::Error(format!(
                        "Interface {} not enabled for PIM",
                        neighbor.interface
                    ));
                }
            }
        }
        CommandAction::RemoveExternalNeighbor { address, interface } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                if coordinator
                    .state
                    .pim_state
                    .remove_external_neighbor(address, &interface)
                {
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!(
                            "External PIM neighbor {} removed from {}",
                            address, interface
                        )
                    );
                    // Emit event for external neighbor down
                    coordinator.state.emit_event(
                        crate::ProtocolEventNotification::PimNeighborChange {
                            interface: interface.clone(),
                            neighbor: address,
                            action: crate::NeighborAction::Down,
                            source: crate::NeighborSource::External { tag: None },
                            timestamp: unix_timestamp(),
                        },
                    );
                } else {
                    log_warning!(
                        logger,
                        Facility::Supervisor,
                        &format!(
                            "External neighbor {} not found on {} (or not external)",
                            address, interface
                        )
                    );
                    final_response = Response::Error(format!(
                        "External neighbor {} not found on {}",
                        address, interface
                    ));
                }
            }
        }
        CommandAction::ClearExternalNeighbors { interface } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                let count = coordinator
                    .state
                    .pim_state
                    .clear_external_neighbors(interface.as_deref());
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!(
                        "Cleared {} external PIM neighbor(s){}",
                        count,
                        interface
                            .as_ref()
                            .map(|i| format!(" from {}", i))
                            .unwrap_or_default()
                    )
                );
            }
        }
        CommandAction::SetRpfProvider { provider } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                coordinator
                    .state
                    .pim_state
                    .set_rpf_provider(provider.clone());
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!("RPF provider set to {}", provider)
                );
            }
        }
        CommandAction::AddRpfRoute { source, rpf } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                coordinator
                    .state
                    .pim_state
                    .add_rpf_route(source, rpf.clone());
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!(
                        "Static RPF route added for {} via {}",
                        source, rpf.upstream_interface
                    )
                );
            }
        }
        CommandAction::RemoveRpfRoute { source } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                if coordinator.state.pim_state.remove_rpf_route(source) {
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!("Static RPF route removed for {}", source)
                    );
                } else {
                    log_warning!(
                        logger,
                        Facility::Supervisor,
                        &format!("Static RPF route not found for {}", source)
                    );
                    final_response =
                        Response::Error(format!("Static RPF route not found for {}", source));
                }
            }
        }
        CommandAction::ClearRpfRoutes => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                let count = coordinator.state.pim_state.clear_rpf_routes();
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!("Cleared {} static RPF route(s)", count)
                );
            }
        }
    }

    // Send final response to client
    let response_bytes = serde_json::to_vec(&final_response)?;
    client_stream.write_all(&response_bytes).await?;

    Ok(())
}

// --- Supervisor Core Logic ---

#[allow(clippy::too_many_arguments)]
pub async fn run(
    _interface: &str, // Unused: workers spawn lazily when rules are added
    control_socket_path: PathBuf,
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
    num_workers: Option<usize>,
    startup_config: Option<Config>,
    startup_config_path: Option<PathBuf>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    // Determine number of cores to use
    // TODO: ARCHITECTURAL FIX NEEDED
    // Per architecture (D21, D23): One worker per CPU core, rules hashed to cores.
    // The --num-workers override exists to avoid resource exhaustion on single-interface tests
    // until lazy socket creation is implemented.
    let detected_cores = num_cpus::get();
    let num_cores = num_workers.unwrap_or(detected_cores);

    // Initialize logging early (before spawning workers)
    let supervisor_ringbuffer = Arc::new(MPSCRingBuffer::new(Facility::Supervisor.buffer_size()));

    // Initialize log-level filtering (default: Info)
    let global_min_level = Arc::new(std::sync::atomic::AtomicU8::new(
        crate::logging::Severity::Info as u8,
    ));
    let facility_min_levels = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

    let supervisor_logger = Logger::from_mpsc(
        Arc::clone(&supervisor_ringbuffer),
        Arc::clone(&global_min_level),
        Arc::clone(&facility_min_levels),
    );
    let ringbuffers_for_consumer = vec![(Facility::Supervisor, Arc::clone(&supervisor_ringbuffer))];
    let _log_consumer_handle = tokio::spawn(async move {
        AsyncConsumer::stderr(ringbuffers_for_consumer).run().await;
    });

    log_debug!(
        supervisor_logger,
        Facility::Supervisor,
        &format!(
            "Detected {} CPU cores, {} workers per interface",
            detected_cores, num_cores
        )
    );

    // Set up control socket for client connections
    if control_socket_path.exists() {
        std::fs::remove_file(&control_socket_path)?;
    }
    let listener = {
        let std_listener = std::os::unix::net::UnixListener::bind(&control_socket_path)?;
        std_listener.set_nonblocking(true)?;
        tokio::net::UnixListener::from_std(std_listener)?
    };
    log_info!(
        supervisor_logger,
        Facility::Supervisor,
        &format!("Control socket listening on {:?}", &control_socket_path)
    );

    // Generate a fanout group ID for all data plane workers
    // Only use PACKET_FANOUT when there are multiple workers (num_cores > 1)
    // With a single worker, PACKET_FANOUT is not needed and can cause issues
    let fanout_group_id = if num_cores > 1 {
        let id = (std::process::id() & 0xFFFF) as u16;
        log_debug!(
            supervisor_logger,
            Facility::Supervisor,
            &format!(
                "PACKET_FANOUT group ID: {} (up to {} workers per interface)",
                id, num_cores
            )
        );
        id
    } else {
        log_debug!(
            supervisor_logger,
            Facility::Supervisor,
            "PACKET_FANOUT disabled (single worker mode)"
        );
        0
    };

    // Extract pinning configuration from startup config (if provided)
    let pinning = startup_config
        .as_ref()
        .map(|c| c.pinning.clone())
        .unwrap_or_default();

    // Initialize WorkerManager and wrap it in Arc<Mutex<>>
    let worker_manager = {
        let mut manager = WorkerManager::new(
            num_cores,
            supervisor_logger.clone(),
            fanout_group_id,
            pinning,
        );

        // Spawn workers for all interfaces from config (if provided)
        // Otherwise fall back to default interface from CLI
        if let Some(ref config) = startup_config {
            let interfaces = config.get_interfaces();
            if !interfaces.is_empty() {
                log_info!(
                    supervisor_logger,
                    Facility::Supervisor,
                    &format!(
                        "Starting workers for {} interface(s) from config: {:?}",
                        interfaces.len(),
                        interfaces
                    )
                );
                for iface in interfaces {
                    manager.ensure_workers_for_interface(&iface, true).await?;
                }
            } else {
                // Config provided but no rules - wait for rules to be added dynamically
                log_info!(
                    supervisor_logger,
                    Facility::Supervisor,
                    "No rules in config, workers will spawn when rules are added"
                );
            }
        } else {
            // No config - wait for rules to be added dynamically
            log_info!(
                supervisor_logger,
                Facility::Supervisor,
                "No config provided, workers will spawn when rules are added"
            );
        }

        // Send initial ruleset sync to all data plane workers
        // This ensures workers start with the same ruleset as the supervisor
        // Rules are filtered per-interface so each worker only receives rules for its interface
        let rules_snapshot: Vec<ForwardingRule> = {
            let rules = master_rules.lock().unwrap();
            rules.values().cloned().collect()
        };

        if !rules_snapshot.is_empty() {
            log_info!(
                supervisor_logger,
                Facility::Supervisor,
                &format!(
                    "Sending initial ruleset sync ({} total rules) to data plane workers (per-interface filtered)",
                    rules_snapshot.len()
                )
            );

            // Get streams with interface info for per-interface filtering
            let stream_pairs_with_iface = manager.get_all_dp_cmd_streams_with_interface();
            for (interface, ingress_stream, egress_stream) in stream_pairs_with_iface {
                // Filter rules to only include those matching this worker's input interface
                let interface_rules: Vec<ForwardingRule> = rules_snapshot
                    .iter()
                    .filter(|r| r.input_interface == interface)
                    .cloned()
                    .collect();

                let sync_cmd = RelayCommand::SyncRules(interface_rules);
                if let Ok(cmd_bytes) = serde_json::to_vec(&sync_cmd) {
                    let mut ingress = ingress_stream.lock().await;
                    let mut egress = egress_stream.lock().await;

                    // Send to both ingress and egress workers (fire-and-forget)
                    let _ = ingress.write_all(&cmd_bytes).await;
                    let _ = egress.write_all(&cmd_bytes).await;
                }
            }
        } else {
            log_info!(
                supervisor_logger,
                Facility::Supervisor,
                "No rules to sync on startup (empty ruleset)"
            );
        }

        Arc::new(Mutex::new(manager))
    };

    // Initialize protocol subsystem if PIM, IGMP, or MSDP is configured
    // Wrap in Arc<Mutex<>> so it can be shared with handle_client and event processing
    let protocol_coordinator: Arc<Mutex<Option<ProtocolCoordinator>>> = Arc::new(Mutex::new(None));

    if let Some(ref config) = startup_config {
        let pim_enabled = config.pim.as_ref().map(|p| p.enabled).unwrap_or(false);
        let igmp_enabled = config
            .igmp
            .as_ref()
            .map(|i| !i.querier_interfaces.is_empty())
            .unwrap_or(false);
        let msdp_enabled = config.msdp.as_ref().map(|m| m.enabled).unwrap_or(false);

        if pim_enabled || igmp_enabled || msdp_enabled {
            log_info!(
                supervisor_logger,
                Facility::Supervisor,
                &format!(
                    "Initializing protocol subsystem (PIM: {}, IGMP: {}, MSDP: {})",
                    pim_enabled, igmp_enabled, msdp_enabled
                )
            );

            match initialize_protocol_subsystem(config, supervisor_logger.clone()) {
                Ok((mut coordinator, receiver_task, timer_task)) => {
                    // Spawn protocol background tasks
                    tokio::spawn(async move {
                        receiver_task.await;
                    });
                    tokio::spawn(async move {
                        timer_task.await;
                    });

                    // Initialize MSDP TCP if enabled
                    if msdp_enabled {
                        if let Some(msdp_config) = &config.msdp {
                            let local_addr = msdp_config.local_address.unwrap_or_else(|| {
                                // Try to find a suitable local address
                                get_interface_ipv4("lo").unwrap_or(Ipv4Addr::LOCALHOST)
                            });

                            // Create event channel for MSDP TCP
                            let msdp_event_tx = coordinator.event_tx_clone();

                            match crate::protocols::msdp_tcp::start_msdp_tcp(
                                local_addr,
                                msdp_event_tx,
                            )
                            .await
                            {
                                Ok((tcp_cmd_tx, listener_task, runner_task)) => {
                                    // Store the command channel in protocol state
                                    coordinator.state.msdp_tcp_tx = Some(tcp_cmd_tx);

                                    // Spawn MSDP TCP tasks
                                    tokio::spawn(async move {
                                        listener_task.await;
                                    });
                                    tokio::spawn(async move {
                                        runner_task.await;
                                    });

                                    log_info!(
                                        supervisor_logger,
                                        Facility::Supervisor,
                                        &format!(
                                            "MSDP TCP subsystem initialized on {}:639",
                                            local_addr
                                        )
                                    );
                                }
                                Err(e) => {
                                    log_warning!(
                                        supervisor_logger,
                                        Facility::Supervisor,
                                        &format!("Failed to initialize MSDP TCP: {}", e)
                                    );
                                }
                            }
                        }
                    }

                    // Store coordinator in the shared Arc<Mutex<>>
                    *protocol_coordinator.lock().unwrap() = Some(coordinator);

                    log_info!(
                        supervisor_logger,
                        Facility::Supervisor,
                        "Protocol subsystem initialized successfully"
                    );
                }
                Err(e) => {
                    log_warning!(
                        supervisor_logger,
                        Facility::Supervisor,
                        &format!("Failed to initialize protocol subsystem: {}", e)
                    );
                }
            }
        }
    }

    // If no protocol subsystem was created from config, create a minimal one
    // This allows CLI commands like `pim enable` to work without a config file
    if protocol_coordinator.lock().unwrap().is_none() {
        log_info!(
            supervisor_logger,
            Facility::Supervisor,
            "Initializing minimal protocol subsystem for CLI commands"
        );

        // Create a minimal empty config
        let empty_config = Config {
            rules: vec![],
            pinning: std::collections::HashMap::new(),
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
        };

        match initialize_protocol_subsystem(&empty_config, supervisor_logger.clone()) {
            Ok((coordinator, receiver_task, timer_task)) => {
                // Spawn protocol background tasks
                tokio::spawn(async move {
                    receiver_task.await;
                });
                tokio::spawn(async move {
                    timer_task.await;
                });

                // Store coordinator
                *protocol_coordinator.lock().unwrap() = Some(coordinator);

                log_info!(
                    supervisor_logger,
                    Facility::Supervisor,
                    "Minimal protocol subsystem initialized"
                );
            }
            Err(e) => {
                log_warning!(
                    supervisor_logger,
                    Facility::Supervisor,
                    &format!("Failed to initialize minimal protocol subsystem: {}", e)
                );
            }
        }
    }

    // Wrap startup_config in Arc for sharing with handle_client
    let startup_config: Arc<Option<Config>> = Arc::new(startup_config);

    // Create interval timers outside the loop so they persist across iterations
    // Using tokio::time::interval instead of sleep ensures the timer isn't reset
    // when other select! branches complete (critical bug fix!)
    let mut health_check_interval = tokio::time::interval(Duration::from_millis(250));
    let mut periodic_sync_interval =
        tokio::time::interval(Duration::from_secs(PERIODIC_SYNC_INTERVAL_SECS));
    // Protocol event processing interval (100ms - fast enough for responsive routing)
    let mut protocol_event_interval = tokio::time::interval(Duration::from_millis(100));

    // Main supervisor loop
    loop {
        tokio::select! {
            // Shutdown signal received
            _ = &mut shutdown_rx => {
                let mut manager = worker_manager.lock().unwrap();
                manager.shutdown_all(Duration::from_secs(SHUTDOWN_TIMEOUT_SECS)).await;
                drop(manager);
                break;
            }

            // New client connection
            Ok((client_stream, _)) = listener.accept() => {
                // Handle client inline to avoid unbounded task spawning
                // Client operations are fast (read, execute, write) and don't block data plane
                if let Err(e) = handle_client(
                    client_stream,
                    Arc::clone(&worker_manager),
                    Arc::clone(&master_rules),
                    Arc::clone(&global_min_level),
                    Arc::clone(&facility_min_levels),
                    startup_config_path.clone(),
                    Arc::clone(&startup_config),
                    Arc::clone(&protocol_coordinator),
                    supervisor_logger.clone(),
                )
                .await
                {
                    error!("Error handling client: {}", e);
                }
            }

            // Periodic worker health check (every 250ms)
            _ = health_check_interval.tick() => {
                // Check for crashed workers and restart them
                let restart_result = {
                    let mut manager = worker_manager.lock().unwrap();
                    manager.check_and_restart_worker().await
                };

                match restart_result {
                    Ok(Some((_pid, was_dataplane))) if was_dataplane => {
                        // A data plane worker was restarted - send SyncRules to ensure it has current ruleset
                        // Rules are filtered per-interface so each worker only receives rules for its interface
                        let rules_snapshot: Vec<ForwardingRule> = {
                            let rules = master_rules.lock().unwrap();
                            rules.values().cloned().collect()
                        };

                        if !rules_snapshot.is_empty() {
                            // Send per-interface filtered rules to all data plane workers
                            let stream_pairs_with_iface = {
                                let manager = worker_manager.lock().unwrap();
                                manager.get_all_dp_cmd_streams_with_interface()
                            };

                            for (interface, ingress_stream, egress_stream) in stream_pairs_with_iface {
                                // Filter rules to only include those matching this worker's input interface
                                let interface_rules: Vec<ForwardingRule> = rules_snapshot
                                    .iter()
                                    .filter(|r| r.input_interface == interface)
                                    .cloned()
                                    .collect();

                                let sync_cmd = RelayCommand::SyncRules(interface_rules);
                                if let Ok(cmd_bytes) = serde_json::to_vec(&sync_cmd) {
                                    let mut ingress = ingress_stream.lock().await;
                                    let mut egress = egress_stream.lock().await;

                                    // Fire-and-forget: ignore errors
                                    let _ = ingress.write_all(&cmd_bytes).await;
                                    let _ = egress.write_all(&cmd_bytes).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error checking/restarting worker: {}", e);
                    }
                    _ => {
                        // No worker restarted or control plane worker restarted (no action needed)
                    }
                }
            }

            // Periodic ruleset sync (every 5 minutes)
            // Part of Option C (Hybrid Approach) for fire-and-forget broadcast reliability
            // Recovers from any missed broadcasts due to transient failures
            // Rules are filtered per-interface so each worker only receives rules for its interface
            _ = periodic_sync_interval.tick() => {
                let rules_snapshot: Vec<ForwardingRule> = {
                    let rules = master_rules.lock().unwrap();
                    rules.values().cloned().collect()
                };

                if !rules_snapshot.is_empty() {
                    log_info!(
                        supervisor_logger,
                        Facility::Supervisor,
                        &format!(
                            "Periodic ruleset sync: sending {} total rules (per-interface filtered)",
                            rules_snapshot.len()
                        )
                    );

                    // Send per-interface filtered rules to all data plane workers
                    let stream_pairs_with_iface = {
                        let manager = worker_manager.lock().unwrap();
                        manager.get_all_dp_cmd_streams_with_interface()
                    };

                    for (interface, ingress_stream, egress_stream) in stream_pairs_with_iface {
                        // Filter rules to only include those matching this worker's input interface
                        let interface_rules: Vec<ForwardingRule> = rules_snapshot
                            .iter()
                            .filter(|r| r.input_interface == interface)
                            .cloned()
                            .collect();

                        let sync_cmd = RelayCommand::SyncRules(interface_rules);
                        if let Ok(cmd_bytes) = serde_json::to_vec(&sync_cmd) {
                            let mut ingress = ingress_stream.lock().await;
                            let mut egress = egress_stream.lock().await;

                            // Fire-and-forget: ignore errors (recovery will happen on next periodic sync)
                            let _ = ingress.write_all(&cmd_bytes).await;
                            let _ = egress.write_all(&cmd_bytes).await;
                        }
                    }
                } else {
                    log_info!(
                        supervisor_logger,
                        Facility::Supervisor,
                        "Periodic ruleset sync: no rules to sync (empty ruleset)"
                    );
                }
            }

            // Protocol event processing (every 100ms)
            // Processes IGMP reports, PIM messages, and timer events
            _ = protocol_event_interval.tick() => {
                let mut coordinator_guard = protocol_coordinator.lock().unwrap();
                if let Some(ref mut coordinator) = *coordinator_guard {
                    // Process any pending protocol events
                    let mrib_modified = coordinator.process_pending_events().await;

                    // If MRIB was modified, sync rules to workers
                    if mrib_modified && coordinator.rules_dirty() {
                        // Compile rules from MRIB (merges static + protocol-learned)
                        let protocol_rules = coordinator.compile_rules();

                        // Merge with static rules from master_rules
                        let mut all_rules: Vec<ForwardingRule> = {
                            let rules = master_rules.lock().unwrap();
                            rules.values().cloned().collect()
                        };

                        // Add protocol-learned rules (avoid duplicates by rule_id)
                        let static_rule_ids: std::collections::HashSet<_> =
                            all_rules.iter().map(|r| r.rule_id.clone()).collect();
                        for rule in protocol_rules {
                            if !static_rule_ids.contains(&rule.rule_id) {
                                all_rules.push(rule);
                            }
                        }

                        // Drop the lock before the async call
                        drop(coordinator_guard);

                        // Sync merged rules to all workers
                        sync_rules_to_workers(&all_rules, &worker_manager, &supervisor_logger).await;

                        // Re-acquire lock to clear dirty flag
                        let mut coordinator_guard = protocol_coordinator.lock().unwrap();
                        if let Some(ref mut coordinator) = *coordinator_guard {
                            coordinator.clear_dirty();
                        }

                        log_debug!(
                            supervisor_logger,
                            Facility::Supervisor,
                            &format!(
                                "Protocol MRIB changed: synced {} rules to workers",
                                all_rules.len()
                            )
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{MPSCRingBuffer, Severity};
    use std::sync::atomic::AtomicU8;
    use std::sync::{Arc, RwLock};

    /// Create a test logger for unit tests
    fn create_test_logger() -> Logger {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));
        Logger::from_mpsc(ringbuffer, global_min_level, facility_min_levels)
    }

    // ===========================================
    // get_source_addr_for_dest tests
    // ===========================================

    #[test]
    fn test_get_source_addr_for_dest_localhost() {
        let result = get_source_addr_for_dest(Ipv4Addr::LOCALHOST);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn test_get_source_addr_for_dest_external() {
        let result = get_source_addr_for_dest(Ipv4Addr::new(8, 8, 8, 8));
        if let Some(addr) = result {
            assert_ne!(addr, Ipv4Addr::UNSPECIFIED);
        }
    }

    #[test]
    fn test_get_source_addr_for_dest_link_local() {
        let result = get_source_addr_for_dest(Ipv4Addr::new(169, 254, 1, 1));
        let _ = result; // Just verify no panic
    }

    // ===========================================
    // ProtocolState initialization tests
    // ===========================================

    #[test]
    fn test_protocol_state_new() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        // Verify initial state
        assert!(!state.igmp_enabled);
        assert!(!state.pim_enabled);
        assert!(!state.msdp_enabled);
        assert!(state.igmp_socket.is_none());
        assert!(state.pim_socket.is_none());
        assert!(state.timer_tx.is_none());
        assert!(state.msdp_tcp_tx.is_none());
        assert!(state.igmp_state.is_empty());
        assert!(state.event_manager.is_none());
    }

    #[test]
    fn test_protocol_state_enable_event_subscriptions() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        assert!(state.event_manager.is_none());
        assert_eq!(state.event_buffer_size(), 256); // Default

        state.enable_event_subscriptions(512);

        assert!(state.event_manager.is_some());
        assert_eq!(state.event_buffer_size(), 512);
    }

    // ===========================================
    // MRIB action tests
    // ===========================================

    #[test]
    fn test_apply_mrib_action_add_igmp_membership() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let group = Ipv4Addr::new(239, 1, 1, 1);
        let membership = crate::mroute::IgmpMembership {
            group,
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: Some(Ipv4Addr::new(10, 0, 0, 100)),
        };

        let actions = vec![MribAction::AddIgmpMembership {
            interface: "eth0".to_string(),
            group,
            membership: membership.clone(),
        }];

        state.apply_mrib_actions(actions);

        // Verify membership was added
        let interfaces = state.mrib.get_igmp_interfaces_for_group(group);
        assert!(interfaces.contains(&"eth0".to_string()));
    }

    #[test]
    fn test_apply_mrib_action_remove_igmp_membership() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let group = Ipv4Addr::new(239, 1, 1, 1);
        let membership = crate::mroute::IgmpMembership {
            group,
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: Some(Ipv4Addr::new(10, 0, 0, 100)),
        };

        // First add
        state.mrib.add_igmp_membership("eth0", group, membership);
        assert!(!state.mrib.get_igmp_interfaces_for_group(group).is_empty());

        // Then remove via action
        let actions = vec![MribAction::RemoveIgmpMembership {
            interface: "eth0".to_string(),
            group,
        }];

        state.apply_mrib_actions(actions);

        // Verify removal
        let interfaces = state.mrib.get_igmp_interfaces_for_group(group);
        assert!(interfaces.is_empty());
    }

    #[test]
    fn test_apply_mrib_action_add_sg_route() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let source = Ipv4Addr::new(10, 0, 0, 1);
        let group = Ipv4Addr::new(239, 1, 1, 1);

        let mut downstream = std::collections::HashSet::new();
        downstream.insert("eth1".to_string());

        let route = crate::mroute::SGRoute {
            source,
            group,
            upstream_interface: Some("eth0".to_string()),
            downstream_interfaces: downstream,
            spt_bit: false,
            created_at: Instant::now(),
            expires_at: None,
        };

        let actions = vec![MribAction::AddSgRoute(route)];
        state.apply_mrib_actions(actions);

        // Verify route was added
        assert!(state.mrib.get_sg_route(source, group).is_some());
    }

    #[test]
    fn test_apply_mrib_action_remove_sg_route() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let source = Ipv4Addr::new(10, 0, 0, 1);
        let group = Ipv4Addr::new(239, 1, 1, 1);

        // Add first
        let mut downstream = std::collections::HashSet::new();
        downstream.insert("eth1".to_string());

        let route = crate::mroute::SGRoute {
            source,
            group,
            upstream_interface: Some("eth0".to_string()),
            downstream_interfaces: downstream,
            spt_bit: false,
            created_at: Instant::now(),
            expires_at: None,
        };
        state.mrib.add_sg_route(route);
        assert!(state.mrib.get_sg_route(source, group).is_some());

        // Remove via action
        let actions = vec![MribAction::RemoveSgRoute { source, group }];
        state.apply_mrib_actions(actions);

        assert!(state.mrib.get_sg_route(source, group).is_none());
    }

    // ===========================================
    // PIM state tests
    // ===========================================

    #[test]
    fn test_protocol_state_enable_pim_interface() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();

        let timers = state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // Should return Hello timer
        assert!(!timers.is_empty());
        assert!(matches!(timers[0].timer_type, TimerType::PimHello { .. }));

        // Verify interface is enabled
        assert!(state.pim_state.interfaces.contains_key("eth0"));
        let iface_state = state.pim_state.interfaces.get("eth0").unwrap();
        assert_eq!(iface_state.address, interface_ip);
    }

    #[test]
    fn test_protocol_state_disable_pim_interface() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable first
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);
        assert!(state.pim_state.interfaces.contains_key("eth0"));

        // Disable
        state.pim_state.disable_interface("eth0");
        assert!(!state.pim_state.interfaces.contains_key("eth0"));
    }

    #[test]
    fn test_get_pim_neighbors_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let neighbors = state.get_pim_neighbors();
        assert!(neighbors.is_empty());
    }

    #[test]
    fn test_get_pim_neighbors_with_data() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable interface
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // Add a neighbor manually
        let neighbor_addr = Ipv4Addr::new(10, 0, 0, 2);
        if let Some(iface_state) = state.pim_state.interfaces.get_mut("eth0") {
            iface_state.neighbors.insert(
                neighbor_addr,
                crate::protocols::pim::PimNeighbor {
                    address: neighbor_addr,
                    interface: "eth0".to_string(),
                    dr_priority: 100,
                    generation_id: Some(12345),
                    expires_at: Some(Instant::now() + std::time::Duration::from_secs(105)),
                    source: crate::NeighborSource::PimHello,
                },
            );
        }

        let neighbors = state.get_pim_neighbors();
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].address, neighbor_addr);
        assert_eq!(neighbors[0].interface, "eth0");
    }

    // ===========================================
    // IGMP state tests
    // ===========================================

    #[test]
    fn test_get_igmp_groups_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let groups = state.get_igmp_groups();
        assert!(groups.is_empty());
    }

    #[test]
    fn test_mrib_igmp_membership() {
        // Note: get_igmp_groups() reads from igmp_state, not mrib
        // This test verifies MRIB membership tracking separately
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let group = Ipv4Addr::new(239, 1, 1, 1);
        let membership = crate::mroute::IgmpMembership {
            group,
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: Some(Ipv4Addr::new(10, 0, 0, 100)),
        };

        state.mrib.add_igmp_membership("eth0", group, membership);

        // Verify via MRIB interface query (not get_igmp_groups which uses igmp_state)
        let interfaces = state.mrib.get_igmp_interfaces_for_group(group);
        assert_eq!(interfaces.len(), 1);
        assert!(interfaces.contains(&"eth0".to_string()));
    }

    // ===========================================
    // MSDP state tests
    // ===========================================

    #[test]
    fn test_get_msdp_peers_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let peers = state.get_msdp_peers();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_get_msdp_peers_with_data() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable MSDP first (required for add_peer to schedule timers)
        state.msdp_state.config.enabled = true;

        let peer_config = crate::protocols::msdp::MsdpPeerConfig {
            address: Ipv4Addr::new(10, 0, 0, 2),
            description: Some("Test peer".to_string()),
            mesh_group: None,
            default_peer: false,
            keepalive_interval: std::time::Duration::from_secs(60),
            hold_time: std::time::Duration::from_secs(90),
        };

        let timers = state.msdp_state.add_peer(peer_config);

        // With config.enabled = true, should get connection timer
        assert!(!timers.is_empty());

        let peers = state.get_msdp_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(peers[0].description, Some("Test peer".to_string()));
    }

    #[test]
    fn test_msdp_add_peer_without_enabled_returns_no_timers() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Don't enable MSDP - config.enabled defaults to false
        assert!(!state.msdp_state.config.enabled);

        let peer_config = crate::protocols::msdp::MsdpPeerConfig {
            address: Ipv4Addr::new(10, 0, 0, 2),
            description: None,
            mesh_group: None,
            default_peer: false,
            keepalive_interval: std::time::Duration::from_secs(60),
            hold_time: std::time::Duration::from_secs(90),
        };

        let timers = state.msdp_state.add_peer(peer_config);

        // Without config.enabled, should get NO timers (this was the bug!)
        assert!(
            timers.is_empty(),
            "add_peer should return no timers when config.enabled=false"
        );

        // Peer is still added to state
        let peers = state.get_msdp_peers();
        assert_eq!(peers.len(), 1);

        // But state should be "disabled"
        assert_eq!(peers[0].state.to_lowercase(), "disabled");
    }

    #[test]
    fn test_msdp_add_peer_with_enabled_returns_timers() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable MSDP
        state.msdp_state.config.enabled = true;

        let peer_config = crate::protocols::msdp::MsdpPeerConfig {
            address: Ipv4Addr::new(10, 0, 0, 2),
            description: None,
            mesh_group: None,
            default_peer: false,
            keepalive_interval: std::time::Duration::from_secs(60),
            hold_time: std::time::Duration::from_secs(90),
        };

        let timers = state.msdp_state.add_peer(peer_config);

        // With config.enabled, should get connection timer
        assert!(
            !timers.is_empty(),
            "add_peer should return timers when config.enabled=true"
        );
        assert!(matches!(
            timers[0].timer_type,
            TimerType::MsdpConnectRetry { .. }
        ));
    }

    // ===========================================
    // MSDP SA cache tests
    // ===========================================

    #[test]
    fn test_get_msdp_sa_cache_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let cache = state.get_msdp_sa_cache();
        assert!(cache.is_empty());
    }

    // ===========================================
    // Mroute entry tests
    // ===========================================

    #[test]
    fn test_get_mroute_entries_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let entries = state.get_mroute_entries();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_get_mroute_entries_with_sg_route() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let source = Ipv4Addr::new(10, 0, 0, 1);
        let group = Ipv4Addr::new(239, 1, 1, 1);

        // get_mroute_entries() reads from pim_state.sg, not mrib
        let mut sg_state = crate::protocols::pim::SGState::new(source, group);
        sg_state.upstream_interface = Some("eth0".to_string());
        sg_state.downstream_interfaces.insert("eth1".to_string());

        state.pim_state.sg.insert((source, group), sg_state);

        let entries = state.get_mroute_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, Some(source));
        assert_eq!(entries[0].group, group);
    }

    // ===========================================
    // Rule compilation tests
    // ===========================================

    #[test]
    fn test_compile_forwarding_rules_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let rules = state.compile_forwarding_rules();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_compile_forwarding_rules_with_sg_route() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let source = Ipv4Addr::new(10, 0, 0, 1);
        let group = Ipv4Addr::new(239, 1, 1, 1);

        let mut downstream = std::collections::HashSet::new();
        downstream.insert("eth1".to_string());

        let route = crate::mroute::SGRoute {
            source,
            group,
            upstream_interface: Some("eth0".to_string()),
            downstream_interfaces: downstream,
            spt_bit: false,
            created_at: Instant::now(),
            expires_at: None,
        };
        state.mrib.add_sg_route(route);

        let rules = state.compile_forwarding_rules();

        // Should have rules for downstream interface
        assert!(!rules.is_empty());
    }

    // ===========================================
    // PIM Join/Prune → MRIB action tests
    // ===========================================

    #[test]
    fn test_pim_join_creates_star_g_route_action() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable PIM on interface
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // Configure an RP for the group
        let group = Ipv4Addr::new(239, 1, 1, 1);
        let rp = Ipv4Addr::new(10, 0, 0, 100);
        state.pim_state.config.static_rp.insert(group, rp);

        // Process a (*,G) join
        let joins = vec![(None, group)]; // None source = (*,G)
        let prunes = vec![];
        let timers = state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &joins,
            &prunes,
            std::time::Duration::from_secs(210),
        );

        // Should have created (*,G) state
        assert!(state.pim_state.star_g.contains_key(&group));
        let star_g = state.pim_state.star_g.get(&group).unwrap();
        assert!(star_g.downstream_interfaces.contains("eth0"));
        assert!(!timers.is_empty()); // Should have expiry timer
    }

    #[test]
    fn test_pim_join_creates_sg_route_action() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable PIM on interface
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // Process an (S,G) join
        let source = Ipv4Addr::new(192, 168, 1, 100);
        let group = Ipv4Addr::new(239, 1, 1, 1);
        let joins = vec![(Some(source), group)];
        let prunes = vec![];
        let timers = state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &joins,
            &prunes,
            std::time::Duration::from_secs(210),
        );

        // Should have created (S,G) state
        assert!(state.pim_state.sg.contains_key(&(source, group)));
        let sg = state.pim_state.sg.get(&(source, group)).unwrap();
        assert!(sg.downstream_interfaces.contains("eth0"));
        assert!(!timers.is_empty()); // Should have expiry timer
    }

    #[test]
    fn test_pim_prune_removes_route_when_no_downstream() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable PIM on interface
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // First add an (S,G) via join
        let source = Ipv4Addr::new(192, 168, 1, 100);
        let group = Ipv4Addr::new(239, 1, 1, 1);
        let joins = vec![(Some(source), group)];
        state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &joins,
            &[],
            std::time::Duration::from_secs(210),
        );
        assert!(state.pim_state.sg.contains_key(&(source, group)));

        // Now prune it
        let prunes = vec![(Some(source), group)];
        state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &[],
            &prunes,
            std::time::Duration::from_secs(210),
        );

        // Route should be removed (no more downstreams)
        assert!(!state.pim_state.sg.contains_key(&(source, group)));
    }

    #[test]
    fn test_pim_prune_keeps_route_with_other_downstream() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable PIM on two interfaces
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", Ipv4Addr::new(10, 0, 0, 1), config.clone());
        state
            .pim_state
            .enable_interface("eth1", Ipv4Addr::new(10, 0, 1, 1), config);

        // Add (S,G) via join on eth0
        let source = Ipv4Addr::new(192, 168, 1, 100);
        let group = Ipv4Addr::new(239, 1, 1, 1);
        state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &[(Some(source), group)],
            &[],
            std::time::Duration::from_secs(210),
        );

        // Also add on eth1
        state.pim_state.process_join_prune(
            "eth1",
            Ipv4Addr::new(10, 0, 1, 2),
            &[(Some(source), group)],
            &[],
            std::time::Duration::from_secs(210),
        );

        // Route should have both downstreams
        let sg = state.pim_state.sg.get(&(source, group)).unwrap();
        assert_eq!(sg.downstream_interfaces.len(), 2);

        // Prune on eth0
        state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &[],
            &[(Some(source), group)],
            std::time::Duration::from_secs(210),
        );

        // Route should still exist with eth1 downstream
        assert!(state.pim_state.sg.contains_key(&(source, group)));
        let sg = state.pim_state.sg.get(&(source, group)).unwrap();
        assert_eq!(sg.downstream_interfaces.len(), 1);
        assert!(sg.downstream_interfaces.contains("eth1"));
    }
}
