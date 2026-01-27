// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Protocol state management for IGMP, PIM, and MSDP.
//!
//! This module contains `ProtocolState` which holds all protocol state machines
//! and raw sockets needed for multicast routing protocol support.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::logging::{Facility, Logger};
use crate::mroute::MulticastRib;
use crate::protocols::igmp::InterfaceIgmpState;
use crate::protocols::msdp::MsdpState;
use crate::protocols::pim::PimState;
use crate::protocols::{ProtocolEvent, TimerRequest, TimerType};
use crate::{log_debug, log_info, log_warning, ForwardingRule};

use super::actions::{MribAction, OutgoingPacket, ProtocolHandlerResult, ProtocolType};
use super::socket_helpers;
use super::{
    get_interface_ipv4, lookup_rpf_interface, parse_group_prefix, parse_pim_join_prune,
    EventSubscriptionManager,
};

#[allow(dead_code)]
const ALL_PIM_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

/// Get current Unix timestamp in seconds
pub(super) fn unix_timestamp() -> u64 {
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

    /// Raw socket for sending IGMP packets (protocol 2)
    pub igmp_send_socket: Option<OwnedFd>,

    /// AF_PACKET socket for receiving IGMP packets (captures at L2)
    pub igmp_recv_socket: Option<OwnedFd>,

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

    /// Shutdown signal for the protocol receiver loop (to restart with new sockets)
    pub receiver_loop_shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,

    /// Handle for the protocol receiver task (needed to abort on restart)
    pub receiver_loop_handle: Option<tokio::task::JoinHandle<()>>,

    /// Whether protocols are enabled
    pub igmp_enabled: bool,
    pub pim_enabled: bool,
    pub msdp_enabled: bool,

    /// Logger for protocol events
    pub(super) logger: Logger,

    /// Event subscription manager for push notifications
    pub event_manager: Option<EventSubscriptionManager>,

    /// Event buffer size for subscription manager
    event_buffer_size: usize,

    /// Pending timers from protocol init (processed after timer_tx is available)
    pub(super) pending_igmp_timers: Vec<TimerRequest>,
}

impl ProtocolState {
    /// Create a new ProtocolState with protocols disabled
    pub fn new(logger: Logger) -> Self {
        Self {
            igmp_state: HashMap::new(),
            pim_state: PimState::new(),
            msdp_state: MsdpState::new(),
            mrib: MulticastRib::new(),
            igmp_send_socket: None,
            igmp_recv_socket: None,
            pim_socket: None,
            timer_tx: None,
            msdp_tcp_tx: None,
            event_tx: None,
            receiver_loop_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            receiver_loop_shutdown_tx: None,
            receiver_loop_handle: None,
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
            // Check multicast capability
            if let Err(e) = socket_helpers::check_multicast_capability(iface) {
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("IGMP on {}: {}", iface, e)
                );
            }

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
            // Check multicast capability
            if let Err(e) = socket_helpers::check_multicast_capability(&iface_config.name) {
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!("PIM on {}: {}", iface_config.name, e)
                );
            }

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

                                // If PIM is enabled, create (*,G) route towards RP
                                if self.pim_enabled {
                                    // Check if we already have a (*,G) route for this group
                                    if !self.pim_state.star_g.contains_key(&group) {
                                        // Look up RP for this group
                                        if let Some(rp) =
                                            self.pim_state.config.get_rp_for_group(group)
                                        {
                                            // Do RPF lookup towards RP to get upstream interface
                                            let upstream_interface = lookup_rpf_interface(rp);

                                            if let Some(ref upstream) = upstream_interface {
                                                log_info!(
                                                    self.logger,
                                                    Facility::Supervisor,
                                                    &format!(
                                                        "IGMP triggered (*,{}) route creation: RP={}, upstream={}",
                                                        group, rp, upstream
                                                    )
                                                );
                                            }

                                            // Create (*,G) state in PIM
                                            let mut star_g_state =
                                                crate::protocols::pim::StarGState::new(group, rp);
                                            star_g_state.upstream_interface =
                                                upstream_interface.clone();
                                            // The IGMP interface is a downstream
                                            star_g_state
                                                .downstream_interfaces
                                                .insert(interface.clone());
                                            star_g_state.expires_at =
                                                Some(now + Duration::from_secs(210)); // Default PIM holdtime

                                            // Add route to MRIB
                                            let route = crate::mroute::StarGRoute {
                                                group,
                                                rp,
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

                                            // Store in PIM state
                                            self.pim_state.star_g.insert(group, star_g_state);

                                            result.notify(
                                                crate::ProtocolEventNotification::PimRouteChange {
                                                    route_type: crate::PimTreeType::StarG,
                                                    group,
                                                    source: None,
                                                    action: crate::RouteAction::Add,
                                                    timestamp: unix_timestamp(),
                                                },
                                            );

                                            // Send PIM Join towards RP on the upstream interface
                                            if let Some(ref upstream_iface) = upstream_interface {
                                                // Check if we have PIM enabled on the upstream interface
                                                if let Some(upstream_state) =
                                                    self.pim_state.get_interface(upstream_iface)
                                                {
                                                    use crate::protocols::pim::{
                                                        PimJoinPruneBuilder, ALL_PIM_ROUTERS,
                                                    };
                                                    use crate::protocols::PacketBuilder;

                                                    // The upstream neighbor is the RPF neighbor towards the RP
                                                    // For directly connected RPs, this is the RP itself
                                                    // For non-directly-connected RPs, use any neighbor as next-hop
                                                    // Note: DO NOT use designated_router - that could be ourselves!
                                                    let upstream_neighbor = if upstream_state
                                                        .neighbors
                                                        .contains_key(&rp)
                                                    {
                                                        rp // RP is directly connected
                                                    } else {
                                                        upstream_state
                                                            .neighbors
                                                            .keys()
                                                            .next()
                                                            .copied()
                                                            .unwrap_or(rp)
                                                    };

                                                    let builder = PimJoinPruneBuilder::star_g_join(
                                                        upstream_neighbor,
                                                        group,
                                                        rp,
                                                    );
                                                    let packet_data = builder.build();

                                                    result.send_packet(OutgoingPacket {
                                                        protocol: ProtocolType::Pim,
                                                        interface: upstream_iface.clone(),
                                                        destination: ALL_PIM_ROUTERS,
                                                        source: Some(upstream_state.address),
                                                        data: packet_data,
                                                    });

                                                    log_info!(
                                                        self.logger,
                                                        Facility::Supervisor,
                                                        &format!(
                                                            "PIM: Sending (*,{}) Join to {} on {}",
                                                            group,
                                                            upstream_neighbor,
                                                            upstream_iface
                                                        )
                                                    );

                                                    // Schedule Join/Prune refresh timer
                                                    result.add_timers(vec![TimerRequest {
                                                        timer_type: TimerType::PimJoinPrune {
                                                            interface: upstream_iface.clone(),
                                                            group,
                                                        },
                                                        fire_at: now
                                                            + crate::protocols::pim::DEFAULT_JOIN_PRUNE_PERIOD,
                                                        replace_existing: true,
                                                    }]);
                                                }
                                            }
                                        }
                                    } else {
                                        // Route exists - add this interface as downstream
                                        if let Some(star_g_state) =
                                            self.pim_state.star_g.get_mut(&group)
                                        {
                                            if !star_g_state
                                                .downstream_interfaces
                                                .contains(&interface)
                                            {
                                                star_g_state
                                                    .downstream_interfaces
                                                    .insert(interface.clone());
                                                // Update MRIB with new downstream
                                                let route = crate::mroute::StarGRoute {
                                                    group,
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
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        0x17 => {
                            // Leave Group
                            result.add_timers(igmp_state.received_leave(group, now));
                        }
                        _ => {}
                    }
                } else {
                    // IGMP not explicitly enabled on this interface - auto-enable in passive mode
                    // for Membership Reports (0x16) to track group membership and trigger PIM joins
                    if msg_type == 0x16 {
                        // Look up interface IP for IGMP state
                        if let Some(interface_ip) = get_interface_ipv4(&interface) {
                            log_info!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "Auto-enabling IGMP (passive mode) on interface '{}' due to received report for group {}",
                                    interface, group
                                )
                            );

                            // Create IGMP state in passive mode (no query timer scheduled)
                            let igmp_config = crate::protocols::igmp::IgmpConfig::default();
                            let mut passive_state = InterfaceIgmpState::new(
                                interface.clone(),
                                interface_ip,
                                igmp_config,
                            );
                            // Set as non-querier since we're in passive mode
                            passive_state.is_querier = false;

                            // Process the report
                            let timers = passive_state.received_report(src_ip, group, now);
                            result.add_timers(timers);

                            // Add IGMP membership to MRIB
                            let membership = crate::mroute::IgmpMembership {
                                group,
                                expires_at: now + passive_state.config.group_membership_interval(),
                                last_reporter: Some(src_ip),
                            };
                            result.add_action(MribAction::AddIgmpMembership {
                                interface: interface.clone(),
                                group,
                                membership,
                            });
                            result.notify(crate::ProtocolEventNotification::IgmpMembershipChange {
                                interface: interface.clone(),
                                group,
                                action: crate::MembershipAction::Join,
                                reporter: Some(src_ip),
                                timestamp: unix_timestamp(),
                            });

                            // If PIM is enabled, create (*,G) route towards RP
                            if self.pim_enabled && !self.pim_state.star_g.contains_key(&group) {
                                if let Some(rp) = self.pim_state.config.get_rp_for_group(group) {
                                    let upstream_interface = lookup_rpf_interface(rp);

                                    if let Some(ref upstream) = upstream_interface {
                                        log_info!(
                                                self.logger,
                                                Facility::Supervisor,
                                                &format!(
                                                    "IGMP (passive) triggered (*,{}) route creation: RP={}, upstream={}",
                                                    group, rp, upstream
                                                )
                                            );
                                    }

                                    // Create (*,G) state in PIM
                                    let mut star_g_state =
                                        crate::protocols::pim::StarGState::new(group, rp);
                                    star_g_state.upstream_interface = upstream_interface.clone();
                                    star_g_state.downstream_interfaces.insert(interface.clone());
                                    star_g_state.expires_at = Some(now + Duration::from_secs(210));

                                    // Add route to MRIB
                                    let route = crate::mroute::StarGRoute {
                                        group,
                                        rp,
                                        upstream_interface: star_g_state.upstream_interface.clone(),
                                        downstream_interfaces: star_g_state
                                            .downstream_interfaces
                                            .clone(),
                                        created_at: star_g_state.created_at,
                                        expires_at: star_g_state.expires_at,
                                    };
                                    result.add_action(MribAction::AddStarGRoute(route));

                                    // Store in PIM state
                                    self.pim_state.star_g.insert(group, star_g_state);

                                    result.notify(
                                        crate::ProtocolEventNotification::PimRouteChange {
                                            route_type: crate::PimTreeType::StarG,
                                            group,
                                            source: None,
                                            action: crate::RouteAction::Add,
                                            timestamp: unix_timestamp(),
                                        },
                                    );

                                    // Send PIM Join towards RP on the upstream interface
                                    if let Some(ref upstream_iface) = upstream_interface {
                                        if let Some(upstream_state) =
                                            self.pim_state.get_interface(upstream_iface)
                                        {
                                            use crate::protocols::pim::{
                                                PimJoinPruneBuilder, ALL_PIM_ROUTERS,
                                            };
                                            use crate::protocols::PacketBuilder;

                                            // The upstream neighbor should be:
                                            // 1. The RP if it's a neighbor on this interface (directly connected)
                                            // 2. Any neighbor on this interface (as RPF next-hop)
                                            // 3. Fallback to RP address (won't reach if not directly connected)
                                            // Note: DO NOT use designated_router - that could be ourselves!
                                            let upstream_neighbor =
                                                if upstream_state.neighbors.contains_key(&rp) {
                                                    rp // RP is directly connected
                                                } else {
                                                    // Use first neighbor as RPF next-hop, or fallback to RP
                                                    upstream_state
                                                        .neighbors
                                                        .keys()
                                                        .next()
                                                        .copied()
                                                        .unwrap_or(rp)
                                                };

                                            let builder = PimJoinPruneBuilder::star_g_join(
                                                upstream_neighbor,
                                                group,
                                                rp,
                                            );
                                            let packet_data = builder.build();

                                            result.send_packet(OutgoingPacket {
                                                protocol: ProtocolType::Pim,
                                                interface: upstream_iface.clone(),
                                                destination: ALL_PIM_ROUTERS,
                                                source: Some(upstream_state.address),
                                                data: packet_data,
                                            });

                                            log_info!(
                                                    self.logger,
                                                    Facility::Supervisor,
                                                    &format!(
                                                        "PIM: Sending (*,{}) Join to {} on {} (passive IGMP trigger)",
                                                        group, upstream_neighbor, upstream_iface
                                                    )
                                                );

                                            // Schedule Join/Prune refresh timer
                                            result.add_timers(vec![TimerRequest {
                                                    timer_type: TimerType::PimJoinPrune {
                                                        interface: upstream_iface.clone(),
                                                        group,
                                                    },
                                                    fire_at: now
                                                        + crate::protocols::pim::DEFAULT_JOIN_PRUNE_PERIOD,
                                                    replace_existing: true,
                                                }]);
                                        }
                                    }
                                }
                            }

                            // Store the passive IGMP state
                            self.igmp_state.insert(interface.clone(), passive_state);
                            self.igmp_enabled = true;
                        } else {
                            log_warning!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "Cannot auto-enable IGMP on interface '{}': no IPv4 address found",
                                    interface
                                )
                            );
                        }
                    } else {
                        // Ignore queries and leaves on interfaces without IGMP state
                        log_debug!(
                            self.logger,
                            Facility::Supervisor,
                            &format!(
                                "Ignoring IGMP {} from {} for group {} on interface '{}' (IGMP not enabled)",
                                match msg_type {
                                    0x11 => "Query",
                                    0x17 => "Leave",
                                    _ => "Unknown",
                                },
                                src_ip, group, interface
                            )
                        );
                    }
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
                            // Ignore our own Join/Prune messages (can happen due to multicast loopback)
                            let is_own_message = if let Some(iface_state) =
                                self.pim_state.get_interface(&reported_interface)
                            {
                                src_ip == iface_state.address
                            } else {
                                false
                            };

                            if is_own_message {
                                log_debug!(
                                    self.logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "PIM: Ignoring own Join/Prune on {}",
                                        reported_interface
                                    )
                                );
                            } else {
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

                                // Populate upstream_interface via RPF lookup for any routes that need it
                                for (source, group) in &joins {
                                    match source {
                                        None => {
                                            // (*,G) - RPF towards RP
                                            if let Some(star_g_state) =
                                                self.pim_state.star_g.get_mut(group)
                                            {
                                                if star_g_state.upstream_interface.is_none() {
                                                    star_g_state.upstream_interface =
                                                        lookup_rpf_interface(star_g_state.rp);
                                                    if let Some(ref iface) =
                                                        star_g_state.upstream_interface
                                                    {
                                                        log_debug!(
                                                        self.logger,
                                                        Facility::Supervisor,
                                                        &format!(
                                                            "RPF lookup for (*,{}) towards RP {}: upstream={}",
                                                            group, star_g_state.rp, iface
                                                        )
                                                    );
                                                    }
                                                }
                                            }
                                        }
                                        Some(src) => {
                                            // (S,G) - RPF towards source
                                            if let Some(sg_state) =
                                                self.pim_state.sg.get_mut(&(*src, *group))
                                            {
                                                if sg_state.upstream_interface.is_none() {
                                                    sg_state.upstream_interface =
                                                        lookup_rpf_interface(*src);
                                                    if let Some(ref iface) =
                                                        sg_state.upstream_interface
                                                    {
                                                        log_debug!(
                                                        self.logger,
                                                        Facility::Supervisor,
                                                        &format!(
                                                            "RPF lookup for ({},{}) towards source: upstream={}",
                                                            src, group, iface
                                                        )
                                                    );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // Generate MRIB actions for joins
                                for (source, group) in &joins {
                                    match source {
                                        None => {
                                            // (*,G) join - look up the resulting state
                                            if let Some(star_g_state) =
                                                self.pim_state.star_g.get(group)
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
                                                result.add_action(MribAction::RemoveStarGRoute {
                                                    group,
                                                });
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
                            } // end else (not own message)
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
            PimEvent::DirectSourceDetected {
                interface,
                source,
                group,
            } => {
                // Direct-connect source detection: when we receive multicast traffic
                // on an interface where we are both the DR and the RP for the group,
                // we can shortcut the PIM Register process and directly create (S,G) state.

                // Check if we're the RP for this group
                let is_rp_for_group =
                    self.pim_state.config.rp_address.is_some_and(|rp| {
                        self.pim_state.config.get_rp_for_group(group) == Some(rp)
                    });

                // Check if we're the DR on this interface
                let is_dr = self
                    .pim_state
                    .get_interface(&interface)
                    .is_some_and(|iface_state| iface_state.is_dr());

                // Check if we already have (S,G) state for this source
                let already_has_sg = self.pim_state.sg.contains_key(&(source, group));

                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "PIM: DirectSourceDetected check: ({}, {}) on {} - is_rp={}, is_dr={}, has_sg={}",
                        source, group, interface, is_rp_for_group, is_dr, already_has_sg
                    )
                );

                if is_rp_for_group && is_dr && !already_has_sg {
                    log_info!(
                        self.logger,
                        Facility::Supervisor,
                        &format!(
                            "PIM: Direct-connect source active ({}, {}) on {} - creating (S,G) state",
                            source, group, interface
                        )
                    );

                    let now = Instant::now();

                    // Inherit downstream interfaces from (*,G) route if it exists
                    // This ensures traffic from this source is forwarded to existing receivers
                    let inherited_downstream = self
                        .pim_state
                        .star_g
                        .get(&group)
                        .map(|star_g| {
                            // Filter out the upstream interface (where traffic comes from)
                            star_g
                                .downstream_interfaces
                                .iter()
                                .filter(|&iface| iface != &interface)
                                .cloned()
                                .collect::<std::collections::HashSet<String>>()
                        })
                        .unwrap_or_default();

                    log_info!(
                        self.logger,
                        Facility::Supervisor,
                        &format!(
                            "PIM: (S,G) inheriting {} downstream interfaces from (*,G): {:?}",
                            inherited_downstream.len(),
                            inherited_downstream
                        )
                    );

                    // Create (S,G) state
                    let sg_state = crate::protocols::pim::SGState {
                        source,
                        group,
                        upstream_interface: Some(interface.clone()), // Source is directly connected
                        downstream_interfaces: inherited_downstream.clone(),
                        spt_bit: true, // We're on the SPT since source is direct
                        created_at: now,
                        expires_at: Some(now + Duration::from_secs(210)), // PIM holdtime
                    };

                    // Store in PIM state
                    self.pim_state.sg.insert((source, group), sg_state.clone());

                    // Add route to MRIB
                    let route = crate::mroute::SGRoute {
                        source,
                        group,
                        upstream_interface: Some(interface.clone()),
                        downstream_interfaces: inherited_downstream,
                        spt_bit: true,
                        created_at: now,
                        expires_at: Some(now + Duration::from_secs(210)),
                    };
                    result.add_action(MribAction::AddSgRoute(route));

                    // Notify of route change
                    result.notify(crate::ProtocolEventNotification::PimRouteChange {
                        route_type: crate::PimTreeType::SG,
                        group,
                        source: Some(source),
                        action: crate::RouteAction::Add,
                        timestamp: unix_timestamp(),
                    });

                    // Schedule expiry timer
                    result.add_timer(TimerRequest {
                        timer_type: TimerType::PimSGExpiry { source, group },
                        fire_at: now + Duration::from_secs(210),
                        replace_existing: true,
                    });

                    // Notify MSDP of local source active
                    if self.msdp_enabled {
                        if let Some(rp_address) = self.pim_state.config.rp_address {
                            log_info!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "PIM: Notifying MSDP of direct source ({}, {})",
                                    source, group
                                )
                            );

                            let msdp_result = self
                                .msdp_state
                                .local_source_active(source, group, rp_address, now);

                            log_info!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "MSDP: local_source_active returned {} floods, {} timers",
                                    msdp_result.floods.len(),
                                    msdp_result.timers.len()
                                )
                            );

                            // Process flood requests (originate SA to peers)
                            self.process_msdp_floods(msdp_result.floods);

                            result.add_timers(msdp_result.timers);
                        }
                    }
                }
            }
        }
        result
    }

    /// Process MSDP flood requests by sending them via the TCP command channel
    fn process_msdp_floods(&self, floods: Vec<crate::protocols::msdp::SaFloodRequest>) {
        use crate::protocols::msdp_tcp::MsdpTcpCommand;

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "MSDP: Processing {} flood request(s), tcp_tx available: {}",
                floods.len(),
                self.msdp_tcp_tx.is_some()
            )
        );

        if let Some(ref tcp_tx) = self.msdp_tcp_tx {
            for flood in floods {
                log_info!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "MSDP: Sending FloodSa for {} entries from RP {}, exclude: {:?}",
                        flood.entries.len(),
                        flood.rp_address,
                        flood.exclude_peer
                    )
                );
                let cmd = MsdpTcpCommand::FloodSa {
                    rp_address: flood.rp_address,
                    entries: flood.entries,
                    exclude_peer: flood.exclude_peer,
                };
                // Fire and forget - don't block on channel send
                match tcp_tx.try_send(cmd) {
                    Ok(_) => {
                        log_info!(
                            self.logger,
                            Facility::Supervisor,
                            "MSDP: FloodSa command sent to TCP runner"
                        );
                    }
                    Err(e) => {
                        log_warning!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("MSDP: Failed to send FloodSa command: {}", e)
                        );
                    }
                }
            }
        } else {
            log_warning!(
                self.logger,
                Facility::Supervisor,
                "MSDP: Cannot process floods - msdp_tcp_tx is None"
            );
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
            TimerType::PimJoinPrune { interface, group } => {
                // Send periodic Join/Prune refresh for (*,G) routes
                if let Some(star_g_state) = self.pim_state.star_g.get(&group) {
                    // Only refresh if the route is still valid and has downstream interest
                    if star_g_state.has_downstream() {
                        if let Some(upstream_state) = self.pim_state.get_interface(&interface) {
                            use crate::protocols::pim::{PimJoinPruneBuilder, ALL_PIM_ROUTERS};
                            use crate::protocols::PacketBuilder;

                            let rp = star_g_state.rp;
                            // Use RPF neighbor, not DR (DR could be ourselves)
                            let upstream_neighbor = if upstream_state.neighbors.contains_key(&rp) {
                                rp // RP is directly connected
                            } else {
                                upstream_state
                                    .neighbors
                                    .keys()
                                    .next()
                                    .copied()
                                    .unwrap_or(rp)
                            };

                            let builder =
                                PimJoinPruneBuilder::star_g_join(upstream_neighbor, group, rp);
                            let packet_data = builder.build();

                            result.send_packet(OutgoingPacket {
                                protocol: ProtocolType::Pim,
                                interface: interface.clone(),
                                destination: ALL_PIM_ROUTERS,
                                source: Some(upstream_state.address),
                                data: packet_data,
                            });

                            log_debug!(
                                self.logger,
                                Facility::Supervisor,
                                &format!(
                                    "PIM: Refreshing (*,{}) Join to {} on {}",
                                    group, upstream_neighbor, interface
                                )
                            );

                            // Reschedule the refresh timer
                            result.add_timers(vec![TimerRequest {
                                timer_type: TimerType::PimJoinPrune {
                                    interface: interface.clone(),
                                    group,
                                },
                                fire_at: now + crate::protocols::pim::DEFAULT_JOIN_PRUNE_PERIOD,
                                replace_existing: true,
                            }]);
                        }
                    }
                }
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
    ///
    /// This includes expansion for RP scenarios: when this router is the RP
    /// for a (*,G) route, forwarding rules are generated for each
    /// PIM-enabled interface as a potential input interface.
    pub fn compile_forwarding_rules(&self) -> Vec<ForwardingRule> {
        // Collect all PIM-enabled interfaces for RP rule expansion
        let pim_interfaces: std::collections::HashSet<String> =
            self.pim_state.interfaces.keys().cloned().collect();

        // Get this router's RP address (if configured)
        let local_rp_address = self.pim_state.config.rp_address;

        // Debug: log MRIB state
        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "compile_forwarding_rules: mrib has {} star_g, {} sg, {} static, pim_interfaces={:?}, local_rp={:?}",
                self.mrib.star_g_routes.len(),
                self.mrib.sg_routes.len(),
                self.mrib.static_rules.len(),
                pim_interfaces,
                local_rp_address
            )
        );

        self.mrib
            .compile_forwarding_rules_with_pim_interfaces(&pim_interfaces, local_rp_address)
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

    /// Create sockets for IGMP
    ///
    /// Creates two sockets:
    /// - Raw IP socket for sending IGMP queries (with IP_HDRINCL)
    /// - AF_PACKET socket for receiving IGMP packets (captures at L2, sees all IGMP)
    ///
    /// The AF_PACKET approach is required because:
    /// - Raw IP sockets only receive packets destined to addresses the kernel has joined
    /// - MRT_INIT requires MRT_ADD_VIF for each interface, limited to 32 VIFs
    /// - AF_PACKET captures at L2 and sees ALL packets, including IGMP from other hosts
    pub fn create_igmp_socket(&mut self) -> Result<()> {
        // === Create raw IP socket for SENDING IGMP ===
        const IPPROTO_IGMP: i32 = 2;

        let send_fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                IPPROTO_IGMP,
            )
        };

        if send_fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create IGMP send socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set IP_HDRINCL so we can craft our own IP headers for IGMP messages
        let hdrincl: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                send_fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &hdrincl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            unsafe { libc::close(send_fd) };
            return Err(anyhow::anyhow!(
                "Failed to set IP_HDRINCL on IGMP send socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        let send_sock = unsafe { OwnedFd::from_raw_fd(send_fd) };
        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("Created IGMP send socket (fd: {})", send_sock.as_raw_fd())
        );

        // === Create AF_PACKET socket for RECEIVING IGMP ===
        // ETH_P_IP = 0x0800, but we need to filter for IGMP at IP layer
        // Use ETH_P_ALL to receive all packets, then filter for IGMP in userspace
        let recv_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                (libc::ETH_P_IP as u16).to_be() as i32,
            )
        };

        if recv_fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create IGMP AF_PACKET recv socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Don't bind to a specific interface - receive from all interfaces
        // The sockaddr_ll in recvfrom will tell us which interface the packet came from

        // Set PACKET_AUXDATA to get packet metadata including interface index
        let auxdata: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                recv_fd,
                libc::SOL_PACKET,
                libc::PACKET_AUXDATA,
                &auxdata as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if result < 0 {
            log_warning!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Failed to set PACKET_AUXDATA on IGMP recv socket (non-fatal): {}",
                    std::io::Error::last_os_error()
                )
            );
        }

        let recv_sock = unsafe { OwnedFd::from_raw_fd(recv_fd) };
        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Created IGMP AF_PACKET recv socket (fd: {})",
                recv_sock.as_raw_fd()
            )
        );

        self.igmp_send_socket = Some(send_sock);
        self.igmp_recv_socket = Some(recv_sock);
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
        // Use the send socket to join the multicast group
        // (AF_PACKET recv socket doesn't need group membership - it sees all L2 traffic)
        let fd = self
            .igmp_send_socket
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IGMP send socket not created"))?
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
    ///
    /// The IGMP sockets (send and recv) are created when IGMP OR PIM is enabled because:
    /// - The AF_PACKET recv socket is needed for source detection (used by both IGMP and PIM/MSDP)
    /// - The IGMP send socket is only used when IGMP is enabled, but creating it is harmless
    pub fn create_protocol_sockets(&mut self) -> Result<()> {
        // Create IGMP/source-detection sockets when IGMP OR PIM is enabled
        // The AF_PACKET recv socket is essential for direct source detection,
        // which is needed for MSDP SA origination even in PIM-only deployments
        if (self.igmp_enabled || self.pim_enabled) && self.igmp_recv_socket.is_none() {
            self.create_igmp_socket()?;

            // IGMP-specific interface setup: only when IGMP is enabled
            if self.igmp_enabled {
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
    /// Get the IGMP receive socket fd for async monitoring (AF_PACKET)
    pub fn igmp_socket_fd(&self) -> Option<RawFd> {
        self.igmp_recv_socket.as_ref().map(|s| s.as_raw_fd())
    }

    /// Get the IGMP send socket fd for sending packets (raw IP)
    pub fn igmp_send_socket_fd(&self) -> Option<RawFd> {
        self.igmp_send_socket.as_ref().map(|s| s.as_raw_fd())
    }

    /// Get the PIM socket fd for async monitoring
    pub fn pim_socket_fd(&self) -> Option<RawFd> {
        self.pim_socket.as_ref().map(|s| s.as_raw_fd())
    }

    /// Spawn the protocol receiver loop if it's not already running and we have sockets.
    ///
    /// This is used when creating protocol sockets via CLI after startup.
    /// Returns true if a new receiver loop was spawned.
    pub fn spawn_receiver_loop_if_needed(&mut self) -> bool {
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

        // Create shutdown channel for this loop instance
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.receiver_loop_shutdown_tx = Some(shutdown_tx);

        // Mark as running before spawning
        self.receiver_loop_running.store(true, Ordering::SeqCst);

        // Clone the running flag for the loop to reset on exit
        let running_flag = self.receiver_loop_running.clone();

        // Spawn the receiver loop and store the handle
        let receiver_logger = self.logger.clone();
        let handle = tokio::spawn(async move {
            protocol_receiver_loop(igmp_fd, pim_fd, event_tx, shutdown_rx, receiver_logger).await;
            // Reset running flag when loop exits
            running_flag.store(false, Ordering::SeqCst);
        });
        self.receiver_loop_handle = Some(handle);

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

    /// Restart the protocol receiver loop with current sockets.
    ///
    /// This is needed when a new protocol socket is added after the loop is already running
    /// (e.g., enabling IGMP after PIM is already running).
    pub fn restart_receiver_loop(&mut self) {
        use std::sync::atomic::Ordering;

        // Abort old task if running - this ensures AsyncFd resources are released
        if let Some(handle) = self.receiver_loop_handle.take() {
            log_info!(
                self.logger,
                Facility::Supervisor,
                "Aborting old protocol receiver loop for restart"
            );
            handle.abort();
            // Delay to allow tokio to process the cancellation and release AsyncFd resources
            // This is necessary because AsyncFd::new() will fail if there's already an AsyncFd
            // registered for the same fd. The delay needs to be long enough for tokio's
            // task scheduler to run the abort and drop the AsyncFd.
            // Using 50ms instead of 10ms to be more robust.
            std::thread::sleep(std::time::Duration::from_millis(50));
            log_info!(
                self.logger,
                Facility::Supervisor,
                "Old receiver loop aborted, spawning new loop"
            );
        }

        // Reset the running flag
        self.receiver_loop_running.store(false, Ordering::SeqCst);

        // Spawn new loop with current sockets
        let spawned = self.spawn_receiver_loop_if_needed();
        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("Receiver loop restart: spawned={}", spawned)
        );
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
                .igmp_send_socket
                .as_ref()
                .map(|s| s.as_raw_fd())
                .ok_or_else(|| anyhow::anyhow!("IGMP send socket not available"))?,
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

// No explicit Drop needed - OwnedFd handles socket cleanup automatically

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

    /// Read a packet from AF_PACKET socket, getting interface index from sockaddr_ll
    ///
    /// AF_PACKET with SOCK_DGRAM returns IP packets (no ethernet header).
    /// The interface index comes from sockaddr_ll.sll_ifindex.
    fn try_read_af_packet(&self, buf: &mut [u8]) -> std::io::Result<RecvResult> {
        let mut sockaddr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut sockaddr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut sockaddr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut sockaddr_len,
            )
        };

        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(RecvResult {
            len: n as usize,
            iface_index: sockaddr.sll_ifindex,
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
/// It also performs direct-connect source detection for multicast traffic.
pub async fn protocol_receiver_loop(
    igmp_fd: Option<RawFd>,
    pim_fd: Option<RawFd>,
    event_tx: mpsc::Sender<ProtocolEvent>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    logger: Logger,
) {
    use std::collections::HashMap;
    use tokio::io::unix::AsyncFd;

    let mut buf = vec![0u8; 65536]; // Maximum IP packet size

    // Source detection cache: (source, group) -> last_seen timestamp
    // This prevents sending duplicate DirectSourceDetected events
    // Sources are re-detected after SOURCE_CACHE_TIMEOUT_SECS
    const SOURCE_CACHE_TIMEOUT_SECS: u64 = 60;
    const SOURCE_CACHE_CLEANUP_INTERVAL: u64 = 30;
    let mut source_cache: HashMap<(Ipv4Addr, Ipv4Addr), Instant> = HashMap::new();
    let mut last_cache_cleanup = Instant::now();

    // Create async fds for non-blocking socket I/O
    // Log errors instead of silently discarding them - AsyncFd creation can fail
    // if the fd is already registered (race condition during restart)
    let igmp_async = igmp_fd.and_then(|fd| {
        let sock = AsyncRawSocket::new(fd);
        match AsyncFd::new(sock) {
            Ok(async_fd) => Some(async_fd),
            Err(e) => {
                log_warning!(
                    logger,
                    Facility::Supervisor,
                    &format!("Failed to create AsyncFd for IGMP socket (fd={}): {} - IGMP packets will not be received", fd, e)
                );
                None
            }
        }
    });

    let pim_async = pim_fd.and_then(|fd| {
        let sock = AsyncRawSocket::new(fd);
        match AsyncFd::new(sock) {
            Ok(async_fd) => Some(async_fd),
            Err(e) => {
                log_warning!(
                    logger,
                    Facility::Supervisor,
                    &format!("Failed to create AsyncFd for PIM socket (fd={}): {} - PIM packets will not be received", fd, e)
                );
                None
            }
        }
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
        // Wait for either socket to be readable or shutdown signal
        tokio::select! {
            // Shutdown signal
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        "Protocol receiver loop received shutdown signal, exiting for restart"
                    );
                    return;
                }
            }

            // IGMP socket readable (AF_PACKET)
            result = async {
                if let Some(ref async_fd) = igmp_async {
                    async_fd.readable().await
                } else {
                    // Never completes if no IGMP socket
                    std::future::pending().await
                }
            } => {
                if let Ok(mut guard) = result {
                    // Use AF_PACKET read for IGMP - gets interface from sockaddr_ll
                    // Note: AF_PACKET with ETH_P_IP receives ALL IP packets, not just IGMP
                    // Periodic source cache cleanup
                    let now = Instant::now();
                    if now.duration_since(last_cache_cleanup).as_secs() >= SOURCE_CACHE_CLEANUP_INTERVAL {
                        source_cache.retain(|_, last_seen| {
                            now.duration_since(*last_seen).as_secs() < SOURCE_CACHE_TIMEOUT_SECS
                        });
                        last_cache_cleanup = now;
                    }

                    match guard.get_inner().try_read_af_packet(&mut buf) {
                        Ok(recv) if recv.len > 0 => {
                            // Minimum IP header is 20 bytes
                            if recv.len >= 20 {
                                let protocol = buf[9];
                                let interface = interface_name_from_index(recv.iface_index);

                                // Log all multicast-destined packets for source detection debugging
                                let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
                                if dst_ip.octets()[0] >= 224 && dst_ip.octets()[0] <= 239 && protocol != 2 {
                                    // Log non-IGMP multicast (IGMP is logged separately)
                                    let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                                    log_info!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!(
                                            "Multicast data packet: proto={}, src={}, dst={}, iface={:?}",
                                            protocol, src_ip, dst_ip, interface
                                        )
                                    );
                                }

                                // IGMP packet (protocol 2)
                                if protocol == 2 {
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
                                // UDP packet (protocol 17) - check for multicast destination
                                else if protocol == 17 {
                                    // Extract source and destination IPs
                                    let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                                    let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

                                    // Check if destination is multicast (224.0.0.0/4)
                                    // but not link-local (224.0.0.0/24)
                                    if dst_ip.octets()[0] >= 224
                                        && dst_ip.octets()[0] <= 239
                                        && !(dst_ip.octets()[0] == 224
                                            && dst_ip.octets()[1] == 0
                                            && dst_ip.octets()[2] == 0)
                                    {
                                        let source_key = (src_ip, dst_ip);

                                        // Check if this is a new source or cached entry expired
                                        let is_new_source = match source_cache.get(&source_key) {
                                            Some(last_seen) => {
                                                now.duration_since(*last_seen).as_secs()
                                                    >= SOURCE_CACHE_TIMEOUT_SECS
                                            }
                                            None => true,
                                        };

                                        log_info!(
                                            logger,
                                            Facility::Supervisor,
                                            &format!(
                                                "Source check: ({}, {}) is_new={}, cache_size={}",
                                                src_ip, dst_ip, is_new_source, source_cache.len()
                                            )
                                        );

                                        if is_new_source {
                                            // Update cache
                                            source_cache.insert(source_key, now);

                                            if let Some(ref iface_name) = interface {
                                                log_info!(
                                                    logger,
                                                    Facility::Supervisor,
                                                    &format!(
                                                        "Direct source detected: ({}, {}) on {}",
                                                        src_ip, dst_ip, iface_name
                                                    )
                                                );

                                                // Send DirectSourceDetected event
                                                use crate::protocols::pim::PimEvent;
                                                let event = ProtocolEvent::Pim(
                                                    PimEvent::DirectSourceDetected {
                                                        interface: iface_name.clone(),
                                                        source: src_ip,
                                                        group: dst_ip,
                                                    },
                                                );

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
                                    }
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
