// SPDX-License-Identifier: Apache-2.0 OR MIT
// Allow await_holding_lock for std::sync::Mutex - these are intentional short-lived locks
#![allow(clippy::await_holding_lock)]

use anyhow::{Context, Result};
use futures::SinkExt;
use log::error;
use nix::sys::socket::{
    sendmsg, socketpair, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
};
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::logging::{AsyncConsumer, Facility, Logger, MPSCRingBuffer};
use crate::mroute::MulticastRib;
use crate::protocols::igmp::InterfaceIgmpState;
use crate::protocols::pim::PimState;
use crate::protocols::{ProtocolEvent, TimerRequest, TimerType};
use crate::{log_debug, log_info, log_warning, ForwardingRule, RelayCommand};
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 16000; // 16 seconds
const SHUTDOWN_TIMEOUT_SECS: u64 = 10; // Timeout for graceful worker shutdown
const PERIODIC_SYNC_INTERVAL_SECS: u64 = 300; // 5 minutes - periodic full ruleset sync to all workers

/// Maximum interface name length (IFNAMSIZ - 1 for null terminator)
const MAX_INTERFACE_NAME_LEN: usize = 15;

// Protocol constants
#[allow(dead_code)]
const ALL_PIM_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

/// Protocol state management for IGMP and PIM
///
/// This struct holds all protocol state machines and raw sockets needed
/// for multicast routing protocol support. It runs in the supervisor
/// process to maintain centralized state.
pub struct ProtocolState {
    /// IGMP state per interface (querier election, group membership)
    pub igmp_state: HashMap<String, InterfaceIgmpState>,

    /// Global PIM-SM state (neighbors, (*,G) and (S,G) entries)
    pub pim_state: PimState,

    /// Multicast Routing Information Base - merges static + dynamic routes
    pub mrib: MulticastRib,

    /// Raw socket for IGMP packets (protocol 2)
    pub igmp_socket: Option<OwnedFd>,

    /// Raw socket for PIM packets (protocol 103)
    pub pim_socket: Option<OwnedFd>,

    /// Channel to send timer requests
    pub timer_tx: Option<mpsc::Sender<TimerRequest>>,

    /// Whether protocols are enabled
    pub igmp_enabled: bool,
    pub pim_enabled: bool,

    /// Logger for protocol events
    logger: Logger,
}

impl ProtocolState {
    /// Create a new ProtocolState with protocols disabled
    pub fn new(logger: Logger) -> Self {
        Self {
            igmp_state: HashMap::new(),
            pim_state: PimState::new(),
            mrib: MulticastRib::new(),
            igmp_socket: None,
            pim_socket: None,
            timer_tx: None,
            igmp_enabled: false,
            pim_enabled: false,
            logger,
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
                    ..PimInterfaceConfig::default()
                };
                self.pim_state
                    .enable_interface(&iface_config.name, ip, pim_iface_config);
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
        match event {
            ProtocolEvent::Igmp(igmp_event) => self.handle_igmp_event(igmp_event),
            ProtocolEvent::Pim(pim_event) => self.handle_pim_event(pim_event),
            ProtocolEvent::TimerExpired(timer_type) => self.handle_timer_expired(timer_type),
        }
    }

    fn handle_igmp_event(&mut self, event: crate::protocols::igmp::IgmpEvent) -> Vec<TimerRequest> {
        use crate::protocols::igmp::IgmpEvent;
        let now = Instant::now();

        match event {
            IgmpEvent::EnableQuerier {
                interface,
                interface_ip,
            } => {
                let igmp_config = crate::protocols::igmp::IgmpConfig::default();
                let state = InterfaceIgmpState::new(interface.clone(), interface_ip, igmp_config);
                self.igmp_state.insert(interface, state);
                Vec::new()
            }
            IgmpEvent::DisableQuerier { interface } => {
                self.igmp_state.remove(&interface);
                Vec::new()
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
                            igmp_state.received_query(src_ip, now)
                        }
                        0x16 => {
                            // V2 Membership Report
                            let timers = igmp_state.received_report(src_ip, group, now);
                            // Add to MRIB if this is a new group
                            if !self
                                .mrib
                                .get_igmp_interfaces_for_group(group)
                                .contains(&interface)
                            {
                                let membership = crate::mroute::IgmpMembership {
                                    group,
                                    expires_at: now + igmp_state.config.group_membership_interval(),
                                    last_reporter: Some(src_ip),
                                };
                                self.mrib.add_igmp_membership(&interface, group, membership);
                            }
                            timers
                        }
                        0x17 => {
                            // Leave Group
                            igmp_state.received_leave(group, now)
                        }
                        _ => Vec::new(),
                    }
                } else {
                    Vec::new()
                }
            }
            IgmpEvent::QueryTimerExpired { interface } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    igmp_state.query_timer_expired(now)
                } else {
                    Vec::new()
                }
            }
            IgmpEvent::OtherQuerierExpired { interface } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    igmp_state.other_querier_expired(now)
                } else {
                    Vec::new()
                }
            }
            IgmpEvent::GroupExpired { interface, group } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    igmp_state.group_expired(group, now);
                    // Remove from MRIB
                    self.mrib.remove_igmp_membership(&interface, group);
                }
                Vec::new()
            }
            IgmpEvent::GroupQueryExpired { interface, group } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    let (timers, expired) = igmp_state.group_query_expired(group, now);
                    if expired {
                        self.mrib.remove_igmp_membership(&interface, group);
                    }
                    timers
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn handle_pim_event(&mut self, event: crate::protocols::pim::PimEvent) -> Vec<TimerRequest> {
        use crate::protocols::pim::PimEvent;

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
                self.pim_state
                    .enable_interface(&interface, interface_ip, config);
                Vec::new()
            }
            PimEvent::DisableInterface { interface } => {
                self.pim_state.disable_interface(&interface);
                Vec::new()
            }
            PimEvent::PacketReceived {
                interface,
                src_ip,
                msg_type,
                payload,
            } => {
                match msg_type {
                    0 => {
                        // Hello - parse options and process
                        if let Some(iface_state) = self.pim_state.get_interface_mut(&interface) {
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

                            let timers = iface_state.received_hello(
                                src_ip,
                                holdtime,
                                dr_priority,
                                generation_id,
                                Instant::now(),
                            );

                            // Check if DR election changed
                            if iface_state.elect_dr() {
                                log_debug!(
                                    self.logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "DR election on {} - we are {}DR",
                                        interface,
                                        if iface_state.is_dr() { "" } else { "not " }
                                    )
                                );
                            }
                            timers
                        } else {
                            Vec::new()
                        }
                    }
                    1 => {
                        // Register - only if we're RP
                        if self.pim_state.config.rp_address.is_some() {
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
                                    let _ = self.pim_state.process_register(
                                        source,
                                        group,
                                        null_register,
                                    );
                                }
                            }
                        }
                        Vec::new()
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
                            let _ = self.pim_state.process_join_prune(
                                &interface,
                                upstream,
                                &joins,
                                &prunes,
                                Duration::from_secs(holdtime as u64),
                            );
                        }
                        Vec::new()
                    }
                    _ => Vec::new(),
                }
            }
            PimEvent::HelloTimerExpired { interface } => {
                if let Some(iface_state) = self.pim_state.get_interface_mut(&interface) {
                    iface_state.hello_timer_expired(Instant::now())
                } else {
                    Vec::new()
                }
            }
            PimEvent::NeighborExpired {
                interface,
                neighbor,
            } => {
                if let Some(iface_state) = self.pim_state.get_interface_mut(&interface) {
                    iface_state.neighbor_expired(neighbor);
                    // Re-run DR election
                    let _ = iface_state.elect_dr();
                }
                Vec::new()
            }
            PimEvent::RouteExpired { source, group } => {
                // Remove the expired route from state
                if let Some(src) = source {
                    // (S,G) expired
                    self.pim_state.sg.remove(&(src, group));
                    self.mrib.remove_sg_route(src, group);
                } else {
                    // (*,G) expired
                    self.pim_state.star_g.remove(&group);
                    self.mrib.remove_star_g_route(group);
                }
                Vec::new()
            }
            PimEvent::SetStaticRp { group, rp } => {
                self.pim_state.config.static_rp.insert(group, rp);
                Vec::new()
            }
            PimEvent::SetRpAddress { rp } => {
                self.pim_state.config.rp_address = Some(rp);
                Vec::new()
            }
        }
    }

    fn handle_timer_expired(&mut self, timer_type: TimerType) -> Vec<TimerRequest> {
        let now = Instant::now();

        match timer_type {
            TimerType::IgmpGeneralQuery { interface } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    igmp_state.query_timer_expired(now)
                } else {
                    Vec::new()
                }
            }
            TimerType::IgmpGroupQuery { interface, group } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    let (timers, _expired) = igmp_state.group_query_expired(group, now);
                    timers
                } else {
                    Vec::new()
                }
            }
            TimerType::IgmpGroupExpiry { interface, group } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    if igmp_state.group_expired(group, now) {
                        self.mrib.remove_igmp_membership(&interface, group);
                    }
                }
                Vec::new()
            }
            TimerType::IgmpOtherQuerierPresent { interface } => {
                if let Some(igmp_state) = self.igmp_state.get_mut(&interface) {
                    igmp_state.other_querier_expired(now)
                } else {
                    Vec::new()
                }
            }
            TimerType::PimHello { interface } => {
                if let Some(iface_state) = self.pim_state.get_interface_mut(&interface) {
                    iface_state.hello_timer_expired(now)
                } else {
                    Vec::new()
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
                Vec::new()
            }
            TimerType::PimJoinPrune {
                interface: _,
                group: _,
            } => {
                // TODO: Send periodic Join/Prune refresh
                Vec::new()
            }
            TimerType::PimStarGExpiry { group } => {
                self.mrib.remove_star_g_route(group);
                Vec::new()
            }
            TimerType::PimSGExpiry { source, group } => {
                self.mrib.remove_sg_route(source, group);
                Vec::new()
            }
        }
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
                let expires_in_secs = neighbor.expires_at.saturating_duration_since(now).as_secs();
                neighbors.push(crate::PimNeighborInfo {
                    interface: interface.clone(),
                    address: *neighbor_ip,
                    dr_priority: neighbor.dr_priority,
                    is_dr: iface_state.designated_router == Some(*neighbor_ip),
                    expires_in_secs,
                    generation_id: neighbor.generation_id,
                });
            }
        }
        neighbors
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

        // Join ALL-PIM-ROUTERS multicast group (224.0.0.13) on all interfaces
        let all_pim_routers = Ipv4Addr::new(224, 0, 0, 13);
        let mreq = libc::ip_mreq {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from(all_pim_routers).to_be(),
            },
            imr_interface: libc::in_addr {
                s_addr: libc::INADDR_ANY,
            },
        };

        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_ADD_MEMBERSHIP,
                &mreq as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::ip_mreq>() as libc::socklen_t,
            )
        };

        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(anyhow::anyhow!(
                "Failed to join ALL-PIM-ROUTERS multicast group: {}",
                std::io::Error::last_os_error()
            ));
        }

        let sock = unsafe { OwnedFd::from_raw_fd(fd) };

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Created PIM raw socket (fd: {}), joined {}",
                sock.as_raw_fd(),
                all_pim_routers
            )
        );

        self.pim_socket = Some(sock);
        Ok(())
    }

    /// Create both protocol sockets if protocols are enabled
    pub fn create_protocol_sockets(&mut self) -> Result<()> {
        if self.igmp_enabled && self.igmp_socket.is_none() {
            self.create_igmp_socket()?;
        }
        if self.pim_enabled && self.pim_socket.is_none() {
            self.create_pim_socket()?;
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
}

/// Async wrapper for raw socket I/O using tokio
///
/// This allows us to use raw sockets in an async context with tokio.
struct AsyncRawSocket {
    fd: RawFd,
}

impl AsyncRawSocket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Read a packet from the socket (non-blocking)
    fn try_read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
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
                    match guard.get_inner().try_read(&mut buf) {
                        Ok(n) if n > 0 => {
                            if let Some(event) = parse_igmp_packet(&buf[..n], &logger) {
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
                    match guard.get_inner().try_read(&mut buf) {
                        Ok(n) if n > 0 => {
                            if let Some(event) = parse_pim_packet(&buf[..n], &logger) {
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
fn parse_igmp_packet(packet: &[u8], logger: &Logger) -> Option<ProtocolEvent> {
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

    // Find interface by source IP (simplified - in real implementation would use recvmsg)
    let interface = find_interface_by_ip(src_ip).unwrap_or_else(|| "unknown".to_string());

    // Parse IGMP header (after IP header)
    let igmp = &packet[ihl..];
    if igmp.len() < 8 {
        return None;
    }

    let msg_type = igmp[0];
    let max_resp_time = igmp[1];
    let group = Ipv4Addr::new(igmp[4], igmp[5], igmp[6], igmp[7]);

    log_debug!(
        logger,
        Facility::Supervisor,
        &format!(
            "Received IGMP packet: type={:#x}, src={}, group={}, interface={}",
            msg_type, src_ip, group, interface
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
fn parse_pim_packet(packet: &[u8], logger: &Logger) -> Option<ProtocolEvent> {
    use crate::protocols::pim::PimEvent;

    // IP header is at least 20 bytes
    if packet.len() < 24 {
        // 20 IP + 4 PIM minimum
        return None;
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    // Get IP header length
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 4 {
        return None;
    }

    // Check protocol is PIM (103)
    if packet[9] != 103 {
        return None;
    }

    // Extract source IP
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

    // Find interface by source IP
    let interface = find_interface_by_ip(src_ip).unwrap_or_else(|| "unknown".to_string());

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
fn find_interface_by_ip(ip: Ipv4Addr) -> Option<String> {
    for iface in pnet::datalink::interfaces() {
        for ip_net in &iface.ips {
            if let std::net::IpAddr::V4(v4) = ip_net.ip() {
                // Check if this IP is on the same subnet
                // For simplicity, we check if it's the same interface IP
                // In production, would check subnet membership
                if v4 == ip || ip_net.contains(std::net::IpAddr::V4(ip)) {
                    return Some(iface.name.clone());
                }
            }
        }
    }
    None
}

/// Protocol timer management
///
/// This struct manages all protocol timers using a sorted list of pending timers.
/// Timers are processed in order, with the next timer to fire determining the
/// sleep duration.
pub struct ProtocolTimerManager {
    /// Pending timers sorted by fire time
    timers: std::collections::BinaryHeap<std::cmp::Reverse<ScheduledTimer>>,
    /// Channel to receive new timer requests
    timer_rx: mpsc::Receiver<TimerRequest>,
    /// Channel to send timer expiry events
    event_tx: mpsc::Sender<ProtocolEvent>,
    /// Logger
    logger: Logger,
}

/// A scheduled timer with its fire time and type
#[derive(Debug, Clone)]
struct ScheduledTimer {
    fire_at: Instant,
    timer_type: TimerType,
}

impl PartialEq for ScheduledTimer {
    fn eq(&self, other: &Self) -> bool {
        self.fire_at == other.fire_at && self.timer_type == other.timer_type
    }
}

impl Eq for ScheduledTimer {}

impl PartialOrd for ScheduledTimer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledTimer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.fire_at.cmp(&other.fire_at)
    }
}

impl ProtocolTimerManager {
    /// Create a new timer manager
    pub fn new(
        timer_rx: mpsc::Receiver<TimerRequest>,
        event_tx: mpsc::Sender<ProtocolEvent>,
        logger: Logger,
    ) -> Self {
        Self {
            timers: std::collections::BinaryHeap::new(),
            timer_rx,
            event_tx,
            logger,
        }
    }

    /// Schedule a new timer
    fn schedule(&mut self, request: TimerRequest) {
        if request.replace_existing {
            // Remove any existing timer of the same type
            self.timers = self
                .timers
                .drain()
                .filter(|t| t.0.timer_type != request.timer_type)
                .collect();
        }

        self.timers.push(std::cmp::Reverse(ScheduledTimer {
            fire_at: request.fire_at,
            timer_type: request.timer_type,
        }));

        log_debug!(
            self.logger,
            Facility::Supervisor,
            &format!("Scheduled timer, {} pending", self.timers.len())
        );
    }

    /// Run the timer management loop
    pub async fn run(mut self) {
        log_info!(
            self.logger,
            Facility::Supervisor,
            "Protocol timer manager started"
        );

        loop {
            // Calculate sleep duration based on next timer
            let sleep_duration = if let Some(std::cmp::Reverse(next)) = self.timers.peek() {
                let now = Instant::now();
                if next.fire_at <= now {
                    Duration::ZERO
                } else {
                    next.fire_at - now
                }
            } else {
                // No timers, sleep for a long time (or until new timer request)
                Duration::from_secs(3600)
            };

            tokio::select! {
                // Wait for next timer or timeout
                _ = sleep(sleep_duration) => {
                    // Fire all expired timers
                    let now = Instant::now();
                    while let Some(std::cmp::Reverse(timer)) = self.timers.peek() {
                        if timer.fire_at <= now {
                            let timer = self.timers.pop().unwrap().0;
                            let event = ProtocolEvent::TimerExpired(timer.timer_type.clone());

                            log_debug!(
                                self.logger,
                                Facility::Supervisor,
                                &format!("Timer expired: {:?}", timer.timer_type)
                            );

                            if self.event_tx.send(event).await.is_err() {
                                log_warning!(
                                    self.logger,
                                    Facility::Supervisor,
                                    "Event channel closed, timer manager exiting"
                                );
                                return;
                            }
                        } else {
                            break;
                        }
                    }
                }

                // Receive new timer requests
                request = self.timer_rx.recv() => {
                    match request {
                        Some(req) => {
                            self.schedule(req);
                        }
                        None => {
                            log_info!(
                                self.logger,
                                Facility::Supervisor,
                                "Timer request channel closed, timer manager exiting"
                            );
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Protocol coordinator that manages the integration between
/// protocol state machines and the supervisor's main loop
pub struct ProtocolCoordinator {
    /// Protocol state machines and MRIB
    pub state: ProtocolState,
    /// Channel to receive protocol events
    event_rx: mpsc::Receiver<ProtocolEvent>,
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
        timer_tx: mpsc::Sender<TimerRequest>,
    ) -> Self {
        Self {
            state,
            event_rx,
            timer_tx,
            rules_dirty: false,
        }
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

    // Initialize from config
    state.initialize_from_config(config);

    // Create protocol sockets if needed
    if state.igmp_enabled || state.pim_enabled {
        state.create_protocol_sockets()?;
    }

    // Get socket file descriptors for the receiver loop
    let igmp_fd = state.igmp_socket_fd();
    let pim_fd = state.pim_socket_fd();

    // Create background tasks
    let receiver_logger = logger.clone();
    let receiver_event_tx = event_tx.clone();
    let receiver_task = async move {
        protocol_receiver_loop(igmp_fd, pim_fd, receiver_event_tx, receiver_logger).await;
    };

    let timer_manager = ProtocolTimerManager::new(timer_rx, event_tx, logger.clone());
    let timer_task = async move {
        timer_manager.run().await;
    };

    // Create coordinator
    let coordinator = ProtocolCoordinator::new(state, event_rx, timer_tx);

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

/// Parse a group prefix like "239.0.0.0/8" or "239.1.1.1" into a base address
fn parse_group_prefix(prefix: &str) -> Result<Ipv4Addr> {
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

/// Validate an interface name according to Linux kernel rules.
/// Returns Ok(()) if valid, Err(reason) if invalid.
fn validate_interface_name(name: &str) -> Result<(), String> {
    // Must not be empty
    if name.is_empty() {
        return Err("interface name cannot be empty".to_string());
    }

    // Must not exceed IFNAMSIZ - 1 (15 chars)
    if name.len() > MAX_INTERFACE_NAME_LEN {
        return Err(format!(
            "interface name '{}' exceeds maximum length of {} characters",
            name, MAX_INTERFACE_NAME_LEN
        ));
    }

    // Must contain only valid characters: alphanumeric, dash, underscore
    // (Linux allows most characters but these are the safe/common ones)
    for (i, c) in name.chars().enumerate() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
            return Err(format!(
                "interface name '{}' contains invalid character '{}' at position {}; \
                only alphanumeric, dash, underscore, and dot are allowed",
                name, c, i
            ));
        }
    }

    // Must not start with a dash or dot (kernel restriction)
    if name.starts_with('-') || name.starts_with('.') {
        return Err(format!(
            "interface name '{}' cannot start with '{}'; must start with alphanumeric or underscore",
            name,
            name.chars().next().unwrap()
        ));
    }

    Ok(())
}

/// Validate a port number.
/// Port 0 is rejected as it's typically reserved and indicates a configuration error.
fn validate_port(port: u16, context: &str) -> Result<(), String> {
    if port == 0 {
        return Err(format!(
            "{} cannot be 0; valid port range is 1-65535",
            context
        ));
    }
    Ok(())
}

// --- WorkerManager Types ---

/// Differentiates worker types for unified handling
#[derive(Debug, Clone, PartialEq)]
enum WorkerType {
    DataPlane { interface: String, core_id: u32 },
}

/// Holds all information about a single worker process
struct Worker {
    pid: u32,
    worker_type: WorkerType,
    child: Child,
    // Data plane workers have TWO command streams (ingress + egress)
    ingress_cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
    egress_cmd_stream: Option<Arc<tokio::sync::Mutex<UnixStream>>>,
    #[cfg_attr(feature = "testing", allow(dead_code))]
    log_pipe: Option<std::os::unix::io::OwnedFd>, // Pipe for reading worker's stderr (JSON logs)
    #[cfg_attr(feature = "testing", allow(dead_code))]
    stats_pipe: Option<std::os::unix::io::OwnedFd>, // Pipe for reading worker's stats (JSON)
}

/// Per-interface worker configuration and state
struct InterfaceWorkers {
    /// Number of workers for this interface (from pinning config or default 1)
    num_workers: usize,
    /// Fanout group ID for this interface (auto-assigned, unique per interface)
    fanout_group_id: u16,
    /// Specific core IDs to pin workers to (from config pinning section)
    /// If None, workers use sequential core IDs starting from 0
    pinned_cores: Option<Vec<u32>>,
}

/// Centralized manager for all worker lifecycle operations
struct WorkerManager {
    // Configuration
    num_cores_per_interface: usize, // Default workers per interface
    logger: Logger,
    /// Core pinning configuration from startup config (interface -> core list)
    pinning: HashMap<String, Vec<u32>>,

    // Per-interface state
    interfaces: HashMap<String, InterfaceWorkers>,
    next_fanout_group_id: u16, // Auto-increment for new interfaces

    // Worker state
    workers: HashMap<u32, Worker>,                 // keyed by PID
    backoff_counters: HashMap<(String, u32), u64>, // keyed by (interface, core_id)
    worker_stats: Arc<Mutex<HashMap<u32, Vec<crate::FlowStats>>>>, // Stats from data plane workers (keyed by PID)
}

/// Action that may need to be taken after handling a supervisor command
#[derive(Debug, Clone, PartialEq)]
pub enum CommandAction {
    /// No further action needed
    None,
    /// Broadcast a relay command to all data plane workers
    BroadcastToDataPlane(RelayCommand),
    /// Ensure workers exist for interface, then broadcast command
    /// (interface, is_pinned, command)
    EnsureWorkersAndBroadcast {
        interface: String,
        is_pinned: bool,
        command: RelayCommand,
    },
}

/// Handle a supervisor command by updating state and returning a response + action.
///
/// This function is pure (no I/O) and unit-testable. It handles state updates
/// and returns what async actions need to be taken (like broadcasting to workers).
///
/// # Arguments
/// * `command` - The supervisor command to process
/// * `master_rules` - Shared state of all forwarding rules
/// * `worker_map` - Map of active workers (pid -> WorkerInfo)
/// * `global_min_level` - Global minimum log level
/// * `facility_min_levels` - Per-facility log level overrides
/// * `worker_stats` - Latest stats from all data plane workers (keyed by PID)
///
/// # Returns
/// A tuple of (Response to send to client, Action to take)
pub fn handle_supervisor_command(
    command: crate::SupervisorCommand,
    master_rules: &Mutex<HashMap<String, ForwardingRule>>,
    worker_map: &Mutex<HashMap<u32, crate::WorkerInfo>>,
    global_min_level: &std::sync::atomic::AtomicU8,
    facility_min_levels: &std::sync::RwLock<
        HashMap<crate::logging::Facility, crate::logging::Severity>,
    >,
    worker_stats: &Mutex<HashMap<u32, Vec<crate::FlowStats>>>,
    startup_config_path: Option<&PathBuf>,
) -> (crate::Response, CommandAction) {
    use crate::{Response, SupervisorCommand};
    use std::sync::atomic::Ordering;

    match command {
        SupervisorCommand::ListWorkers => {
            let workers = worker_map.lock().unwrap().values().cloned().collect();
            (Response::Workers(workers), CommandAction::None)
        }

        SupervisorCommand::AddRule {
            rule_id,
            name,
            input_interface,
            input_group,
            input_port,
            outputs,
        } => {
            // Validate input interface name
            if let Err(e) = validate_interface_name(&input_interface) {
                return (
                    Response::Error(format!("Invalid input_interface: {}", e)),
                    CommandAction::None,
                );
            }

            // Validate all output interface names
            for (i, output) in outputs.iter().enumerate() {
                if let Err(e) = validate_interface_name(&output.interface) {
                    return (
                        Response::Error(format!(
                            "Invalid output_interface in output[{}]: {}",
                            i, e
                        )),
                        CommandAction::None,
                    );
                }
            }

            // Validate port numbers (reject port 0)
            if let Err(e) = validate_port(input_port, "input_port") {
                return (Response::Error(e), CommandAction::None);
            }
            for (i, output) in outputs.iter().enumerate() {
                if let Err(e) = validate_port(output.port, &format!("output[{}].port", i)) {
                    return (Response::Error(e), CommandAction::None);
                }
            }

            // Generate stable rule ID if not provided
            let rule_id = if rule_id.is_empty() {
                crate::generate_rule_id(&input_interface, input_group, input_port)
            } else {
                rule_id
            };

            let rule = ForwardingRule {
                rule_id,
                name,
                input_interface,
                input_group,
                input_port,
                input_source: None, // CLI-added rules don't have source filtering
                outputs,
                source: crate::RuleSource::Dynamic, // Rules added via CLI are dynamic
            };

            // Validate interface configuration to prevent packet loops and reflection
            for output in &rule.outputs {
                // Reject self-loops: input and output on same interface creates packet feedback loops
                if rule.input_interface == output.interface {
                    return (
                        Response::Error(format!(
                            "Rule rejected: input_interface '{}' and output_interface '{}' cannot be the same. \
                            This creates packet loops where transmitted packets are received again by the same interface, \
                            causing exponential packet multiplication and invalid statistics. \
                            Use different interfaces (e.g., eth0 → eth1) for proper forwarding.",
                            rule.input_interface, output.interface
                        )),
                        CommandAction::None,
                    );
                }
            }

            // Warn about loopback interface usage (allowed but not recommended)
            if rule.input_interface == "lo" || rule.outputs.iter().any(|o| o.interface == "lo") {
                eprintln!(
                    "[Supervisor] WARNING: Rule '{}' uses loopback interface. \
                    This can cause packet reflection artifacts where transmitted packets are \
                    received again by AF_PACKET sockets, leading to inflated statistics and \
                    unexpected behavior. Loopback is suitable for local testing only. \
                    For production use, configure rules with real network interfaces (e.g., eth0, eth1) \
                    or use veth pairs for virtual topologies.",
                    rule.rule_id
                );
            }

            // Extract input_interface before inserting
            let input_interface = rule.input_interface.clone();

            master_rules
                .lock()
                .unwrap()
                .insert(rule.rule_id.clone(), rule.clone());

            let response = Response::Success(format!("Rule {} added", rule.rule_id));
            // Use EnsureWorkersAndBroadcast to dynamically spawn workers for new interfaces
            let action = CommandAction::EnsureWorkersAndBroadcast {
                interface: input_interface,
                is_pinned: false, // Runtime rules create dynamic (non-pinned) workers
                command: RelayCommand::AddRule(rule),
            };
            (response, action)
        }

        SupervisorCommand::RemoveRule { rule_id } => {
            let removed = master_rules.lock().unwrap().remove(&rule_id).is_some();
            if removed {
                let response = Response::Success(format!("Rule {} removed", rule_id.clone()));
                let action =
                    CommandAction::BroadcastToDataPlane(RelayCommand::RemoveRule { rule_id });
                (response, action)
            } else {
                (
                    Response::Error(format!("Rule {} not found", rule_id)),
                    CommandAction::None,
                )
            }
        }

        SupervisorCommand::ListRules => {
            let rules = master_rules.lock().unwrap().values().cloned().collect();
            (Response::Rules(rules), CommandAction::None)
        }

        SupervisorCommand::GetStats => {
            // Aggregate stats from all data plane workers
            // Multiple workers may report stats for the same flow (same input_group:port)
            // With PACKET_FANOUT_CPU, each worker handles a subset of packets, so we sum
            // both counters and rates to get the total system throughput
            use std::collections::HashMap as StdHashMap;

            let worker_stats_locked = worker_stats.lock().unwrap();
            let mut aggregated: StdHashMap<(std::net::Ipv4Addr, u16), crate::FlowStats> =
                StdHashMap::new();

            // Aggregate stats from all workers
            for stats_vec in worker_stats_locked.values() {
                for stat in stats_vec {
                    let key = (stat.input_group, stat.input_port);
                    aggregated
                        .entry(key)
                        .and_modify(|existing| {
                            // Sum counters
                            existing.packets_relayed += stat.packets_relayed;
                            existing.bytes_relayed += stat.bytes_relayed;
                            // Sum rates (each worker handles distinct packets via fanout)
                            existing.packets_per_second += stat.packets_per_second;
                            existing.bits_per_second += stat.bits_per_second;
                        })
                        .or_insert_with(|| stat.clone());
                }
            }

            let stats: Vec<crate::FlowStats> = aggregated.into_values().collect();
            (Response::Stats(stats), CommandAction::None)
        }

        SupervisorCommand::SetGlobalLogLevel { level } => {
            global_min_level.store(level as u8, Ordering::Relaxed);
            (
                Response::Success(format!("Global log level set to {}", level)),
                CommandAction::None,
            )
        }

        SupervisorCommand::SetFacilityLogLevel { facility, level } => {
            facility_min_levels.write().unwrap().insert(facility, level);
            (
                Response::Success(format!("Log level for {} set to {}", facility, level)),
                CommandAction::None,
            )
        }

        SupervisorCommand::GetLogLevels => {
            let global =
                crate::logging::Severity::from_u8(global_min_level.load(Ordering::Relaxed))
                    .unwrap_or(crate::logging::Severity::Info);
            let facility_overrides = facility_min_levels.read().unwrap().clone();
            (
                Response::LogLevels {
                    global,
                    facility_overrides,
                },
                CommandAction::None,
            )
        }

        SupervisorCommand::GetVersion => (
            Response::Version {
                protocol_version: crate::PROTOCOL_VERSION,
            },
            CommandAction::None,
        ),

        SupervisorCommand::Ping => {
            // Health check - broadcast ping to all data plane workers
            // If they can receive and process this command, they're ready
            eprintln!("[PING] Supervisor received ping, broadcasting to workers");
            (
                Response::Success("pong".to_string()),
                CommandAction::BroadcastToDataPlane(RelayCommand::Ping),
            )
        }

        SupervisorCommand::RemoveRuleByName { name } => {
            // Find rule by name and remove it
            let mut rules = master_rules.lock().unwrap();

            // Find the rule ID by matching the name
            let rule_id = rules
                .values()
                .find(|r| r.name.as_ref() == Some(&name))
                .map(|r| r.rule_id.clone());

            match rule_id {
                Some(id) => {
                    // Remove the rule
                    rules.remove(&id);
                    (
                        Response::Success(format!("Removed rule '{}' (id: {})", name, id)),
                        CommandAction::BroadcastToDataPlane(RelayCommand::RemoveRule {
                            rule_id: id,
                        }),
                    )
                }
                None => (
                    Response::Error(format!(
                        "No rule found with name '{}'. Use 'mcrctl list' to see available rules.",
                        name
                    )),
                    CommandAction::None,
                ),
            }
        }

        SupervisorCommand::GetConfig => {
            // Return current running configuration
            let rules = master_rules.lock().unwrap();
            let rules_vec: Vec<crate::ForwardingRule> = rules.values().cloned().collect();
            let config = crate::Config::from_forwarding_rules(&rules_vec);
            (Response::Config(config), CommandAction::None)
        }

        SupervisorCommand::LoadConfig { config, replace } => {
            // Validate the config first
            if let Err(e) = config.validate() {
                return (
                    Response::Error(format!("Invalid configuration: {}", e)),
                    CommandAction::None,
                );
            }

            let new_rules = config.to_forwarding_rules();

            if replace {
                // Replace all existing rules
                let mut rules = master_rules.lock().unwrap();
                rules.clear();
                for rule in new_rules {
                    rules.insert(rule.rule_id.clone(), rule);
                }
                let rules_for_sync: Vec<crate::ForwardingRule> = rules.values().cloned().collect();
                drop(rules);
                (
                    Response::Success(format!(
                        "Configuration loaded ({} rules, replaced existing)",
                        rules_for_sync.len()
                    )),
                    CommandAction::BroadcastToDataPlane(RelayCommand::SyncRules(rules_for_sync)),
                )
            } else {
                // Merge: add new rules that don't conflict
                let mut rules = master_rules.lock().unwrap();
                let mut added = 0;
                let mut skipped = 0;
                for new_rule in new_rules {
                    // Check for duplicate input tuple
                    let exists = rules.values().any(|r| {
                        r.input_interface == new_rule.input_interface
                            && r.input_group == new_rule.input_group
                            && r.input_port == new_rule.input_port
                    });
                    if exists {
                        skipped += 1;
                    } else {
                        rules.insert(new_rule.rule_id.clone(), new_rule);
                        added += 1;
                    }
                }
                let rules_for_sync: Vec<crate::ForwardingRule> = rules.values().cloned().collect();
                drop(rules);
                (
                    Response::Success(format!(
                        "Configuration merged ({} rules added, {} skipped as duplicates)",
                        added, skipped
                    )),
                    CommandAction::BroadcastToDataPlane(RelayCommand::SyncRules(rules_for_sync)),
                )
            }
        }

        SupervisorCommand::SaveConfig { path } => {
            // Save running config to a file
            let rules = master_rules.lock().unwrap();
            let rules_vec: Vec<crate::ForwardingRule> = rules.values().cloned().collect();
            let config = crate::Config::from_forwarding_rules(&rules_vec);
            drop(rules);

            // Use explicit path, or fall back to startup config path
            let save_path = path.as_ref().or(startup_config_path);

            match save_path {
                Some(p) => match config.save_to_file(p) {
                    Ok(()) => (
                        Response::Success(format!("Configuration saved to {}", p.display())),
                        CommandAction::None,
                    ),
                    Err(e) => (
                        Response::Error(format!("Failed to save configuration: {}", e)),
                        CommandAction::None,
                    ),
                },
                None => (
                    Response::Error(
                        "No path specified and mcrd was not started with --config".to_string(),
                    ),
                    CommandAction::None,
                ),
            }
        }

        SupervisorCommand::CheckConfig { config } => {
            // Validate configuration without loading
            match config.validate() {
                Ok(()) => (
                    Response::ConfigValidation {
                        valid: true,
                        errors: vec![],
                    },
                    CommandAction::None,
                ),
                Err(e) => (
                    Response::ConfigValidation {
                        valid: false,
                        errors: vec![e.to_string()],
                    },
                    CommandAction::None,
                ),
            }
        }

        // --- PIM Commands ---
        // Note: These commands require protocol state integration.
        // Full implementation requires passing ProtocolCoordinator to this function.
        SupervisorCommand::GetPimNeighbors => {
            // Return empty list until protocol integration is complete
            (Response::PimNeighbors(Vec::new()), CommandAction::None)
        }

        SupervisorCommand::EnablePim {
            interface,
            dr_priority,
        } => {
            // Validate interface name
            if let Err(e) = validate_interface_name(&interface) {
                return (
                    Response::Error(format!("Invalid interface: {}", e)),
                    CommandAction::None,
                );
            }
            (
                Response::Success(format!(
                    "PIM enable requested for interface {} (dr_priority: {:?}). \
                     Note: Full protocol integration pending.",
                    interface, dr_priority
                )),
                CommandAction::None,
            )
        }

        SupervisorCommand::DisablePim { interface } => {
            if let Err(e) = validate_interface_name(&interface) {
                return (
                    Response::Error(format!("Invalid interface: {}", e)),
                    CommandAction::None,
                );
            }
            (
                Response::Success(format!(
                    "PIM disable requested for interface {}. Note: Full protocol integration pending.",
                    interface
                )),
                CommandAction::None,
            )
        }

        SupervisorCommand::SetStaticRp {
            group_prefix,
            rp_address,
        } => {
            // Validate RP address is unicast
            if rp_address.is_multicast() {
                return (
                    Response::Error("RP address must be unicast".to_string()),
                    CommandAction::None,
                );
            }
            // Validate group prefix
            if let Err(e) = parse_group_prefix(&group_prefix) {
                return (
                    Response::Error(format!("Invalid group prefix: {}", e)),
                    CommandAction::None,
                );
            }
            (
                Response::Success(format!(
                    "Static RP {} set for group {}. Note: Full protocol integration pending.",
                    rp_address, group_prefix
                )),
                CommandAction::None,
            )
        }

        // --- IGMP Commands ---
        SupervisorCommand::GetIgmpGroups => {
            // Return empty list until protocol integration is complete
            (Response::IgmpGroups(Vec::new()), CommandAction::None)
        }

        SupervisorCommand::EnableIgmpQuerier { interface } => {
            if let Err(e) = validate_interface_name(&interface) {
                return (
                    Response::Error(format!("Invalid interface: {}", e)),
                    CommandAction::None,
                );
            }
            (
                Response::Success(format!(
                    "IGMP querier enable requested for interface {}. Note: Full protocol integration pending.",
                    interface
                )),
                CommandAction::None,
            )
        }

        SupervisorCommand::DisableIgmpQuerier { interface } => {
            if let Err(e) = validate_interface_name(&interface) {
                return (
                    Response::Error(format!("Invalid interface: {}", e)),
                    CommandAction::None,
                );
            }
            (
                Response::Success(format!(
                    "IGMP querier disable requested for interface {}. Note: Full protocol integration pending.",
                    interface
                )),
                CommandAction::None,
            )
        }

        // --- Multicast Routing Table ---
        SupervisorCommand::GetMroute => {
            // Return empty list until protocol integration is complete
            (Response::Mroute(Vec::new()), CommandAction::None)
        }
    }
}

pub async fn spawn_data_plane_worker(
    core_id: u32,
    interface: String,
    fanout_group_id: u16,
    logger: &crate::logging::Logger,
) -> Result<(
    Child,
    UnixStream,
    UnixStream,
    Option<std::os::unix::io::OwnedFd>, // log_pipe
    Option<std::os::unix::io::OwnedFd>, // stats_pipe
)> {
    logger.debug(
        Facility::Supervisor,
        &format!("Spawning worker for core {}", core_id),
    );

    // Create pipe for worker stderr (for JSON logging)
    #[cfg(not(feature = "testing"))]
    let (log_read_fd, log_write_fd) = {
        use nix::unistd::pipe;
        use std::os::unix::io::IntoRawFd;
        let (read_fd, write_fd) = pipe()?;
        // Convert to raw FDs to prevent auto-close when OwnedFd goes out of scope
        (Some(read_fd.into_raw_fd()), Some(write_fd.into_raw_fd()))
    };
    #[cfg(feature = "testing")]
    let (_log_read_fd, _log_write_fd): (Option<RawFd>, Option<RawFd>) = (None, None);

    // Create pipe for worker stats (JSON stats reporting)
    #[cfg(not(feature = "testing"))]
    let (stats_read_fd, stats_write_fd) = {
        use nix::unistd::pipe;
        use std::os::unix::io::IntoRawFd;
        let (read_fd, write_fd) = pipe()?;
        // Convert to raw FDs to prevent auto-close when OwnedFd goes out of scope
        (Some(read_fd.into_raw_fd()), Some(write_fd.into_raw_fd()))
    };
    #[cfg(feature = "testing")]
    let (_stats_read_fd, _stats_write_fd): (Option<RawFd>, Option<RawFd>) = (None, None);

    // Create the supervisor-worker communication socket pair
    // This will be passed as FD 3 to the worker
    let (supervisor_sock, worker_sock) = UnixStream::pair()?;

    // Keep worker_sock alive as FD 3 for the child process
    let worker_sock_std = worker_sock.into_std()?;
    let worker_fd = worker_sock_std.into_raw_fd();

    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("worker")
        .arg("--core-id")
        .arg(core_id.to_string())
        .arg("--data-plane")
        .arg("--input-interface-name")
        .arg(&interface)
        .arg("--fanout-group-id")
        .arg(fanout_group_id.to_string())
        .process_group(0); // Put worker in its own process group to prevent SIGTERM propagation

    // Pass stats pipe FD via environment variable (secure FD passing)
    // Clear close-on-exec flag so the FD is inherited
    #[cfg(not(feature = "testing"))]
    if let Some(write_fd) = stats_write_fd {
        command.env("MCR_STATS_PIPE_FD", write_fd.to_string());
        // Clear FD_CLOEXEC flag to allow FD to be inherited across exec
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        use std::os::fd::BorrowedFd;
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(write_fd) };
        let flags = fcntl(borrowed_fd, FcntlArg::F_GETFD)?;
        let mut fd_flags = FdFlag::from_bits_truncate(flags);
        fd_flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(borrowed_fd, FcntlArg::F_SETFD(fd_flags))?;
    }

    // Ensure worker_sock becomes FD 3 in the child, and redirect stderr to pipe
    unsafe {
        command.pre_exec(move || {
            // Dup worker_fd to FD 3
            if worker_fd != 3 {
                if libc::dup2(worker_fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(worker_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            // Redirect stderr to pipe write end (for JSON logging)
            #[cfg(not(feature = "testing"))]
            if let Some(write_fd) = log_write_fd {
                if libc::dup2(write_fd, 2) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::close(write_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                // Also close read end in child (not needed)
                if let Some(read_fd) = log_read_fd {
                    if libc::close(read_fd) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }

            // Close stats read end in child (not needed)
            #[cfg(not(feature = "testing"))]
            if let Some(read_fd) = stats_read_fd {
                if libc::close(read_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }

    let child = command.spawn()?;

    // Close write end in parent (child has it via FD 2)
    // Keep read end open - we'll use it to read worker logs
    #[cfg(not(feature = "testing"))]
    if let Some(write_fd) = log_write_fd {
        nix::unistd::close(write_fd).ok();
    }

    // Convert read end to OwnedFd (it's still open, we didn't close it)
    #[cfg(not(feature = "testing"))]
    let log_pipe = log_read_fd.map(|fd| unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) });
    #[cfg(feature = "testing")]
    let log_pipe = None;

    // Close stats write end in parent (child has it via FD 4)
    // Keep read end open - we'll use it to read worker stats
    #[cfg(not(feature = "testing"))]
    if let Some(write_fd) = stats_write_fd {
        nix::unistd::close(write_fd).ok();
    }

    // Convert stats read end to OwnedFd (it's still open, we didn't close it)
    #[cfg(not(feature = "testing"))]
    let stats_pipe = stats_read_fd.map(|fd| unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) });
    #[cfg(feature = "testing")]
    let stats_pipe = None;

    // Send TWO command sockets to the child process (one for ingress, one for egress)
    let ingress_cmd_supervisor_stream = create_and_send_socketpair(&supervisor_sock).await?;
    let egress_cmd_supervisor_stream = create_and_send_socketpair(&supervisor_sock).await?;

    // Create the AF_PACKET socket in the supervisor (requires CAP_NET_RAW/root)
    // and send it to the worker. This enables full privilege separation:
    // the worker can drop all privileges after receiving this pre-configured socket.
    let af_packet_socket = create_af_packet_socket(&interface, fanout_group_id, logger)?;
    send_fd(&supervisor_sock, af_packet_socket.as_raw_fd()).await?;
    // Keep the socket alive until the worker receives it
    drop(af_packet_socket);

    Ok((
        child,
        ingress_cmd_supervisor_stream,
        egress_cmd_supervisor_stream,
        log_pipe,
        stats_pipe,
    ))
}

// --- WorkerManager Implementation ---

impl WorkerManager {
    /// Create a new WorkerManager with the given configuration
    fn new(
        num_cores_per_interface: usize,
        logger: Logger,
        initial_fanout_group_id: u16,
        pinning: HashMap<String, Vec<u32>>,
    ) -> Self {
        Self {
            num_cores_per_interface,
            logger,
            pinning,
            interfaces: HashMap::new(),
            next_fanout_group_id: initial_fanout_group_id,
            workers: HashMap::new(),
            backoff_counters: HashMap::new(),
            worker_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create fanout group ID for an interface
    fn get_or_create_interface(&mut self, interface: &str, is_pinned: bool) -> u16 {
        if let Some(iface_workers) = self.interfaces.get(interface) {
            return iface_workers.fanout_group_id;
        }

        // Allocate new fanout group ID
        let fanout_group_id = self.next_fanout_group_id;
        self.next_fanout_group_id = self.next_fanout_group_id.wrapping_add(1);

        // Check for pinning configuration for this interface
        let pinned_cores = self.pinning.get(interface).cloned();

        // Determine number of workers:
        // 1. If pinning config exists, use the number of specified cores
        // 2. If pinned (from startup config) but no pinning config, use default num_cores
        // 3. If dynamic (runtime AddRule), use 1 worker
        let num_workers = if let Some(ref cores) = pinned_cores {
            cores.len()
        } else if is_pinned {
            self.num_cores_per_interface
        } else {
            1 // Dynamic interfaces get 1 worker by default
        };

        self.interfaces.insert(
            interface.to_string(),
            InterfaceWorkers {
                num_workers,
                fanout_group_id,
                pinned_cores: pinned_cores.clone(),
            },
        );

        if let Some(ref cores) = pinned_cores {
            log_debug!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Registered interface '{}' with fanout_group_id={}, pinned to cores {:?}",
                    interface, fanout_group_id, cores
                )
            );
        } else {
            log_debug!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Registered interface '{}' with fanout_group_id={}, workers={}",
                    interface, fanout_group_id, num_workers
                )
            );
        }

        fanout_group_id
    }

    /// Check if workers exist for a given interface
    fn has_workers_for_interface(&self, interface: &str) -> bool {
        self.workers.values().any(|w| {
            matches!(&w.worker_type, WorkerType::DataPlane { interface: iface, .. } if iface == interface)
        })
    }

    /// Spawn a data plane worker for the given interface and core
    async fn spawn_data_plane_for_interface(
        &mut self,
        interface: &str,
        core_id: u32,
        fanout_group_id: u16,
    ) -> Result<()> {
        let (child, ingress_cmd_stream, egress_cmd_stream, log_pipe, stats_pipe) =
            spawn_data_plane_worker(
                core_id,
                interface.to_string(),
                fanout_group_id,
                &self.logger,
            )
            .await?;

        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("Worker process exited immediately after spawn"))?;
        let ingress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(ingress_cmd_stream));
        let egress_cmd_stream_arc = Arc::new(tokio::sync::Mutex::new(egress_cmd_stream));

        // Store worker info with separate command streams
        self.workers.insert(
            pid,
            Worker {
                pid,
                worker_type: WorkerType::DataPlane {
                    interface: interface.to_string(),
                    core_id,
                },
                child,
                ingress_cmd_stream: Some(ingress_cmd_stream_arc),
                egress_cmd_stream: Some(egress_cmd_stream_arc),
                log_pipe,
                stats_pipe,
            },
        );

        // Initialize backoff counter - key by (interface, core_id) tuple
        self.backoff_counters
            .insert((interface.to_string(), core_id), INITIAL_BACKOFF_MS);

        // Spawn log consumer task for this worker
        #[cfg(not(feature = "testing"))]
        if let Some(pipe_fd) = self.workers.get(&pid).and_then(|w| w.log_pipe.as_ref()) {
            self.spawn_log_consumer(pid, pipe_fd)?;
        }

        // Spawn stats consumer task for this worker
        #[cfg(not(feature = "testing"))]
        if let Some(pipe_fd) = self.workers.get(&pid).and_then(|w| w.stats_pipe.as_ref()) {
            self.spawn_stats_consumer(pid, pipe_fd)?;
        }

        Ok(())
    }

    /// Spawn workers for an interface (if not already spawned)
    /// Returns true if workers were spawned, false if they already existed
    async fn ensure_workers_for_interface(
        &mut self,
        interface: &str,
        is_pinned: bool,
    ) -> Result<bool> {
        if self.has_workers_for_interface(interface) {
            return Ok(false);
        }

        // Get or create interface config (assigns fanout group ID)
        let fanout_group_id = self.get_or_create_interface(interface, is_pinned);

        // Get interface config to determine worker count and pinned cores
        let (num_workers, pinned_cores) = self
            .interfaces
            .get(interface)
            .map(|i| (i.num_workers, i.pinned_cores.clone()))
            .unwrap_or((1, None));

        log_debug!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Spawning {} worker(s) for interface '{}' (fanout_group_id={}{})",
                num_workers,
                interface,
                fanout_group_id,
                if pinned_cores.is_some() {
                    ", pinned"
                } else {
                    ""
                }
            )
        );

        // Spawn workers for this interface using pinned cores if specified,
        // otherwise use sequential core IDs starting from 0
        if let Some(ref cores) = pinned_cores {
            for &core_id in cores {
                self.spawn_data_plane_for_interface(interface, core_id, fanout_group_id)
                    .await?;
            }
        } else {
            for core_id in 0..num_workers as u32 {
                self.spawn_data_plane_for_interface(interface, core_id, fanout_group_id)
                    .await?;
            }
        }

        Ok(true)
    }

    /// Check for exited workers and restart them with exponential backoff
    /// Returns Some((pid, was_dataplane)) if a worker exited, None otherwise
    async fn check_and_restart_worker(&mut self) -> Result<Option<(u32, bool)>> {
        // Check each worker to see if it has exited
        let mut exited_workers = Vec::new();
        for (pid, worker) in &mut self.workers {
            // Try to check if the worker has exited (non-blocking)
            match worker.child.try_wait()? {
                Some(status) => {
                    exited_workers.push((*pid, worker.worker_type.clone(), status));
                }
                None => continue,
            }
        }

        // If no workers exited, return None
        if exited_workers.is_empty() {
            return Ok(None);
        }

        // Handle the first exited worker
        let (pid, worker_type, status) = exited_workers.remove(0);

        // Remove from workers map (should always exist, but handle gracefully)
        if self.workers.remove(&pid).is_none() {
            log_warning!(
                self.logger,
                Facility::Supervisor,
                &format!("Worker {} not found in workers map during restart", pid)
            );
        }

        // Restart the data plane worker
        let WorkerType::DataPlane { interface, core_id } = worker_type;
        let backoff_key = (interface.clone(), core_id);
        let backoff = self
            .backoff_counters
            .entry(backoff_key)
            .or_insert(INITIAL_BACKOFF_MS);
        if status.success() {
            log_info!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Data Plane worker (interface={}, core={}) exited gracefully, restarting immediately",
                    interface, core_id
                )
            );
            *backoff = INITIAL_BACKOFF_MS;
        } else {
            log_warning!(
                self.logger,
                Facility::Supervisor,
                &format!(
                    "Data Plane worker (interface={}, core={}) failed (status: {}), restarting after {}ms",
                    interface, core_id, status, *backoff
                )
            );
            sleep(Duration::from_millis(*backoff)).await;
            *backoff = (*backoff * 2).min(MAX_BACKOFF_MS);
        }

        // Get the fanout group ID for this interface (should exist since worker was running)
        let fanout_group_id = self
            .interfaces
            .get(&interface)
            .map(|i| i.fanout_group_id)
            .unwrap_or(0);

        self.spawn_data_plane_for_interface(&interface, core_id, fanout_group_id)
            .await?;
        Ok(Some((pid, true)))
    }

    /// Initiate graceful shutdown of all workers with timeout
    async fn shutdown_all(&mut self, timeout: Duration) {
        log_info!(
            self.logger,
            Facility::Supervisor,
            "Graceful shutdown initiated, signaling workers"
        );

        // Collect join handles for shutdown command sends
        let mut shutdown_tasks = Vec::new();

        // Signal all workers to shut down by sending explicit Shutdown command
        for worker in self.workers.values() {
            let cmd_bytes = serde_json::to_vec(&RelayCommand::Shutdown).unwrap();

            // Send to ingress stream if present
            if let Some(ingress_stream) = &worker.ingress_cmd_stream {
                let stream_mutex = ingress_stream.clone();
                let worker_type_desc = format!("{:?}", worker.worker_type);
                let cmd_bytes_clone = cmd_bytes.clone();

                let task = tokio::spawn(async move {
                    let mut stream = stream_mutex.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    if let Err(e) = framed.send(cmd_bytes_clone.into()).await {
                        eprintln!(
                            "[Supervisor] Failed to send Shutdown to {} ingress: {}",
                            worker_type_desc, e
                        );
                    }
                });
                shutdown_tasks.push(task);
            }

            // Send to egress stream if present (for data plane workers, this is a separate stream)
            if let Some(egress_stream) = &worker.egress_cmd_stream {
                let stream_mutex = egress_stream.clone();
                let worker_type_desc = format!("{:?}", worker.worker_type);
                let cmd_bytes_clone = cmd_bytes.clone();

                let task = tokio::spawn(async move {
                    let mut stream = stream_mutex.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    if let Err(e) = framed.send(cmd_bytes_clone.into()).await {
                        eprintln!(
                            "[Supervisor] Failed to send Shutdown to {} egress: {}",
                            worker_type_desc, e
                        );
                    }
                });
                shutdown_tasks.push(task);
            }
        }

        // Wait for all shutdown commands to be sent (with 1 second timeout)
        let send_timeout = Duration::from_secs(1);
        match tokio::time::timeout(send_timeout, futures::future::join_all(shutdown_tasks)).await {
            Ok(_) => {
                eprintln!("[Supervisor] All shutdown commands sent successfully");
            }
            Err(_) => {
                eprintln!("[Supervisor] Warning: Timeout sending shutdown commands");
            }
        }

        // Grace period: Give workers time to process shutdown and print final stats
        // This allows workers to cleanly exit their event loops and call print_final_stats()
        let grace_period = Duration::from_millis(500);
        eprintln!(
            "[Supervisor] Waiting {:?} grace period for workers to process shutdown",
            grace_period
        );
        tokio::time::sleep(grace_period).await;

        // Wait for all workers to exit with timeout
        let num_workers = self.workers.len();
        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!(
                "Waiting for {} workers to exit (timeout: {:?})",
                num_workers, timeout
            )
        );

        let shutdown_start = tokio::time::Instant::now();
        let mut exited_count = 0;

        while !self.workers.is_empty() {
            // Check if we've exceeded the timeout
            if shutdown_start.elapsed() >= timeout {
                log_warning!(
                    self.logger,
                    Facility::Supervisor,
                    &format!(
                        "Shutdown timeout exceeded, {} workers still running, force killing",
                        self.workers.len()
                    )
                );

                // Force kill any remaining workers
                for (pid, worker) in self.workers.iter_mut() {
                    log_warning!(
                        self.logger,
                        Facility::Supervisor,
                        &format!("Force killing worker {} ({:?})", pid, worker.worker_type)
                    );
                    let _ = worker.child.kill().await;
                }
                break;
            }

            // Check for exited workers (non-blocking)
            let mut exited_pids = Vec::new();
            for (pid, worker) in &mut self.workers {
                match worker.child.try_wait() {
                    Ok(Some(status)) => {
                        log_info!(
                            self.logger,
                            Facility::Supervisor,
                            &format!(
                                "Worker {} ({:?}) exited with status: {}",
                                pid, worker.worker_type, status
                            )
                        );
                        exited_pids.push(*pid);
                        exited_count += 1;
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        log_warning!(
                            self.logger,
                            Facility::Supervisor,
                            &format!("Error checking worker {}: {}", pid, e)
                        );
                        exited_pids.push(*pid);
                    }
                }
            }

            // Remove exited workers
            for pid in exited_pids {
                self.workers.remove(&pid);
            }

            // Brief sleep before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        log_info!(
            self.logger,
            Facility::Supervisor,
            &format!("All workers exited ({} total)", exited_count)
        );
    }

    /// Get all data plane command streams for broadcasting
    /// Returns pairs of (ingress_stream, egress_stream) for each worker
    #[allow(clippy::type_complexity)]
    fn get_all_dp_cmd_streams(
        &self,
    ) -> Vec<(
        Arc<tokio::sync::Mutex<UnixStream>>,
        Arc<tokio::sync::Mutex<UnixStream>>,
    )> {
        self.workers
            .values()
            .filter(|w| matches!(w.worker_type, WorkerType::DataPlane { .. }))
            .filter_map(|w| match (&w.ingress_cmd_stream, &w.egress_cmd_stream) {
                (Some(ingress), Some(egress)) => Some((ingress.clone(), egress.clone())),
                _ => None,
            })
            .collect()
    }

    /// Get all data plane command streams with interface name for per-interface rule filtering
    /// Returns tuples of (interface_name, ingress_stream, egress_stream) for each worker
    #[allow(clippy::type_complexity)]
    fn get_all_dp_cmd_streams_with_interface(
        &self,
    ) -> Vec<(
        String,
        Arc<tokio::sync::Mutex<UnixStream>>,
        Arc<tokio::sync::Mutex<UnixStream>>,
    )> {
        self.workers
            .values()
            .filter_map(|w| {
                let WorkerType::DataPlane { interface, .. } = &w.worker_type;
                match (&w.ingress_cmd_stream, &w.egress_cmd_stream) {
                    (Some(ingress), Some(egress)) => {
                        Some((interface.clone(), ingress.clone(), egress.clone()))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// Get worker info for all workers (for ListWorkers command)
    fn get_worker_info(&self) -> Vec<crate::WorkerInfo> {
        self.workers
            .values()
            .map(|w| {
                let WorkerType::DataPlane {
                    interface: _,
                    core_id,
                } = &w.worker_type;
                crate::WorkerInfo {
                    pid: w.pid,
                    worker_type: "DataPlane".to_string(),
                    core_id: Some(*core_id),
                }
            })
            .collect()
    }

    /// Spawn async task to consume JSON logs from worker's stderr pipe
    #[cfg(not(feature = "testing"))]
    fn spawn_log_consumer(
        &self,
        worker_pid: u32,
        pipe_fd: &std::os::unix::io::OwnedFd,
    ) -> Result<()> {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        use tokio::io::{AsyncBufReadExt, BufReader};

        // Duplicate the FD so we can convert to tokio File
        let dup_fd_owned = nix::unistd::dup(pipe_fd)?;
        let dup_fd = dup_fd_owned.into_raw_fd(); // Transfer ownership out of OwnedFd

        // Convert to tokio async file
        let std_file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let tokio_file = tokio::fs::File::from_std(std_file);
        let reader = BufReader::new(tokio_file);
        let mut lines = reader.lines();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                // For now, just print raw lines to supervisor's stderr
                // In Phase 2.2, worker will output JSON and we'll parse it here
                eprintln!("[Worker {}] {}", worker_pid, line);
            }
            eprintln!("[Supervisor] Worker {} log stream closed", worker_pid);
        });

        Ok(())
    }

    /// Spawn async task to consume JSON stats from worker's stats pipe (FD 4)
    #[cfg(not(feature = "testing"))]
    fn spawn_stats_consumer(
        &self,
        worker_pid: u32,
        pipe_fd: &std::os::unix::io::OwnedFd,
    ) -> Result<()> {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        use tokio::io::{AsyncBufReadExt, BufReader};

        // Duplicate the FD so we can convert to tokio File
        let dup_fd_owned = nix::unistd::dup(pipe_fd)?;
        let dup_fd = dup_fd_owned.into_raw_fd(); // Transfer ownership out of OwnedFd

        // Convert to tokio async file
        let std_file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let tokio_file = tokio::fs::File::from_std(std_file);
        let reader = BufReader::new(tokio_file);
        let mut lines = reader.lines();

        // Clone Arc for async task
        let worker_stats = self.worker_stats.clone();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                // Parse JSON stats from worker
                match serde_json::from_str::<Vec<crate::FlowStats>>(&line) {
                    Ok(stats) => {
                        // Store latest stats for this worker
                        worker_stats.lock().unwrap().insert(worker_pid, stats);
                    }
                    Err(e) => {
                        eprintln!(
                            "[Supervisor] Failed to parse stats from worker {}: {}",
                            worker_pid, e
                        );
                    }
                }
            }
            eprintln!("[Supervisor] Worker {} stats stream closed", worker_pid);
            // Remove stats for this worker when stream closes
            worker_stats.lock().unwrap().remove(&worker_pid);
        });

        Ok(())
    }
}

// --- Client Handling ---

/// Handle a single client connection on the control socket
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
    protocol_coordinator: Arc<Mutex<Option<ProtocolCoordinator>>>,
) -> Result<()> {
    use crate::{Response, SupervisorCommand};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = Vec::new();
    client_stream.read_to_end(&mut buffer).await?;

    let command: SupervisorCommand = serde_json::from_slice(&buffer)?;

    // Handle protocol-specific queries directly (need access to ProtocolCoordinator state)
    // These queries need real data from the protocol state machines
    let protocol_response: Option<Response> = {
        let coordinator_guard = protocol_coordinator.lock().unwrap();
        if let Some(ref coordinator) = *coordinator_guard {
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

    // Initialize protocol subsystem if PIM or IGMP is configured
    // Wrap in Arc<Mutex<>> so it can be shared with handle_client and event processing
    let protocol_coordinator: Arc<Mutex<Option<ProtocolCoordinator>>> = Arc::new(Mutex::new(None));

    if let Some(ref config) = startup_config {
        let pim_enabled = config.pim.as_ref().map(|p| p.enabled).unwrap_or(false);
        let igmp_enabled = config
            .igmp
            .as_ref()
            .map(|i| !i.querier_interfaces.is_empty())
            .unwrap_or(false);

        if pim_enabled || igmp_enabled {
            log_info!(
                supervisor_logger,
                Facility::Supervisor,
                &format!(
                    "Initializing protocol subsystem (PIM: {}, IGMP: {})",
                    pim_enabled, igmp_enabled
                )
            );

            match initialize_protocol_subsystem(config, supervisor_logger.clone()) {
                Ok((coordinator, receiver_task, timer_task)) => {
                    // Spawn protocol background tasks
                    tokio::spawn(async move {
                        receiver_task.await;
                    });
                    tokio::spawn(async move {
                        timer_task.await;
                    });

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
                    Arc::clone(&protocol_coordinator),
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

/// Create and configure an AF_PACKET socket bound to a specific interface.
///
/// This function creates the socket with CAP_NET_RAW privileges in the supervisor,
/// then the socket FD can be passed to unprivileged workers via SCM_RIGHTS.
///
/// # Arguments
/// * `interface_name` - Network interface to bind to (e.g., "eth0")
/// * `fanout_group_id` - PACKET_FANOUT group ID for load balancing (0 = disabled)
/// * `logger` - Logger instance for status messages
///
/// # Returns
/// An owned file descriptor for the configured AF_PACKET socket
fn create_af_packet_socket(
    interface_name: &str,
    fanout_group_id: u16,
    logger: &Logger,
) -> Result<std::os::fd::OwnedFd> {
    use socket2::{Domain, Protocol, Socket, Type};

    logger.debug(
        Facility::Supervisor,
        &format!(
            "Creating AF_PACKET socket for interface {} (fanout_group_id={})",
            interface_name, fanout_group_id
        ),
    );

    // Create AF_PACKET socket for receiving
    let recv_socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0x0003)))
        .context("Failed to create AF_PACKET socket")?;

    // Set large receive buffer to prevent drops during traffic bursts.
    // Default system buffer (~212KB) can only hold ~150 packets at 1400 bytes each.
    // At 100k pps, that's only 1.5ms of buffering - not enough for io_uring latency.
    // We request 16MB which gives ~11k packets / ~110ms of burst tolerance.
    // Note: Actual size may be limited by net.core.rmem_max sysctl.
    const RECV_BUFFER_SIZE: i32 = 16 * 1024 * 1024; // 16MB
    unsafe {
        let ret = libc::setsockopt(
            recv_socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &RECV_BUFFER_SIZE as *const _ as *const _,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret < 0 {
            // Log warning but don't fail - system may have lower limits
            logger.warning(
                Facility::Supervisor,
                &format!(
                    "Failed to set SO_RCVBUF to {}MB, using system default",
                    RECV_BUFFER_SIZE / 1024 / 1024
                ),
            );
        } else {
            // Read back actual size (kernel may have adjusted it)
            let mut actual_size: i32 = 0;
            let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;
            libc::getsockopt(
                recv_socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &mut actual_size as *mut _ as *mut _,
                &mut len,
            );
            logger.debug(
                Facility::Supervisor,
                &format!(
                    "AF_PACKET SO_RCVBUF set to {}KB (requested {}MB)",
                    actual_size / 1024,
                    RECV_BUFFER_SIZE / 1024 / 1024
                ),
            );
        }
    }

    // Get interface index
    let iface_index = get_interface_index(interface_name)?;

    // Bind to interface using raw libc bind
    unsafe {
        let sockaddr_ll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: iface_index,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let ret = libc::bind(
            recv_socket.as_raw_fd(),
            &sockaddr_ll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "Failed to bind AF_PACKET socket to {}: {}",
                interface_name,
                std::io::Error::last_os_error()
            ));
        }
    }

    // Configure PACKET_FANOUT if fanout_group_id is non-zero
    if fanout_group_id > 0 {
        let fanout_arg: u32 = (fanout_group_id as u32) | (libc::PACKET_FANOUT_CPU << 16);

        unsafe {
            if libc::setsockopt(
                recv_socket.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_FANOUT,
                &fanout_arg as *const _ as *const _,
                std::mem::size_of::<u32>() as _,
            ) < 0
            {
                return Err(anyhow::anyhow!(
                    "PACKET_FANOUT failed for {}: {}",
                    interface_name,
                    std::io::Error::last_os_error()
                ));
            }
        }
        logger.debug(
            Facility::Supervisor,
            &format!(
                "PACKET_FANOUT configured for {} (group_id={}, mode=CPU)",
                interface_name, fanout_group_id
            ),
        );
    }

    // Set non-blocking
    recv_socket.set_nonblocking(true)?;

    // Convert to OwnedFd
    Ok(std::os::fd::OwnedFd::from(recv_socket))
}

/// Get network interface index by name
fn get_interface_index(interface_name: &str) -> Result<i32> {
    for iface in pnet::datalink::interfaces() {
        if iface.name == interface_name {
            return Ok(iface.index as i32);
        }
    }
    Err(anyhow::anyhow!("Interface not found: {}", interface_name))
}

/// Send a file descriptor to a worker process via SCM_RIGHTS
///
/// # Safety
/// This function uses unsafe FFI to send file descriptors. The caller must ensure:
/// - `sock` is a valid Unix domain socket
/// - `fd` is a valid open file descriptor
async fn send_fd(sock: &UnixStream, fd: RawFd) -> Result<()> {
    let data = [0u8; 1];
    let iov = [std::io::IoSlice::new(&data)];
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    sock.ready(tokio::io::Interest::WRITABLE).await?;
    sock.try_io(tokio::io::Interest::WRITABLE, || {
        sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .map_err(std::io::Error::other)
    })?;

    Ok(())
}

/// Create a socketpair and send one end to the worker, returning the supervisor's end
///
/// This helper reduces duplication when setting up IPC channels with workers.
/// Creates a Unix domain socket pair with CLOEXEC and NONBLOCK flags, then
/// sends the worker's end via file descriptor passing.
async fn create_and_send_socketpair(supervisor_sock: &UnixStream) -> Result<UnixStream> {
    let (supervisor_fd, worker_fd) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )?;

    send_fd(supervisor_sock, worker_fd.into_raw_fd()).await?;

    Ok(UnixStream::from_std(unsafe {
        std::os::unix::net::UnixStream::from_raw_fd(supervisor_fd.into_raw_fd())
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Unit Tests for handle_supervisor_command ---

    #[test]
    fn test_handle_list_workers() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        worker_map.lock().unwrap().insert(
            1234,
            crate::WorkerInfo {
                pid: 1234,
                worker_type: "DataPlane".to_string(),
                core_id: None,
            },
        );
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::ListWorkers,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        assert!(matches!(response, crate::Response::Workers(workers) if workers.len() == 1));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_add_rule() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                name: None,
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert!(matches!(
            action,
            CommandAction::EnsureWorkersAndBroadcast { .. }
        ));
        assert_eq!(master_rules.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_handle_remove_rule_exists() {
        let master_rules = Mutex::new(HashMap::new());
        master_rules.lock().unwrap().insert(
            "test-rule".to_string(),
            ForwardingRule {
                rule_id: "test-rule".to_string(),
                name: None,
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                input_source: None,
                outputs: vec![],
                source: crate::RuleSource::Static,
            },
        );
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::RemoveRule {
                rule_id: "test-rule".to_string(),
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert!(matches!(action, CommandAction::BroadcastToDataPlane(_)));
        assert_eq!(master_rules.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_handle_remove_rule_not_found() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::RemoveRule {
                rule_id: "nonexistent".to_string(),
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        assert!(matches!(response, crate::Response::Error(_)));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_list_rules() {
        let master_rules = Mutex::new(HashMap::new());
        master_rules.lock().unwrap().insert(
            "test-rule".to_string(),
            ForwardingRule {
                rule_id: "test-rule".to_string(),
                name: None,
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                input_source: None,
                outputs: vec![],
                source: crate::RuleSource::Static,
            },
        );
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::ListRules,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        assert!(matches!(response, crate::Response::Rules(rules) if rules.len() == 1));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_stats() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetStats,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        assert!(matches!(response, crate::Response::Stats(_)));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_set_global_log_level() {
        use std::sync::atomic::Ordering;

        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::SetGlobalLogLevel {
                level: crate::logging::Severity::Debug,
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert_eq!(action, CommandAction::None);
        assert_eq!(
            global_min_level.load(Ordering::Relaxed),
            crate::logging::Severity::Debug as u8
        );
    }

    #[test]
    fn test_handle_set_facility_log_level() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::SetFacilityLogLevel {
                facility: crate::logging::Facility::Ingress,
                level: crate::logging::Severity::Debug,
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert_eq!(action, CommandAction::None);
        assert_eq!(
            facility_min_levels
                .read()
                .unwrap()
                .get(&crate::logging::Facility::Ingress),
            Some(&crate::logging::Severity::Debug)
        );
    }

    #[test]
    fn test_handle_get_log_levels() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Warning as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        facility_min_levels.write().unwrap().insert(
            crate::logging::Facility::Ingress,
            crate::logging::Severity::Debug,
        );

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetLogLevels,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        match response {
            crate::Response::LogLevels {
                global,
                facility_overrides,
            } => {
                assert_eq!(global, crate::logging::Severity::Warning);
                assert_eq!(
                    facility_overrides.get(&crate::logging::Facility::Ingress),
                    Some(&crate::logging::Severity::Debug)
                );
            }
            _ => panic!("Expected LogLevels response"),
        }
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_version() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetVersion,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        match response {
            crate::Response::Version { protocol_version } => {
                assert_eq!(protocol_version, crate::PROTOCOL_VERSION);
            }
            _ => panic!("Expected Version response"),
        }
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_stats_multi_worker_aggregation() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        // Simulate stats from 3 data plane workers reporting for the same flow
        let mut worker_stats_map = HashMap::new();

        // Worker 1: 100 packets, 10000 bytes, 50 pps, 4000 bps
        worker_stats_map.insert(
            1001,
            vec![crate::FlowStats {
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                packets_relayed: 100,
                bytes_relayed: 10000,
                packets_per_second: 50.0,
                bits_per_second: 4000.0,
            }],
        );

        // Worker 2: 200 packets, 20000 bytes, 100 pps, 8000 bps
        worker_stats_map.insert(
            1002,
            vec![crate::FlowStats {
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                packets_relayed: 200,
                bytes_relayed: 20000,
                packets_per_second: 100.0,
                bits_per_second: 8000.0,
            }],
        );

        // Worker 3: 150 packets, 15000 bytes, 75 pps, 6000 bps
        worker_stats_map.insert(
            1003,
            vec![crate::FlowStats {
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                packets_relayed: 150,
                bytes_relayed: 15000,
                packets_per_second: 75.0,
                bits_per_second: 6000.0,
            }],
        );

        let worker_stats = Mutex::new(worker_stats_map);

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetStats,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        match response {
            crate::Response::Stats(stats) => {
                assert_eq!(stats.len(), 1, "Should have one aggregated flow");
                let flow = &stats[0];

                // Check aggregated counters (should be summed)
                assert_eq!(
                    flow.packets_relayed, 450,
                    "Should sum packets from all workers: 100+200+150"
                );
                assert_eq!(
                    flow.bytes_relayed, 45000,
                    "Should sum bytes from all workers: 10000+20000+15000"
                );

                // Check aggregated rates (currently summed, not averaged)
                assert_eq!(
                    flow.packets_per_second, 225.0,
                    "Should sum pps from all workers: 50+100+75"
                );
                assert_eq!(
                    flow.bits_per_second, 18000.0,
                    "Should sum bps from all workers: 4000+8000+6000"
                );

                // Check flow identification
                assert_eq!(
                    flow.input_group,
                    "224.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
                );
                assert_eq!(flow.input_port, 5000);
            }
            _ => panic!("Expected Response::Stats, got {:?}", response),
        }

        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_stats_multiple_flows() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        // Simulate 2 workers with different flows
        let mut worker_stats_map = HashMap::new();

        // Worker 1: Flow A (224.0.0.1:5000) and Flow B (224.0.0.2:5001)
        worker_stats_map.insert(
            2001,
            vec![
                crate::FlowStats {
                    input_group: "224.0.0.1".parse().unwrap(),
                    input_port: 5000,
                    packets_relayed: 100,
                    bytes_relayed: 10000,
                    packets_per_second: 10.0,
                    bits_per_second: 8000.0,
                },
                crate::FlowStats {
                    input_group: "224.0.0.2".parse().unwrap(),
                    input_port: 5001,
                    packets_relayed: 50,
                    bytes_relayed: 5000,
                    packets_per_second: 5.0,
                    bits_per_second: 4000.0,
                },
            ],
        );

        // Worker 2: Only Flow A (224.0.0.1:5000)
        worker_stats_map.insert(
            2002,
            vec![crate::FlowStats {
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                packets_relayed: 200,
                bytes_relayed: 20000,
                packets_per_second: 20.0,
                bits_per_second: 16000.0,
            }],
        );

        let worker_stats = Mutex::new(worker_stats_map);

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::GetStats,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        match response {
            crate::Response::Stats(stats) => {
                assert_eq!(stats.len(), 2, "Should have two distinct flows");

                // Find Flow A and Flow B in the results
                let flow_a = stats
                    .iter()
                    .find(|s| s.input_port == 5000)
                    .expect("Should have Flow A");
                let flow_b = stats
                    .iter()
                    .find(|s| s.input_port == 5001)
                    .expect("Should have Flow B");

                // Flow A: aggregated from both workers
                assert_eq!(flow_a.packets_relayed, 300, "Flow A packets: 100+200");
                assert_eq!(flow_a.bytes_relayed, 30000, "Flow A bytes: 10000+20000");
                assert_eq!(flow_a.packets_per_second, 30.0, "Flow A pps: 10+20");

                // Flow B: only from worker 1
                assert_eq!(flow_b.packets_relayed, 50, "Flow B packets: 50");
                assert_eq!(flow_b.bytes_relayed, 5000, "Flow B bytes: 5000");
                assert_eq!(flow_b.packets_per_second, 5.0, "Flow B pps: 5.0");
            }
            _ => panic!("Expected Response::Stats, got {:?}", response),
        }

        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_reject_self_loop_same_interface() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        // Attempt to create a self-loop: eth0 -> eth0
        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "bad-loop".to_string(),
                name: None,
                input_interface: "eth0".to_string(),
                input_group: "239.1.1.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth0".to_string(), // Same as input!
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        // Should reject with error
        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("cannot be the same"));
                assert!(msg.contains("packet loops"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }

        assert_eq!(action, CommandAction::None);

        // Verify rule was not added
        assert_eq!(master_rules.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_accept_valid_different_interfaces() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        // Valid rule: eth0 -> eth1 (different interfaces)
        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "valid-rule".to_string(),
                name: None,
                input_interface: "eth0".to_string(),
                input_group: "239.1.1.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(), // Different from input
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        // Should succeed
        match response {
            crate::Response::Success(msg) => {
                assert!(msg.contains("valid-rule"));
                assert!(msg.contains("added"));
            }
            _ => panic!("Expected Success response, got {:?}", response),
        }

        // Should ensure workers and broadcast to data plane
        match action {
            CommandAction::EnsureWorkersAndBroadcast { .. } => {}
            _ => panic!(
                "Expected EnsureWorkersAndBroadcast action, got {:?}",
                action
            ),
        }

        // Verify rule was added
        assert_eq!(master_rules.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_loopback_allowed_with_warning() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        // Loopback should be allowed but warned
        let (response, _action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "loopback-rule".to_string(),
                name: None,
                input_interface: "eth0".to_string(),
                input_group: "239.1.1.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "239.2.2.2".parse().unwrap(),
                    port: 5001,
                    interface: "lo".to_string(), // Loopback output
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        // Should succeed (loopback allowed, just warned)
        match response {
            crate::Response::Success(_) => {}
            _ => panic!("Expected Success response for loopback, got {:?}", response),
        }

        // Rule should be added despite loopback warning
        assert_eq!(master_rules.lock().unwrap().len(), 1);
    }

    // --- Interface Name Validation Tests ---

    #[test]
    fn test_validate_interface_name_valid() {
        // Standard interface names
        assert!(validate_interface_name("lo").is_ok());
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("eth1").is_ok());
        assert!(validate_interface_name("enp0s3").is_ok());
        assert!(validate_interface_name("wlan0").is_ok());
        assert!(validate_interface_name("br0").is_ok());
        assert!(validate_interface_name("docker0").is_ok());
        assert!(validate_interface_name("veth123abc").is_ok());

        // Names with underscores and dashes
        assert!(validate_interface_name("my_bridge").is_ok());
        assert!(validate_interface_name("veth-peer").is_ok());
        assert!(validate_interface_name("tap_vm1").is_ok());

        // Names with dots
        assert!(validate_interface_name("eth0.100").is_ok()); // VLAN interface

        // Maximum length (15 chars)
        assert!(validate_interface_name("123456789012345").is_ok());
    }

    #[test]
    fn test_validate_interface_name_empty() {
        let result = validate_interface_name("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_interface_name_too_long() {
        // 16 characters - too long
        let result = validate_interface_name("1234567890123456");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum length"));

        // 20 characters - definitely too long
        let result = validate_interface_name("12345678901234567890");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_interface_name_invalid_chars() {
        // Space
        let result = validate_interface_name("eth 0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid character"));

        // Slash
        let result = validate_interface_name("eth/0");
        assert!(result.is_err());

        // Colon
        let result = validate_interface_name("eth:0");
        assert!(result.is_err());

        // At sign
        let result = validate_interface_name("eth@0");
        assert!(result.is_err());

        // Unicode
        let result = validate_interface_name("ethö0");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_interface_name_invalid_start() {
        // Cannot start with dash
        let result = validate_interface_name("-eth0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot start with"));

        // Cannot start with dot
        let result = validate_interface_name(".eth0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot start with"));
    }

    #[test]
    fn test_add_rule_rejects_invalid_input_interface() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                name: None,
                input_interface: "this_interface_name_is_way_too_long".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(),
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("Invalid input_interface"));
                assert!(msg.contains("exceeds maximum length"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
    }

    #[test]
    fn test_add_rule_rejects_invalid_output_interface() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                name: None,
                input_interface: "eth0".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "invalid/name".to_string(),
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("Invalid output_interface"));
                assert!(msg.contains("output[0]"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
    }

    // --- Port Number Validation Tests ---

    #[test]
    fn test_validate_port_valid() {
        assert!(validate_port(1, "test").is_ok());
        assert!(validate_port(80, "test").is_ok());
        assert!(validate_port(5000, "test").is_ok());
        assert!(validate_port(65535, "test").is_ok());
    }

    #[test]
    fn test_validate_port_zero() {
        let result = validate_port(0, "input_port");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("input_port"));
        assert!(err.contains("cannot be 0"));
        assert!(err.contains("1-65535"));
    }

    #[test]
    fn test_add_rule_rejects_zero_input_port() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                name: None,
                input_interface: "eth0".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 0, // Invalid
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(),
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("input_port"));
                assert!(msg.contains("cannot be 0"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
    }

    #[test]
    fn test_add_rule_rejects_zero_output_port() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                name: None,
                input_interface: "eth0".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 0, // Invalid
                    interface: "eth1".to_string(),
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
        );

        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("output[0].port"));
                assert!(msg.contains("cannot be 0"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
    }
}
