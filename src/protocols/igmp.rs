// SPDX-License-Identifier: Apache-2.0 OR MIT
//! IGMPv2 State Machine Implementation (RFC 2236)
//!
//! This module implements the IGMP querier functionality for tracking
//! multicast group membership on each interface.
//!
//! ## Key Features
//!
//! - **Querier Election**: Lower IP address wins
//! - **General Queries**: Periodic queries to all hosts
//! - **Group-Specific Queries**: Sent on Leave to verify no remaining members
//! - **Membership Tracking**: Learn which groups have active receivers
//!
//! ## Timers (RFC 2236 Defaults)
//!
//! | Timer | Default Value | Purpose |
//! |-------|--------------|---------|
//! | Query Interval | 125s | Time between General Queries |
//! | Query Response Interval | 10s | Max response time in queries |
//! | Group Membership Interval | 260s | Time to consider group inactive |
//! | Other Querier Present Interval | 255s | Time before assuming querier role |
//! | Last Member Query Interval | 1s | Time between group-specific queries |
//!
//! ## IGMP Message Types
//!
//! | Type | Value | Description |
//! |------|-------|-------------|
//! | Membership Query | 0x11 | Sent by querier |
//! | V1 Membership Report | 0x12 | Legacy (ignored) |
//! | V2 Membership Report | 0x16 | Host joined group |
//! | Leave Group | 0x17 | Host left group |

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::{PacketBuilder, TimerRequest, TimerType};

// IGMP message types
pub const IGMP_MEMBERSHIP_QUERY: u8 = 0x11;
pub const IGMP_V1_MEMBERSHIP_REPORT: u8 = 0x12;
pub const IGMP_V2_MEMBERSHIP_REPORT: u8 = 0x16;
pub const IGMP_LEAVE_GROUP: u8 = 0x17;

// Default timer values (RFC 2236)
pub const DEFAULT_QUERY_INTERVAL: Duration = Duration::from_secs(125);
pub const DEFAULT_QUERY_RESPONSE_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_ROBUSTNESS_VARIABLE: u8 = 2;
pub const DEFAULT_LAST_MEMBER_QUERY_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_LAST_MEMBER_QUERY_COUNT: u8 = 2;

/// All IGMP routers multicast address (224.0.0.1)
pub const ALL_HOSTS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

/// All IGMP routers address for Leave messages (224.0.0.2)
pub const ALL_ROUTERS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);

/// Compute Group Membership Interval (GMI)
/// GMI = (Robustness Variable * Query Interval) + Query Response Interval
pub fn group_membership_interval(
    robustness: u8,
    query_interval: Duration,
    query_response: Duration,
) -> Duration {
    query_interval * robustness as u32 + query_response
}

/// Compute Other Querier Present Interval
/// OQPI = (Robustness Variable * Query Interval) + (Query Response Interval / 2)
pub fn other_querier_present_interval(
    robustness: u8,
    query_interval: Duration,
    query_response: Duration,
) -> Duration {
    query_interval * robustness as u32 + query_response / 2
}

/// Configuration for IGMP on an interface
#[derive(Debug, Clone)]
pub struct IgmpConfig {
    /// Time between general queries when we are the querier
    pub query_interval: Duration,
    /// Maximum response time advertised in queries
    pub query_response_interval: Duration,
    /// Robustness variable (number of retransmissions)
    pub robustness_variable: u8,
    /// Time between group-specific queries after Leave
    pub last_member_query_interval: Duration,
    /// Number of group-specific queries to send after Leave
    pub last_member_query_count: u8,
}

impl Default for IgmpConfig {
    fn default() -> Self {
        Self {
            query_interval: DEFAULT_QUERY_INTERVAL,
            query_response_interval: DEFAULT_QUERY_RESPONSE_INTERVAL,
            robustness_variable: DEFAULT_ROBUSTNESS_VARIABLE,
            last_member_query_interval: DEFAULT_LAST_MEMBER_QUERY_INTERVAL,
            last_member_query_count: DEFAULT_LAST_MEMBER_QUERY_COUNT,
        }
    }
}

impl IgmpConfig {
    /// Compute the Group Membership Interval for this config
    pub fn group_membership_interval(&self) -> Duration {
        group_membership_interval(
            self.robustness_variable,
            self.query_interval,
            self.query_response_interval,
        )
    }

    /// Compute the Other Querier Present Interval for this config
    pub fn other_querier_present_interval(&self) -> Duration {
        other_querier_present_interval(
            self.robustness_variable,
            self.query_interval,
            self.query_response_interval,
        )
    }
}

/// Events that can occur in the IGMP state machine
#[derive(Debug, Clone)]
pub enum IgmpEvent {
    /// Enable IGMP querier on an interface
    EnableQuerier {
        interface: String,
        interface_ip: Ipv4Addr,
    },
    /// Disable IGMP querier on an interface
    DisableQuerier { interface: String },
    /// Received an IGMP packet
    PacketReceived {
        interface: String,
        src_ip: Ipv4Addr,
        msg_type: u8,
        max_resp_time: u8,
        group: Ipv4Addr,
    },
    /// Query timer expired - time to send a General Query
    QueryTimerExpired { interface: String },
    /// Other querier present timer expired - we become querier
    OtherQuerierExpired { interface: String },
    /// Group membership expired
    GroupExpired { interface: String, group: Ipv4Addr },
    /// Group-specific query timer expired
    GroupQueryExpired { interface: String, group: Ipv4Addr },
}

/// Group membership state on an interface
#[derive(Debug, Clone)]
pub struct GroupState {
    /// Multicast group address
    pub group: Ipv4Addr,
    /// When the membership expires
    pub expires_at: Instant,
    /// Last host to report membership
    pub last_reporter: Option<Ipv4Addr>,
    /// Pending group-specific queries remaining
    pub pending_queries: u8,
    /// Timer for group-specific query
    pub query_timer: Option<Instant>,
}

impl GroupState {
    /// Create new group state with the given expiry time
    pub fn new(group: Ipv4Addr, expires_at: Instant) -> Self {
        Self {
            group,
            expires_at,
            last_reporter: None,
            pending_queries: 0,
            query_timer: None,
        }
    }

    /// Check if membership has expired
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Refresh the membership expiry time
    pub fn refresh(&mut self, expires_at: Instant, reporter: Option<Ipv4Addr>) {
        self.expires_at = expires_at;
        if reporter.is_some() {
            self.last_reporter = reporter;
        }
        // Cancel any pending group-specific queries
        self.pending_queries = 0;
        self.query_timer = None;
    }
}

/// Per-interface IGMP state
#[derive(Debug)]
pub struct InterfaceIgmpState {
    /// Interface name
    pub interface: String,
    /// Our IP address on this interface
    pub interface_ip: Ipv4Addr,
    /// Configuration
    pub config: IgmpConfig,
    /// Whether we are the elected querier
    pub is_querier: bool,
    /// Other querier's IP and when it expires
    pub other_querier: Option<(Ipv4Addr, Instant)>,
    /// Active group memberships on this interface
    pub groups: HashMap<Ipv4Addr, GroupState>,
    /// When the next general query should be sent (if we're querier)
    pub next_query_time: Option<Instant>,
}

impl InterfaceIgmpState {
    /// Create new IGMP state for an interface
    pub fn new(interface: String, interface_ip: Ipv4Addr, config: IgmpConfig) -> Self {
        Self {
            interface,
            interface_ip,
            config,
            is_querier: true, // Assume querier until we hear from another
            other_querier: None,
            groups: HashMap::new(),
            next_query_time: None,
        }
    }

    /// Get the current querier IP (us or other)
    pub fn querier_ip(&self) -> Ipv4Addr {
        if let Some((ip, _)) = self.other_querier {
            ip
        } else {
            self.interface_ip
        }
    }

    /// Check if we should be querier (lower IP wins)
    fn should_be_querier(&self, other_ip: Ipv4Addr) -> bool {
        // Lower IP address wins the election
        self.interface_ip < other_ip
    }

    /// Handle receiving a query from another querier
    pub fn received_query(&mut self, src_ip: Ipv4Addr, now: Instant) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        if src_ip == self.interface_ip {
            // Ignore our own queries
            return timers;
        }

        // Querier election: lower IP wins
        if !self.should_be_querier(src_ip) {
            // Other querier has lower IP - step down
            self.is_querier = false;
            let expiry = now + self.config.other_querier_present_interval();
            self.other_querier = Some((src_ip, expiry));

            // Schedule timer to reclaim querier role if other goes silent
            timers.push(TimerRequest {
                timer_type: TimerType::IgmpOtherQuerierPresent {
                    interface: self.interface.clone(),
                },
                fire_at: expiry,
                replace_existing: true,
            });
        }

        timers
    }

    /// Handle receiving a membership report
    pub fn received_report(
        &mut self,
        src_ip: Ipv4Addr,
        group: Ipv4Addr,
        now: Instant,
    ) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        // Ignore reports for all-hosts group or router groups
        if group == ALL_HOSTS_GROUP || group == ALL_ROUTERS_GROUP {
            return timers;
        }

        // Ignore non-multicast groups
        if !group.is_multicast() {
            return timers;
        }

        let expiry = now + self.config.group_membership_interval();

        if let Some(state) = self.groups.get_mut(&group) {
            // Refresh existing membership
            state.refresh(expiry, Some(src_ip));
        } else {
            // New group membership
            let mut state = GroupState::new(group, expiry);
            state.last_reporter = Some(src_ip);
            self.groups.insert(group, state);
        }

        // Schedule expiry timer
        timers.push(TimerRequest {
            timer_type: TimerType::IgmpGroupExpiry {
                interface: self.interface.clone(),
                group,
            },
            fire_at: expiry,
            replace_existing: true,
        });

        timers
    }

    /// Handle receiving a Leave message
    pub fn received_leave(&mut self, group: Ipv4Addr, now: Instant) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        // Only the querier sends group-specific queries
        if !self.is_querier {
            return timers;
        }

        // Check if we have this group
        if let Some(state) = self.groups.get_mut(&group) {
            // Start group-specific query process
            state.pending_queries = self.config.last_member_query_count;
            let query_time = now + self.config.last_member_query_interval;
            state.query_timer = Some(query_time);

            timers.push(TimerRequest {
                timer_type: TimerType::IgmpGroupQuery {
                    interface: self.interface.clone(),
                    group,
                },
                fire_at: query_time,
                replace_existing: true,
            });
        }

        timers
    }

    /// Handle group-specific query timer expiry
    pub fn group_query_expired(
        &mut self,
        group: Ipv4Addr,
        now: Instant,
    ) -> (Vec<TimerRequest>, bool) {
        let mut timers = Vec::new();
        let mut send_query = false;

        if let Some(state) = self.groups.get_mut(&group) {
            if state.pending_queries > 0 {
                state.pending_queries -= 1;
                send_query = true;

                if state.pending_queries > 0 {
                    // Schedule next group-specific query
                    let query_time = now + self.config.last_member_query_interval;
                    state.query_timer = Some(query_time);

                    timers.push(TimerRequest {
                        timer_type: TimerType::IgmpGroupQuery {
                            interface: self.interface.clone(),
                            group,
                        },
                        fire_at: query_time,
                        replace_existing: true,
                    });
                } else {
                    // Last query - schedule final expiry check
                    let expiry = now
                        + self.config.last_member_query_interval
                            * self.config.robustness_variable as u32;
                    state.expires_at = expiry;

                    timers.push(TimerRequest {
                        timer_type: TimerType::IgmpGroupExpiry {
                            interface: self.interface.clone(),
                            group,
                        },
                        fire_at: expiry,
                        replace_existing: true,
                    });
                }
            }
        }

        (timers, send_query)
    }

    /// Handle other querier present timer expiry
    pub fn other_querier_expired(&mut self, now: Instant) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        // Become querier again
        self.is_querier = true;
        self.other_querier = None;

        // Schedule first general query
        let query_time = now; // Send immediately
        self.next_query_time = Some(query_time);

        timers.push(TimerRequest {
            timer_type: TimerType::IgmpGeneralQuery {
                interface: self.interface.clone(),
            },
            fire_at: query_time,
            replace_existing: true,
        });

        timers
    }

    /// Handle general query timer expiry
    pub fn query_timer_expired(&mut self, now: Instant) -> Vec<TimerRequest> {
        let mut timers = Vec::new();

        if !self.is_querier {
            return timers;
        }

        // Schedule next general query
        let next_query = now + self.config.query_interval;
        self.next_query_time = Some(next_query);

        timers.push(TimerRequest {
            timer_type: TimerType::IgmpGeneralQuery {
                interface: self.interface.clone(),
            },
            fire_at: next_query,
            replace_existing: true,
        });

        timers
    }

    /// Handle group membership expiry
    pub fn group_expired(&mut self, group: Ipv4Addr, now: Instant) -> bool {
        if let Some(state) = self.groups.get(&group) {
            if state.is_expired(now) {
                self.groups.remove(&group);
                return true;
            }
        }
        false
    }

    /// Get all active groups on this interface
    pub fn active_groups(&self) -> Vec<Ipv4Addr> {
        self.groups.keys().copied().collect()
    }

    /// Clean up expired memberships
    pub fn cleanup_expired(&mut self, now: Instant) -> Vec<Ipv4Addr> {
        let expired: Vec<Ipv4Addr> = self
            .groups
            .iter()
            .filter(|(_, state)| state.is_expired(now))
            .map(|(group, _)| *group)
            .collect();

        for group in &expired {
            self.groups.remove(group);
        }

        expired
    }
}

/// Builder for IGMP Membership Query packets
#[derive(Debug)]
pub struct IgmpQueryBuilder {
    /// Max response time (in 1/10 seconds)
    pub max_resp_time: u8,
    /// Group address (0.0.0.0 for general query)
    pub group: Ipv4Addr,
}

impl IgmpQueryBuilder {
    /// Create a general query (all groups)
    pub fn general_query(max_resp_time_tenths: u8) -> Self {
        Self {
            max_resp_time: max_resp_time_tenths,
            group: Ipv4Addr::UNSPECIFIED,
        }
    }

    /// Create a group-specific query
    pub fn group_specific_query(group: Ipv4Addr, max_resp_time_tenths: u8) -> Self {
        Self {
            max_resp_time: max_resp_time_tenths,
            group,
        }
    }
}

impl PacketBuilder for IgmpQueryBuilder {
    fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8);

        // Type: Membership Query (0x11)
        packet.push(IGMP_MEMBERSHIP_QUERY);

        // Max Response Time
        packet.push(self.max_resp_time);

        // Checksum placeholder
        packet.push(0);
        packet.push(0);

        // Group Address
        packet.extend_from_slice(&self.group.octets());

        // Calculate and insert checksum
        let checksum = self.calculate_checksum(&packet);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = (checksum & 0xFF) as u8;

        packet
    }
}

/// Builder for IGMP Membership Report packets
#[derive(Debug)]
pub struct IgmpReportBuilder {
    /// Group address being reported
    pub group: Ipv4Addr,
}

impl IgmpReportBuilder {
    /// Create a new membership report
    pub fn new(group: Ipv4Addr) -> Self {
        Self { group }
    }
}

impl PacketBuilder for IgmpReportBuilder {
    fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8);

        // Type: V2 Membership Report (0x16)
        packet.push(IGMP_V2_MEMBERSHIP_REPORT);

        // Max Response Time (unused, set to 0)
        packet.push(0);

        // Checksum placeholder
        packet.push(0);
        packet.push(0);

        // Group Address
        packet.extend_from_slice(&self.group.octets());

        // Calculate and insert checksum
        let checksum = self.calculate_checksum(&packet);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = (checksum & 0xFF) as u8;

        packet
    }
}

/// Builder for IGMP Leave Group packets
#[derive(Debug)]
pub struct IgmpLeaveBuilder {
    /// Group address being left
    pub group: Ipv4Addr,
}

impl IgmpLeaveBuilder {
    /// Create a new leave message
    pub fn new(group: Ipv4Addr) -> Self {
        Self { group }
    }
}

impl PacketBuilder for IgmpLeaveBuilder {
    fn build(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8);

        // Type: Leave Group (0x17)
        packet.push(IGMP_LEAVE_GROUP);

        // Max Response Time (unused, set to 0)
        packet.push(0);

        // Checksum placeholder
        packet.push(0);
        packet.push(0);

        // Group Address
        packet.extend_from_slice(&self.group.octets());

        // Calculate and insert checksum
        let checksum = self.calculate_checksum(&packet);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = (checksum & 0xFF) as u8;

        packet
    }
}

/// Parsed IGMP header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpHeader {
    /// Message type
    pub msg_type: u8,
    /// Max response time (in 1/10 seconds) - only meaningful for queries
    pub max_resp_time: u8,
    /// Checksum
    pub checksum: u16,
    /// Group address
    pub group: Ipv4Addr,
}

impl IgmpHeader {
    /// Parse an IGMP header from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        Some(Self {
            msg_type: data[0],
            max_resp_time: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            group: Ipv4Addr::new(data[4], data[5], data[6], data[7]),
        })
    }

    /// Check if this is a general query (group = 0.0.0.0)
    pub fn is_general_query(&self) -> bool {
        self.msg_type == IGMP_MEMBERSHIP_QUERY && self.group == Ipv4Addr::UNSPECIFIED
    }

    /// Check if this is a group-specific query
    pub fn is_group_specific_query(&self) -> bool {
        self.msg_type == IGMP_MEMBERSHIP_QUERY && self.group != Ipv4Addr::UNSPECIFIED
    }

    /// Get the message type as a string
    pub fn type_name(&self) -> &'static str {
        match self.msg_type {
            IGMP_MEMBERSHIP_QUERY => "Membership Query",
            IGMP_V1_MEMBERSHIP_REPORT => "V1 Membership Report",
            IGMP_V2_MEMBERSHIP_REPORT => "V2 Membership Report",
            IGMP_LEAVE_GROUP => "Leave Group",
            _ => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IgmpConfig::default();
        assert_eq!(config.query_interval, Duration::from_secs(125));
        assert_eq!(config.robustness_variable, 2);
    }

    #[test]
    fn test_group_membership_interval() {
        let config = IgmpConfig::default();
        let gmi = config.group_membership_interval();
        // GMI = (2 * 125s) + 10s = 260s
        assert_eq!(gmi, Duration::from_secs(260));
    }

    #[test]
    fn test_other_querier_present_interval() {
        let config = IgmpConfig::default();
        let oqpi = config.other_querier_present_interval();
        // OQPI = (2 * 125s) + (10s / 2) = 255s
        assert_eq!(oqpi, Duration::from_secs(255));
    }

    #[test]
    fn test_interface_state_new() {
        let state = InterfaceIgmpState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            IgmpConfig::default(),
        );

        assert_eq!(state.interface, "eth0");
        assert!(state.is_querier);
        assert!(state.other_querier.is_none());
        assert!(state.groups.is_empty());
    }

    #[test]
    fn test_querier_election() {
        let mut state = InterfaceIgmpState::new(
            "eth0".to_string(),
            "192.168.1.10".parse().unwrap(),
            IgmpConfig::default(),
        );

        let now = Instant::now();

        // Receive query from lower IP - should step down
        let timers = state.received_query("192.168.1.5".parse().unwrap(), now);
        assert!(!state.is_querier);
        assert!(state.other_querier.is_some());
        assert!(!timers.is_empty());

        // Receive query from higher IP - should remain non-querier
        let _ = state.received_query("192.168.1.15".parse().unwrap(), now);
        assert!(!state.is_querier);
    }

    #[test]
    fn test_membership_report() {
        let mut state = InterfaceIgmpState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            IgmpConfig::default(),
        );

        let now = Instant::now();
        let group: Ipv4Addr = "239.1.1.1".parse().unwrap();

        let timers = state.received_report("192.168.1.100".parse().unwrap(), group, now);

        assert_eq!(state.groups.len(), 1);
        assert!(state.groups.contains_key(&group));
        assert!(!timers.is_empty());
    }

    #[test]
    fn test_leave_handling() {
        let mut state = InterfaceIgmpState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            IgmpConfig::default(),
        );

        let now = Instant::now();
        let group: Ipv4Addr = "239.1.1.1".parse().unwrap();

        // First add membership
        state.received_report("192.168.1.100".parse().unwrap(), group, now);

        // Then process leave
        let timers = state.received_leave(group, now);

        assert!(!timers.is_empty());
        assert!(state.groups.get(&group).unwrap().pending_queries > 0);
    }

    #[test]
    fn test_igmp_header_parse() {
        // General query: type=0x11, max_resp=100 (10s), checksum=0, group=0.0.0.0
        let data = [0x11, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let header = IgmpHeader::parse(&data).unwrap();

        assert_eq!(header.msg_type, IGMP_MEMBERSHIP_QUERY);
        assert_eq!(header.max_resp_time, 100);
        assert!(header.is_general_query());
        assert!(!header.is_group_specific_query());
    }

    #[test]
    fn test_igmp_header_parse_group_specific() {
        // Group-specific query for 239.1.1.1
        let data = [0x11, 0x64, 0x00, 0x00, 239, 1, 1, 1];
        let header = IgmpHeader::parse(&data).unwrap();

        assert!(header.is_group_specific_query());
        assert!(!header.is_general_query());
        assert_eq!(header.group, "239.1.1.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_query_builder_general() {
        let builder = IgmpQueryBuilder::general_query(100);
        let packet = builder.build();

        assert_eq!(packet.len(), 8);
        assert_eq!(packet[0], IGMP_MEMBERSHIP_QUERY);
        assert_eq!(packet[1], 100);
        // Group should be 0.0.0.0
        assert_eq!(&packet[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_query_builder_group_specific() {
        let builder = IgmpQueryBuilder::group_specific_query("239.2.2.2".parse().unwrap(), 10);
        let packet = builder.build();

        assert_eq!(packet.len(), 8);
        assert_eq!(packet[0], IGMP_MEMBERSHIP_QUERY);
        assert_eq!(&packet[4..8], &[239, 2, 2, 2]);
    }

    #[test]
    fn test_report_builder() {
        let builder = IgmpReportBuilder::new("239.3.3.3".parse().unwrap());
        let packet = builder.build();

        assert_eq!(packet.len(), 8);
        assert_eq!(packet[0], IGMP_V2_MEMBERSHIP_REPORT);
        assert_eq!(&packet[4..8], &[239, 3, 3, 3]);
    }

    #[test]
    fn test_leave_builder() {
        let builder = IgmpLeaveBuilder::new("239.4.4.4".parse().unwrap());
        let packet = builder.build();

        assert_eq!(packet.len(), 8);
        assert_eq!(packet[0], IGMP_LEAVE_GROUP);
        assert_eq!(&packet[4..8], &[239, 4, 4, 4]);
    }

    #[test]
    fn test_ignore_special_groups() {
        let mut state = InterfaceIgmpState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            IgmpConfig::default(),
        );

        let now = Instant::now();

        // Report for all-hosts should be ignored
        state.received_report("192.168.1.100".parse().unwrap(), ALL_HOSTS_GROUP, now);
        assert!(state.groups.is_empty());

        // Report for all-routers should be ignored
        state.received_report("192.168.1.100".parse().unwrap(), ALL_ROUTERS_GROUP, now);
        assert!(state.groups.is_empty());

        // Report for non-multicast should be ignored
        state.received_report(
            "192.168.1.100".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            now,
        );
        assert!(state.groups.is_empty());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut state = InterfaceIgmpState::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            IgmpConfig::default(),
        );

        // Add a group that will expire
        let group: Ipv4Addr = "239.1.1.1".parse().unwrap();
        let expired_time = Instant::now() - Duration::from_secs(1);
        state
            .groups
            .insert(group, GroupState::new(group, expired_time));

        // Add a group that won't expire
        let valid_group: Ipv4Addr = "239.2.2.2".parse().unwrap();
        state.groups.insert(
            valid_group,
            GroupState::new(valid_group, Instant::now() + Duration::from_secs(260)),
        );

        let expired = state.cleanup_expired(Instant::now());
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], group);
        assert_eq!(state.groups.len(), 1);
        assert!(state.groups.contains_key(&valid_group));
    }
}
