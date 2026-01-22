// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Multicast Routing Information Base (MRIB)
//!
//! This module provides a unified abstraction for multicast routing that merges
//! static forwarding rules with protocol-learned routes from PIM and IGMP.
//!
//! ## Design Principles
//!
//! 1. **Static rules are explicit operator intent** - they always take precedence
//! 2. **PIM/IGMP are learned routes** - they fill gaps where no static rules exist
//! 3. **Union semantics for outputs** - static and dynamic outputs are merged
//! 4. **Unified view** - single interface for all routing sources
//!
//! ## Route Priority (highest to lowest)
//!
//! 1. Static rules (from config file)
//! 2. PIM (S,G) routes (source-specific shortest-path trees)
//! 3. PIM (*,G) routes (shared trees rooted at RP)
//! 4. IGMP-learned membership (local receiver interest)

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::{ForwardingRule, OutputDestination, PimTreeType, RuleSource};

/// PIM (*,G) shared tree state
#[derive(Debug, Clone)]
pub struct StarGRoute {
    /// Multicast group address
    pub group: Ipv4Addr,
    /// RP (Rendezvous Point) for this group
    pub rp: Ipv4Addr,
    /// Interface toward the RP (upstream)
    pub upstream_interface: Option<String>,
    /// Interfaces with downstream receivers or PIM neighbors
    pub downstream_interfaces: HashSet<String>,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry expires (if no refresh)
    pub expires_at: Option<Instant>,
}

impl StarGRoute {
    /// Create a new (*,G) route
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
    pub fn add_downstream(&mut self, interface: &str) {
        self.downstream_interfaces.insert(interface.to_string());
    }

    /// Remove a downstream interface
    pub fn remove_downstream(&mut self, interface: &str) {
        self.downstream_interfaces.remove(interface);
    }

    /// Check if this route has any downstream interfaces
    pub fn has_downstream(&self) -> bool {
        !self.downstream_interfaces.is_empty()
    }

    /// Convert to forwarding rules for a specific input interface and port
    pub fn to_forwarding_rules(&self, input_interface: &str, port: u16) -> Vec<ForwardingRule> {
        if self.downstream_interfaces.is_empty() {
            return Vec::new();
        }

        let outputs: Vec<OutputDestination> = self
            .downstream_interfaces
            .iter()
            .map(|iface| OutputDestination {
                group: self.group,
                port,
                interface: iface.clone(),
            })
            .collect();

        let rule_id = format!("pim-star-g-{}-{}-{}", input_interface, self.group, port);

        vec![ForwardingRule {
            rule_id,
            name: Some(format!("(*,{}) PIM shared tree", self.group)),
            input_interface: input_interface.to_string(),
            input_group: self.group,
            input_port: port,
            input_source: None, // (*,G) matches any source
            outputs,
            source: RuleSource::Pim {
                tree_type: PimTreeType::StarG,
                created_at: self.created_at.elapsed().as_secs().saturating_add(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .saturating_sub(self.created_at.elapsed().as_secs()),
                ),
            },
        }]
    }
}

/// PIM (S,G) shortest-path tree state
#[derive(Debug, Clone)]
pub struct SGRoute {
    /// Source IP address
    pub source: Ipv4Addr,
    /// Multicast group address
    pub group: Ipv4Addr,
    /// Interface toward the source (upstream)
    pub upstream_interface: Option<String>,
    /// Interfaces with downstream receivers
    pub downstream_interfaces: HashSet<String>,
    /// Whether SPT (shortest-path tree) bit is set
    pub spt_bit: bool,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry expires (if no refresh)
    pub expires_at: Option<Instant>,
}

impl SGRoute {
    /// Create a new (S,G) route
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
    pub fn add_downstream(&mut self, interface: &str) {
        self.downstream_interfaces.insert(interface.to_string());
    }

    /// Remove a downstream interface
    pub fn remove_downstream(&mut self, interface: &str) {
        self.downstream_interfaces.remove(interface);
    }

    /// Check if this route has any downstream interfaces
    pub fn has_downstream(&self) -> bool {
        !self.downstream_interfaces.is_empty()
    }

    /// Convert to forwarding rules for a specific input interface and port
    pub fn to_forwarding_rules(&self, input_interface: &str, port: u16) -> Vec<ForwardingRule> {
        if self.downstream_interfaces.is_empty() {
            return Vec::new();
        }

        let outputs: Vec<OutputDestination> = self
            .downstream_interfaces
            .iter()
            .map(|iface| OutputDestination {
                group: self.group,
                port,
                interface: iface.clone(),
            })
            .collect();

        let rule_id = format!(
            "pim-sg-{}-{}-{}-{}",
            input_interface, self.source, self.group, port
        );

        vec![ForwardingRule {
            rule_id,
            name: Some(format!("({},{}) PIM SPT", self.source, self.group)),
            input_interface: input_interface.to_string(),
            input_group: self.group,
            input_port: port,
            input_source: Some(self.source), // (S,G) matches specific source
            outputs,
            source: RuleSource::Pim {
                tree_type: PimTreeType::SG,
                created_at: self.created_at.elapsed().as_secs().saturating_add(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .saturating_sub(self.created_at.elapsed().as_secs()),
                ),
            },
        }]
    }
}

/// IGMP group membership on an interface
#[derive(Debug, Clone)]
pub struct IgmpMembership {
    /// Multicast group address
    pub group: Ipv4Addr,
    /// When this membership expires
    pub expires_at: Instant,
    /// IP address of the last host that reported membership
    pub last_reporter: Option<Ipv4Addr>,
}

/// Multicast Routing Information Base (MRIB)
///
/// Unified table for static rules and protocol-learned routes.
/// Provides methods to merge different route sources and compile
/// forwarding rules for the data plane.
#[derive(Debug, Default)]
pub struct MulticastRib {
    /// Static forwarding rules (from config/CLI), keyed by rule_id
    pub static_rules: HashMap<String, ForwardingRule>,

    /// PIM-learned (*,G) entries, keyed by group address
    pub star_g_routes: HashMap<Ipv4Addr, StarGRoute>,

    /// PIM-learned (S,G) entries, keyed by (source, group) tuple
    pub sg_routes: HashMap<(Ipv4Addr, Ipv4Addr), SGRoute>,

    /// IGMP group membership per interface, keyed by interface name
    /// Value is a map of group -> membership info
    pub igmp_membership: HashMap<String, HashMap<Ipv4Addr, IgmpMembership>>,
}

impl MulticastRib {
    /// Create a new empty MRIB
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a static rule
    pub fn add_static_rule(&mut self, rule: ForwardingRule) {
        self.static_rules.insert(rule.rule_id.clone(), rule);
    }

    /// Remove a static rule by ID
    pub fn remove_static_rule(&mut self, rule_id: &str) -> Option<ForwardingRule> {
        self.static_rules.remove(rule_id)
    }

    /// Get a static rule by ID
    pub fn get_static_rule(&self, rule_id: &str) -> Option<&ForwardingRule> {
        self.static_rules.get(rule_id)
    }

    /// Add or update a (*,G) route
    pub fn add_star_g_route(&mut self, route: StarGRoute) {
        self.star_g_routes.insert(route.group, route);
    }

    /// Get a (*,G) route
    pub fn get_star_g_route(&self, group: Ipv4Addr) -> Option<&StarGRoute> {
        self.star_g_routes.get(&group)
    }

    /// Get a mutable (*,G) route
    pub fn get_star_g_route_mut(&mut self, group: Ipv4Addr) -> Option<&mut StarGRoute> {
        self.star_g_routes.get_mut(&group)
    }

    /// Remove a (*,G) route
    pub fn remove_star_g_route(&mut self, group: Ipv4Addr) -> Option<StarGRoute> {
        self.star_g_routes.remove(&group)
    }

    /// Add or update an (S,G) route
    pub fn add_sg_route(&mut self, route: SGRoute) {
        self.sg_routes.insert((route.source, route.group), route);
    }

    /// Get an (S,G) route
    pub fn get_sg_route(&self, source: Ipv4Addr, group: Ipv4Addr) -> Option<&SGRoute> {
        self.sg_routes.get(&(source, group))
    }

    /// Get a mutable (S,G) route
    pub fn get_sg_route_mut(&mut self, source: Ipv4Addr, group: Ipv4Addr) -> Option<&mut SGRoute> {
        self.sg_routes.get_mut(&(source, group))
    }

    /// Remove an (S,G) route
    pub fn remove_sg_route(&mut self, source: Ipv4Addr, group: Ipv4Addr) -> Option<SGRoute> {
        self.sg_routes.remove(&(source, group))
    }

    /// Add IGMP membership for a group on an interface
    pub fn add_igmp_membership(
        &mut self,
        interface: &str,
        group: Ipv4Addr,
        membership: IgmpMembership,
    ) {
        self.igmp_membership
            .entry(interface.to_string())
            .or_default()
            .insert(group, membership);
    }

    /// Remove IGMP membership for a group on an interface
    pub fn remove_igmp_membership(
        &mut self,
        interface: &str,
        group: Ipv4Addr,
    ) -> Option<IgmpMembership> {
        self.igmp_membership
            .get_mut(interface)
            .and_then(|groups| groups.remove(&group))
    }

    /// Get all interfaces with IGMP membership for a group
    pub fn get_igmp_interfaces_for_group(&self, group: Ipv4Addr) -> Vec<String> {
        self.igmp_membership
            .iter()
            .filter(|(_, groups)| groups.contains_key(&group))
            .map(|(iface, _)| iface.clone())
            .collect()
    }

    /// Check if there's a static rule for a specific (interface, group, port) tuple
    pub fn has_static_rule_for(&self, interface: &str, group: Ipv4Addr, port: u16) -> bool {
        self.static_rules.values().any(|r| {
            r.input_interface == interface && r.input_group == group && r.input_port == port
        })
    }

    /// Check if there's any static rule for a group (any interface/port)
    pub fn has_static_rule_for_group(&self, group: Ipv4Addr) -> bool {
        self.static_rules.values().any(|r| r.input_group == group)
    }

    /// Compile all routes into forwarding rules for distribution to workers.
    ///
    /// This merges static rules with PIM and IGMP learned routes using union semantics:
    /// - Static rule outputs + IGMP-joined interfaces
    /// - Static rule outputs + PIM downstream interfaces
    /// - (S,G) is more specific than (*,G) for the same group
    ///
    /// The resulting rules can be sent to workers via SyncRules command.
    pub fn compile_forwarding_rules(&self) -> Vec<ForwardingRule> {
        let mut rules = Vec::new();

        // 1. Add all static rules (highest priority)
        for rule in self.static_rules.values() {
            rules.push(rule.clone());
        }

        // 2. Add PIM (S,G) routes
        // These are source-specific and don't conflict with static rules
        // (static rules typically don't have input_source set)
        for sg_route in self.sg_routes.values() {
            // Use the upstream interface as input, if set
            if let Some(ref upstream) = sg_route.upstream_interface {
                // For now, use port 0 as placeholder - will be refined when
                // we integrate with actual PIM state machine
                let port = 0;
                let mut sg_rules = sg_route.to_forwarding_rules(upstream, port);
                rules.append(&mut sg_rules);
            }
        }

        // 3. Add PIM (*,G) routes where no static rule conflicts
        for star_g_route in self.star_g_routes.values() {
            // Skip if there's a static rule for this group
            if self.has_static_rule_for_group(star_g_route.group) {
                continue;
            }

            if let Some(ref upstream) = star_g_route.upstream_interface {
                let port = 0;
                let mut star_g_rules = star_g_route.to_forwarding_rules(upstream, port);
                rules.append(&mut star_g_rules);
            }
        }

        // 4. TODO: Merge IGMP membership with existing rules
        // For each (interface, group) with IGMP membership:
        // - If there's a static rule, add IGMP interface to outputs
        // - If there's a PIM route, add IGMP interface to outputs
        // - If neither, create a new rule (requires upstream configuration)

        rules
    }

    /// Filter forwarding rules to only those relevant for a specific interface.
    ///
    /// This is used when distributing rules to workers - each worker only needs
    /// rules where `input_interface` matches its bound interface.
    pub fn filter_rules_for_interface(&self, interface: &str) -> Vec<ForwardingRule> {
        self.compile_forwarding_rules()
            .into_iter()
            .filter(|r| r.input_interface == interface)
            .collect()
    }

    /// Get all unique input interfaces from the routing table
    pub fn get_input_interfaces(&self) -> HashSet<String> {
        let mut interfaces = HashSet::new();

        for rule in self.static_rules.values() {
            interfaces.insert(rule.input_interface.clone());
        }

        for star_g in self.star_g_routes.values() {
            if let Some(ref upstream) = star_g.upstream_interface {
                interfaces.insert(upstream.clone());
            }
        }

        for sg in self.sg_routes.values() {
            if let Some(ref upstream) = sg.upstream_interface {
                interfaces.insert(upstream.clone());
            }
        }

        interfaces
    }

    /// Clean up expired entries (IGMP memberships, PIM routes)
    pub fn cleanup_expired(&mut self, now: Instant) {
        // Clean up expired IGMP memberships
        for (_, groups) in self.igmp_membership.iter_mut() {
            groups.retain(|_, membership| membership.expires_at > now);
        }
        // Remove interfaces with no memberships
        self.igmp_membership.retain(|_, groups| !groups.is_empty());

        // Clean up expired (*,G) routes
        self.star_g_routes
            .retain(|_, route| route.expires_at.is_none_or(|expires| expires > now));

        // Clean up expired (S,G) routes
        self.sg_routes
            .retain(|_, route| route.expires_at.is_none_or(|expires| expires > now));
    }

    /// Get summary statistics about the routing table
    pub fn stats(&self) -> MribStats {
        MribStats {
            static_rules: self.static_rules.len(),
            star_g_routes: self.star_g_routes.len(),
            sg_routes: self.sg_routes.len(),
            igmp_memberships: self.igmp_membership.values().map(|g| g.len()).sum(),
            igmp_interfaces: self.igmp_membership.len(),
        }
    }
}

/// Statistics about the MRIB
#[derive(Debug, Clone, Default)]
pub struct MribStats {
    /// Number of static forwarding rules
    pub static_rules: usize,
    /// Number of (*,G) PIM routes
    pub star_g_routes: usize,
    /// Number of (S,G) PIM routes
    pub sg_routes: usize,
    /// Total number of IGMP group memberships
    pub igmp_memberships: usize,
    /// Number of interfaces with IGMP memberships
    pub igmp_interfaces: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_static_rule(
        id: &str,
        interface: &str,
        group: &str,
        port: u16,
    ) -> ForwardingRule {
        ForwardingRule {
            rule_id: id.to_string(),
            name: Some(format!("Test rule {}", id)),
            input_interface: interface.to_string(),
            input_group: group.parse().unwrap(),
            input_port: port,
            input_source: None,
            outputs: vec![OutputDestination {
                group: group.parse().unwrap(),
                port,
                interface: "eth1".to_string(),
            }],
            source: RuleSource::Static,
        }
    }

    #[test]
    fn test_mrib_new() {
        let mrib = MulticastRib::new();
        assert!(mrib.static_rules.is_empty());
        assert!(mrib.star_g_routes.is_empty());
        assert!(mrib.sg_routes.is_empty());
        assert!(mrib.igmp_membership.is_empty());
    }

    #[test]
    fn test_static_rule_crud() {
        let mut mrib = MulticastRib::new();

        let rule = create_test_static_rule("rule1", "eth0", "239.1.1.1", 5000);
        mrib.add_static_rule(rule.clone());

        assert_eq!(mrib.static_rules.len(), 1);
        assert!(mrib.get_static_rule("rule1").is_some());
        assert!(mrib.has_static_rule_for("eth0", "239.1.1.1".parse().unwrap(), 5000));
        assert!(mrib.has_static_rule_for_group("239.1.1.1".parse().unwrap()));

        let removed = mrib.remove_static_rule("rule1");
        assert!(removed.is_some());
        assert!(mrib.static_rules.is_empty());
    }

    #[test]
    fn test_star_g_route() {
        let mut mrib = MulticastRib::new();

        let mut route = StarGRoute::new("239.2.2.2".parse().unwrap(), "10.0.0.1".parse().unwrap());
        route.upstream_interface = Some("eth0".to_string());
        route.add_downstream("eth1");
        route.add_downstream("eth2");

        mrib.add_star_g_route(route);

        let retrieved = mrib.get_star_g_route("239.2.2.2".parse().unwrap());
        assert!(retrieved.is_some());
        let r = retrieved.unwrap();
        assert_eq!(r.downstream_interfaces.len(), 2);
        assert!(r.has_downstream());
    }

    #[test]
    fn test_sg_route() {
        let mut mrib = MulticastRib::new();

        let mut route = SGRoute::new("10.0.0.5".parse().unwrap(), "239.3.3.3".parse().unwrap());
        route.upstream_interface = Some("eth0".to_string());
        route.add_downstream("eth1");

        mrib.add_sg_route(route);

        let retrieved =
            mrib.get_sg_route("10.0.0.5".parse().unwrap(), "239.3.3.3".parse().unwrap());
        assert!(retrieved.is_some());
        let r = retrieved.unwrap();
        assert_eq!(r.source, "10.0.0.5".parse::<Ipv4Addr>().unwrap());
        assert!(r.has_downstream());
    }

    #[test]
    fn test_igmp_membership() {
        let mut mrib = MulticastRib::new();

        let membership = IgmpMembership {
            group: "239.4.4.4".parse().unwrap(),
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: Some("192.168.1.100".parse().unwrap()),
        };

        mrib.add_igmp_membership("eth1", "239.4.4.4".parse().unwrap(), membership);

        let interfaces = mrib.get_igmp_interfaces_for_group("239.4.4.4".parse().unwrap());
        assert_eq!(interfaces, vec!["eth1"]);

        // Add another interface
        let membership2 = IgmpMembership {
            group: "239.4.4.4".parse().unwrap(),
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: Some("192.168.2.100".parse().unwrap()),
        };
        mrib.add_igmp_membership("eth2", "239.4.4.4".parse().unwrap(), membership2);

        let interfaces = mrib.get_igmp_interfaces_for_group("239.4.4.4".parse().unwrap());
        assert_eq!(interfaces.len(), 2);
    }

    #[test]
    fn test_compile_forwarding_rules_static_only() {
        let mut mrib = MulticastRib::new();

        mrib.add_static_rule(create_test_static_rule("rule1", "eth0", "239.1.1.1", 5000));
        mrib.add_static_rule(create_test_static_rule("rule2", "eth0", "239.2.2.2", 5001));

        let rules = mrib.compile_forwarding_rules();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_filter_rules_for_interface() {
        let mut mrib = MulticastRib::new();

        mrib.add_static_rule(create_test_static_rule("rule1", "eth0", "239.1.1.1", 5000));
        mrib.add_static_rule(create_test_static_rule("rule2", "eth1", "239.2.2.2", 5001));
        mrib.add_static_rule(create_test_static_rule("rule3", "eth0", "239.3.3.3", 5002));

        let eth0_rules = mrib.filter_rules_for_interface("eth0");
        assert_eq!(eth0_rules.len(), 2);
        assert!(eth0_rules.iter().all(|r| r.input_interface == "eth0"));

        let eth1_rules = mrib.filter_rules_for_interface("eth1");
        assert_eq!(eth1_rules.len(), 1);
    }

    #[test]
    fn test_get_input_interfaces() {
        let mut mrib = MulticastRib::new();

        mrib.add_static_rule(create_test_static_rule("rule1", "eth0", "239.1.1.1", 5000));
        mrib.add_static_rule(create_test_static_rule("rule2", "eth1", "239.2.2.2", 5001));

        let interfaces = mrib.get_input_interfaces();
        assert_eq!(interfaces.len(), 2);
        assert!(interfaces.contains("eth0"));
        assert!(interfaces.contains("eth1"));
    }

    #[test]
    fn test_star_g_to_forwarding_rules() {
        let mut route = StarGRoute::new("239.5.5.5".parse().unwrap(), "10.0.0.1".parse().unwrap());
        route.add_downstream("eth1");
        route.add_downstream("eth2");

        let rules = route.to_forwarding_rules("eth0", 5000);
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.input_interface, "eth0");
        assert_eq!(rule.input_group, "239.5.5.5".parse::<Ipv4Addr>().unwrap());
        assert!(rule.input_source.is_none()); // (*,G) has no source filter
        assert_eq!(rule.outputs.len(), 2);
        assert!(matches!(
            rule.source,
            RuleSource::Pim {
                tree_type: PimTreeType::StarG,
                ..
            }
        ));
    }

    #[test]
    fn test_sg_to_forwarding_rules() {
        let mut route = SGRoute::new("10.0.0.5".parse().unwrap(), "239.6.6.6".parse().unwrap());
        route.add_downstream("eth1");

        let rules = route.to_forwarding_rules("eth0", 5000);
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.input_interface, "eth0");
        assert_eq!(rule.input_group, "239.6.6.6".parse::<Ipv4Addr>().unwrap());
        assert_eq!(rule.input_source, Some("10.0.0.5".parse().unwrap())); // (S,G) has source filter
        assert!(matches!(
            rule.source,
            RuleSource::Pim {
                tree_type: PimTreeType::SG,
                ..
            }
        ));
    }

    #[test]
    fn test_mrib_stats() {
        let mut mrib = MulticastRib::new();

        mrib.add_static_rule(create_test_static_rule("rule1", "eth0", "239.1.1.1", 5000));
        mrib.add_star_g_route(StarGRoute::new(
            "239.2.2.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ));
        mrib.add_sg_route(SGRoute::new(
            "10.0.0.5".parse().unwrap(),
            "239.3.3.3".parse().unwrap(),
        ));

        let membership = IgmpMembership {
            group: "239.4.4.4".parse().unwrap(),
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: None,
        };
        mrib.add_igmp_membership("eth1", "239.4.4.4".parse().unwrap(), membership);

        let stats = mrib.stats();
        assert_eq!(stats.static_rules, 1);
        assert_eq!(stats.star_g_routes, 1);
        assert_eq!(stats.sg_routes, 1);
        assert_eq!(stats.igmp_memberships, 1);
        assert_eq!(stats.igmp_interfaces, 1);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut mrib = MulticastRib::new();

        // Add an expired IGMP membership
        let expired_membership = IgmpMembership {
            group: "239.1.1.1".parse().unwrap(),
            expires_at: Instant::now() - std::time::Duration::from_secs(1),
            last_reporter: None,
        };
        mrib.add_igmp_membership("eth0", "239.1.1.1".parse().unwrap(), expired_membership);

        // Add a valid IGMP membership
        let valid_membership = IgmpMembership {
            group: "239.2.2.2".parse().unwrap(),
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: None,
        };
        mrib.add_igmp_membership("eth1", "239.2.2.2".parse().unwrap(), valid_membership);

        // Run cleanup
        mrib.cleanup_expired(Instant::now());

        // Expired should be gone, valid should remain
        assert!(!mrib.igmp_membership.contains_key("eth0"));
        assert!(mrib.igmp_membership.contains_key("eth1"));
    }
}
