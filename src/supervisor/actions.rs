// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Protocol handler action types
//!
//! This module defines the actions that protocol handlers can return instead of
//! directly mutating MRIB state. This decoupling makes handlers pure functions
//! that are easier to test and reason about.

use std::net::Ipv4Addr;

use crate::mroute::{IgmpMembership, SGRoute, StarGRoute};
use crate::protocols::TimerRequest;
use crate::ProtocolEventNotification;

/// Actions that protocol handlers can request on the MRIB
#[derive(Debug, Clone)]
pub enum MribAction {
    /// Add IGMP membership for a group on an interface
    AddIgmpMembership {
        interface: String,
        group: Ipv4Addr,
        membership: IgmpMembership,
    },
    /// Remove IGMP membership for a group on an interface
    RemoveIgmpMembership { interface: String, group: Ipv4Addr },
    /// Add or update a (*,G) route
    AddStarGRoute(StarGRoute),
    /// Remove a (*,G) route
    RemoveStarGRoute { group: Ipv4Addr },
    /// Add or update an (S,G) route
    AddSgRoute(SGRoute),
    /// Remove an (S,G) route
    RemoveSgRoute { source: Ipv4Addr, group: Ipv4Addr },
}

/// Result returned by protocol event handlers
///
/// Contains all the side effects that the handler wants to perform:
/// - Timer requests for scheduling/canceling timers
/// - MRIB actions for routing table modifications
/// - Notifications for external subscribers
#[derive(Debug, Default)]
pub struct ProtocolHandlerResult {
    /// Timer requests to schedule or cancel
    pub timers: Vec<TimerRequest>,
    /// Actions to apply to the MRIB
    pub mrib_actions: Vec<MribAction>,
    /// Notifications to emit to subscribers
    pub notifications: Vec<ProtocolEventNotification>,
}

impl ProtocolHandlerResult {
    /// Create a new empty result
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a result with only timer requests
    pub fn with_timers(timers: Vec<TimerRequest>) -> Self {
        Self {
            timers,
            ..Default::default()
        }
    }

    /// Add a timer request
    pub fn add_timer(&mut self, timer: TimerRequest) {
        self.timers.push(timer);
    }

    /// Add multiple timer requests
    pub fn add_timers(&mut self, timers: Vec<TimerRequest>) {
        self.timers.extend(timers);
    }

    /// Add an MRIB action
    pub fn add_action(&mut self, action: MribAction) {
        self.mrib_actions.push(action);
    }

    /// Add a notification
    pub fn notify(&mut self, notification: ProtocolEventNotification) {
        self.notifications.push(notification);
    }

    /// Merge another result into this one
    pub fn merge(&mut self, other: ProtocolHandlerResult) {
        self.timers.extend(other.timers);
        self.mrib_actions.extend(other.mrib_actions);
        self.notifications.extend(other.notifications);
    }

    /// Check if the result is empty (no actions, timers, or notifications)
    pub fn is_empty(&self) -> bool {
        self.timers.is_empty() && self.mrib_actions.is_empty() && self.notifications.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_protocol_handler_result_new() {
        let result = ProtocolHandlerResult::new();
        assert!(result.is_empty());
        assert!(result.timers.is_empty());
        assert!(result.mrib_actions.is_empty());
        assert!(result.notifications.is_empty());
    }

    #[test]
    fn test_protocol_handler_result_with_timers() {
        use crate::protocols::TimerType;

        let timer = TimerRequest {
            timer_type: TimerType::IgmpGeneralQuery {
                interface: "eth0".to_string(),
            },
            fire_at: Instant::now(),
            replace_existing: false,
        };
        let result = ProtocolHandlerResult::with_timers(vec![timer]);
        assert!(!result.is_empty());
        assert_eq!(result.timers.len(), 1);
        assert!(result.mrib_actions.is_empty());
    }

    #[test]
    fn test_protocol_handler_result_add_action() {
        let mut result = ProtocolHandlerResult::new();
        result.add_action(MribAction::RemoveIgmpMembership {
            interface: "eth0".to_string(),
            group: "239.1.1.1".parse().unwrap(),
        });
        assert!(!result.is_empty());
        assert_eq!(result.mrib_actions.len(), 1);
    }

    #[test]
    fn test_protocol_handler_result_merge() {
        use crate::protocols::TimerType;

        let mut result1 = ProtocolHandlerResult::new();
        result1.add_action(MribAction::RemoveIgmpMembership {
            interface: "eth0".to_string(),
            group: "239.1.1.1".parse().unwrap(),
        });

        let mut result2 = ProtocolHandlerResult::new();
        result2.add_timer(TimerRequest {
            timer_type: TimerType::IgmpGeneralQuery {
                interface: "eth0".to_string(),
            },
            fire_at: Instant::now(),
            replace_existing: false,
        });

        result1.merge(result2);
        assert_eq!(result1.mrib_actions.len(), 1);
        assert_eq!(result1.timers.len(), 1);
    }
}
