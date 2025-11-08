//! Network State Monitoring and Reconciliation
//!
//! **Priority: HIGH - Sprint 1, Days 3-4**
//!
//! This module monitors network interface state changes using Netlink sockets
//! and triggers rule reconciliation when interfaces go up, down, or are removed.
//!
//! ## Design References
//! - D19: Supervisor uses Netlink to monitor network state
//! - D20: Rules automatically pause when interface goes down
//! - D21: Rules resume when interface comes back up
//!
//! ## Implementation Status
//! - [ ] Netlink socket setup and monitoring
//! - [ ] Interface up/down detection
//! - [ ] Interface removal detection
//! - [ ] Rule pause/resume logic
//! - [ ] Integration with RuleDispatcher
//!
//! ## Related Experiments
//! - EXPERIMENT_CANDIDATES.md lists "Netlink for Network Monitoring" as pending

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};

/// Represents the state of a network interface
#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceState {
    /// Interface is up and operational
    Up,
    /// Interface is down (cable unplugged, ifdown, etc.)
    Down,
    /// Interface has been removed from the system
    Removed,
}

/// Event emitted when a network interface changes state
#[derive(Debug, Clone)]
pub struct InterfaceEvent {
    /// Name of the interface (e.g., "eth0", "wlan0")
    pub interface_name: String,

    /// New state of the interface
    pub new_state: InterfaceState,

    /// Previous state (if known)
    pub previous_state: Option<InterfaceState>,
}

/// Action to take in response to an interface event
#[derive(Debug, Clone, PartialEq)]
pub enum ReconciliationAction {
    /// Pause all rules using this interface
    PauseRules { interface_name: String },

    /// Resume all rules using this interface
    ResumeRules { interface_name: String },

    /// Remove all rules using this interface (interface deleted)
    RemoveRules { interface_name: String },

    /// No action needed
    NoAction,
}

/// Monitors network interface state and determines reconciliation actions
pub struct NetworkMonitor {
    /// Current state of all known interfaces
    interface_states: HashMap<String, InterfaceState>,

    /// Set of interfaces that have active rules
    interfaces_with_rules: HashSet<String>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            interface_states: HashMap::new(),
            interfaces_with_rules: HashSet::new(),
        }
    }

    /// Start monitoring network interfaces via Netlink
    ///
    /// **TODO: IMPLEMENT THIS - HIGH PRIORITY**
    ///
    /// This is the core monitoring loop. It should:
    /// 1. Create a Netlink socket (NETLINK_ROUTE family)
    /// 2. Subscribe to link state change notifications
    /// 3. Listen for events in an async loop
    /// 4. Parse Netlink messages into InterfaceEvent structs
    /// 5. Call handle_interface_event() for each event
    ///
    /// ## Implementation Notes
    /// - Use the `neli` crate for Netlink communication
    /// - Run this in a separate tokio task
    /// - Send events to supervisor via a channel
    ///
    /// ## Example Netlink Code Structure
    /// ```rust,ignore
    /// use neli::socket::{NlSocket, NlSocketHandle};
    /// use neli::consts::nl::*;
    /// use neli::consts::rtnl::*;
    ///
    /// let mut socket = NlSocketHandle::connect(
    ///     NlFamily::Route,
    ///     Some(0),
    ///     &[],
    /// )?;
    ///
    /// // Subscribe to link notifications
    /// socket.add_mcast_membership(&[RtAddrFamily::Unspec])?;
    ///
    /// loop {
    ///     let msg = socket.recv()?;
    ///     // Parse msg and create InterfaceEvent
    /// }
    /// ```
    pub async fn start_monitoring(
        &mut self,
        event_tx: tokio::sync::mpsc::Sender<InterfaceEvent>,
    ) -> Result<()> {
        // TODO: Step 1 - Create Netlink socket
        // TODO: Step 2 - Subscribe to RTNLGRP_LINK notifications
        // TODO: Step 3 - Enter event loop
        // TODO: Step 4 - Parse events and send to channel

        todo!("Implement Netlink monitoring - see comments above")
    }

    /// Handle an interface state change event
    ///
    /// **TODO: IMPLEMENT THIS - HIGH PRIORITY**
    ///
    /// This method determines what action to take when an interface changes state.
    ///
    /// ## Decision Logic
    /// - Interface goes DOWN: Return PauseRules if we have rules on it
    /// - Interface comes UP: Return ResumeRules if we have paused rules on it
    /// - Interface REMOVED: Return RemoveRules if we have rules on it
    /// - Otherwise: Return NoAction
    pub fn handle_interface_event(&mut self, event: InterfaceEvent) -> ReconciliationAction {
        let old_state = self.interface_states.get(&event.interface_name);

        // Update our state tracking
        match event.new_state {
            InterfaceState::Removed => {
                self.interface_states.remove(&event.interface_name);
            }
            _ => {
                self.interface_states
                    .insert(event.interface_name.clone(), event.new_state.clone());
            }
        }

        // TODO: Implement decision logic
        // Check if we have rules on this interface
        // Determine appropriate action based on state transition

        todo!("Implement reconciliation action decision")
    }

    /// Register that we have active rules on an interface
    ///
    /// Called when a rule is added that uses this interface.
    pub fn register_interface(&mut self, interface_name: String) {
        self.interfaces_with_rules.insert(interface_name);
    }

    /// Unregister an interface (all rules removed)
    pub fn unregister_interface(&mut self, interface_name: &str) {
        self.interfaces_with_rules.remove(interface_name);
    }

    /// Get the current state of an interface
    pub fn get_interface_state(&self, interface_name: &str) -> Option<&InterfaceState> {
        self.interface_states.get(interface_name)
    }

    /// Check if an interface is currently operational
    pub fn is_interface_up(&self, interface_name: &str) -> bool {
        matches!(
            self.interface_states.get(interface_name),
            Some(InterfaceState::Up)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify interface registration tracking
    /// - **Method:** Register interfaces and check state
    /// - **Tier:** 1 (Logic)
    #[test]
    fn test_register_interface() {
        let mut monitor = NetworkMonitor::new();
        monitor.register_interface("eth0".to_string());

        assert!(monitor.interfaces_with_rules.contains("eth0"));
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify interface state tracking
    /// - **Method:** Simulate state change and verify
    /// - **Tier:** 1 (Logic)
    #[test]
    fn test_interface_state_tracking() {
        let mut monitor = NetworkMonitor::new();
        monitor
            .interface_states
            .insert("eth0".to_string(), InterfaceState::Up);

        assert!(monitor.is_interface_up("eth0"));
        assert!(!monitor.is_interface_up("eth1"));
    }

    // TODO: Add test for handle_interface_event with Down transition
    // TODO: Add test for handle_interface_event with Up transition
    // TODO: Add test for handle_interface_event with Removed transition
    // TODO: Add integration test with real Netlink socket (feature-gated)
}
