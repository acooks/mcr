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
    /// 2. Subscribe to link state change notifications (RTM_NEWLINK, RTM_DELLINK)
    /// 3. Listen for events in an async loop
    /// 4. Parse Netlink messages into InterfaceEvent structs
    /// 5. Call handle_interface_event() for each event
    ///
    /// ## Implementation Notes
    /// - Add `rtnetlink = "0.13"` to Cargo.toml dependencies (recommended, higher-level than neli)
    /// - Alternative: Use `neli` crate for lower-level control
    /// - Run this in a separate tokio task
    /// - Send events to supervisor via the provided channel
    ///
    /// ## Recommended Implementation using rtnetlink
    /// ```rust,ignore
    /// use rtnetlink::{new_connection, IpVersion};
    /// use futures::stream::TryStreamExt;
    ///
    /// // Create connection to Netlink
    /// let (connection, handle, _) = new_connection()?;
    ///
    /// // Spawn the connection in background
    /// tokio::spawn(connection);
    ///
    /// // Subscribe to link events
    /// let mut link_stream = handle.link().get().execute();
    ///
    /// // Monitor for changes
    /// while let Some(msg) = link_stream.try_next().await? {
    ///     let interface_name = msg.header.name;
    ///     let is_up = msg.header.flags.contains(LinkFlag::Up);
    ///
    ///     let event = InterfaceEvent {
    ///         interface_name: interface_name.clone(),
    ///         new_state: if is_up { InterfaceState::Up } else { InterfaceState::Down },
    ///         previous_state: self.interface_states.get(&interface_name).cloned(),
    ///     };
    ///
    ///     event_tx.send(event).await?;
    /// }
    /// ```
    ///
    /// ## Alternative: Lower-level neli Implementation
    /// ```rust,ignore
    /// use neli::socket::{tokio::NlSocket, NlSocketHandle};
    /// use neli::consts::nl::*;
    /// use neli::consts::rtnl::*;
    /// use neli::nl::{Nlmsghdr, NlPayload};
    /// use neli::rtnl::Ifinfomsg;
    ///
    /// let mut socket = NlSocket::connect(
    ///     NlFamily::Route,
    ///     Some(0),
    ///     &[RtGrp::Link],  // Subscribe to link events
    /// )?;
    ///
    /// loop {
    ///     let msg: Nlmsghdr<Rtm, Ifinfomsg> = socket.recv().await?;
    ///
    ///     match msg.nl_type {
    ///         Rtm::Newlink => {
    ///             // Interface added or state changed
    ///             if let NlPayload::Payload(ifinfo) = msg.nl_payload {
    ///                 let is_up = ifinfo.ifi_flags & libc::IFF_UP as u32 != 0;
    ///                 // Create and send InterfaceEvent
    ///             }
    ///         }
    ///         Rtm::Dellink => {
    ///             // Interface removed
    ///             // Send InterfaceState::Removed event
    ///         }
    ///         _ => continue,
    ///     }
    /// }
    /// ```
    ///
    /// ## Testing Strategy
    /// 1. Unit test: Mock events, verify handle_interface_event() logic
    /// 2. Integration test (feature-gated): Create dummy interface, bring up/down, verify events
    /// 3. Manual test: `ip link set eth0 down` while monitoring
    ///
    /// ## Example Test Commands
    /// ```bash
    /// # Create dummy interface for testing
    /// sudo ip link add dummy0 type dummy
    /// sudo ip link set dummy0 up
    /// # Your code should detect this
    ///
    /// sudo ip link set dummy0 down
    /// # Your code should detect this
    ///
    /// sudo ip link delete dummy0
    /// # Your code should detect removal
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
    /// This method determines what action to take when an interface changes state.
    ///
    /// ## Decision Logic
    /// - Interface goes DOWN: Return PauseRules if we have rules on it
    /// - Interface comes UP: Return ResumeRules if we have paused rules on it
    /// - Interface REMOVED: Return RemoveRules if we have rules on it
    /// - Otherwise: Return NoAction
    ///
    /// **Status**: ✅ IMPLEMENTED
    pub fn handle_interface_event(&mut self, event: InterfaceEvent) -> ReconciliationAction {
        let old_state = self.interface_states.get(&event.interface_name).cloned();

        // Update our state tracking first
        match event.new_state {
            InterfaceState::Removed => {
                self.interface_states.remove(&event.interface_name);
            }
            _ => {
                self.interface_states
                    .insert(event.interface_name.clone(), event.new_state.clone());
            }
        }

        // Only take action if we have rules on this interface
        if !self.interfaces_with_rules.contains(&event.interface_name) {
            return ReconciliationAction::NoAction;
        }

        // Determine action based on state transition
        match (&old_state, &event.new_state) {
            // Interface went down -> pause rules
            (Some(InterfaceState::Up), InterfaceState::Down) => {
                ReconciliationAction::PauseRules {
                    interface_name: event.interface_name,
                }
            }

            // Interface came up -> resume rules
            (Some(InterfaceState::Down), InterfaceState::Up) |
            (None, InterfaceState::Up) => {
                ReconciliationAction::ResumeRules {
                    interface_name: event.interface_name,
                }
            }

            // Interface was removed -> remove rules
            (_, InterfaceState::Removed) => {
                self.interfaces_with_rules.remove(&event.interface_name);
                ReconciliationAction::RemoveRules {
                    interface_name: event.interface_name,
                }
            }

            // No significant state change
            _ => ReconciliationAction::NoAction,
        }
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

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify interface down triggers PauseRules action
    /// - **Method:** Simulate Up->Down transition with registered interface
    /// - **Tier:** 1 (Logic)
    #[test]
    fn test_handle_interface_event_down_transition() {
        let mut monitor = NetworkMonitor::new();
        monitor
            .interface_states
            .insert("eth0".to_string(), InterfaceState::Up);
        monitor.register_interface("eth0".to_string());

        let event = InterfaceEvent {
            interface_name: "eth0".to_string(),
            new_state: InterfaceState::Down,
            previous_state: Some(InterfaceState::Up),
        };

        let action = monitor.handle_interface_event(event);

        assert_eq!(
            action,
            ReconciliationAction::PauseRules {
                interface_name: "eth0".to_string()
            }
        );
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify interface up triggers ResumeRules action
    /// - **Method:** Simulate Down->Up transition with registered interface
    /// - **Tier:** 1 (Logic)
    #[test]
    fn test_handle_interface_event_up_transition() {
        let mut monitor = NetworkMonitor::new();
        monitor
            .interface_states
            .insert("eth0".to_string(), InterfaceState::Down);
        monitor.register_interface("eth0".to_string());

        let event = InterfaceEvent {
            interface_name: "eth0".to_string(),
            new_state: InterfaceState::Up,
            previous_state: Some(InterfaceState::Down),
        };

        let action = monitor.handle_interface_event(event);

        assert_eq!(
            action,
            ReconciliationAction::ResumeRules {
                interface_name: "eth0".to_string()
            }
        );
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify interface removal triggers RemoveRules action
    /// - **Method:** Simulate interface deletion with active rules
    /// - **Tier:** 1 (Logic)
    #[test]
    fn test_handle_interface_event_removed_transition() {
        let mut monitor = NetworkMonitor::new();
        monitor
            .interface_states
            .insert("eth0".to_string(), InterfaceState::Up);
        monitor.register_interface("eth0".to_string());

        let event = InterfaceEvent {
            interface_name: "eth0".to_string(),
            new_state: InterfaceState::Removed,
            previous_state: Some(InterfaceState::Up),
        };

        let action = monitor.handle_interface_event(event);

        assert_eq!(
            action,
            ReconciliationAction::RemoveRules {
                interface_name: "eth0".to_string()
            }
        );
        // Verify interface was unregistered
        assert!(!monitor.interfaces_with_rules.contains("eth0"));
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify no action when interface has no rules
    /// - **Method:** Simulate state change on unregistered interface
    /// - **Tier:** 1 (Logic)
    #[test]
    fn test_handle_interface_event_no_rules() {
        let mut monitor = NetworkMonitor::new();
        monitor
            .interface_states
            .insert("eth0".to_string(), InterfaceState::Up);
        // Note: Not calling register_interface

        let event = InterfaceEvent {
            interface_name: "eth0".to_string(),
            new_state: InterfaceState::Down,
            previous_state: Some(InterfaceState::Up),
        };

        let action = monitor.handle_interface_event(event);

        assert_eq!(action, ReconciliationAction::NoAction);
    }

    // TODO: Add integration test with real Netlink socket (feature-gated)
    // This would require:
    // 1. Creating a dummy network interface
    // 2. Starting the monitor
    // 3. Changing interface state
    // 4. Verifying events are received
    // 5. Cleaning up the dummy interface
    //
    // Example:
    // #[tokio::test]
    // #[cfg(feature = "netlink_integration_test")]
    // #[ignore] // Requires root
    // async fn test_netlink_integration() {
    //     // Proposed Implementation:
    //     // 1.  **Check for Root:** Skip if not running as root.
    //     // 2.  **Create Dummy Interface:** Use `tokio::process::Command` to run
    //     //     `ip link add dev veth-test type dummy`.
    //     // 3.  **Setup Monitor:** Create a `NetworkMonitor` and an MPSC channel.
    //     // 4.  **Start Monitoring:** Spawn `monitor.start_monitoring(tx)` in a tokio task.
    //     // 5.  **Bring Interface Up:** Run `ip link set dev veth-test up`.
    //     // 6.  **Verify "Up" Event:** Receive from the channel and assert that an
    //     //     `InterfaceEvent` for `veth-test` with state `Up` is received.
    //     // 7.  **Bring Interface Down:** Run `ip link set dev veth-test down`.
    //     // 8.  **Verify "Down" Event:** Assert a `Down` event is received.
    //     // 9.  **Cleanup:** Run `ip link delete dev veth-test` to remove the
    //     //     dummy interface. Ensure this runs even if the test fails.
    // }
}
