// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Event subscription management for external control plane integration.

use crate::ProtocolEventNotification;

/// Manages event subscriptions for external control plane integration.
///
/// Provides a broadcast channel for protocol events (IGMP membership changes,
/// PIM neighbor/route changes, MSDP SA cache updates) to be pushed to
/// subscribed clients.
#[derive(Clone)]
pub struct EventSubscriptionManager {
    /// Broadcast sender for protocol events
    event_tx: tokio::sync::broadcast::Sender<ProtocolEventNotification>,
}

impl EventSubscriptionManager {
    /// Create a new EventSubscriptionManager with the specified buffer size
    pub fn new(buffer_size: usize) -> Self {
        let (event_tx, _) = tokio::sync::broadcast::channel(buffer_size);
        Self { event_tx }
    }

    /// Get a new receiver for subscribing to events
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ProtocolEventNotification> {
        self.event_tx.subscribe()
    }

    /// Send an event to all subscribers
    ///
    /// Returns the number of receivers that received the event.
    /// If there are no subscribers, returns 0 (not an error).
    pub fn send(&self, event: ProtocolEventNotification) -> usize {
        self.event_tx.send(event).unwrap_or_default()
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.event_tx.receiver_count()
    }
}

impl Default for EventSubscriptionManager {
    fn default() -> Self {
        // Default buffer size of 256 events
        Self::new(256)
    }
}
