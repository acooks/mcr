// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Netlink-based interface change monitoring
//!
//! This module provides real-time detection of network interface changes
//! (add, remove, up, down) using Linux netlink sockets. When changes are
//! detected, the global interface cache is refreshed immediately rather
//! than waiting for the TTL to expire.
//!
//! Interface events are also sent to the supervisor via a channel, enabling
//! immediate retry of pending worker spawns when interfaces come up.
//!
//! # Usage
//!
//! ```ignore
//! // In supervisor startup:
//! let (handle, mut rx) = spawn_netlink_monitor(logger.clone());
//!
//! // In select! loop:
//! Some(event) = rx.recv() => { ... }
//!
//! // On shutdown:
//! handle.abort();
//! ```

use crate::logging::{Facility, Logger};
use futures::stream::StreamExt;
use rtnetlink::sys::{AsyncSocket, SocketAddr};
use tokio::sync::mpsc;

use super::socket_helpers::global_interface_cache;

/// Events from the netlink monitor to the supervisor
#[derive(Debug, Clone)]
pub enum InterfaceEvent {
    /// Interface has come up or been added
    Up(String),
    /// Interface has gone down or been removed
    #[allow(dead_code)] // Reserved for future use
    Down(String),
}

/// Spawn a background task that monitors netlink for interface changes.
///
/// When a link event is detected (interface added, removed, or state changed),
/// the global interface cache is refreshed immediately and an event is sent
/// to the supervisor via the returned channel.
///
/// Returns a tuple of:
/// - `JoinHandle` that can be used to abort the monitor on shutdown
/// - `Receiver` for interface events to be processed by the supervisor
pub fn spawn_netlink_monitor(
    logger: Logger,
) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<InterfaceEvent>) {
    let (tx, rx) = mpsc::channel::<InterfaceEvent>(32);

    let handle = tokio::spawn(async move {
        if let Err(e) = run_netlink_monitor(&logger, tx).await {
            logger.warning(
                Facility::Supervisor,
                &format!("Netlink monitor exited with error: {}", e),
            );
        }
    });

    (handle, rx)
}

/// Internal function that runs the netlink monitoring loop.
async fn run_netlink_monitor(
    logger: &Logger,
    tx: mpsc::Sender<InterfaceEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    use rtnetlink::packet_core::NetlinkPayload;
    use rtnetlink::packet_route::RouteNetlinkMessage;

    // Create netlink connection
    let (mut connection, _handle, mut messages) = rtnetlink::new_connection()?;

    // Subscribe to link (interface) events via multicast group
    // RTMGRP_LINK = 1, receives RTM_NEWLINK, RTM_DELLINK
    let mgroup_flags = rtnetlink::constants::RTMGRP_LINK;

    // Bind to the multicast address to receive link change notifications
    let addr = SocketAddr::new(0, mgroup_flags);
    connection
        .socket_mut()
        .socket_mut()
        .bind(&addr)
        .map_err(|e| format!("Failed to bind netlink socket: {}", e))?;

    // Spawn the connection handler - this drives the netlink socket I/O
    tokio::spawn(connection);

    logger.info(
        Facility::Supervisor,
        "Netlink monitor started - watching for interface changes",
    );

    // Process incoming netlink messages
    while let Some((message, _)) = messages.next().await {
        match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
                let name = link
                    .attributes
                    .iter()
                    .find_map(|attr| {
                        if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) = attr {
                            Some(name.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| format!("index {}", link.header.index));

                logger.debug(
                    Facility::Supervisor,
                    &format!(
                        "Netlink: interface {} added/changed, refreshing cache",
                        name
                    ),
                );
                global_interface_cache().refresh();

                // Notify supervisor of interface up event
                let _ = tx.send(InterfaceEvent::Up(name)).await;
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
                let name = link
                    .attributes
                    .iter()
                    .find_map(|attr| {
                        if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) = attr {
                            Some(name.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| format!("index {}", link.header.index));

                logger.debug(
                    Facility::Supervisor,
                    &format!("Netlink: interface {} removed, refreshing cache", name),
                );
                global_interface_cache().refresh();

                // Notify supervisor of interface down event
                let _ = tx.send(InterfaceEvent::Down(name)).await;
            }
            _ => {
                // Ignore other message types (addresses, routes, etc.)
            }
        }
    }

    logger.info(Facility::Supervisor, "Netlink monitor stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_netlink_connection() {
        // Test that we can create a netlink connection
        let result = rtnetlink::new_connection();
        assert!(result.is_ok(), "Failed to create netlink connection");
    }
}
