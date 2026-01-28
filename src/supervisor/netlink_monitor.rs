// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Netlink-based interface change monitoring
//!
//! This module provides real-time detection of network interface changes
//! (add, remove, up, down) using Linux netlink sockets. When changes are
//! detected, the global interface cache is refreshed immediately rather
//! than waiting for the TTL to expire.
//!
//! # Usage
//!
//! ```ignore
//! // In supervisor startup:
//! let handle = spawn_netlink_monitor(logger.clone());
//!
//! // On shutdown:
//! handle.abort();
//! ```

use crate::logging::{Facility, Logger};
use futures::stream::StreamExt;
use rtnetlink::sys::{AsyncSocket, SocketAddr};

use super::socket_helpers::global_interface_cache;

/// Spawn a background task that monitors netlink for interface changes.
///
/// When a link event is detected (interface added, removed, or state changed),
/// the global interface cache is refreshed immediately.
///
/// Returns a `JoinHandle` that can be used to abort the monitor on shutdown.
pub fn spawn_netlink_monitor(logger: Logger) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_netlink_monitor(&logger).await {
            logger.warning(
                Facility::Supervisor,
                &format!("Netlink monitor exited with error: {}", e),
            );
        }
    })
}

/// Internal function that runs the netlink monitoring loop.
async fn run_netlink_monitor(logger: &Logger) -> Result<(), Box<dyn std::error::Error>> {
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
