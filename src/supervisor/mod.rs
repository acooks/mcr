// SPDX-License-Identifier: Apache-2.0 OR MIT

// Submodules
mod actions;
mod command_handler;
mod event_subscription;
mod netlink_monitor;
mod protocol_state;
pub mod socket_helpers;
mod timer_manager;
mod worker_manager;

// Re-exports
pub use actions::{MribAction, OutgoingPacket, ProtocolHandlerResult, ProtocolType};
pub use command_handler::{handle_supervisor_command, CommandAction};
pub use event_subscription::EventSubscriptionManager;
pub use protocol_state::{protocol_receiver_loop, ProtocolState};
pub use timer_manager::ProtocolTimerManager;

// Internal imports from submodules
use protocol_state::unix_timestamp;
use worker_manager::WorkerManager;

use anyhow::Result;
use bytes::Bytes;
use futures::SinkExt;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;

use crate::config::Config;
use crate::logging::{AsyncConsumer, Facility, Logger, MPSCRingBuffer};
use crate::protocols::{ProtocolEvent, TimerRequest};
use crate::{
    log_debug, log_error, log_info, log_warning, ForwardingRule, RelayCommand, WorkerResponse,
};
use futures::StreamExt;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const SHUTDOWN_TIMEOUT_SECS: u64 = 10; // Timeout for graceful worker shutdown
const PERIODIC_SYNC_INTERVAL_SECS: u64 = 300; // 5 minutes - periodic full ruleset sync to all workers
/// Protocol coordinator that manages the integration between
/// protocol state machines and the supervisor's main loop
pub struct ProtocolCoordinator {
    /// Protocol state machines and MRIB
    pub state: ProtocolState,
    /// Channel to receive protocol events
    event_rx: mpsc::Receiver<ProtocolEvent>,
    /// Channel to send protocol events (for MSDP TCP)
    event_tx: mpsc::Sender<ProtocolEvent>,
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
        event_tx: mpsc::Sender<ProtocolEvent>,
        timer_tx: mpsc::Sender<TimerRequest>,
    ) -> Self {
        Self {
            state,
            event_rx,
            event_tx,
            timer_tx,
            rules_dirty: false,
        }
    }

    /// Get a clone of the event sender (for MSDP TCP)
    pub fn event_tx_clone(&self) -> mpsc::Sender<ProtocolEvent> {
        self.event_tx.clone()
    }

    /// Process any pending protocol events (non-blocking)
    ///
    /// Returns true if the MRIB was modified and rules need syncing
    pub async fn process_pending_events(&mut self) -> bool {
        let mut mrib_modified = false;
        let mut event_count = 0;

        // Process all available events without blocking
        loop {
            match self.event_rx.try_recv() {
                Ok(event) => {
                    event_count += 1;
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
            log_info!(
                self.state.logger,
                Facility::Supervisor,
                &format!(
                    "process_pending_events: {} events processed, rules_dirty=true",
                    event_count
                )
            );
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

    // Enable event subscriptions for external control plane integration
    // Use buffer size from config if specified, otherwise use default
    let event_buffer_size = config
        .control_plane
        .as_ref()
        .map(|cp| cp.event_buffer_size)
        .unwrap_or(256);
    state.enable_event_subscriptions(event_buffer_size);

    // Initialize from config
    state.initialize_from_config(config);

    // Create protocol sockets if needed
    if state.igmp_enabled || state.pim_enabled {
        state.create_protocol_sockets()?;
    }

    // Schedule any pending timers from protocol initialization
    // This must happen AFTER socket creation so timers can send packets
    for timer in state.pending_igmp_timers.drain(..) {
        if let Err(e) = timer_tx.try_send(timer) {
            log_warning!(
                logger,
                Facility::Supervisor,
                &format!("Failed to schedule pending IGMP timer: {}", e)
            );
        }
    }

    // Store event_tx in state for later use (e.g., spawning receiver loop via CLI)
    state.event_tx = Some(event_tx.clone());

    // Get socket file descriptors for the receiver loop
    let igmp_fd = state.igmp_socket_fd();
    let pim_fd = state.pim_socket_fd();

    // Mark receiver loop as running if we have sockets
    let receiver_will_run = igmp_fd.is_some() || pim_fd.is_some();

    // Create shutdown channel for the receiver loop
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    state.receiver_loop_shutdown_tx = Some(shutdown_tx);

    // Clone the running flag for the receiver loop to reset on exit
    let running_flag = state.receiver_loop_running.clone();

    if receiver_will_run {
        state
            .receiver_loop_running
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // Create background tasks
    let receiver_logger = logger.clone();
    let receiver_event_tx = event_tx.clone();
    let receiver_task = async move {
        protocol_receiver_loop(
            igmp_fd,
            pim_fd,
            receiver_event_tx,
            shutdown_rx,
            receiver_logger,
        )
        .await;
        // Reset running flag when loop exits
        running_flag.store(false, std::sync::atomic::Ordering::SeqCst);
    };

    // Clone event_tx before giving it to timer manager
    let coordinator_event_tx = event_tx.clone();

    let timer_manager = ProtocolTimerManager::new(timer_rx, event_tx, logger.clone());
    let timer_task = async move {
        timer_manager.run().await;
    };

    // Create coordinator
    let coordinator = ProtocolCoordinator::new(state, event_rx, coordinator_event_tx, timer_tx);

    Ok((coordinator, receiver_task, timer_task))
}

/// Sync forwarding rules to all data plane workers
///
/// This function sends the compiled rules to all workers, filtering by interface.
async fn sync_rules_to_workers(
    rules: &[ForwardingRule],
    worker_manager: &Arc<Mutex<WorkerManager>>,
    logger: &Logger,
) -> bool {
    if rules.is_empty() {
        return false;
    }

    let stream_pairs_with_iface = {
        let manager = worker_manager.lock().unwrap();
        manager.get_all_dp_cmd_streams_with_interface()
    };

    log_info!(
        logger,
        Facility::Supervisor,
        &format!(
            "sync_rules_to_workers: {} workers available",
            stream_pairs_with_iface.len()
        )
    );

    // Track whether we synced rules to at least one worker
    let mut synced_to_any = false;

    for (interface, ingress_stream, egress_stream) in stream_pairs_with_iface {
        // Filter rules to only include those matching this worker's input interface
        let interface_rules: Vec<ForwardingRule> = rules
            .iter()
            .filter(|r| r.input_interface == interface)
            .cloned()
            .collect();

        log_debug!(
            logger,
            Facility::Supervisor,
            &format!(
                "sync_rules_to_workers: worker interface={}, matched {} of {} rules",
                interface,
                interface_rules.len(),
                rules.len()
            )
        );

        if interface_rules.is_empty() {
            log_debug!(
                logger,
                Facility::Supervisor,
                &format!(
                    "sync_rules_to_workers: skipping worker {} - no matching rules (rule interfaces: {:?})",
                    interface,
                    rules.iter().map(|r| &r.input_interface).collect::<Vec<_>>()
                )
            );
            continue;
        }

        let sync_cmd = RelayCommand::SyncRules(interface_rules);
        if let Ok(cmd_bytes) = serde_json::to_vec(&sync_cmd) {
            // Send to worker via ingress stream and wait for ACK
            // Note: In unified mode, the worker only monitors the ingress command stream,
            // so we only need to send once and wait for one ACK.
            // The egress_stream is kept for compatibility but not used here.
            let _ = egress_stream; // Suppress unused variable warning

            let worker_ack = {
                let mut stream = ingress_stream.lock().await;
                let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                if framed.send(cmd_bytes.into()).await.is_ok() {
                    // Wait for ACK response with timeout
                    match tokio::time::timeout(std::time::Duration::from_secs(5), framed.next())
                        .await
                    {
                        Ok(Some(Ok(response_bytes))) => {
                            match serde_json::from_slice::<WorkerResponse>(&response_bytes) {
                                Ok(WorkerResponse::SyncRulesAck { rule_count, .. }) => {
                                    log_debug!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!(
                                            "Worker {} ACK: {} rules applied",
                                            interface, rule_count
                                        )
                                    );
                                    true
                                }
                                Ok(WorkerResponse::Error { message }) => {
                                    log_warning!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!("Worker {} error: {}", interface, message)
                                    );
                                    false
                                }
                                Err(e) => {
                                    log_warning!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!("Failed to parse worker response: {}", e)
                                    );
                                    false
                                }
                            }
                        }
                        Ok(Some(Err(e))) => {
                            log_warning!(
                                logger,
                                Facility::Supervisor,
                                &format!("Worker {} read error: {}", interface, e)
                            );
                            false
                        }
                        Ok(None) => {
                            log_warning!(
                                logger,
                                Facility::Supervisor,
                                &format!("Worker {} stream closed", interface)
                            );
                            false
                        }
                        Err(_) => {
                            log_warning!(
                                logger,
                                Facility::Supervisor,
                                &format!("Worker {} ACK timeout", interface)
                            );
                            false
                        }
                    }
                } else {
                    false
                }
            };

            if worker_ack {
                synced_to_any = true;
            }
        }
    }

    log_debug!(
        logger,
        Facility::Supervisor,
        &format!(
            "Synced {} rules to workers (synced_to_any={})",
            rules.len(),
            synced_to_any
        )
    );

    synced_to_any
}

/// Get IPv4 address for an interface
pub(super) fn get_interface_ipv4(interface: &str) -> Option<Ipv4Addr> {
    for iface in socket_helpers::get_interfaces() {
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

/// Get the local source address that would be used to reach a destination.
///
/// Uses the UDP connect trick: connect a UDP socket to the destination
/// (without sending anything), then getsockname() to see which local
/// address the kernel chose based on the routing table.
fn get_source_addr_for_dest(dest: Ipv4Addr) -> Option<Ipv4Addr> {
    use std::net::{SocketAddr, UdpSocket};

    // Create a UDP socket and "connect" to the destination
    // This doesn't send anything, just sets the route
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket
        .connect(SocketAddr::from((dest, 9))) // Port doesn't matter
        .ok()?;

    // Get the local address the kernel chose
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

/// Get the interface name for an IP address.
///
/// Iterates through all interfaces to find one with the given IP address.
fn get_interface_for_ip(ip: Ipv4Addr) -> Option<String> {
    for iface in socket_helpers::get_interfaces() {
        for ip_net in &iface.ips {
            if let std::net::IpAddr::V4(iface_ip) = ip_net.ip() {
                if iface_ip == ip {
                    return Some(iface.name.clone());
                }
            }
        }
    }
    None
}

/// Perform RPF (Reverse Path Forwarding) lookup for a destination.
///
/// Returns the interface that would be used to reach the destination,
/// based on the kernel's routing table. This uses the UDP connect trick
/// to query the kernel's route selection.
///
/// For PIM:
/// - For (*,G) routes: lookup RPF towards the RP
/// - For (S,G) routes: lookup RPF towards the source
pub(super) fn lookup_rpf_interface(dest: Ipv4Addr) -> Option<String> {
    // Get the source IP the kernel would use to reach this destination
    let source_ip = get_source_addr_for_dest(dest)?;
    // Find which interface has this IP
    get_interface_for_ip(source_ip)
}

/// Parse a group prefix like "239.0.0.0/8" or "239.1.1.1" into a base address
pub(super) fn parse_group_prefix(prefix: &str) -> Result<Ipv4Addr> {
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
pub(super) fn parse_pim_join_prune(
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

// --- Client Handling ---

/// Handle a single client connection on the control socket
#[allow(clippy::too_many_arguments)]
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
    startup_config: Arc<Option<Config>>,
    protocol_coordinator: Arc<Mutex<Option<ProtocolCoordinator>>>,
    logger: Logger,
) -> Result<()> {
    use crate::{Response, SupervisorCommand};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = Vec::new();
    client_stream.read_to_end(&mut buffer).await?;

    let command: SupervisorCommand = serde_json::from_slice(&buffer)?;

    // Handle subscription requests specially (they need persistent connections)
    if let SupervisorCommand::Subscribe { events } = &command {
        let subscription_result: Option<(
            crate::SubscriptionId,
            Vec<crate::EventType>,
            tokio::sync::broadcast::Receiver<crate::ProtocolEventNotification>,
        )> = {
            let coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref coordinator) = *coordinator_guard {
                if let Some(ref event_manager) = coordinator.state.event_manager {
                    let id = crate::SubscriptionId::new();
                    let rx = event_manager.subscribe();
                    Some((id, events.clone(), rx))
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some((subscription_id, subscribed_events, mut event_rx)) = subscription_result {
            // Send subscription confirmation
            let response = Response::Subscribed {
                subscription_id: subscription_id.clone(),
                events: subscribed_events.clone(),
            };
            let response_bytes = serde_json::to_vec(&response)?;
            client_stream.write_all(&response_bytes).await?;
            client_stream.write_all(b"\n").await?; // Delimiter for streaming

            // Stream events until connection is closed
            let subscribed_set: std::collections::HashSet<_> =
                subscribed_events.into_iter().collect();
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        // Only send events that match subscription
                        if subscribed_set.contains(&event.event_type()) {
                            let event_response = Response::Event(event);
                            let event_bytes = serde_json::to_vec(&event_response)?;
                            if client_stream.write_all(&event_bytes).await.is_err() {
                                break; // Client disconnected
                            }
                            if client_stream.write_all(b"\n").await.is_err() {
                                break; // Client disconnected
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Log lag but continue - subscriber missed some events
                        log_warning!(
                            logger,
                            Facility::Supervisor,
                            &format!("Event subscriber lagged by {} events", n)
                        );
                    }
                }
            }
            return Ok(());
        } else {
            // Event subscriptions not available
            let response = Response::Error("Event subscriptions not available".to_string());
            let response_bytes = serde_json::to_vec(&response)?;
            client_stream.write_all(&response_bytes).await?;
            return Ok(());
        }
    }

    // Handle protocol-specific queries and mutations directly (need access to ProtocolCoordinator state)
    // These commands need real data from the protocol state machines
    let protocol_response: Option<Response> = {
        let mut coordinator_guard = protocol_coordinator.lock().unwrap();
        if let Some(ref mut coordinator) = *coordinator_guard {
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
                SupervisorCommand::GetMsdpPeers => {
                    let peers = coordinator.state.get_msdp_peers();
                    Some(Response::MsdpPeers(peers))
                }
                SupervisorCommand::GetMsdpSaCache => {
                    let sa_cache = coordinator.state.get_msdp_sa_cache();
                    Some(Response::MsdpSaCache(sa_cache))
                }
                SupervisorCommand::ListExternalNeighbors => {
                    let neighbors = coordinator.state.get_external_neighbors();
                    Some(Response::ExternalNeighbors(neighbors))
                }
                SupervisorCommand::GetRpfProvider => {
                    let provider = coordinator.state.pim_state.get_rpf_provider().clone();
                    let static_entries = coordinator.state.pim_state.static_rpf.len();
                    Some(Response::RpfProvider(crate::RpfProviderInfo {
                        provider,
                        static_entries,
                        cached_entries: 0, // No caching implemented yet
                    }))
                }
                SupervisorCommand::QueryRpf { source } => {
                    let rpf = coordinator.state.pim_state.lookup_rpf(*source).cloned();
                    Some(Response::RpfResult(rpf))
                }
                SupervisorCommand::ListRpfRoutes => {
                    let routes: Vec<crate::RpfRouteEntry> = coordinator
                        .state
                        .pim_state
                        .get_rpf_routes()
                        .into_iter()
                        .map(|(source, rpf)| crate::RpfRouteEntry {
                            source,
                            rpf: rpf.clone(),
                        })
                        .collect();
                    Some(Response::RpfRoutes(routes))
                }
                SupervisorCommand::GetControlPlaneConfig => {
                    let rpf_provider_str = match coordinator.state.pim_state.get_rpf_provider() {
                        crate::RpfProvider::Disabled => "disabled".to_string(),
                        crate::RpfProvider::Static => "static".to_string(),
                        crate::RpfProvider::External { socket_path } => socket_path.clone(),
                    };
                    Some(Response::ControlPlaneConfig {
                        rpf_provider: rpf_provider_str,
                        external_neighbors_enabled: true, // External neighbors are always accepted via API
                        event_buffer_size: coordinator.state.event_buffer_size(),
                    })
                }
                SupervisorCommand::AddExternalNeighbor { ref neighbor } => {
                    // Validate and add in one atomic operation
                    if coordinator.state.pim_state.add_external_neighbor(neighbor) {
                        log_info!(
                            logger,
                            Facility::Supervisor,
                            &format!(
                                "External PIM neighbor {} added on {}",
                                neighbor.address, neighbor.interface
                            )
                        );
                        // Emit event for external neighbor up
                        coordinator.state.emit_event(
                            crate::ProtocolEventNotification::PimNeighborChange {
                                interface: neighbor.interface.clone(),
                                neighbor: neighbor.address,
                                action: crate::NeighborAction::Up,
                                source: crate::NeighborSource::External {
                                    tag: neighbor.tag.clone(),
                                },
                                timestamp: unix_timestamp(),
                            },
                        );
                        Some(Response::Success(format!(
                            "External neighbor {} added on {}",
                            neighbor.address, neighbor.interface
                        )))
                    } else {
                        Some(Response::Error(format!(
                            "Interface {} not enabled for PIM. Enable PIM on the interface first.",
                            neighbor.interface
                        )))
                    }
                }
                SupervisorCommand::RemoveExternalNeighbor { address, interface } => {
                    // Remove in one atomic operation
                    if coordinator
                        .state
                        .pim_state
                        .remove_external_neighbor(*address, interface)
                    {
                        log_info!(
                            logger,
                            Facility::Supervisor,
                            &format!(
                                "External PIM neighbor {} removed from {}",
                                address, interface
                            )
                        );
                        // Emit event for external neighbor down
                        coordinator.state.emit_event(
                            crate::ProtocolEventNotification::PimNeighborChange {
                                interface: interface.clone(),
                                neighbor: *address,
                                action: crate::NeighborAction::Down,
                                source: crate::NeighborSource::External { tag: None },
                                timestamp: unix_timestamp(),
                            },
                        );
                        Some(Response::Success(format!(
                            "External neighbor {} removed from {}",
                            address, interface
                        )))
                    } else {
                        Some(Response::Error(format!(
                            "External neighbor {} not found on interface {}",
                            address, interface
                        )))
                    }
                }
                SupervisorCommand::ClearExternalNeighbors { ref interface } => {
                    // Clear in one atomic operation
                    let removed = coordinator
                        .state
                        .pim_state
                        .clear_external_neighbors(interface.as_deref());
                    let msg = match interface {
                        Some(iface) => {
                            format!("Cleared {} external neighbors from {}", removed, iface)
                        }
                        None => {
                            format!("Cleared {} external neighbors from all interfaces", removed)
                        }
                    };
                    log_info!(logger, Facility::Supervisor, &msg);
                    Some(Response::Success(msg))
                }
                SupervisorCommand::EnablePim {
                    ref interface,
                    dr_priority,
                } => {
                    // Check multicast capability
                    if let Err(e) = socket_helpers::check_multicast_capability(interface) {
                        log_warning!(
                            logger,
                            Facility::Supervisor,
                            &format!("PIM on {}: {}", interface, e)
                        );
                    }

                    // Look up interface IP
                    match get_interface_ipv4(interface) {
                        None => Some(Response::Error(format!(
                            "Interface {} not found or has no IPv4 address",
                            interface
                        ))),
                        Some(interface_ip) => {
                            // Create PIM interface config
                            let pim_config = if let Some(priority) = *dr_priority {
                                crate::protocols::pim::PimInterfaceConfig {
                                    dr_priority: priority,
                                    ..Default::default()
                                }
                            } else {
                                crate::protocols::pim::PimInterfaceConfig::default()
                            };

                            // Enable PIM on the interface
                            let timers = coordinator.state.pim_state.enable_interface(
                                interface,
                                interface_ip,
                                pim_config,
                            );

                            // Schedule the returned timers (Hello timer)
                            if let Some(ref timer_tx) = coordinator.state.timer_tx {
                                for timer in timers {
                                    if let Err(e) = timer_tx.try_send(timer) {
                                        log_warning!(
                                            logger,
                                            Facility::Supervisor,
                                            &format!("Failed to schedule PIM timer: {}", e)
                                        );
                                    }
                                }
                            }

                            // Ensure PIM socket exists and join multicast on this interface
                            coordinator.state.pim_enabled = true;
                            let need_pim_socket = coordinator.state.pim_socket.is_none();
                            if need_pim_socket {
                                if let Err(e) = coordinator.state.create_pim_socket() {
                                    log_error!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!("Failed to create PIM socket: {}", e)
                                    );
                                }
                            }

                            // Also create IGMP socket for source detection
                            // The AF_PACKET recv socket is needed for detecting local sources
                            // which triggers MSDP SA origination
                            let need_source_detect_socket =
                                coordinator.state.igmp_recv_socket.is_none();
                            if need_source_detect_socket {
                                if let Err(e) = coordinator.state.create_igmp_socket() {
                                    log_error!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!("Failed to create source detection socket: {}", e)
                                    );
                                }
                            }

                            // Restart receiver loop to include PIM socket
                            // (this handles both initial spawn and restart after IGMP-only)
                            coordinator.state.restart_receiver_loop();
                            if let Err(e) =
                                coordinator.state.join_pim_multicast_on_interface(interface)
                            {
                                log_warning!(
                                    logger,
                                    Facility::Supervisor,
                                    &format!("Failed to join PIM multicast on {}: {} (may already be joined)", interface, e)
                                );
                            }

                            log_info!(
                                logger,
                                Facility::Supervisor,
                                &format!(
                                    "PIM enabled on interface {} (IP: {}, DR priority: {:?})",
                                    interface, interface_ip, dr_priority
                                )
                            );
                            Some(Response::Success(format!(
                                "PIM enabled on {} (IP: {}, DR priority: {})",
                                interface,
                                interface_ip,
                                dr_priority.unwrap_or(1)
                            )))
                        }
                    }
                }
                SupervisorCommand::DisablePim { ref interface } => {
                    // Disable PIM on the interface
                    coordinator.state.pim_state.disable_interface(interface);
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!("PIM disabled on interface {}", interface)
                    );
                    Some(Response::Success(format!("PIM disabled on {}", interface)))
                }
                SupervisorCommand::SetRpAddress { address } => {
                    // Validate address is unicast
                    if address.is_multicast() {
                        Some(Response::Error("RP address must be unicast".to_string()))
                    } else {
                        // Set this router's RP address
                        coordinator.state.pim_state.config.rp_address = Some(*address);
                        log_info!(
                            logger,
                            Facility::Supervisor,
                            &format!(
                                "This router is now an RP at address {} (MSDP SA origination enabled)",
                                address
                            )
                        );
                        Some(Response::Success(format!(
                            "RP address set to {}. This router will originate MSDP SA messages for directly-connected sources.",
                            address
                        )))
                    }
                }
                SupervisorCommand::SetStaticRp {
                    ref group_prefix,
                    rp_address,
                } => {
                    // Validate RP address is unicast
                    if rp_address.is_multicast() {
                        Some(Response::Error("RP address must be unicast".to_string()))
                    } else {
                        // Parse group prefix to get base address
                        match parse_group_prefix(group_prefix) {
                            Err(e) => Some(Response::Error(format!("Invalid group prefix: {}", e))),
                            Ok(group) => {
                                // Set the static RP mapping
                                coordinator
                                    .state
                                    .pim_state
                                    .config
                                    .static_rp
                                    .insert(group, *rp_address);
                                log_info!(
                                    logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "Static RP {} configured for group prefix {}",
                                        rp_address, group_prefix
                                    )
                                );
                                Some(Response::Success(format!(
                                    "Static RP {} set for group prefix {}",
                                    rp_address, group_prefix
                                )))
                            }
                        }
                    }
                }
                SupervisorCommand::EnableIgmpQuerier { ref interface } => {
                    // Check multicast capability
                    if let Err(e) = socket_helpers::check_multicast_capability(interface) {
                        log_warning!(
                            logger,
                            Facility::Supervisor,
                            &format!("IGMP on {}: {}", interface, e)
                        );
                    }

                    // Look up interface IP
                    match get_interface_ipv4(interface) {
                        None => Some(Response::Error(format!(
                            "Interface {} not found or has no IPv4 address",
                            interface
                        ))),
                        Some(interface_ip) => {
                            // Create IGMP interface state
                            let igmp_config = crate::protocols::igmp::IgmpConfig::default();
                            let state = crate::protocols::igmp::InterfaceIgmpState::new(
                                interface.clone(),
                                interface_ip,
                                igmp_config,
                            );
                            coordinator
                                .state
                                .igmp_state
                                .insert(interface.clone(), state);

                            // Schedule initial General Query timer
                            if let Some(ref timer_tx) = coordinator.state.timer_tx {
                                let timer = crate::protocols::TimerRequest {
                                    timer_type: crate::protocols::TimerType::IgmpGeneralQuery {
                                        interface: interface.clone(),
                                    },
                                    fire_at: std::time::Instant::now(),
                                    replace_existing: true,
                                };
                                if let Err(e) = timer_tx.try_send(timer) {
                                    log_warning!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!("Failed to schedule IGMP timer: {}", e)
                                    );
                                }
                            }

                            // Ensure IGMP socket exists
                            coordinator.state.igmp_enabled = true;
                            let need_socket = coordinator.state.igmp_recv_socket.is_none();
                            if need_socket {
                                if let Err(e) = coordinator.state.create_igmp_socket() {
                                    log_error!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!("Failed to create IGMP socket: {}", e)
                                    );
                                }
                            }
                            // Restart receiver loop to include IGMP socket
                            // (this handles both initial spawn and restart after PIM-only)
                            coordinator.state.restart_receiver_loop();

                            // Enable ALLMULTI and join IGMPv3 all-routers on this interface
                            if let Err(e) =
                                coordinator.state.enable_allmulti_on_interface(interface)
                            {
                                log_warning!(
                                    logger,
                                    Facility::Supervisor,
                                    &format!("Failed to enable ALLMULTI on {}: {}", interface, e)
                                );
                            }
                            if let Err(e) = coordinator.state.join_igmp_v3_all_routers(interface) {
                                log_warning!(
                                    logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "Failed to join IGMPv3 all-routers on {}: {} (may already be joined)",
                                        interface, e
                                    )
                                );
                            }

                            log_info!(
                                logger,
                                Facility::Supervisor,
                                &format!(
                                    "IGMP querier enabled on interface {} (IP: {})",
                                    interface, interface_ip
                                )
                            );
                            Some(Response::Success(format!(
                                "IGMP querier enabled on {} (IP: {})",
                                interface, interface_ip
                            )))
                        }
                    }
                }
                SupervisorCommand::DisableIgmpQuerier { ref interface } => {
                    // Remove IGMP state for the interface
                    coordinator.state.igmp_state.remove(interface);
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!("IGMP querier disabled on interface {}", interface)
                    );
                    Some(Response::Success(format!(
                        "IGMP querier disabled on {}",
                        interface
                    )))
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
        startup_config.as_ref().as_ref(),
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
                // Move rules out of relay_cmd to avoid clone (relay_cmd not used after this)
                let all_rules = if let RelayCommand::SyncRules(rules) = relay_cmd {
                    rules
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
                    let cmd_bytes: Bytes = match serde_json::to_vec(&interface_cmd) {
                        Ok(bytes) => bytes.into(),
                        Err(e) => {
                            log_error!(
                                logger,
                                Facility::Supervisor,
                                &format!(
                                    "Failed to serialize SyncRules for interface {}: {}",
                                    interface, e
                                )
                            );
                            continue;
                        }
                    };

                    // Send to ingress worker (Bytes::clone is cheap - Arc-based)
                    let cmd_bytes_clone = cmd_bytes.clone();
                    tokio::spawn(async move {
                        let mut stream = ingress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        let _ = framed.send(cmd_bytes_clone).await;
                    });

                    // Send to egress worker
                    tokio::spawn(async move {
                        let mut stream = egress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        let _ = framed.send(cmd_bytes).await;
                    });
                }
            } else {
                // For non-SyncRules commands, broadcast same command to all workers
                // Convert to Bytes upfront for cheap Arc-based cloning
                let cmd_bytes: Bytes = serde_json::to_vec(&relay_cmd)?.into();

                // Get cmd stream pairs from WorkerManager
                let stream_pairs = {
                    let manager = worker_manager.lock().unwrap();
                    manager.get_all_dp_cmd_streams()
                };

                if is_ping {
                    // For ping, wait for all sends to complete and verify success
                    let mut send_tasks = Vec::new();

                    for (ingress_stream, egress_stream) in stream_pairs {
                        // Send to ingress (Bytes::clone is cheap - Arc-based)
                        let cmd_bytes_clone = cmd_bytes.clone();
                        let task = tokio::spawn(async move {
                            let mut stream = ingress_stream.lock().await;
                            let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                            framed.send(cmd_bytes_clone).await
                        });
                        send_tasks.push(task);

                        // Send to egress
                        let cmd_bytes_clone = cmd_bytes.clone();
                        let task = tokio::spawn(async move {
                            let mut stream = egress_stream.lock().await;
                            let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                            framed.send(cmd_bytes_clone).await
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
                        // Send to ingress (Bytes::clone is cheap - Arc-based)
                        let cmd_bytes_clone = cmd_bytes.clone();
                        tokio::spawn(async move {
                            let mut stream = ingress_stream.lock().await;
                            let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                            let _ = framed.send(cmd_bytes_clone).await;
                        });

                        // Send to egress
                        let cmd_bytes_clone = cmd_bytes.clone();
                        tokio::spawn(async move {
                            let mut stream = egress_stream.lock().await;
                            let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                            let _ = framed.send(cmd_bytes_clone).await;
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
            // Check if workers need spawning (brief lock to plan, then spawn without lock)
            let plan = {
                let mut mgr = worker_manager.lock().unwrap();
                mgr.plan_workers_for_interface(&interface, is_pinned)
            };

            if let Some((core_ids, fanout_group_id)) = plan {
                // Spawn workers synchronously — this is a one-time operation per interface
                // (no backoff sleep) so brief blocking is acceptable for correctness.
                for core_id in core_ids {
                    match worker_manager::spawn_data_plane_worker(
                        core_id,
                        interface.clone(),
                        fanout_group_id,
                        &logger,
                    )
                    .await
                    {
                        Ok((child, ingress, egress, log_pipe, stats_pipe)) => {
                            let mut mgr = worker_manager.lock().unwrap();
                            if let Err(e) = mgr.register_spawned_worker(
                                child, ingress, egress, log_pipe, stats_pipe, &interface, core_id,
                            ) {
                                log_error!(
                                    logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "Failed to register worker for '{}' core {}: {}",
                                        interface, core_id, e
                                    )
                                );
                            }
                        }
                        Err(e) => {
                            log_error!(
                                logger,
                                Facility::Supervisor,
                                &format!(
                                    "Failed to spawn worker for '{}' core {}: {}",
                                    interface, core_id, e
                                )
                            );
                        }
                    }
                }
            }

            // Send the command to workers for the specified interface
            let cmd_bytes: Bytes = serde_json::to_vec(&command)?.into();
            let stream_pairs_with_iface = {
                let manager = worker_manager.lock().unwrap();
                manager.get_all_dp_cmd_streams_with_interface()
            };

            for (worker_interface, ingress_stream, egress_stream) in stream_pairs_with_iface {
                if worker_interface != interface {
                    continue;
                }

                let cmd_bytes_clone = cmd_bytes.clone();
                tokio::spawn(async move {
                    let mut stream = ingress_stream.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    let _ = framed.send(cmd_bytes_clone).await;
                });

                let cmd_bytes_clone = cmd_bytes.clone();
                tokio::spawn(async move {
                    let mut stream = egress_stream.lock().await;
                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                    let _ = framed.send(cmd_bytes_clone).await;
                });
            }
        }
        CommandAction::AddMsdpPeer {
            address,
            description,
            mesh_group,
            default_peer,
        } => {
            // First, check if MSDP TCP needs to be initialized
            let needs_msdp_tcp = {
                let coordinator_guard = protocol_coordinator.lock().unwrap();
                if let Some(ref coordinator) = *coordinator_guard {
                    coordinator.state.msdp_tcp_tx.is_none()
                } else {
                    false
                }
            };

            // Initialize MSDP TCP if needed (must be done outside the lock since it's async)
            if needs_msdp_tcp {
                let event_tx = {
                    let coordinator_guard = protocol_coordinator.lock().unwrap();
                    coordinator_guard
                        .as_ref()
                        .and_then(|c| c.state.event_tx.clone())
                };

                if let Some(event_tx) = event_tx {
                    // Find local address that can reach the peer
                    let local_addr = get_source_addr_for_dest(address)
                        .unwrap_or_else(|| get_interface_ipv4("lo").unwrap_or(Ipv4Addr::LOCALHOST));

                    match crate::protocols::msdp_tcp::start_msdp_tcp(local_addr, event_tx).await {
                        Ok((tcp_cmd_tx, listener_task, runner_task)) => {
                            // Store the command channel
                            {
                                let mut coordinator_guard = protocol_coordinator.lock().unwrap();
                                if let Some(ref mut coordinator) = *coordinator_guard {
                                    coordinator.state.msdp_tcp_tx = Some(tcp_cmd_tx);
                                    coordinator.state.msdp_enabled = true;
                                }
                            }

                            // Spawn MSDP TCP tasks
                            tokio::spawn(async move {
                                listener_task.await;
                            });
                            tokio::spawn(async move {
                                runner_task.await;
                            });

                            log_info!(
                                logger,
                                Facility::Supervisor,
                                &format!("MSDP TCP subsystem initialized on {}:639", local_addr)
                            );
                        }
                        Err(e) => {
                            log_warning!(
                                logger,
                                Facility::Supervisor,
                                &format!("Failed to initialize MSDP TCP: {}", e)
                            );
                        }
                    }
                } else {
                    log_warning!(
                        logger,
                        Facility::Supervisor,
                        "Cannot initialize MSDP TCP: event_tx not available"
                    );
                }
            }

            // Now add the peer
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                use crate::protocols::msdp::MsdpPeerConfig;

                // Enable MSDP in the state config (required for add_peer to schedule timers)
                coordinator.state.msdp_state.config.enabled = true;

                let peer_config = MsdpPeerConfig {
                    address,
                    description: description.clone(),
                    mesh_group,
                    default_peer,
                    keepalive_interval: coordinator.state.msdp_state.config.keepalive_interval,
                    hold_time: coordinator.state.msdp_state.config.hold_time,
                };
                let timers = coordinator.state.msdp_state.add_peer(peer_config);

                // Schedule connection timers
                for timer in timers {
                    if let Err(e) = coordinator.timer_tx.try_send(timer) {
                        log_warning!(
                            logger,
                            Facility::Supervisor,
                            &format!("Failed to schedule MSDP timer: {}", e)
                        );
                    }
                }

                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!(
                        "MSDP peer {} added{}",
                        address,
                        description
                            .as_ref()
                            .map(|d| format!(" ({})", d))
                            .unwrap_or_default()
                    )
                );
            }
        }
        CommandAction::RemoveMsdpPeer { address } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                coordinator.state.msdp_state.remove_peer(address);
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!("MSDP peer {} removed", address)
                );
            }
        }
        CommandAction::ClearMsdpSaCache => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                coordinator.state.msdp_state.sa_cache.clear();
                log_info!(logger, Facility::Supervisor, "MSDP SA cache cleared");
            }
        }
        CommandAction::AddExternalNeighbor { neighbor } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                if coordinator.state.pim_state.add_external_neighbor(&neighbor) {
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!(
                            "External PIM neighbor {} added on {}",
                            neighbor.address, neighbor.interface
                        )
                    );
                    // Emit event for external neighbor up
                    coordinator.state.emit_event(
                        crate::ProtocolEventNotification::PimNeighborChange {
                            interface: neighbor.interface.clone(),
                            neighbor: neighbor.address,
                            action: crate::NeighborAction::Up,
                            source: crate::NeighborSource::External {
                                tag: neighbor.tag.clone(),
                            },
                            timestamp: unix_timestamp(),
                        },
                    );
                } else {
                    log_warning!(
                        logger,
                        Facility::Supervisor,
                        &format!(
                            "Failed to add external neighbor {}: interface {} not enabled for PIM",
                            neighbor.address, neighbor.interface
                        )
                    );
                    final_response = Response::Error(format!(
                        "Interface {} not enabled for PIM",
                        neighbor.interface
                    ));
                }
            }
        }
        CommandAction::RemoveExternalNeighbor { address, interface } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                if coordinator
                    .state
                    .pim_state
                    .remove_external_neighbor(address, &interface)
                {
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!(
                            "External PIM neighbor {} removed from {}",
                            address, interface
                        )
                    );
                    // Emit event for external neighbor down
                    coordinator.state.emit_event(
                        crate::ProtocolEventNotification::PimNeighborChange {
                            interface: interface.clone(),
                            neighbor: address,
                            action: crate::NeighborAction::Down,
                            source: crate::NeighborSource::External { tag: None },
                            timestamp: unix_timestamp(),
                        },
                    );
                } else {
                    log_warning!(
                        logger,
                        Facility::Supervisor,
                        &format!(
                            "External neighbor {} not found on {} (or not external)",
                            address, interface
                        )
                    );
                    final_response = Response::Error(format!(
                        "External neighbor {} not found on {}",
                        address, interface
                    ));
                }
            }
        }
        CommandAction::ClearExternalNeighbors { interface } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                let count = coordinator
                    .state
                    .pim_state
                    .clear_external_neighbors(interface.as_deref());
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!(
                        "Cleared {} external PIM neighbor(s){}",
                        count,
                        interface
                            .as_ref()
                            .map(|i| format!(" from {}", i))
                            .unwrap_or_default()
                    )
                );
            }
        }
        CommandAction::SetRpfProvider { provider } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                coordinator
                    .state
                    .pim_state
                    .set_rpf_provider(provider.clone());
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!("RPF provider set to {}", provider)
                );
            }
        }
        CommandAction::AddRpfRoute { source, rpf } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                coordinator
                    .state
                    .pim_state
                    .add_rpf_route(source, rpf.clone());
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!(
                        "Static RPF route added for {} via {}",
                        source, rpf.upstream_interface
                    )
                );
            }
        }
        CommandAction::RemoveRpfRoute { source } => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                if coordinator.state.pim_state.remove_rpf_route(source) {
                    log_info!(
                        logger,
                        Facility::Supervisor,
                        &format!("Static RPF route removed for {}", source)
                    );
                } else {
                    log_warning!(
                        logger,
                        Facility::Supervisor,
                        &format!("Static RPF route not found for {}", source)
                    );
                    final_response =
                        Response::Error(format!("Static RPF route not found for {}", source));
                }
            }
        }
        CommandAction::ClearRpfRoutes => {
            let mut coordinator_guard = protocol_coordinator.lock().unwrap();
            if let Some(ref mut coordinator) = *coordinator_guard {
                let count = coordinator.state.pim_state.clear_rpf_routes();
                log_info!(
                    logger,
                    Facility::Supervisor,
                    &format!("Cleared {} static RPF route(s)", count)
                );
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
#[allow(clippy::await_holding_lock)] // Remaining cases: shutdown (runs once) and protocol coordinator (requires lock for correctness)
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
    let detected_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
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

    // Start netlink monitor for real-time interface change detection (H3.4)
    // This refreshes the interface cache immediately when interfaces change,
    // rather than waiting for the TTL to expire.
    let _netlink_monitor_handle = netlink_monitor::spawn_netlink_monitor(supervisor_logger.clone());

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
                    let cmd_bytes: Bytes = cmd_bytes.into();
                    // Send to ingress worker using length-delimited framing
                    {
                        let mut stream = ingress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        let _ = framed.send(cmd_bytes.clone()).await;
                    }
                    // Send to egress worker using length-delimited framing
                    {
                        let mut stream = egress_stream.lock().await;
                        let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                        let _ = framed.send(cmd_bytes).await;
                    }
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

    // Initialize protocol subsystem if PIM, IGMP, or MSDP is configured
    // Wrap in Arc<Mutex<>> so it can be shared with handle_client and event processing
    let protocol_coordinator: Arc<Mutex<Option<ProtocolCoordinator>>> = Arc::new(Mutex::new(None));

    if let Some(ref config) = startup_config {
        let pim_enabled = config.pim.as_ref().map(|p| p.enabled).unwrap_or(false);
        let igmp_enabled = config
            .igmp
            .as_ref()
            .map(|i| !i.querier_interfaces.is_empty())
            .unwrap_or(false);
        let msdp_enabled = config.msdp.as_ref().map(|m| m.enabled).unwrap_or(false);

        if pim_enabled || igmp_enabled || msdp_enabled {
            log_info!(
                supervisor_logger,
                Facility::Supervisor,
                &format!(
                    "Initializing protocol subsystem (PIM: {}, IGMP: {}, MSDP: {})",
                    pim_enabled, igmp_enabled, msdp_enabled
                )
            );

            match initialize_protocol_subsystem(config, supervisor_logger.clone()) {
                Ok((mut coordinator, receiver_task, timer_task)) => {
                    // Spawn protocol background tasks
                    // Store the handle so we can abort it on restart
                    let receiver_handle = tokio::spawn(async move {
                        receiver_task.await;
                    });
                    coordinator.state.receiver_loop_handle = Some(receiver_handle);
                    tokio::spawn(async move {
                        timer_task.await;
                    });

                    // Initialize MSDP TCP if enabled
                    if msdp_enabled {
                        if let Some(msdp_config) = &config.msdp {
                            let local_addr = msdp_config.local_address.unwrap_or_else(|| {
                                // Try to find a suitable local address
                                get_interface_ipv4("lo").unwrap_or(Ipv4Addr::LOCALHOST)
                            });

                            // Create event channel for MSDP TCP
                            let msdp_event_tx = coordinator.event_tx_clone();

                            match crate::protocols::msdp_tcp::start_msdp_tcp(
                                local_addr,
                                msdp_event_tx,
                            )
                            .await
                            {
                                Ok((tcp_cmd_tx, listener_task, runner_task)) => {
                                    // Store the command channel in protocol state
                                    coordinator.state.msdp_tcp_tx = Some(tcp_cmd_tx);

                                    // Spawn MSDP TCP tasks
                                    tokio::spawn(async move {
                                        listener_task.await;
                                    });
                                    tokio::spawn(async move {
                                        runner_task.await;
                                    });

                                    log_info!(
                                        supervisor_logger,
                                        Facility::Supervisor,
                                        &format!(
                                            "MSDP TCP subsystem initialized on {}:639",
                                            local_addr
                                        )
                                    );
                                }
                                Err(e) => {
                                    log_warning!(
                                        supervisor_logger,
                                        Facility::Supervisor,
                                        &format!("Failed to initialize MSDP TCP: {}", e)
                                    );
                                }
                            }
                        }
                    }

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

    // If no protocol subsystem was created from config, create a minimal one
    // This allows CLI commands like `pim enable` to work without a config file
    if protocol_coordinator.lock().unwrap().is_none() {
        log_info!(
            supervisor_logger,
            Facility::Supervisor,
            "Initializing minimal protocol subsystem for CLI commands"
        );

        // Create a minimal empty config
        let empty_config = Config {
            rules: vec![],
            pinning: std::collections::HashMap::new(),
            pim: None,
            igmp: None,
            msdp: None,
            control_plane: None,
            multicast_ttl: None,
        };

        match initialize_protocol_subsystem(&empty_config, supervisor_logger.clone()) {
            Ok((mut coordinator, receiver_task, timer_task)) => {
                // Spawn protocol background tasks
                // Store the handle so we can abort it on restart
                let receiver_handle = tokio::spawn(async move {
                    receiver_task.await;
                });
                coordinator.state.receiver_loop_handle = Some(receiver_handle);
                tokio::spawn(async move {
                    timer_task.await;
                });

                // Store coordinator
                *protocol_coordinator.lock().unwrap() = Some(coordinator);

                log_info!(
                    supervisor_logger,
                    Facility::Supervisor,
                    "Minimal protocol subsystem initialized"
                );
            }
            Err(e) => {
                log_warning!(
                    supervisor_logger,
                    Facility::Supervisor,
                    &format!("Failed to initialize minimal protocol subsystem: {}", e)
                );
            }
        }
    }

    // Wrap startup_config in Arc for sharing with handle_client
    let startup_config: Arc<Option<Config>> = Arc::new(startup_config);

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
                    Arc::clone(&startup_config),
                    Arc::clone(&protocol_coordinator),
                    supervisor_logger.clone(),
                )
                .await
                {
                    log_error!(
                        supervisor_logger,
                        Facility::Supervisor,
                        &format!("Error handling client: {}", e)
                    );
                }
            }

            // Periodic worker health check (every 250ms)
            // Fast: detect exited workers (non-blocking try_wait), then spawn
            // async restart tasks so backoff sleep doesn't block the select loop.
            _ = health_check_interval.tick() => {
                let exited = {
                    let mut manager = worker_manager.lock().unwrap();
                    manager.detect_exited_workers()
                };

                for info in exited {
                    let wm = Arc::clone(&worker_manager);
                    let logger = supervisor_logger.clone();
                    let rules = Arc::clone(&master_rules);
                    tokio::spawn(async move {
                        // Slow phase: backoff sleep + subprocess spawn
                        if !info.graceful {
                            tokio::time::sleep(Duration::from_millis(info.backoff_ms)).await;
                        }

                        match worker_manager::spawn_data_plane_worker(
                            info.core_id,
                            info.interface.clone(),
                            info.fanout_group_id,
                            &logger,
                        ).await {
                            Ok((child, ingress, egress, log_pipe, stats_pipe)) => {
                                let new_pid = {
                                    let mut mgr = wm.lock().unwrap();
                                    mgr.register_spawned_worker(
                                        child, ingress, egress, log_pipe, stats_pipe,
                                        &info.interface, info.core_id,
                                    )
                                };

                                // Sync rules to the restarted worker
                                if let Ok(pid) = new_pid {
                                    let rules_snapshot: Vec<ForwardingRule> = {
                                        let r = rules.lock().unwrap();
                                        r.values().cloned().collect()
                                    };
                                    if !rules_snapshot.is_empty() {
                                        let streams = {
                                            let mgr = wm.lock().unwrap();
                                            mgr.get_all_dp_cmd_streams_with_interface()
                                        };
                                        for (iface, ingress_stream, egress_stream) in streams {
                                            if iface != info.interface {
                                                continue;
                                            }
                                            let iface_rules: Vec<ForwardingRule> = rules_snapshot
                                                .iter()
                                                .filter(|r| r.input_interface == iface)
                                                .cloned()
                                                .collect();
                                            let sync_cmd = RelayCommand::SyncRules(iface_rules);
                                            if let Ok(cmd_bytes) = serde_json::to_vec(&sync_cmd) {
                                                let cmd_bytes: Bytes = cmd_bytes.into();
                                                {
                                                    let mut stream = ingress_stream.lock().await;
                                                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                                                    let _ = framed.send(cmd_bytes.clone()).await;
                                                }
                                                {
                                                    let mut stream = egress_stream.lock().await;
                                                    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
                                                    let _ = framed.send(cmd_bytes).await;
                                                }
                                            }
                                        }
                                    }
                                    log_info!(
                                        logger,
                                        Facility::Supervisor,
                                        &format!("Worker PID {} restarted for interface '{}' core {}",
                                            pid, info.interface, info.core_id)
                                    );
                                }
                            }
                            Err(e) => {
                                let mut mgr = wm.lock().unwrap();
                                mgr.restarting.remove(&(info.interface.clone(), info.core_id));
                                log_error!(
                                    logger,
                                    Facility::Supervisor,
                                    &format!("Failed to restart worker for interface '{}' core {}: {}",
                                        info.interface, info.core_id, e)
                                );
                            }
                        }
                    });
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
                            let cmd_bytes: Bytes = cmd_bytes.into();
                            // Send to ingress worker using length-delimited framing
                            {
                                let mut stream = ingress_stream.lock().await;
                                let mut framed =
                                    Framed::new(&mut *stream, LengthDelimitedCodec::new());
                                let _ = framed.send(cmd_bytes.clone()).await;
                            }
                            // Send to egress worker using length-delimited framing
                            {
                                let mut stream = egress_stream.lock().await;
                                let mut framed =
                                    Framed::new(&mut *stream, LengthDelimitedCodec::new());
                                let _ = framed.send(cmd_bytes).await;
                            }
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

                    // Debug: log when MRIB is modified
                    if mrib_modified {
                        log_info!(
                            supervisor_logger,
                            Facility::Supervisor,
                            &format!(
                                "MRIB modified, rules_dirty={}",
                                coordinator.rules_dirty()
                            )
                        );
                    }

                    // Sync rules whenever the dirty flag is set
                    // Previously required mrib_modified && rules_dirty(), but this caused
                    // issues when workers didn't exist during the tick that modified MRIB.
                    // Now we check only rules_dirty() to ensure rules are synced on the
                    // next tick even if no new events are processed.
                    if coordinator.rules_dirty() {
                        // Compile rules from MRIB (merges static + protocol-learned)
                        let protocol_rules = coordinator.compile_rules();

                        log_info!(
                            supervisor_logger,
                            Facility::Supervisor,
                            &format!(
                                "Compiling rules: {} protocol rules from MRIB",
                                protocol_rules.len()
                            )
                        );

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
                                log_info!(
                                    supervisor_logger,
                                    Facility::Supervisor,
                                    &format!(
                                        "Adding protocol rule: input={}, group={}, outputs={:?}",
                                        rule.input_interface, rule.input_group, rule.outputs
                                    )
                                );
                                all_rules.push(rule);
                            }
                        }

                        // Drop the lock before the async call
                        drop(coordinator_guard);

                        // Ensure workers exist for all interfaces with rules
                        let interfaces_needing_workers: Vec<String> =
                            all_rules.iter().map(|r| r.input_interface.clone()).collect();
                        let interfaces_needing_workers: std::collections::HashSet<String> =
                            interfaces_needing_workers.into_iter().collect();

                        // Check which interfaces need workers (quick check with lock)
                        let interfaces_to_spawn: Vec<String> = {
                            let manager = worker_manager.lock().unwrap();
                            interfaces_needing_workers
                                .into_iter()
                                .filter(|iface| !manager.has_workers_for_interface(iface))
                                .collect()
                        };

                        // Spawn workers in background tasks to avoid blocking the select loop.
                        // The dirty flag will remain set, so rules will be synced on the next
                        // tick once workers are ready.
                        if !interfaces_to_spawn.is_empty() {
                            log_info!(
                                supervisor_logger,
                                Facility::Supervisor,
                                &format!(
                                    "Spawning workers for {} interfaces in background: {:?}",
                                    interfaces_to_spawn.len(),
                                    interfaces_to_spawn
                                )
                            );
                            // Plan spawns under lock, then execute async spawn outside lock
                            let spawn_plans: Vec<(String, Vec<u32>, u16)> = {
                                let mut mgr = worker_manager.lock().unwrap();
                                interfaces_to_spawn.into_iter().filter_map(|iface| {
                                    mgr.plan_workers_for_interface(&iface, false)
                                        .map(|(cores, fgid)| (iface, cores, fgid))
                                }).collect()
                            };
                            for (iface, core_ids, fanout_group_id) in spawn_plans {
                                let wm = Arc::clone(&worker_manager);
                                let logger_clone = supervisor_logger.clone();
                                tokio::spawn(async move {
                                    for core_id in core_ids {
                                        match worker_manager::spawn_data_plane_worker(
                                            core_id, iface.clone(), fanout_group_id, &logger_clone,
                                        ).await {
                                            Ok((child, ingress, egress, log_pipe, stats_pipe)) => {
                                                let mut mgr = wm.lock().unwrap();
                                                if let Err(e) = mgr.register_spawned_worker(
                                                    child, ingress, egress, log_pipe, stats_pipe, &iface, core_id,
                                                ) {
                                                    log_warning!(
                                                        logger_clone, Facility::Supervisor,
                                                        &format!("Failed to register worker for '{}' core {}: {}", iface, core_id, e)
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                log_warning!(
                                                    logger_clone, Facility::Supervisor,
                                                    &format!("Failed to spawn worker for '{}' core {}: {}", iface, core_id, e)
                                                );
                                            }
                                        }
                                    }
                                });
                            }
                        }

                        // Sync merged rules to all workers
                        log_info!(
                            supervisor_logger,
                            Facility::Supervisor,
                            &format!("Syncing {} rules to workers", all_rules.len())
                        );
                        let rules_synced = sync_rules_to_workers(&all_rules, &worker_manager, &supervisor_logger).await;

                        // Only clear dirty flag if rules were actually synced to workers
                        // This ensures we retry on the next tick if no workers existed
                        if rules_synced {
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
                        } else {
                            log_info!(
                                supervisor_logger,
                                Facility::Supervisor,
                                "No workers available to sync rules, keeping dirty flag set"
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{MPSCRingBuffer, Severity};
    use crate::protocols::TimerType;
    use std::sync::atomic::AtomicU8;
    use std::sync::{Arc, RwLock};
    use std::time::Instant;

    /// Create a test logger for unit tests
    fn create_test_logger() -> Logger {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));
        Logger::from_mpsc(ringbuffer, global_min_level, facility_min_levels)
    }

    // ===========================================
    // get_source_addr_for_dest tests
    // ===========================================

    #[test]
    fn test_get_source_addr_for_dest_localhost() {
        let result = get_source_addr_for_dest(Ipv4Addr::LOCALHOST);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn test_get_source_addr_for_dest_external() {
        let result = get_source_addr_for_dest(Ipv4Addr::new(8, 8, 8, 8));
        if let Some(addr) = result {
            assert_ne!(addr, Ipv4Addr::UNSPECIFIED);
        }
    }

    #[test]
    fn test_get_source_addr_for_dest_link_local() {
        let result = get_source_addr_for_dest(Ipv4Addr::new(169, 254, 1, 1));
        let _ = result; // Just verify no panic
    }

    // ===========================================
    // ProtocolState initialization tests
    // ===========================================

    #[test]
    fn test_protocol_state_new() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        // Verify initial state
        assert!(!state.igmp_enabled);
        assert!(!state.pim_enabled);
        assert!(!state.msdp_enabled);
        assert!(state.igmp_send_socket.is_none());
        assert!(state.igmp_recv_socket.is_none());
        assert!(state.pim_socket.is_none());
        assert!(state.timer_tx.is_none());
        assert!(state.msdp_tcp_tx.is_none());
        assert!(state.igmp_state.is_empty());
        assert!(state.event_manager.is_none());
    }

    #[test]
    fn test_protocol_state_enable_event_subscriptions() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        assert!(state.event_manager.is_none());
        assert_eq!(state.event_buffer_size(), 256); // Default

        state.enable_event_subscriptions(512);

        assert!(state.event_manager.is_some());
        assert_eq!(state.event_buffer_size(), 512);
    }

    // ===========================================
    // MRIB action tests
    // ===========================================

    #[test]
    fn test_apply_mrib_action_add_igmp_membership() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let group = Ipv4Addr::new(239, 1, 1, 1);
        let membership = crate::mroute::IgmpMembership {
            group,
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: Some(Ipv4Addr::new(10, 0, 0, 100)),
        };

        let actions = vec![MribAction::AddIgmpMembership {
            interface: "eth0".to_string(),
            group,
            membership: membership.clone(),
        }];

        state.apply_mrib_actions(actions);

        // Verify membership was added
        let interfaces = state.mrib.get_igmp_interfaces_for_group(group);
        assert!(interfaces.contains(&"eth0".to_string()));
    }

    #[test]
    fn test_apply_mrib_action_remove_igmp_membership() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let group = Ipv4Addr::new(239, 1, 1, 1);
        let membership = crate::mroute::IgmpMembership {
            group,
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: Some(Ipv4Addr::new(10, 0, 0, 100)),
        };

        // First add
        state.mrib.add_igmp_membership("eth0", group, membership);
        assert!(!state.mrib.get_igmp_interfaces_for_group(group).is_empty());

        // Then remove via action
        let actions = vec![MribAction::RemoveIgmpMembership {
            interface: "eth0".to_string(),
            group,
        }];

        state.apply_mrib_actions(actions);

        // Verify removal
        let interfaces = state.mrib.get_igmp_interfaces_for_group(group);
        assert!(interfaces.is_empty());
    }

    #[test]
    fn test_apply_mrib_action_add_sg_route() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let source = Ipv4Addr::new(10, 0, 0, 1);
        let group = Ipv4Addr::new(239, 1, 1, 1);

        let mut downstream = std::collections::HashSet::new();
        downstream.insert("eth1".to_string());

        let route = crate::mroute::SGRoute {
            source,
            group,
            upstream_interface: Some("eth0".to_string()),
            downstream_interfaces: downstream,
            spt_bit: false,
            created_at: Instant::now(),
            expires_at: None,
        };

        let actions = vec![MribAction::AddSgRoute(route)];
        state.apply_mrib_actions(actions);

        // Verify route was added
        assert!(state.mrib.get_sg_route(source, group).is_some());
    }

    #[test]
    fn test_apply_mrib_action_remove_sg_route() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let source = Ipv4Addr::new(10, 0, 0, 1);
        let group = Ipv4Addr::new(239, 1, 1, 1);

        // Add first
        let mut downstream = std::collections::HashSet::new();
        downstream.insert("eth1".to_string());

        let route = crate::mroute::SGRoute {
            source,
            group,
            upstream_interface: Some("eth0".to_string()),
            downstream_interfaces: downstream,
            spt_bit: false,
            created_at: Instant::now(),
            expires_at: None,
        };
        state.mrib.add_sg_route(route);
        assert!(state.mrib.get_sg_route(source, group).is_some());

        // Remove via action
        let actions = vec![MribAction::RemoveSgRoute { source, group }];
        state.apply_mrib_actions(actions);

        assert!(state.mrib.get_sg_route(source, group).is_none());
    }

    // ===========================================
    // PIM state tests
    // ===========================================

    #[test]
    fn test_protocol_state_enable_pim_interface() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();

        let timers = state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // Should return Hello timer
        assert!(!timers.is_empty());
        assert!(matches!(timers[0].timer_type, TimerType::PimHello { .. }));

        // Verify interface is enabled
        assert!(state.pim_state.interfaces.contains_key("eth0"));
        let iface_state = state.pim_state.interfaces.get("eth0").unwrap();
        assert_eq!(iface_state.address, interface_ip);
    }

    #[test]
    fn test_protocol_state_disable_pim_interface() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable first
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);
        assert!(state.pim_state.interfaces.contains_key("eth0"));

        // Disable
        state.pim_state.disable_interface("eth0");
        assert!(!state.pim_state.interfaces.contains_key("eth0"));
    }

    #[test]
    fn test_get_pim_neighbors_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let neighbors = state.get_pim_neighbors();
        assert!(neighbors.is_empty());
    }

    #[test]
    fn test_get_pim_neighbors_with_data() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable interface
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // Add a neighbor manually
        let neighbor_addr = Ipv4Addr::new(10, 0, 0, 2);
        if let Some(iface_state) = state.pim_state.interfaces.get_mut("eth0") {
            iface_state.neighbors.insert(
                neighbor_addr,
                crate::protocols::pim::PimNeighbor {
                    address: neighbor_addr,
                    interface: "eth0".to_string(),
                    dr_priority: 100,
                    generation_id: Some(12345),
                    expires_at: Some(Instant::now() + std::time::Duration::from_secs(105)),
                    source: crate::NeighborSource::PimHello,
                },
            );
        }

        let neighbors = state.get_pim_neighbors();
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].address, neighbor_addr);
        assert_eq!(neighbors[0].interface, "eth0");
    }

    // ===========================================
    // IGMP state tests
    // ===========================================

    #[test]
    fn test_get_igmp_groups_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let groups = state.get_igmp_groups();
        assert!(groups.is_empty());
    }

    #[test]
    fn test_mrib_igmp_membership() {
        // Note: get_igmp_groups() reads from igmp_state, not mrib
        // This test verifies MRIB membership tracking separately
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let group = Ipv4Addr::new(239, 1, 1, 1);
        let membership = crate::mroute::IgmpMembership {
            group,
            expires_at: Instant::now() + std::time::Duration::from_secs(260),
            last_reporter: Some(Ipv4Addr::new(10, 0, 0, 100)),
        };

        state.mrib.add_igmp_membership("eth0", group, membership);

        // Verify via MRIB interface query (not get_igmp_groups which uses igmp_state)
        let interfaces = state.mrib.get_igmp_interfaces_for_group(group);
        assert_eq!(interfaces.len(), 1);
        assert!(interfaces.contains(&"eth0".to_string()));
    }

    // ===========================================
    // MSDP state tests
    // ===========================================

    #[test]
    fn test_get_msdp_peers_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let peers = state.get_msdp_peers();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_get_msdp_peers_with_data() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable MSDP first (required for add_peer to schedule timers)
        state.msdp_state.config.enabled = true;

        let peer_config = crate::protocols::msdp::MsdpPeerConfig {
            address: Ipv4Addr::new(10, 0, 0, 2),
            description: Some("Test peer".to_string()),
            mesh_group: None,
            default_peer: false,
            keepalive_interval: std::time::Duration::from_secs(60),
            hold_time: std::time::Duration::from_secs(90),
        };

        let timers = state.msdp_state.add_peer(peer_config);

        // With config.enabled = true, should get connection timer
        assert!(!timers.is_empty());

        let peers = state.get_msdp_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(peers[0].description, Some("Test peer".to_string()));
    }

    #[test]
    fn test_msdp_add_peer_without_enabled_returns_no_timers() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Don't enable MSDP - config.enabled defaults to false
        assert!(!state.msdp_state.config.enabled);

        let peer_config = crate::protocols::msdp::MsdpPeerConfig {
            address: Ipv4Addr::new(10, 0, 0, 2),
            description: None,
            mesh_group: None,
            default_peer: false,
            keepalive_interval: std::time::Duration::from_secs(60),
            hold_time: std::time::Duration::from_secs(90),
        };

        let timers = state.msdp_state.add_peer(peer_config);

        // Without config.enabled, should get NO timers (this was the bug!)
        assert!(
            timers.is_empty(),
            "add_peer should return no timers when config.enabled=false"
        );

        // Peer is still added to state
        let peers = state.get_msdp_peers();
        assert_eq!(peers.len(), 1);

        // But state should be "disabled"
        assert_eq!(peers[0].state.to_lowercase(), "disabled");
    }

    #[test]
    fn test_msdp_add_peer_with_enabled_returns_timers() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable MSDP
        state.msdp_state.config.enabled = true;

        let peer_config = crate::protocols::msdp::MsdpPeerConfig {
            address: Ipv4Addr::new(10, 0, 0, 2),
            description: None,
            mesh_group: None,
            default_peer: false,
            keepalive_interval: std::time::Duration::from_secs(60),
            hold_time: std::time::Duration::from_secs(90),
        };

        let timers = state.msdp_state.add_peer(peer_config);

        // With config.enabled, should get connection timer
        assert!(
            !timers.is_empty(),
            "add_peer should return timers when config.enabled=true"
        );
        assert!(matches!(
            timers[0].timer_type,
            TimerType::MsdpConnectRetry { .. }
        ));
    }

    // ===========================================
    // MSDP SA cache tests
    // ===========================================

    #[test]
    fn test_get_msdp_sa_cache_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let cache = state.get_msdp_sa_cache();
        assert!(cache.is_empty());
    }

    // ===========================================
    // Mroute entry tests
    // ===========================================

    #[test]
    fn test_get_mroute_entries_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let entries = state.get_mroute_entries();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_get_mroute_entries_with_sg_route() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let source = Ipv4Addr::new(10, 0, 0, 1);
        let group = Ipv4Addr::new(239, 1, 1, 1);

        // get_mroute_entries() reads from pim_state.sg, not mrib
        let mut sg_state = crate::protocols::pim::SGState::new(source, group);
        sg_state.upstream_interface = Some("eth0".to_string());
        sg_state.downstream_interfaces.insert("eth1".to_string());

        state.pim_state.sg.insert((source, group), sg_state);

        let entries = state.get_mroute_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, Some(source));
        assert_eq!(entries[0].group, group);
    }

    // ===========================================
    // Rule compilation tests
    // ===========================================

    #[test]
    fn test_compile_forwarding_rules_empty() {
        let logger = create_test_logger();
        let state = ProtocolState::new(logger);

        let rules = state.compile_forwarding_rules();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_compile_forwarding_rules_with_sg_route() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        let source = Ipv4Addr::new(10, 0, 0, 1);
        let group = Ipv4Addr::new(239, 1, 1, 1);

        let mut downstream = std::collections::HashSet::new();
        downstream.insert("eth1".to_string());

        let route = crate::mroute::SGRoute {
            source,
            group,
            upstream_interface: Some("eth0".to_string()),
            downstream_interfaces: downstream,
            spt_bit: false,
            created_at: Instant::now(),
            expires_at: None,
        };
        state.mrib.add_sg_route(route);

        let rules = state.compile_forwarding_rules();

        // Should have rules for downstream interface
        assert!(!rules.is_empty());
    }

    // ===========================================
    // PIM Join/Prune → MRIB action tests
    // ===========================================

    #[test]
    fn test_pim_join_creates_star_g_route_action() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable PIM on interface
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // Configure an RP for the group
        let group = Ipv4Addr::new(239, 1, 1, 1);
        let rp = Ipv4Addr::new(10, 0, 0, 100);
        state.pim_state.config.static_rp.insert(group, rp);

        // Process a (*,G) join
        let joins = vec![(None, group)]; // None source = (*,G)
        let prunes = vec![];
        let timers = state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &joins,
            &prunes,
            std::time::Duration::from_secs(210),
        );

        // Should have created (*,G) state
        assert!(state.pim_state.star_g.contains_key(&group));
        let star_g = state.pim_state.star_g.get(&group).unwrap();
        assert!(star_g.downstream_interfaces.contains("eth0"));
        assert!(!timers.is_empty()); // Should have expiry timer
    }

    #[test]
    fn test_pim_join_creates_sg_route_action() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable PIM on interface
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // Process an (S,G) join
        let source = Ipv4Addr::new(192, 168, 1, 100);
        let group = Ipv4Addr::new(239, 1, 1, 1);
        let joins = vec![(Some(source), group)];
        let prunes = vec![];
        let timers = state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &joins,
            &prunes,
            std::time::Duration::from_secs(210),
        );

        // Should have created (S,G) state
        assert!(state.pim_state.sg.contains_key(&(source, group)));
        let sg = state.pim_state.sg.get(&(source, group)).unwrap();
        assert!(sg.downstream_interfaces.contains("eth0"));
        assert!(!timers.is_empty()); // Should have expiry timer
    }

    #[test]
    fn test_pim_prune_removes_route_when_no_downstream() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable PIM on interface
        let interface_ip = Ipv4Addr::new(10, 0, 0, 1);
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", interface_ip, config);

        // First add an (S,G) via join
        let source = Ipv4Addr::new(192, 168, 1, 100);
        let group = Ipv4Addr::new(239, 1, 1, 1);
        let joins = vec![(Some(source), group)];
        state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &joins,
            &[],
            std::time::Duration::from_secs(210),
        );
        assert!(state.pim_state.sg.contains_key(&(source, group)));

        // Now prune it
        let prunes = vec![(Some(source), group)];
        state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &[],
            &prunes,
            std::time::Duration::from_secs(210),
        );

        // Route should be removed (no more downstreams)
        assert!(!state.pim_state.sg.contains_key(&(source, group)));
    }

    #[test]
    fn test_pim_prune_keeps_route_with_other_downstream() {
        let logger = create_test_logger();
        let mut state = ProtocolState::new(logger);

        // Enable PIM on two interfaces
        let config = crate::protocols::pim::PimInterfaceConfig::default();
        state
            .pim_state
            .enable_interface("eth0", Ipv4Addr::new(10, 0, 0, 1), config.clone());
        state
            .pim_state
            .enable_interface("eth1", Ipv4Addr::new(10, 0, 1, 1), config);

        // Add (S,G) via join on eth0
        let source = Ipv4Addr::new(192, 168, 1, 100);
        let group = Ipv4Addr::new(239, 1, 1, 1);
        state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &[(Some(source), group)],
            &[],
            std::time::Duration::from_secs(210),
        );

        // Also add on eth1
        state.pim_state.process_join_prune(
            "eth1",
            Ipv4Addr::new(10, 0, 1, 2),
            &[(Some(source), group)],
            &[],
            std::time::Duration::from_secs(210),
        );

        // Route should have both downstreams
        let sg = state.pim_state.sg.get(&(source, group)).unwrap();
        assert_eq!(sg.downstream_interfaces.len(), 2);

        // Prune on eth0
        state.pim_state.process_join_prune(
            "eth0",
            Ipv4Addr::new(10, 0, 0, 2),
            &[],
            &[(Some(source), group)],
            std::time::Duration::from_secs(210),
        );

        // Route should still exist with eth1 downstream
        assert!(state.pim_state.sg.contains_key(&(source, group)));
        let sg = state.pim_state.sg.get(&(source, group)).unwrap();
        assert_eq!(sg.downstream_interfaces.len(), 1);
        assert!(sg.downstream_interfaces.contains("eth1"));
    }
}
