// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Supervisor command handling logic.
//!
//! This module contains the pure (no I/O) command handler function and related types.
//! The handler processes supervisor commands and returns responses along with actions
//! that may need async I/O (like broadcasting to workers).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;

use super::{ForwardingRule, RelayCommand};
use crate::validation;

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
    /// Add an MSDP peer
    AddMsdpPeer {
        address: Ipv4Addr,
        description: Option<String>,
        mesh_group: Option<String>,
        default_peer: bool,
    },
    /// Remove an MSDP peer
    RemoveMsdpPeer { address: Ipv4Addr },
    /// Clear MSDP SA cache
    ClearMsdpSaCache,
    /// Add an external PIM neighbor
    AddExternalNeighbor { neighbor: crate::ExternalNeighbor },
    /// Remove an external PIM neighbor
    RemoveExternalNeighbor {
        address: Ipv4Addr,
        interface: String,
    },
    /// Clear all external PIM neighbors
    ClearExternalNeighbors { interface: Option<String> },
    /// Set the RPF provider
    SetRpfProvider { provider: crate::RpfProvider },
    /// Add a static RPF route
    AddRpfRoute {
        source: Ipv4Addr,
        rpf: crate::RpfInfo,
    },
    /// Remove a static RPF route
    RemoveRpfRoute { source: Ipv4Addr },
    /// Clear all static RPF routes
    ClearRpfRoutes,
}

/// Validate an interface name using shared validation logic.
fn validate_interface_name(name: &str) -> Result<(), String> {
    validation::validate_interface_name(name)
}

/// Validate a port number using shared validation logic.
fn validate_port(port: u16, context: &str) -> Result<(), String> {
    validation::validate_port(port, context)
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
/// * `startup_config_path` - Path to startup config file (if mcrd started with --config)
/// * `startup_config` - The startup config (for GetConfig to return protocol configs)
///
/// # Returns
/// A tuple of (Response to send to client, Action to take)
#[allow(clippy::too_many_arguments)]
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
    startup_config: Option<&crate::Config>,
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
            input_protocol,
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
            // ESP (protocol 50) has no port — it uses SPI instead, so port=0 is valid
            if input_protocol != crate::IP_PROTO_ESP {
                if let Err(e) = validate_port(input_port, "input_port") {
                    return (Response::Error(e), CommandAction::None);
                }
            }
            for (i, output) in outputs.iter().enumerate() {
                if input_protocol != crate::IP_PROTO_ESP {
                    if let Err(e) = validate_port(output.port, &format!("output[{}].port", i)) {
                        return (Response::Error(e), CommandAction::None);
                    }
                }
            }

            // Generate stable rule ID if not provided
            let rule_id = if rule_id.is_empty() {
                crate::generate_rule_id(&input_interface, input_group, input_port, input_protocol)
            } else {
                rule_id
            };

            let rule = ForwardingRule {
                rule_id,
                name,
                input_interface,
                input_group,
                input_port,
                input_protocol,
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
                CommandAction::BroadcastToDataPlane(RelayCommand::SetLogLevel {
                    facility: None,
                    level,
                }),
            )
        }

        SupervisorCommand::SetFacilityLogLevel { facility, level } => {
            facility_min_levels.write().unwrap().insert(facility, level);
            (
                Response::Success(format!("Log level for {} set to {}", facility, level)),
                CommandAction::BroadcastToDataPlane(RelayCommand::SetLogLevel {
                    facility: Some(facility),
                    level,
                }),
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
            // Merge startup config (for protocol settings) with current forwarding rules
            let rules = master_rules.lock().unwrap();
            let rules_vec: Vec<crate::ForwardingRule> = rules.values().cloned().collect();

            let config = if let Some(base_config) = startup_config {
                // Clone the startup config and update with current rules
                let mut config = base_config.clone();
                config.rules = rules_vec
                    .iter()
                    .map(crate::ConfigRule::from_forwarding_rule)
                    .collect();
                config
            } else {
                // No startup config, just return rules-only config
                crate::Config::from_forwarding_rules(&rules_vec)
            };
            (Response::Config(config), CommandAction::None)
        }

        SupervisorCommand::GetControlPlaneConfig => {
            // Handled in protocol_response section (requires ProtocolCoordinator access)
            (
                Response::ControlPlaneConfig {
                    rpf_provider: "disabled".to_string(),
                    external_neighbors_enabled: true,
                    event_buffer_size: 256,
                },
                CommandAction::None,
            )
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

        // EnablePim, DisablePim, SetRpAddress, and SetStaticRp are handled in mod.rs protocol_response section
        // They need access to ProtocolCoordinator state (timer_tx, pim_socket, etc.)
        SupervisorCommand::EnablePim { .. }
        | SupervisorCommand::DisablePim { .. }
        | SupervisorCommand::SetRpAddress { .. }
        | SupervisorCommand::SetStaticRp { .. } => {
            // This should never be reached - handled earlier in mod.rs
            (
                Response::Error(
                    "Internal error: PIM commands should be handled by protocol coordinator"
                        .to_string(),
                ),
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

        // --- MSDP Commands ---
        SupervisorCommand::GetMsdpPeers => {
            // Return empty list until protocol integration is complete
            (Response::MsdpPeers(Vec::new()), CommandAction::None)
        }
        SupervisorCommand::GetMsdpSaCache => {
            // Return empty list until protocol integration is complete
            (Response::MsdpSaCache(Vec::new()), CommandAction::None)
        }
        SupervisorCommand::AddMsdpPeer {
            address,
            description,
            mesh_group,
            default_peer,
        } => (
            Response::Success(format!(
                "MSDP peer {} added{}",
                address,
                description
                    .as_ref()
                    .map(|d| format!(" ({})", d))
                    .unwrap_or_default()
            )),
            CommandAction::AddMsdpPeer {
                address,
                description,
                mesh_group,
                default_peer,
            },
        ),
        SupervisorCommand::RemoveMsdpPeer { address } => (
            Response::Success(format!("MSDP peer {} removed", address)),
            CommandAction::RemoveMsdpPeer { address },
        ),
        SupervisorCommand::ClearMsdpSaCache => (
            Response::Success("MSDP SA cache cleared".to_string()),
            CommandAction::ClearMsdpSaCache,
        ),

        // --- External Neighbor Commands ---
        SupervisorCommand::AddExternalNeighbor { neighbor } => (
            Response::Success(format!(
                "External neighbor {} added on {}",
                neighbor.address, neighbor.interface
            )),
            CommandAction::AddExternalNeighbor { neighbor },
        ),
        SupervisorCommand::RemoveExternalNeighbor { address, interface } => (
            Response::Success(format!(
                "External neighbor {} removed from {}",
                address, interface
            )),
            CommandAction::RemoveExternalNeighbor { address, interface },
        ),
        SupervisorCommand::ListExternalNeighbors => {
            // This is handled via protocol coordinator, return empty here
            (Response::ExternalNeighbors(Vec::new()), CommandAction::None)
        }
        SupervisorCommand::ClearExternalNeighbors { interface } => (
            Response::Success(match &interface {
                Some(iface) => format!("External neighbors cleared from {}", iface),
                None => "All external neighbors cleared".to_string(),
            }),
            CommandAction::ClearExternalNeighbors { interface },
        ),

        // --- RPF Commands ---
        SupervisorCommand::SetRpfProvider { provider } => (
            Response::Success(format!("RPF provider set to {}", provider)),
            CommandAction::SetRpfProvider { provider },
        ),
        SupervisorCommand::GetRpfProvider => {
            // Handled via protocol coordinator, return placeholder here
            (
                Response::RpfProvider(crate::RpfProviderInfo {
                    provider: crate::RpfProvider::Disabled,
                    static_entries: 0,
                    cached_entries: 0,
                }),
                CommandAction::None,
            )
        }
        SupervisorCommand::QueryRpf { source } => {
            // Handled via protocol coordinator, return placeholder here
            let _ = source;
            (Response::RpfResult(None), CommandAction::None)
        }
        SupervisorCommand::AddRpfRoute { source, rpf } => (
            Response::Success(format!(
                "Static RPF route added for {} via {}",
                source, rpf.upstream_interface
            )),
            CommandAction::AddRpfRoute { source, rpf },
        ),
        SupervisorCommand::RemoveRpfRoute { source } => (
            Response::Success(format!("Static RPF route removed for {}", source)),
            CommandAction::RemoveRpfRoute { source },
        ),
        SupervisorCommand::ListRpfRoutes => {
            // Handled via protocol coordinator, return placeholder here
            (Response::RpfRoutes(Vec::new()), CommandAction::None)
        }
        SupervisorCommand::ClearRpfRoutes => (
            Response::Success("All static RPF routes cleared".to_string()),
            CommandAction::ClearRpfRoutes,
        ),

        // --- Event Subscription Commands ---
        // These are handled by the control socket handler since subscriptions
        // are per-connection state. Return placeholder responses here.
        SupervisorCommand::Subscribe { events } => {
            let subscription_id = crate::SubscriptionId::new();
            (
                Response::Subscribed {
                    subscription_id,
                    events,
                },
                CommandAction::None,
            )
        }
        SupervisorCommand::Unsubscribe { subscription_id } => (
            Response::Success(format!("Unsubscribed from {}", subscription_id)),
            CommandAction::None,
        ),
        SupervisorCommand::ListSubscriptions => {
            // Return empty list - actual subscriptions tracked per-connection
            (Response::Subscriptions(Vec::new()), CommandAction::None)
        }
    }
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
                interface: Some("lo".to_string()),
                status: crate::WorkerStatus::Running,
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
                input_protocol: 17,
                outputs: vec![],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
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
                input_protocol: 17,
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
            None,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert!(matches!(
            action,
            CommandAction::BroadcastToDataPlane(RelayCommand::RemoveRule { .. })
        ));
        assert!(master_rules.lock().unwrap().is_empty());
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
            None,
        );

        assert!(matches!(response, crate::Response::Error(_)));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_stats_empty() {
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
            None,
        );

        assert!(matches!(response, crate::Response::Stats(stats) if stats.is_empty()));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_get_stats_aggregation() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        // Simulate two workers reporting stats for the same flow
        let flow_stats_1 = crate::FlowStats {
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            input_protocol: 17,
            packets_relayed: 1000,
            bytes_relayed: 1500000,
            packets_per_second: 100.0,
            bits_per_second: 1200000.0,
        };
        let flow_stats_2 = crate::FlowStats {
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            input_protocol: 17,
            packets_relayed: 2000,
            bytes_relayed: 3000000,
            packets_per_second: 200.0,
            bits_per_second: 2400000.0,
        };

        worker_stats
            .lock()
            .unwrap()
            .insert(1, vec![flow_stats_1.clone()]);
        worker_stats
            .lock()
            .unwrap()
            .insert(2, vec![flow_stats_2.clone()]);

        let (response, _action) = handle_supervisor_command(
            crate::SupervisorCommand::GetStats,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );

        if let crate::Response::Stats(stats) = response {
            assert_eq!(stats.len(), 1);
            let aggregated = &stats[0];
            assert_eq!(aggregated.packets_relayed, 3000); // 1000 + 2000
            assert_eq!(aggregated.bytes_relayed, 4500000); // 1500000 + 3000000
            assert_eq!(aggregated.packets_per_second, 300.0); // 100 + 200
            assert_eq!(aggregated.bits_per_second, 3600000.0); // 1200000 + 2400000
        } else {
            panic!("Expected Stats response");
        }
    }

    #[test]
    fn test_handle_set_global_log_level() {
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
            None,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert!(matches!(
            action,
            CommandAction::BroadcastToDataPlane(RelayCommand::SetLogLevel { .. })
        ));
        assert_eq!(
            global_min_level.load(std::sync::atomic::Ordering::Relaxed),
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
                facility: crate::logging::Facility::Supervisor,
                level: crate::logging::Severity::Debug,
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );

        assert!(matches!(response, crate::Response::Success(_)));
        assert!(matches!(
            action,
            CommandAction::BroadcastToDataPlane(RelayCommand::SetLogLevel { .. })
        ));
        assert_eq!(
            *facility_min_levels
                .read()
                .unwrap()
                .get(&crate::logging::Facility::Supervisor)
                .unwrap(),
            crate::logging::Severity::Debug
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
            crate::logging::Facility::Supervisor,
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
            None,
        );

        if let crate::Response::LogLevels {
            global,
            facility_overrides,
        } = response
        {
            assert_eq!(global, crate::logging::Severity::Warning);
            assert_eq!(
                facility_overrides.get(&crate::logging::Facility::Supervisor),
                Some(&crate::logging::Severity::Debug)
            );
        } else {
            panic!("Expected LogLevels response");
        }
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_ping() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::Ping,
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );

        if let crate::Response::Success(msg) = response {
            assert_eq!(msg, "pong");
        } else {
            panic!("Expected Success response with 'pong'");
        }
        assert!(matches!(
            action,
            CommandAction::BroadcastToDataPlane(RelayCommand::Ping)
        ));
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
            None,
        );

        if let crate::Response::Version { protocol_version } = response {
            assert_eq!(protocol_version, crate::PROTOCOL_VERSION);
        } else {
            panic!("Expected Version response");
        }
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_handle_remove_rule_by_name() {
        let master_rules = Mutex::new(HashMap::new());
        master_rules.lock().unwrap().insert(
            "test-rule-id".to_string(),
            ForwardingRule {
                rule_id: "test-rule-id".to_string(),
                name: Some("my-rule".to_string()),
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                input_protocol: 17,
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
            crate::SupervisorCommand::RemoveRuleByName {
                name: "my-rule".to_string(),
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );

        assert!(matches!(response, crate::Response::Success(msg) if msg.contains("my-rule")));
        assert!(matches!(
            action,
            CommandAction::BroadcastToDataPlane(RelayCommand::RemoveRule { rule_id }) if rule_id == "test-rule-id"
        ));
        assert!(master_rules.lock().unwrap().is_empty());
    }

    #[test]
    fn test_handle_remove_rule_by_name_not_found() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());

        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::RemoveRuleByName {
                name: "nonexistent".to_string(),
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );

        assert!(matches!(response, crate::Response::Error(msg) if msg.contains("nonexistent")));
        assert_eq!(action, CommandAction::None);
    }

    #[test]
    fn test_add_rule_rejects_same_interface() {
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
                input_interface: "eth0".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                input_protocol: 17,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth0".to_string(), // Same as input!
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );

        // Should be rejected
        match response {
            crate::Response::Error(msg) => {
                assert!(msg.contains("cannot be the same"));
                assert!(msg.contains("packet loops"));
            }
            _ => panic!("Expected Error response, got {:?}", response),
        }
        assert_eq!(action, CommandAction::None);
        assert!(master_rules.lock().unwrap().is_empty());
    }

    #[test]
    fn test_add_rule_allows_loopback_with_warning() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        // Loopback as input (with different output) should be allowed (though warned)
        let (response, _action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "test-rule".to_string(),
                name: None,
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                input_protocol: 17,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth0".to_string(), // Different from input - OK
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );

        // Should succeed (warning is just printed to stderr)
        assert!(matches!(response, crate::Response::Success(_)));

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
        assert!(validate_interface_name("abcdefghij12345").is_ok());
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
                input_protocol: 17,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(),
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
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
                input_protocol: 17,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "invalid/name".to_string(),
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
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
                input_port: 0, // Invalid for UDP
                input_protocol: 17,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 5001,
                    interface: "eth1".to_string(),
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
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
                input_protocol: 17,
                outputs: vec![crate::OutputDestination {
                    group: "224.0.0.2".parse().unwrap(),
                    port: 0, // Invalid for UDP
                    interface: "eth1".to_string(),
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
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

    #[test]
    fn test_add_esp_rule_accepts_port_zero() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        let (response, action) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "esp-rule".to_string(),
                name: Some("ESP test".to_string()),
                input_interface: "eth0".to_string(),
                input_group: "239.255.0.100".parse().unwrap(),
                input_port: 0,      // Valid for ESP
                input_protocol: 50, // ESP
                outputs: vec![crate::OutputDestination {
                    group: "239.255.0.100".parse().unwrap(),
                    port: 0, // No port for ESP
                    interface: "eth1".to_string(),
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );

        assert!(
            matches!(response, crate::Response::Success(_)),
            "ESP rule with port=0 should succeed, got: {:?}",
            response
        );
        assert!(matches!(
            action,
            CommandAction::EnsureWorkersAndBroadcast { .. }
        ));

        let rules = master_rules.lock().unwrap();
        assert_eq!(rules.len(), 1);
        let rule = rules.values().next().unwrap();
        assert_eq!(rule.input_protocol, 50);
        assert_eq!(rule.input_port, 0);
    }

    #[test]
    fn test_add_esp_and_udp_rules_coexist() {
        let master_rules = Mutex::new(HashMap::new());
        let worker_map = Mutex::new(HashMap::new());
        let global_min_level =
            std::sync::atomic::AtomicU8::new(crate::logging::Severity::Info as u8);
        let facility_min_levels = std::sync::RwLock::new(HashMap::new());
        let worker_stats = Mutex::new(HashMap::new());

        // Add ESP rule
        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "esp-rule".to_string(),
                name: None,
                input_interface: "eth0".to_string(),
                input_group: "239.1.1.1".parse().unwrap(),
                input_port: 0,
                input_protocol: 50,
                outputs: vec![crate::OutputDestination {
                    group: "239.1.1.1".parse().unwrap(),
                    port: 0,
                    interface: "eth1".to_string(),
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );
        assert!(matches!(response, crate::Response::Success(_)));

        // Add UDP rule for same group
        let (response, _) = handle_supervisor_command(
            crate::SupervisorCommand::AddRule {
                rule_id: "udp-rule".to_string(),
                name: None,
                input_interface: "eth0".to_string(),
                input_group: "239.1.1.1".parse().unwrap(),
                input_port: 5000,
                input_protocol: 17,
                outputs: vec![crate::OutputDestination {
                    group: "239.1.1.1".parse().unwrap(),
                    port: 5000,
                    interface: "eth1".to_string(),
                    ttl: None,
                    source_ip: None,
                }],
            },
            &master_rules,
            &worker_map,
            &global_min_level,
            &facility_min_levels,
            &worker_stats,
            None,
            None,
        );
        assert!(
            matches!(response, crate::Response::Success(_)),
            "UDP and ESP rules for same group should coexist, got: {:?}",
            response
        );

        let rules = master_rules.lock().unwrap();
        assert_eq!(rules.len(), 2, "Both ESP and UDP rules should exist");
    }
}
