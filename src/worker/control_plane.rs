// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::Result;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::logging::{Facility, Logger};
use crate::{FlowStats, ForwardingRule, RelayCommand, Response, SupervisorCommand};

type SharedFlows = Arc<Mutex<HashMap<String, (ForwardingRule, FlowStats)>>>;

use tokio::io::{AsyncRead, AsyncWrite};

/// Handle a supervisor command for the control plane worker.
///
/// This is a pure function extracted from the async I/O loop to enable unit testing.
/// It processes commands that are meant for the control plane worker specifically.
///
/// Most commands return errors indicating they should be handled by the supervisor,
/// since the control plane worker only handles `ListRules` and `GetStats`.
pub fn handle_worker_command(
    command: SupervisorCommand,
    flows: &HashMap<String, (ForwardingRule, FlowStats)>,
) -> Response {
    match command {
        SupervisorCommand::AddRule { .. } => {
            Response::Error("AddRule should be handled by the supervisor directly".to_string())
        }
        SupervisorCommand::RemoveRule { .. } => {
            Response::Error("RemoveRule should be handled by the supervisor directly".to_string())
        }
        SupervisorCommand::ListRules => {
            Response::Rules(flows.values().map(|(r, _)| r.clone()).collect())
        }
        SupervisorCommand::GetStats => {
            Response::Stats(flows.values().map(|(_, s)| s.clone()).collect())
        }
        SupervisorCommand::ListWorkers => {
            Response::Error("ListWorkers command should be handled by the supervisor".to_string())
        }
        SupervisorCommand::SetGlobalLogLevel { .. } => Response::Error(
            "SetGlobalLogLevel command should be handled by the supervisor".to_string(),
        ),
        SupervisorCommand::SetFacilityLogLevel { .. } => Response::Error(
            "SetFacilityLogLevel command should be handled by the supervisor".to_string(),
        ),
        SupervisorCommand::GetLogLevels => {
            Response::Error("GetLogLevels command should be handled by the supervisor".to_string())
        }
        SupervisorCommand::Ping => {
            Response::Error("Ping command should be handled by the supervisor".to_string())
        }
    }
}

pub struct ControlPlane<S> {
    supervisor_stream: S,
    request_stream: UnixStream,
    shared_flows: SharedFlows,
    logger: Option<Logger>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ControlPlane<S> {
    pub fn new(supervisor_stream: S, request_stream: UnixStream) -> Self {
        let shared_flows = Arc::new(Mutex::new(HashMap::new()));
        Self {
            supervisor_stream,
            request_stream,
            shared_flows,
            logger: None,
        }
    }

    pub fn new_with_logger(
        supervisor_stream: S,
        request_stream: UnixStream,
        logger: Logger,
    ) -> Self {
        let shared_flows = Arc::new(Mutex::new(HashMap::new()));
        Self {
            supervisor_stream,
            request_stream,
            shared_flows,
            logger: Some(logger),
        }
    }

    pub async fn run(self) -> Result<()> {
        control_plane_task(
            self.supervisor_stream,
            self.request_stream,
            self.shared_flows,
            self.logger,
        )
        .await
    }
}

pub async fn control_plane_task<S: AsyncRead + AsyncWrite + Unpin>(
    mut supervisor_stream: S,
    request_stream: UnixStream,
    shared_flows: SharedFlows,
    logger: Option<Logger>,
) -> Result<()> {
    let mut framed = Framed::new(request_stream, LengthDelimitedCodec::new());

    loop {
        let mut buffer = vec![0; 4096]; // Read into a pre-allocated buffer

        tokio::select! {
            // Handle commands from the supervisor's main control socket
            read_result = supervisor_stream.read(&mut buffer) => {
                match read_result {
                    Ok(0) => {
                        // Stream closed
                        if let Some(ref log) = logger {
                            log.info(Facility::ControlPlane, "Supervisor stream closed");
                        }
                        break;
                    }
                    Ok(n) => {
                        // Try to parse as RelayCommand first (for Shutdown)
                        if let Ok(relay_cmd) = serde_json::from_slice::<RelayCommand>(&buffer[..n]) {
                            match relay_cmd {
                                RelayCommand::Shutdown => {
                                    if let Some(ref log) = logger {
                                        log.info(Facility::ControlPlane, "Received explicit Shutdown command");
                                    }
                                    break;
                                }
                                _ => {
                                    // RelayCommand variants other than Shutdown are not expected here
                                    if let Some(ref log) = logger {
                                        log.error(Facility::ControlPlane, "Received unexpected RelayCommand variant");
                                    }
                                }
                            }
                        } else {
                            // Fall back to SupervisorCommand handling
                            let command: Result<SupervisorCommand, _> = serde_json::from_slice(&buffer[..n]);
                            let response = match command {
                                Ok(cmd) => {
                                    let flows = shared_flows.lock().await;
                                    handle_worker_command(cmd, &flows)
                                }
                                Err(e) => Response::Error(e.to_string()),
                            };
                            let response_bytes = serde_json::to_vec(&response).unwrap();
                            if supervisor_stream.write_all(&response_bytes).await.is_err() {
                                if let Some(ref log) = logger {
                                    log.error(Facility::ControlPlane, "Failed to write response to supervisor");
                                }
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        if let Some(ref log) = logger {
                            log.error(Facility::ControlPlane, &format!("Failed to read from supervisor stream: {}", e));
                        }
                        break;
                    }
                }
            },
            // Handle requests from the supervisor's request socket
            Some(Ok(bytes)) = framed.next() => {
                let request: crate::ipc::Request = serde_json::from_slice(&bytes).unwrap();
                match request {
                    crate::ipc::Request::ListRules => {
                        let flows = shared_flows.lock().await;
                        let rules = flows.values().map(|(r, _)| r.clone()).collect();
                        let response = crate::ipc::Response::Rules(rules);
                        let bytes = serde_json::to_vec(&response).unwrap();
                        framed.send(bytes.into()).await.unwrap();
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
    use crate::{logging::Severity, SupervisorCommand};
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;

    // Helper to create test flows
    fn create_test_flows() -> HashMap<String, (ForwardingRule, FlowStats)> {
        let mut flows = HashMap::new();
        flows.insert(
            "test-rule".to_string(),
            (
                ForwardingRule {
                    rule_id: "test-rule".to_string(),
                    input_interface: "lo".to_string(),
                    input_group: Ipv4Addr::new(224, 0, 0, 1),
                    input_port: 5000,
                    outputs: vec![],
                    dtls_enabled: false,
                },
                FlowStats {
                    input_group: Ipv4Addr::new(224, 0, 0, 1),
                    input_port: 5000,
                    packets_relayed: 10,
                    bytes_relayed: 1000,
                    packets_per_second: 100.0,
                    bits_per_second: 8000.0,
                },
            ),
        );
        flows
    }

    #[test]
    fn test_handle_list_rules_empty() {
        let flows = HashMap::new();
        let response = handle_worker_command(SupervisorCommand::ListRules, &flows);

        match response {
            Response::Rules(rules) => {
                assert_eq!(rules.len(), 0, "Should return empty list");
            }
            _ => panic!("Expected Response::Rules, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_list_rules_with_flows() {
        let flows = create_test_flows();
        let response = handle_worker_command(SupervisorCommand::ListRules, &flows);

        match response {
            Response::Rules(rules) => {
                assert_eq!(rules.len(), 1, "Should return one rule");
                assert_eq!(rules[0].rule_id, "test-rule");
            }
            _ => panic!("Expected Response::Rules, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_get_stats_empty() {
        let flows = HashMap::new();
        let response = handle_worker_command(SupervisorCommand::GetStats, &flows);

        match response {
            Response::Stats(stats) => {
                assert_eq!(stats.len(), 0, "Should return empty stats");
            }
            _ => panic!("Expected Response::Stats, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_get_stats_with_flows() {
        let flows = create_test_flows();
        let response = handle_worker_command(SupervisorCommand::GetStats, &flows);

        match response {
            Response::Stats(stats) => {
                assert_eq!(stats.len(), 1, "Should return one stat");
                assert_eq!(stats[0].input_group, Ipv4Addr::new(224, 0, 0, 1));
                assert_eq!(stats[0].input_port, 5000);
                assert_eq!(stats[0].packets_relayed, 10);
                assert_eq!(stats[0].bytes_relayed, 1000);
            }
            _ => panic!("Expected Response::Stats, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_add_rule_returns_error() {
        let flows = HashMap::new();
        let response = handle_worker_command(
            SupervisorCommand::AddRule {
                rule_id: "test".to_string(),
                input_interface: "lo".to_string(),
                input_group: Ipv4Addr::new(224, 0, 0, 1),
                input_port: 5000,
                outputs: vec![],
                dtls_enabled: false,
            },
            &flows,
        );

        match response {
            Response::Error(msg) => {
                assert!(msg.contains("supervisor"));
            }
            _ => panic!("Expected Response::Error, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_remove_rule_returns_error() {
        let flows = HashMap::new();
        let response = handle_worker_command(
            SupervisorCommand::RemoveRule {
                rule_id: "test".to_string(),
            },
            &flows,
        );

        match response {
            Response::Error(msg) => {
                assert!(msg.contains("supervisor"));
            }
            _ => panic!("Expected Response::Error, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_list_workers_returns_error() {
        let flows = HashMap::new();
        let response = handle_worker_command(SupervisorCommand::ListWorkers, &flows);

        match response {
            Response::Error(msg) => {
                assert!(msg.contains("supervisor"));
            }
            _ => panic!("Expected Response::Error, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_set_global_log_level_returns_error() {
        let flows = HashMap::new();
        let response = handle_worker_command(
            SupervisorCommand::SetGlobalLogLevel {
                level: Severity::Debug,
            },
            &flows,
        );

        match response {
            Response::Error(msg) => {
                assert!(msg.contains("supervisor"));
            }
            _ => panic!("Expected Response::Error, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_set_facility_log_level_returns_error() {
        let flows = HashMap::new();
        let response = handle_worker_command(
            SupervisorCommand::SetFacilityLogLevel {
                facility: crate::logging::Facility::Ingress,
                level: Severity::Debug,
            },
            &flows,
        );

        match response {
            Response::Error(msg) => {
                assert!(msg.contains("supervisor"));
            }
            _ => panic!("Expected Response::Error, got {:?}", response),
        }
    }

    #[test]
    fn test_handle_get_log_levels_returns_error() {
        let flows = HashMap::new();
        let response = handle_worker_command(SupervisorCommand::GetLogLevels, &flows);

        match response {
            Response::Error(msg) => {
                assert!(msg.contains("supervisor"));
            }
            _ => panic!("Expected Response::Error, got {:?}", response),
        }
    }

    #[tokio::test]
    async fn test_control_plane_task_list_rules() {
        let (mut client_stream, supervisor_stream) = UnixStream::pair().unwrap();
        let (req_stream, _) = UnixStream::pair().unwrap();

        let control_plane = ControlPlane::new(supervisor_stream, req_stream);
        tokio::spawn(control_plane.run());

        // Test ListRules command (which should return empty list initially)
        let command = SupervisorCommand::ListRules;
        let command_bytes = serde_json::to_vec(&command).unwrap();

        client_stream.write_all(&command_bytes).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut response_buffer = Vec::new();
        let n = client_stream
            .read_to_end(&mut response_buffer)
            .await
            .unwrap();

        if n > 0 {
            let response: Response = serde_json::from_slice(&response_buffer[..n]).unwrap();
            match response {
                Response::Rules(rules) => {
                    assert_eq!(rules.len(), 0, "Should have no rules initially");
                }
                _ => panic!("Expected Response::Rules"),
            }
        }
    }
}
