use anyhow::Result;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use uuid::Uuid;

use super::UnixSocketRelayCommandSender;
use crate::{FlowStats, ForwardingRule, Response, SupervisorCommand};

type SharedFlows = Arc<Mutex<HashMap<String, (ForwardingRule, FlowStats)>>>;

use tokio::io::{AsyncRead, AsyncWrite};

pub struct ControlPlane<S, R: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    request_stream: UnixStream,
    relay_command_tx: Arc<UnixSocketRelayCommandSender<R>>,
    shared_flows: SharedFlows,
}

impl<S: AsyncRead + AsyncWrite + Unpin, R: AsyncRead + AsyncWrite + Unpin> ControlPlane<S, R> {
    pub fn new(stream: S, request_stream: UnixStream, relay_stream: R) -> Self {
        let shared_flows = Arc::new(Mutex::new(HashMap::new()));
        let relay_command_tx = Arc::new(UnixSocketRelayCommandSender::new(relay_stream));
        Self {
            stream,
            request_stream,
            relay_command_tx,
            shared_flows,
        }
    }

    pub async fn run(self) -> Result<()> {
        control_plane_task(
            self.stream,
            self.request_stream,
            self.relay_command_tx,
            self.shared_flows,
        )
        .await
    }
}

pub async fn control_plane_task<
    S: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
>(
    mut stream: S,
    request_stream: UnixStream,
    relay_command_tx: Arc<UnixSocketRelayCommandSender<R>>,
    shared_flows: SharedFlows,
) -> Result<()> {
    let mut framed = Framed::new(request_stream, LengthDelimitedCodec::new());

    loop {
        let mut buffer = vec![0; 4096]; // Read into a pre-allocated buffer

        tokio::select! {
            // Handle commands from the supervisor's main control socket
            read_result = stream.read(&mut buffer) => {
                match read_result {
                    Ok(0) => {
                        // Stream closed
                        println!("[Worker] Supervisor stream closed.");
                        break;
                    }
                    Ok(n) => {
                        let command: Result<SupervisorCommand, _> = serde_json::from_slice(&buffer[..n]);
                        let response = match command {
                            Ok(SupervisorCommand::AddRule {
                                rule_id,
                                input_interface,
                                input_group,
                                input_port,
                                outputs,
                                dtls_enabled,
                            }) => {
                                let rule_id = if rule_id.is_empty() {
                                    Uuid::new_v4().to_string()
                                } else {
                                    rule_id
                                };
                                let rule = ForwardingRule {
                                    rule_id: rule_id.clone(),
                                    input_interface,
                                    input_group,
                                    input_port,
                                    outputs,
                                    dtls_enabled,
                                };
                                if relay_command_tx
                                    .send(crate::RelayCommand::AddRule(rule))
                                    .await
                                    .is_ok()
                                {
                                    Response::Success(format!("Rule added with ID: {}", rule_id))
                                } else {
                                    Response::Error("Failed to add rule".to_string())
                                }
                            }
                            Ok(SupervisorCommand::RemoveRule { rule_id }) => {
                                if relay_command_tx
                                    .send(crate::RelayCommand::RemoveRule {
                                        rule_id: rule_id.clone(),
                                    })
                                    .await
                                    .is_ok()
                                {
                                    Response::Success(format!("Rule {} removed", rule_id))
                                } else {
                                    Response::Error(format!("Failed to remove rule {}", rule_id))
                                }
                            }
                            Ok(SupervisorCommand::ListRules) => {
                                let flows = shared_flows.lock().await;
                                Response::Rules(flows.values().map(|(r, _)| r.clone()).collect())
                            }
                            Ok(SupervisorCommand::GetStats) => {
                                let flows = shared_flows.lock().await;
                                Response::Stats(flows.values().map(|(_, s)| s.clone()).collect())
                            }
                            Ok(SupervisorCommand::ListWorkers) => Response::Error(
                                "ListWorkers command should be handled by the supervisor".to_string(),
                            ),
                            Ok(SupervisorCommand::GetWorkerRules { .. }) => Response::Error(
                                "GetWorkerRules command should be handled by the supervisor"
                                    .to_string(),
                            ),
                            Err(e) => Response::Error(e.to_string()),
                        };
                        let response_bytes = serde_json::to_vec(&response).unwrap();
                        if stream.write_all(&response_bytes).await.is_err() {
                            eprintln!("[Worker] Failed to write response to supervisor.");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[Worker] Failed to read from supervisor stream: {}", e);
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
    use crate::{RelayCommand, SupervisorCommand};
    use tokio::io::AsyncWriteExt;

    #[tokio::test]

    async fn test_control_plane_task_add_rule() {
        let (mut client_stream, task_stream) = UnixStream::pair().unwrap();

        let (relay_stream, mut relay_rx) = UnixStream::pair().unwrap();

        let (req_stream, _) = UnixStream::pair().unwrap();

        let control_plane = ControlPlane::new(task_stream, req_stream, relay_stream);

        tokio::spawn(control_plane.run());

        let rule = ForwardingRule {
            rule_id: "test".to_string(),

            input_interface: "lo".to_string(),

            input_group: "224.0.0.1".parse().unwrap(),

            input_port: 1234,

            outputs: vec![],

            dtls_enabled: false,
        };

        let command = SupervisorCommand::AddRule {
            rule_id: rule.rule_id.clone(),

            input_interface: rule.input_interface.clone(),

            input_group: rule.input_group,

            input_port: rule.input_port,

            outputs: vec![],

            dtls_enabled: false,
        };

        let command_bytes = serde_json::to_vec(&command).unwrap();

        client_stream.write_all(&command_bytes).await.unwrap();

        client_stream.shutdown().await.unwrap(); // Close the write half

        let mut relay_buffer = Vec::new();

        let n = relay_rx.read_to_end(&mut relay_buffer).await.unwrap();

        let received_command: RelayCommand = serde_json::from_slice(&relay_buffer[..n]).unwrap();

        assert_eq!(received_command, RelayCommand::AddRule(rule));
    }
}
