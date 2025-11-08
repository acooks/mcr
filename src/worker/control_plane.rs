use anyhow::Result;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::{FlowStats, ForwardingRule, Response, SupervisorCommand};

type SharedFlows = Arc<Mutex<HashMap<String, (ForwardingRule, FlowStats)>>>;

use tokio::io::{AsyncRead, AsyncWrite};

pub struct ControlPlane<S> {
    supervisor_stream: S,
    request_stream: UnixStream,
    shared_flows: SharedFlows,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ControlPlane<S> {
    pub fn new(supervisor_stream: S, request_stream: UnixStream) -> Self {
        let shared_flows = Arc::new(Mutex::new(HashMap::new()));
        Self {
            supervisor_stream,
            request_stream,
            shared_flows,
        }
    }

    pub async fn run(self) -> Result<()> {
        control_plane_task(self.supervisor_stream, self.request_stream, self.shared_flows).await
    }
}

pub async fn control_plane_task<S: AsyncRead + AsyncWrite + Unpin>(
    mut supervisor_stream: S,
    request_stream: UnixStream,
    shared_flows: SharedFlows,
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
                        println!("[Worker] Supervisor stream closed.");
                        break;
                    }
                    Ok(n) => {
                        let command: Result<SupervisorCommand, _> = serde_json::from_slice(&buffer[..n]);
                        let response = match command {
                            Ok(SupervisorCommand::AddRule { .. }) => {
                                Response::Error("AddRule should be handled by the supervisor directly".to_string())
                            }
                            Ok(SupervisorCommand::RemoveRule { .. }) => {
                                Response::Error("RemoveRule should be handled by the supervisor directly".to_string())
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
                        if supervisor_stream.write_all(&response_bytes).await.is_err() {
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
    use crate::SupervisorCommand;
    use tokio::io::AsyncWriteExt;

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
        let n = client_stream.read_to_end(&mut response_buffer).await.unwrap();

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
