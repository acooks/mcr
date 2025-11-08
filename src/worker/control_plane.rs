use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::UnixSocketRelayCommandSender;
use crate::{FlowStats, ForwardingRule, Response, SupervisorCommand};

type SharedFlows = Arc<Mutex<HashMap<String, (ForwardingRule, FlowStats)>>>;

pub async fn control_plane_task(
    mut stream: tokio::net::UnixStream,
    relay_command_tx: Arc<UnixSocketRelayCommandSender<tokio::net::UnixStream>>,
    shared_flows: SharedFlows,
) -> Result<()> {
    loop {
        let mut buffer = vec![0; 4096]; // Read into a pre-allocated buffer
        match stream.read(&mut buffer).await {
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
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OutputDestination, RelayCommand};
    use std::fs;
    use std::path::PathBuf;
    use tokio::net::UnixListener;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_control_plane_task_add_rule() {
        // Create a socket pair for the test client and the task to communicate on.
        let (mut client_stream, task_stream) = UnixStream::pair().unwrap();

        let relay_socket_path =
            PathBuf::from(format!("/tmp/test_relay_command_{}.sock", Uuid::new_v4()));

        // Create a listener for the relay command socket
        let relay_listener = UnixListener::bind(&relay_socket_path).unwrap();

        // Spawn a task to connect to the relay command socket
        let relay_socket_path_clone = relay_socket_path.clone();
        let relay_connection_task =
            tokio::spawn(
                async move { UnixStream::connect(&relay_socket_path_clone).await.unwrap() },
            );

        // Accept the connection on the relay listener
        let (mut relay_stream, _) = relay_listener.accept().await.unwrap();
        let server_relay_stream = relay_connection_task.await.unwrap();

        // Create a mock UnixSocketRelayCommandSender
        let relay_command_tx = Arc::new(UnixSocketRelayCommandSender::new(server_relay_stream));

        let shared_flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));

        // Spawn the control_plane_task
        let task = tokio::spawn(async move {
            control_plane_task(task_stream, relay_command_tx, shared_flows)
                .await
                .unwrap();
        });

        // Send an AddRule command
        let command = SupervisorCommand::AddRule {
            rule_id: "test-rule".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![OutputDestination {
                group: "224.0.0.2".parse().unwrap(),
                port: 5001,
                interface: "eth1".to_string(),
                dtls_enabled: false,
            }],
            dtls_enabled: false,
        };
        let command_bytes = serde_json::to_vec(&command).unwrap();
        client_stream.write_all(&command_bytes).await.unwrap();
        client_stream.shutdown().await.unwrap(); // Close the write half

        // Verify the RelayCommand received by the mock sender
        let mut relay_buffer = [0; 1024];
        let n = relay_stream.read(&mut relay_buffer).await.unwrap();
        let received_relay_command: RelayCommand =
            serde_json::from_slice(&relay_buffer[..n]).unwrap();
        if let RelayCommand::AddRule(rule) = received_relay_command {
            assert_eq!(rule.rule_id, "test-rule");
        } else {
            panic!("Expected AddRule command");
        }

        // Verify the Response received by the client
        let mut response_buffer = Vec::new();
        client_stream
            .read_to_end(&mut response_buffer)
            .await
            .unwrap();
        let response: Response = serde_json::from_slice(&response_buffer).unwrap();
        assert_eq!(
            response,
            Response::Success("Rule added with ID: test-rule".to_string())
        );

        // Clean up
        task.abort();
        fs::remove_file(&relay_socket_path).unwrap();
    }
}
