use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::UnixSocketRelayCommandSender;
use crate::{Command, FlowStats, ForwardingRule, Response};

type SharedFlows = Arc<Mutex<HashMap<String, (ForwardingRule, FlowStats)>>>;

pub async fn control_plane_task(
    socket_path: &Path,
    relay_command_tx: Arc<UnixSocketRelayCommandSender<tokio::net::UnixStream>>,
    shared_flows: SharedFlows,
) -> Result<()> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let relay_command_tx = relay_command_tx.clone();
        let shared_flows = shared_flows.clone();
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            if stream.read_to_end(&mut buffer).await.is_err() {
                let response = Response::Error("Failed to read command".to_string());
                let response_bytes = serde_json::to_vec(&response).unwrap();
                let _ = stream.write_all(&response_bytes).await;
                return;
            }
            let command: Result<Command, _> = serde_json::from_slice(&buffer);
            let response = match command {
                Ok(cmd) => match cmd {
                    Command::AddRule {
                        rule_id,
                        input_interface,
                        input_group,
                        input_port,
                        outputs,
                        dtls_enabled,
                    } => {
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
                    Command::RemoveRule { rule_id } => {
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
                    Command::ListRules => {
                        let flows = shared_flows.lock().await;
                        Response::Rules(flows.values().map(|(r, _)| r.clone()).collect())
                    }
                    Command::GetStats => {
                        let flows = shared_flows.lock().await;
                        Response::Stats(flows.values().map(|(_, s)| s.clone()).collect())
                    }
                },
                Err(e) => Response::Error(e.to_string()),
            };
            let response_bytes = serde_json::to_vec(&response).unwrap();
            let _ = stream.write_all(&response_bytes).await;
        });
    }
}
