use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::{Command, FlowStats, ForwardingRule, RelayCommand, Response};

type SharedFlows = Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>>;

pub async fn control_plane_task(
    socket_path: &Path,
    relay_command_tx: mpsc::Sender<RelayCommand>,
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
                return;
            }
            let command: Result<Command, _> = serde_json::from_slice(&buffer);
            let response = match command {
                Ok(cmd) => match cmd {
                    Command::AddRule {
                        input_group,
                        input_port,
                        outputs,
                        dtls_enabled,
                    } => {
                        let rule = ForwardingRule {
                            input_group,
                            input_port,
                            outputs,
                            dtls_enabled,
                        };
                        if relay_command_tx
                            .send(RelayCommand::AddRule(rule))
                            .await
                            .is_ok()
                        {
                            Response::Success("Rule added".to_string())
                        } else {
                            Response::Error("Failed to add rule".to_string())
                        }
                    }
                    Command::RemoveRule {
                        input_group,
                        input_port,
                    } => {
                        if relay_command_tx
                            .send(RelayCommand::RemoveRule {
                                input_group,
                                input_port,
                            })
                            .await
                            .is_ok()
                        {
                            Response::Success("Rule removed".to_string())
                        } else {
                            Response::Error("Failed to remove rule".to_string())
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
