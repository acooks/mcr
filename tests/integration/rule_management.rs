//! **Tier 2 Integration Tests: Rule Management**
//!
//! These tests verify the end-to-end flow of adding and removing forwarding rules
//! from the control client to the data plane workers.

use anyhow::{Context, Result};
use multicast_relay::{ForwardingRule, Response, SupervisorCommand, WorkerInfo};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use crate::tests::{cleanup_socket, unique_socket_path_with_prefix};

// --- Test Harness: Control Client ---

/// A client for interacting with the supervisor's control socket in tests.
struct ControlClient {
    socket_path: PathBuf,
}

impl ControlClient {
    fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
        }
    }

    async fn send_command(&self, command: SupervisorCommand) -> Result<Response> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let command_bytes = serde_json::to_vec(&command)?;
        stream.write_all(&command_bytes).await?;
        stream.shutdown().await?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await?;

        let response: Response = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    async fn list_workers(&self) -> Result<Vec<WorkerInfo>> {
        match self.send_command(SupervisorCommand::ListWorkers).await? {
            Response::Workers(workers) => Ok(workers),
            Response::Error(e) => anyhow::bail!("Failed to list workers: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for ListWorkers"),
        }
    }

    async fn add_rule(&self, rule: ForwardingRule) -> Result<String> {
        let rule_id = rule.rule_id.clone();
        match self
            .send_command(SupervisorCommand::AddRule {
                rule_id,
                input_interface: rule.input_interface,
                input_group: rule.input_group,
                input_port: rule.input_port,
                outputs: rule.outputs,
                dtls_enabled: rule.dtls_enabled,
            })
            .await?
        {
            Response::Success(_) => Ok(rule.rule_id),
            Response::Error(e) => anyhow::bail!("Failed to add rule: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for AddRule"),
        }
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::RemoveRule {
                rule_id: rule_id.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to remove rule: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for RemoveRule"),
        }
    }

    async fn get_worker_rules(&self, worker_pid: u32) -> Result<Vec<ForwardingRule>> {
        match self
            .send_command(SupervisorCommand::GetWorkerRules { worker_pid })
            .await?
        {
            Response::Rules(rules) => Ok(rules),
            Response::Error(e) => anyhow::bail!("Failed to get worker rules: {}", e),
            _ => anyhow::bail!("Unexpected response from supervisor for GetWorkerRules"),
        }
    }
}

// --- Test Harness: Supervisor Management ---

/// Starts a supervisor process in the background for testing.
async fn start_supervisor() -> Result<(Child, PathBuf)> {
    let control_socket = unique_socket_path_with_prefix("rule_mgmt_control");
    let relay_socket = unique_socket_path_with_prefix("rule_mgmt_relay");

    cleanup_socket(&control_socket);
    cleanup_socket(&relay_socket);

    let binary = env!("CARGO_BIN_EXE_multicast_relay");

    let supervisor = Command::new(binary)
        .arg("supervisor")
        .arg("--control-socket-path")
        .arg(&control_socket)
        .arg("--relay-command-socket-path")
        .arg(&relay_socket)
        .spawn()
        .context("Failed to spawn supervisor")?;

    // Wait for the control socket to be created, with a timeout.
    for _ in 0..30 {
        if control_socket.exists() {
            sleep(Duration::from_millis(200)).await; // Give it a moment to stabilize
            return Ok((supervisor, control_socket));
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Supervisor did not create control socket within timeout")
}

// --- Tests ---

#[tokio::test]
async fn test_add_and_remove_rule_e2e() -> Result<()> {
    // Check for root privileges (required for AF_PACKET sockets and worker spawning)
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test_add_and_remove_rule_e2e: requires root privileges for AF_PACKET sockets.");
        return Ok(());
    }

    // 1. SETUP: Start the supervisor and create a client.
    let (mut supervisor, socket_path) = start_supervisor().await?;
    let client = ControlClient::new(&socket_path);

    // Wait for a data plane worker to be ready.
    let dp_worker_pid = {
        let mut pid = None;
        for _ in 0..20 {
            if let Ok(workers) = client.list_workers().await {
                if let Some(dp) = workers.iter().find(|w| w.worker_type == "DataPlane") {
                    pid = Some(dp.pid);
                    break;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
        pid.context("Data plane worker did not start in time")?
    };
    println!("[TEST] Data plane worker found with PID: {}", dp_worker_pid);

    // 2. VERIFY INITIAL STATE: Ensure the worker has no rules.
    let initial_rules = client.get_worker_rules(dp_worker_pid).await?;
    assert!(
        initial_rules.is_empty(),
        "Worker should have no rules initially"
    );
    println!("[TEST] Verified worker has 0 rules initially.");

    // 3. ADD RULE: Add a new forwarding rule via the supervisor.
    let rule = ForwardingRule {
        rule_id: "test-rule-e2e".to_string(),
        input_interface: "lo".to_string(),
        input_group: "239.1.1.1".parse()?,
        input_port: 5001,
        outputs: vec![],
        dtls_enabled: false,
    };
    client.add_rule(rule.clone()).await?;
    println!("[TEST] AddRule command sent for rule '{}'.", rule.rule_id);

    // Give a moment for the command to propagate.
    sleep(Duration::from_millis(200)).await;

    // 4. VERIFY ADDITION: Query the worker directly to confirm it received the rule.
    let rules_after_add = client.get_worker_rules(dp_worker_pid).await?;
    assert_eq!(
        rules_after_add.len(),
        1,
        "Worker should have 1 rule after addition"
    );
    assert_eq!(
        rules_after_add[0].rule_id, rule.rule_id,
        "Worker has the wrong rule"
    );
    println!("[TEST] Verified worker received the new rule.");

    // 5. REMOVE RULE: Remove the rule via the supervisor.
    client.remove_rule(&rule.rule_id).await?;
    println!("[TEST] RemoveRule command sent for rule '{}'.", rule.rule_id);

    // Give a moment for the command to propagate.
    sleep(Duration::from_millis(200)).await;

    // 6. VERIFY REMOVAL: Query the worker again to confirm the rule is gone.
    let rules_after_remove = client.get_worker_rules(dp_worker_pid).await?;
    assert!(
        rules_after_remove.is_empty(),
        "Worker should have no rules after removal"
    );
    println!("[TEST] Verified worker removed the rule.");

    // 7. CLEANUP
    supervisor.kill().await?;
    cleanup_socket(&socket_path);
    Ok(())
}
