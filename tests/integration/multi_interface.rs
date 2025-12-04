// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **Multi-Interface Integration Tests**
//!
//! Tests for multi-interface architecture features:
//! - Config file startup with multiple interfaces
//! - Dynamic worker spawning when adding rules for new interfaces
//! - Per-interface fanout groups
//! - Rule naming and RemoveRuleByName

use anyhow::{Context, Result};
use multicast_relay::{config::Config, ForwardingRule, Response, SupervisorCommand, WorkerInfo};
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use crate::common::network::{NetworkNamespace, VethPair};
use crate::tests::{cleanup_socket, unique_socket_path_with_prefix};
use std::collections::HashSet;

// --- Test Harness: Automatic Cleanup Guard ---

/// RAII guard for supervisor cleanup
struct TestSupervisor {
    process: Option<Child>,
    control_socket_path: PathBuf,
    relay_socket_path: PathBuf,
    #[allow(dead_code)]
    config_file: Option<NamedTempFile>,
}

impl TestSupervisor {
    fn socket_path(&self) -> &Path {
        &self.control_socket_path
    }
}

impl Drop for TestSupervisor {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.start_kill();
        }
        cleanup_socket(&self.control_socket_path);
        cleanup_socket(&self.relay_socket_path);
    }
}

// --- Test Harness: Control Client ---

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
            _ => anyhow::bail!("Unexpected response for ListWorkers"),
        }
    }

    async fn list_rules(&self) -> Result<Vec<ForwardingRule>> {
        match self.send_command(SupervisorCommand::ListRules).await? {
            Response::Rules(rules) => Ok(rules),
            Response::Error(e) => anyhow::bail!("Failed to list rules: {}", e),
            _ => anyhow::bail!("Unexpected response for ListRules"),
        }
    }

    async fn add_rule_with_name(
        &self,
        rule_id: String,
        name: Option<String>,
        input_interface: String,
        input_group: std::net::Ipv4Addr,
        input_port: u16,
        outputs: Vec<multicast_relay::OutputDestination>,
    ) -> Result<String> {
        match self
            .send_command(SupervisorCommand::AddRule {
                rule_id: rule_id.clone(),
                name,
                input_interface,
                input_group,
                input_port,
                outputs,
            })
            .await?
        {
            Response::Success(_) => Ok(rule_id),
            Response::Error(e) => anyhow::bail!("Failed to add rule: {}", e),
            _ => anyhow::bail!("Unexpected response for AddRule"),
        }
    }

    async fn remove_rule_by_name(&self, name: &str) -> Result<()> {
        match self
            .send_command(SupervisorCommand::RemoveRuleByName {
                name: name.to_string(),
            })
            .await?
        {
            Response::Success(_) => Ok(()),
            Response::Error(e) => anyhow::bail!("Failed to remove rule by name: {}", e),
            _ => anyhow::bail!("Unexpected response for RemoveRuleByName"),
        }
    }

    async fn get_config(&self) -> Result<Config> {
        match self.send_command(SupervisorCommand::GetConfig).await? {
            Response::Config(config) => Ok(config),
            Response::Error(e) => anyhow::bail!("Failed to get config: {}", e),
            _ => anyhow::bail!("Unexpected response for GetConfig"),
        }
    }
}

// --- Test Harness: Supervisor Management ---

/// Start supervisor with a JSON5 config file
async fn start_supervisor_with_config(config_content: &str) -> Result<TestSupervisor> {
    let control_socket = unique_socket_path_with_prefix("multi_iface_control");
    let relay_socket = unique_socket_path_with_prefix("multi_iface_relay");

    cleanup_socket(&control_socket);
    cleanup_socket(&relay_socket);

    // Create a temporary config file
    let mut config_file = NamedTempFile::new()?;
    config_file.write_all(config_content.as_bytes())?;
    config_file.flush()?;

    let binary = env!("CARGO_BIN_EXE_mcrd");

    let supervisor = Command::new(binary)
        .arg("supervisor")
        .arg("--config")
        .arg(config_file.path())
        .arg("--control-socket-path")
        .arg(&control_socket)
        .arg("--relay-command-socket-path")
        .arg(&relay_socket)
        .arg("--num-workers")
        .arg("1") // Use 1 worker per interface for test simplicity
        .spawn()
        .context("Failed to spawn supervisor")?;

    // Wait for socket creation
    for _ in 0..30 {
        if control_socket.exists() {
            sleep(Duration::from_millis(300)).await;
            return Ok(TestSupervisor {
                process: Some(supervisor),
                control_socket_path: control_socket,
                relay_socket_path: relay_socket,
                config_file: Some(config_file),
            });
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Supervisor did not create control socket within timeout")
}

/// Start supervisor without config (default mode)
async fn start_supervisor_default() -> Result<TestSupervisor> {
    let control_socket = unique_socket_path_with_prefix("multi_iface_control");
    let relay_socket = unique_socket_path_with_prefix("multi_iface_relay");

    cleanup_socket(&control_socket);
    cleanup_socket(&relay_socket);

    let binary = env!("CARGO_BIN_EXE_mcrd");

    let supervisor = Command::new(binary)
        .arg("supervisor")
        .arg("--control-socket-path")
        .arg(&control_socket)
        .arg("--relay-command-socket-path")
        .arg(&relay_socket)
        .arg("--num-workers")
        .arg("1")
        .spawn()
        .context("Failed to spawn supervisor")?;

    for _ in 0..30 {
        if control_socket.exists() {
            sleep(Duration::from_millis(300)).await;
            return Ok(TestSupervisor {
                process: Some(supervisor),
                control_socket_path: control_socket,
                relay_socket_path: relay_socket,
                config_file: None,
            });
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Supervisor did not create control socket within timeout")
}

// --- Tests ---

/// Test: Startup config spawns workers for each interface in config
///
/// Verifies that when mcrd starts with a config file containing rules
/// for the 'lo' interface, it spawns workers for that interface.
#[tokio::test]
async fn test_config_startup_spawns_workers_for_interface() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    // Config with one rule for 'lo' interface
    let config = r#"{
        rules: [
            {
                input: { interface: "lo", group: "239.1.1.1", port: 5000 },
                outputs: [{ interface: "lo", group: "239.2.2.2", port: 6000 }]
            }
        ]
    }"#;

    let supervisor = start_supervisor_with_config(config).await?;
    let client = ControlClient::new(supervisor.socket_path());

    sleep(Duration::from_millis(500)).await;

    // Verify workers were spawned
    let workers = client.list_workers().await?;
    assert!(
        !workers.is_empty(),
        "Should have spawned workers for 'lo' interface"
    );
    println!("[TEST] Workers spawned: {}", workers.len());

    // Verify rules were loaded
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1, "Should have 1 rule from config");
    assert_eq!(rules[0].input_interface, "lo");
    println!("[TEST] Rules loaded from config: {}", rules.len());

    Ok(())
}

/// Test: Dynamic worker spawning when adding a rule for a new interface
///
/// When a rule is added for an interface that doesn't have workers yet,
/// the supervisor should dynamically spawn workers for that interface.
#[tokio::test]
async fn test_dynamic_worker_spawn_on_add_rule() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    // Start supervisor without config (default interface 'lo')
    let supervisor = start_supervisor_default().await?;
    let client = ControlClient::new(supervisor.socket_path());

    sleep(Duration::from_millis(500)).await;

    // Get initial worker count
    let initial_workers = client.list_workers().await?;
    let initial_count = initial_workers.len();
    println!("[TEST] Initial workers: {}", initial_count);

    // Add a rule with no outputs (fanout to nothing is valid)
    // This tests rule management without needing separate interfaces
    client
        .add_rule_with_name(
            "test-rule-1".to_string(),
            None,
            "lo".to_string(),
            "239.1.1.1".parse()?,
            5000,
            vec![], // Empty outputs - valid for testing
        )
        .await?;

    sleep(Duration::from_millis(300)).await;

    let workers_after = client.list_workers().await?;
    println!("[TEST] Workers after adding rule: {}", workers_after.len());

    // Verify rule was added
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1, "Should have 1 rule");

    Ok(())
}

/// Test: Multiple rules for the same interface are handled correctly
///
/// All rules for the same interface should be routed to the same workers.
#[tokio::test]
async fn test_multiple_rules_same_interface() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    // Config with multiple rules for 'lo' interface
    let config = r#"{
        rules: [
            {
                name: "rule-1",
                input: { interface: "lo", group: "239.1.1.1", port: 5000 },
                outputs: [{ interface: "lo", group: "239.2.2.2", port: 6000 }]
            },
            {
                name: "rule-2",
                input: { interface: "lo", group: "239.1.1.2", port: 5001 },
                outputs: [{ interface: "lo", group: "239.2.2.3", port: 6001 }]
            }
        ]
    }"#;

    let supervisor = start_supervisor_with_config(config).await?;
    let client = ControlClient::new(supervisor.socket_path());

    sleep(Duration::from_millis(500)).await;

    let workers = client.list_workers().await?;
    println!("[TEST] Total workers: {}", workers.len());
    assert!(!workers.is_empty(), "Should have workers");

    // Both rules should be loaded
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 2, "Should have 2 rules");
    println!("[TEST] Rules loaded: {}", rules.len());

    // Verify both rules have the same input interface
    for rule in &rules {
        assert_eq!(rule.input_interface, "lo");
    }

    Ok(())
}

/// Test: Rule naming and RemoveRuleByName
///
/// Verifies that rules can be added with names and removed by name.
#[tokio::test]
async fn test_remove_rule_by_name() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let client = ControlClient::new(supervisor.socket_path());

    sleep(Duration::from_millis(500)).await;

    // Add a rule with a name (empty outputs to avoid self-loop validation)
    let rule_name = "my-named-rule";
    client
        .add_rule_with_name(
            "rule-1".to_string(),
            Some(rule_name.to_string()),
            "lo".to_string(),
            "239.1.1.1".parse()?,
            5000,
            vec![], // Empty outputs - valid for testing
        )
        .await?;
    println!("[TEST] Added rule with name '{}'", rule_name);

    sleep(Duration::from_millis(200)).await;

    // Verify rule exists
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name.as_deref(), Some(rule_name));
    println!("[TEST] Verified rule has name '{}'", rule_name);

    // Remove by name
    client.remove_rule_by_name(rule_name).await?;
    println!("[TEST] Removed rule by name '{}'", rule_name);

    sleep(Duration::from_millis(200)).await;

    // Verify rule is gone
    let rules_after = client.list_rules().await?;
    assert!(rules_after.is_empty(), "Rule should be removed");
    println!("[TEST] Verified rule was removed");

    Ok(())
}

/// Test: RemoveRuleByName fails gracefully for non-existent name
#[tokio::test]
async fn test_remove_rule_by_name_not_found() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let client = ControlClient::new(supervisor.socket_path());

    sleep(Duration::from_millis(500)).await;

    // Try to remove a rule by name that doesn't exist
    let result = client.remove_rule_by_name("non-existent-rule").await;
    assert!(result.is_err(), "Should fail for non-existent name");
    println!("[TEST] RemoveRuleByName correctly failed for non-existent name");

    Ok(())
}

/// Test: Config show returns rules with names preserved
#[tokio::test]
async fn test_config_preserves_rule_names() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    // Config with named rules
    let config = r#"{
        rules: [
            {
                name: "stream-a",
                input: { interface: "lo", group: "239.1.1.1", port: 5000 },
                outputs: [{ interface: "lo", group: "239.2.2.2", port: 6000 }]
            },
            {
                name: "stream-b",
                input: { interface: "lo", group: "239.1.1.2", port: 5001 },
                outputs: [{ interface: "lo", group: "239.2.2.3", port: 6001 }]
            }
        ]
    }"#;

    let supervisor = start_supervisor_with_config(config).await?;
    let client = ControlClient::new(supervisor.socket_path());

    sleep(Duration::from_millis(500)).await;

    // Get config
    let running_config = client.get_config().await?;
    assert_eq!(running_config.rules.len(), 2);

    // Verify names are preserved
    let names: Vec<_> = running_config
        .rules
        .iter()
        .filter_map(|r| r.name.as_ref())
        .collect();
    assert!(names.contains(&&"stream-a".to_string()));
    assert!(names.contains(&&"stream-b".to_string()));
    println!("[TEST] Config preserves rule names: {:?}", names);

    Ok(())
}

/// Test: Multiple ingress interfaces spawn separate worker groups
///
/// Verifies that when mcrd starts with a config file containing rules
/// for two different input interfaces, it spawns workers for each interface.
/// This tests the core multi-interface architecture.
#[tokio::test]
async fn test_multiple_ingress_interfaces() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    // Enter a network namespace for isolation
    let _ns = NetworkNamespace::enter()?;

    // Create two veth pairs for testing
    // veth0a <-> veth0b (first ingress interface pair)
    // veth1a <-> veth1b (second ingress interface pair)
    let veth0 = VethPair::create("veth0a", "veth0b").await?;
    veth0.up().await?;

    let veth1 = VethPair::create("veth1a", "veth1b").await?;
    veth1.up().await?;

    // Config with rules for two different input interfaces
    // Each input interface should get its own set of workers
    let config = r#"{
        rules: [
            {
                name: "stream-from-veth0",
                input: { interface: "veth0a", group: "239.1.1.1", port: 5000 },
                outputs: [{ interface: "veth0b", group: "239.2.2.2", port: 6000 }]
            },
            {
                name: "stream-from-veth1",
                input: { interface: "veth1a", group: "239.1.1.2", port: 5001 },
                outputs: [{ interface: "veth1b", group: "239.2.2.3", port: 6001 }]
            }
        ]
    }"#;

    let supervisor = start_supervisor_with_config(config).await?;
    let client = ControlClient::new(supervisor.socket_path());

    sleep(Duration::from_millis(500)).await;

    // Verify workers were spawned (should have workers for each interface)
    let workers = client.list_workers().await?;
    println!("[TEST] Workers spawned: {}", workers.len());
    // With --num-workers 1, we should have at least 2 workers (one per interface)
    assert!(
        workers.len() >= 2,
        "Should have at least 2 workers (one per interface), got {}",
        workers.len()
    );

    // Verify both rules were loaded
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 2, "Should have 2 rules");
    println!("[TEST] Rules loaded: {}", rules.len());

    // Verify rules have different input interfaces
    let interfaces: HashSet<_> = rules.iter().map(|r| r.input_interface.as_str()).collect();
    assert!(interfaces.contains("veth0a"), "Should have rule for veth0a");
    assert!(interfaces.contains("veth1a"), "Should have rule for veth1a");
    println!("[TEST] Input interfaces: {:?}", interfaces);

    // Verify rule names are correct
    let names: HashSet<_> = rules.iter().filter_map(|r| r.name.as_ref()).collect();
    assert!(names.contains(&"stream-from-veth0".to_string()));
    assert!(names.contains(&"stream-from-veth1".to_string()));
    println!("[TEST] Rule names: {:?}", names);

    Ok(())
}

/// Test: Dynamic worker spawning for new interface via AddRule
///
/// Start with workers for one interface, then add a rule for a different
/// interface and verify new workers are spawned.
#[tokio::test]
async fn test_dynamic_spawn_for_new_interface() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    // Enter a network namespace for isolation
    let _ns = NetworkNamespace::enter()?;

    // Create veth pairs
    let veth0 = VethPair::create("veth0a", "veth0b").await?;
    veth0.up().await?;

    let veth1 = VethPair::create("veth1a", "veth1b").await?;
    veth1.up().await?;

    // Start with config for only veth0
    let config = r#"{
        rules: [
            {
                name: "initial-rule",
                input: { interface: "veth0a", group: "239.1.1.1", port: 5000 },
                outputs: [{ interface: "veth0b", group: "239.2.2.2", port: 6000 }]
            }
        ]
    }"#;

    let supervisor = start_supervisor_with_config(config).await?;
    let client = ControlClient::new(supervisor.socket_path());

    sleep(Duration::from_millis(500)).await;

    // Get initial worker count
    let initial_workers = client.list_workers().await?;
    let initial_count = initial_workers.len();
    println!("[TEST] Initial workers (veth0a only): {}", initial_count);

    // Add a rule for veth1a - this should spawn new workers
    client
        .add_rule_with_name(
            "dynamic-rule".to_string(),
            Some("dynamic-stream".to_string()),
            "veth1a".to_string(),
            "239.1.1.2".parse()?,
            5001,
            vec![multicast_relay::OutputDestination {
                group: "239.2.2.3".parse()?,
                port: 6001,
                interface: "veth1b".to_string(),
            }],
        )
        .await?;

    sleep(Duration::from_millis(500)).await;

    // Verify more workers were spawned
    let workers_after = client.list_workers().await?;
    println!(
        "[TEST] Workers after adding veth1a rule: {}",
        workers_after.len()
    );
    assert!(
        workers_after.len() > initial_count,
        "Should have spawned new workers for veth1a, was {} now {}",
        initial_count,
        workers_after.len()
    );

    // Verify both rules exist
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 2, "Should have 2 rules");

    let interfaces: HashSet<_> = rules.iter().map(|r| r.input_interface.as_str()).collect();
    assert!(interfaces.contains("veth0a"));
    assert!(interfaces.contains("veth1a"));
    println!(
        "[TEST] Verified rules for both interfaces: {:?}",
        interfaces
    );

    Ok(())
}
