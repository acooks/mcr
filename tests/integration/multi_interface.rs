// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **Multi-Interface Integration Tests**
//!
//! Tests for multi-interface architecture features:
//! - Config file startup with multiple interfaces
//! - Dynamic worker spawning when adding rules for new interfaces
//! - Per-interface fanout groups
//! - Rule naming and RemoveRuleByName

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::sleep;

use crate::common::{ControlClient, McrInstance, NetworkNamespace, VethPair};

// --- Tests ---

/// Test: Startup config spawns workers for each interface in config
///
/// Verifies that when mcrd starts with a config file containing rules
/// for the 'lo' interface, it spawns workers for that interface.
#[tokio::test]
async fn test_config_startup_spawns_workers_for_interface() -> Result<()> {
    require_root!();

    // Config with one rule for 'lo' interface
    let config = r#"{
        rules: [
            {
                input: { interface: "lo", group: "239.1.1.1", port: 5000 },
                outputs: [{ interface: "lo", group: "239.2.2.2", port: 6000 }]
            }
        ]
    }"#;

    let mcr = McrInstance::builder()
        .config_content(config)
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Verify workers were spawned
    let workers = client.list_workers().await?;
    assert!(
        !workers.is_empty(),
        "Should have spawned workers for 'lo' interface"
    );

    // Verify rules were loaded
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1, "Should have 1 rule from config");
    assert_eq!(rules[0].input_interface, "lo");

    Ok(())
}

/// Test: Dynamic worker spawning when adding a rule for a new interface
///
/// When a rule is added for an interface that doesn't have workers yet,
/// the supervisor should dynamically spawn workers for that interface.
#[tokio::test]
async fn test_dynamic_worker_spawn_on_add_rule() -> Result<()> {
    require_root!();

    // Start supervisor without config (default interface 'lo')
    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Get initial worker count
    let initial_workers = client.list_workers().await?;
    let initial_count = initial_workers.len();

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

    // Verify rule was added
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1, "Should have 1 rule");

    // Worker count should not have changed (same interface)
    assert_eq!(
        workers_after.len(),
        initial_count,
        "Worker count should be stable for same interface"
    );

    Ok(())
}

/// Test: Multiple rules for the same interface are handled correctly
///
/// All rules for the same interface should be routed to the same workers.
#[tokio::test]
async fn test_multiple_rules_same_interface() -> Result<()> {
    require_root!();

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

    let mcr = McrInstance::builder()
        .config_content(config)
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    let workers = client.list_workers().await?;
    assert!(!workers.is_empty(), "Should have workers");

    // Both rules should be loaded
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 2, "Should have 2 rules");

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
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

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

    sleep(Duration::from_millis(200)).await;

    // Verify rule exists
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name.as_deref(), Some(rule_name));

    // Remove by name
    client.remove_rule_by_name(rule_name).await?;

    sleep(Duration::from_millis(200)).await;

    // Verify rule is gone
    let rules_after = client.list_rules().await?;
    assert!(rules_after.is_empty(), "Rule should be removed");

    Ok(())
}

/// Test: RemoveRuleByName fails gracefully for non-existent name
#[tokio::test]
async fn test_remove_rule_by_name_not_found() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Try to remove a rule by name that doesn't exist
    let result = client.remove_rule_by_name("non-existent-rule").await;
    assert!(result.is_err(), "Should fail for non-existent name");

    Ok(())
}

/// Test: Config show returns rules with names preserved
#[tokio::test]
async fn test_config_preserves_rule_names() -> Result<()> {
    require_root!();

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

    let mcr = McrInstance::builder()
        .config_content(config)
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

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

    Ok(())
}

/// Test: Multiple ingress interfaces spawn separate worker groups
///
/// Verifies that when mcrd starts with a config file containing rules
/// for two different input interfaces, it spawns workers for each interface.
/// This tests the core multi-interface architecture.
#[tokio::test]
async fn test_multiple_ingress_interfaces() -> Result<()> {
    require_root!();

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

    let mcr = McrInstance::builder()
        .config_content(config)
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Verify workers were spawned (should have workers for each interface)
    let workers = client.list_workers().await?;
    // With --num-workers 1, we should have at least 2 workers (one per interface)
    assert!(
        workers.len() >= 2,
        "Should have at least 2 workers (one per interface), got {}",
        workers.len()
    );

    // Verify both rules were loaded
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 2, "Should have 2 rules");

    // Verify rules have different input interfaces
    let interfaces: HashSet<_> = rules.iter().map(|r| r.input_interface.as_str()).collect();
    assert!(interfaces.contains("veth0a"), "Should have rule for veth0a");
    assert!(interfaces.contains("veth1a"), "Should have rule for veth1a");

    // Verify rule names are correct
    let names: HashSet<_> = rules.iter().filter_map(|r| r.name.as_ref()).collect();
    assert!(names.contains(&"stream-from-veth0".to_string()));
    assert!(names.contains(&"stream-from-veth1".to_string()));

    Ok(())
}

/// Test: Dynamic worker spawning for new interface via AddRule
///
/// Start with workers for one interface, then add a rule for a different
/// interface and verify new workers are spawned.
#[tokio::test]
async fn test_dynamic_spawn_for_new_interface() -> Result<()> {
    require_root!();

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

    let mcr = McrInstance::builder()
        .config_content(config)
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    let client = ControlClient::new(mcr.control_socket());

    sleep(Duration::from_millis(500)).await;

    // Get initial worker count
    let initial_workers = client.list_workers().await?;
    let initial_count = initial_workers.len();

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

    Ok(())
}
