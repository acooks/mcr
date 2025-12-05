// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **CLI Functional Tests**
//!
//! End-to-end tests that verify `mcrctl` CLI commands work correctly
//! when communicating with a running supervisor.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::time::sleep;

use crate::common::{McrInstance, NetworkNamespace, VethPair};

/// Run mcrctl command and return stdout
fn run_mcrctl(socket_path: &Path, args: &[&str]) -> Result<String> {
    let mcr_instance = crate::common::McrInstance::builder();
    // Use the binary_path from common module (accessed via internal helper)
    let binary = get_mcrctl_path();

    let output = Command::new(&binary)
        .arg("--socket-path")
        .arg(socket_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to execute mcrctl")?;

    // Allow this to not reference mcr_instance
    let _ = mcr_instance;

    if !output.status.success() {
        anyhow::bail!("mcrctl failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run mcrctl command expecting it to fail, return stderr
fn run_mcrctl_expect_failure(socket_path: &Path, args: &[&str]) -> Result<String> {
    let binary = get_mcrctl_path();

    let output = Command::new(&binary)
        .arg("--socket-path")
        .arg(socket_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to execute mcrctl")?;

    if output.status.success() {
        anyhow::bail!(
            "Expected mcrctl to fail, but it succeeded with: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    Ok(String::from_utf8_lossy(&output.stderr).to_string())
}

/// Get the path to mcrctl binary
fn get_mcrctl_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/release/mcrctl");
    if path.exists() {
        return path;
    }
    path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/debug/mcrctl");
    path
}

// --- Tests ---

/// Test: mcrctl ping returns Pong
#[tokio::test]
async fn test_cli_ping() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let output = run_mcrctl(mcr.control_socket(), &["ping"])?;

    assert!(
        output.contains("pong"),
        "Expected pong response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl version returns version info
#[tokio::test]
async fn test_cli_version() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let output = run_mcrctl(mcr.control_socket(), &["version"])?;

    assert!(
        output.contains("version"),
        "Expected version in response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl list-workers returns worker info
#[tokio::test]
async fn test_cli_list_workers() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let output = run_mcrctl(mcr.control_socket(), &["list-workers"])?;

    // Should return JSON with Workers array
    assert!(
        output.contains("Workers"),
        "Expected Workers in response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl list returns empty rules initially
#[tokio::test]
async fn test_cli_list_empty() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let output = run_mcrctl(mcr.control_socket(), &["list"])?;

    // Should return JSON with Rules array (empty)
    assert!(
        output.contains("Rules"),
        "Expected Rules in response, got: {}",
        output
    );
    assert!(
        output.contains("[]"),
        "Expected empty rules array, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl add and list workflow
#[tokio::test]
async fn test_cli_add_and_list_rule() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Add a rule with empty outputs (valid - no outputs means input-only rule)
    // Omitting --outputs entirely gives an empty vec, which is valid
    let add_output = run_mcrctl(
        mcr.control_socket(),
        &[
            "add",
            "--rule-id",
            "test-cli-rule",
            "--input-interface",
            "lo",
            "--input-group",
            "239.1.1.1",
            "--input-port",
            "5000",
        ],
    )?;

    // Verify the add command succeeded
    assert!(
        add_output.contains("Success"),
        "Expected Success response for add, got: {}",
        add_output
    );

    // List rules and verify our rule is present
    let list_output = run_mcrctl(mcr.control_socket(), &["list"])?;
    assert!(
        list_output.contains("Rules"),
        "Expected Rules in response, got: {}",
        list_output
    );
    assert!(
        list_output.contains("test-cli-rule"),
        "Expected our rule to be listed, got: {}",
        list_output
    );

    Ok(())
}

/// Test: mcrctl stats returns statistics
#[tokio::test]
async fn test_cli_stats() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let output = run_mcrctl(mcr.control_socket(), &["stats"])?;

    // Should return JSON with Stats response
    assert!(
        output.contains("Stats") || output.contains("flows"),
        "Expected Stats in response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl log-level get returns current levels
#[tokio::test]
async fn test_cli_log_level_get() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let output = run_mcrctl(mcr.control_socket(), &["log-level", "get"])?;

    // Should return log levels info
    assert!(
        output.contains("LogLevels"),
        "Expected LogLevels in response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl log-level set --global changes level
#[tokio::test]
async fn test_cli_log_level_set_global() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Set global log level to debug
    let output = run_mcrctl(
        mcr.control_socket(),
        &["log-level", "set", "--global", "debug"],
    )?;

    assert!(
        output.contains("Success"),
        "Expected Success response, got: {}",
        output
    );

    // Verify the change - should now show Debug level
    let get_output = run_mcrctl(mcr.control_socket(), &["log-level", "get"])?;
    assert!(
        get_output.contains("LogLevels"),
        "Expected LogLevels in response, got: {}",
        get_output
    );
    assert!(
        get_output.contains("Debug") || get_output.contains("debug"),
        "Expected Debug level after setting, got: {}",
        get_output
    );

    Ok(())
}

/// Test: mcrctl log-level set --facility sets per-facility level
#[tokio::test]
async fn test_cli_log_level_set_facility() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Set DataPlane facility to debug
    let output = run_mcrctl(
        mcr.control_socket(),
        &[
            "log-level",
            "set",
            "--facility",
            "DataPlane",
            "--level",
            "debug",
        ],
    )?;

    assert!(
        output.contains("Success"),
        "Expected Success response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config show returns running config
#[tokio::test]
async fn test_cli_config_show() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let output = run_mcrctl(mcr.control_socket(), &["config", "show"])?;

    // Should return Config response
    assert!(
        output.contains("Config"),
        "Expected Config in response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config check validates config file
#[tokio::test]
async fn test_cli_config_check() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Create a valid config file
    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                input: {{ interface: "eth0", group: "239.1.1.1", port: 5000 }},
                outputs: [{{ interface: "eth1", group: "239.2.2.2", port: 6000 }}]
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    let output = run_mcrctl(
        mcr.control_socket(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("ConfigValid") || output.contains("valid"),
        "Expected valid config response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl remove with non-existent rule returns error
#[tokio::test]
async fn test_cli_remove_nonexistent() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Try to remove a rule that doesn't exist
    let output = run_mcrctl(
        mcr.control_socket(),
        &["remove", "--rule-id", "nonexistent-rule"],
    )?;

    // Should return error about rule not found
    assert!(
        output.contains("Error") || output.contains("not found"),
        "Expected error response, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config save writes running rules to file
#[tokio::test]
async fn test_cli_config_save() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Add a rule (input-only, no outputs - avoids same-interface validation)
    let add_output = run_mcrctl(
        mcr.control_socket(),
        &[
            "add",
            "--rule-id",
            "save-test-rule",
            "--input-interface",
            "lo",
            "--input-group",
            "239.10.10.1",
            "--input-port",
            "5001",
        ],
    )?;

    assert!(
        add_output.contains("Success"),
        "Expected Success response for add, got: {}",
        add_output
    );

    // Create a temp file to save config to
    let temp_dir = tempfile::tempdir()?;
    let save_path = temp_dir.path().join("saved_config.json");

    // Save the running configuration
    let save_output = run_mcrctl(
        mcr.control_socket(),
        &["config", "save", "--file", save_path.to_str().unwrap()],
    )?;

    assert!(
        save_output.contains("Success") || save_output.contains("saved"),
        "Expected Success response for save, got: {}",
        save_output
    );

    // Read the saved file and verify it contains our rule
    let saved_content =
        std::fs::read_to_string(&save_path).context("Failed to read saved config file")?;

    // The config should contain our rule's details
    assert!(
        saved_content.contains("239.10.10.1"),
        "Saved config should contain input group, got: {}",
        saved_content
    );
    assert!(
        saved_content.contains("5001"),
        "Saved config should contain input port, got: {}",
        saved_content
    );
    assert!(
        saved_content.contains("lo"),
        "Saved config should contain interface, got: {}",
        saved_content
    );

    // Verify the saved config is valid JSON by parsing it
    let parsed: serde_json::Value =
        serde_json::from_str(&saved_content).context("Saved config should be valid JSON")?;

    // Verify it has a rules array
    assert!(
        parsed.get("rules").is_some(),
        "Saved config should have 'rules' field, got: {}",
        saved_content
    );
    let rules = parsed["rules"].as_array().expect("rules should be array");
    assert_eq!(
        rules.len(),
        1,
        "Should have exactly 1 rule, got: {}",
        saved_content
    );

    Ok(())
}

/// Test: mcrctl add with --outputs creates rule with output destinations
///
/// This test verifies that the CLI can add a rule with output destinations
/// using different interfaces (veth pairs) to avoid same-interface validation.
#[tokio::test]
async fn test_cli_add_with_outputs() -> Result<()> {
    require_root!();

    // Enter a network namespace for isolation
    let _ns = NetworkNamespace::enter()?;

    // Create a veth pair: veth0a <-> veth0b
    let veth = VethPair::create("veth0a", "veth0b").await?;
    veth.up().await?;

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Add a rule with an output using different interfaces
    // Output format is group:port:interface
    let add_output = run_mcrctl(
        mcr.control_socket(),
        &[
            "add",
            "--rule-id",
            "output-test-rule",
            "--input-interface",
            "veth0a",
            "--input-group",
            "239.20.20.1",
            "--input-port",
            "5010",
            "--outputs",
            "239.20.20.2:5011:veth0b",
        ],
    )?;

    assert!(
        add_output.contains("Success"),
        "Expected Success response for add, got: {}",
        add_output
    );

    // Verify the rule was added with correct outputs
    let list_output = run_mcrctl(mcr.control_socket(), &["list"])?;
    assert!(
        list_output.contains("output-test-rule"),
        "Expected rule to be listed, got: {}",
        list_output
    );
    assert!(
        list_output.contains("239.20.20.1"),
        "Expected input group in list, got: {}",
        list_output
    );

    // Save config and verify outputs are persisted
    let temp_dir = tempfile::tempdir()?;
    let save_path = temp_dir.path().join("saved_config_outputs.json");

    let save_output = run_mcrctl(
        mcr.control_socket(),
        &["config", "save", "--file", save_path.to_str().unwrap()],
    )?;

    assert!(
        save_output.contains("Success") || save_output.contains("saved"),
        "Expected Success response for save, got: {}",
        save_output
    );

    // Read and verify saved config contains outputs
    let saved_content =
        std::fs::read_to_string(&save_path).context("Failed to read saved config file")?;

    // Verify the saved config contains output destination details
    assert!(
        saved_content.contains("239.20.20.2"),
        "Saved config should contain output group, got: {}",
        saved_content
    );
    assert!(
        saved_content.contains("5011"),
        "Saved config should contain output port, got: {}",
        saved_content
    );
    assert!(
        saved_content.contains("veth0b"),
        "Saved config should contain output interface, got: {}",
        saved_content
    );

    // Parse and verify structure
    let parsed: serde_json::Value =
        serde_json::from_str(&saved_content).context("Saved config should be valid JSON")?;
    let rules = parsed["rules"].as_array().expect("rules should be array");
    assert_eq!(rules.len(), 1, "Should have exactly 1 rule");

    let rule = &rules[0];
    let outputs = rule["outputs"].as_array().expect("outputs should be array");
    assert_eq!(outputs.len(), 1, "Should have exactly 1 output");

    Ok(())
}

// =============================================================================
// CONFIG VALIDATION ERROR TESTS
// =============================================================================

/// Test: mcrctl config check rejects invalid JSON
#[tokio::test]
async fn test_cli_config_check_invalid_json() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let mut temp = NamedTempFile::new()?;
    writeln!(temp, "{{ this is not valid json")?;
    temp.flush()?;

    let error = run_mcrctl_expect_failure(
        mcr.control_socket(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        error.contains("parse") || error.contains("JSON") || error.contains("syntax"),
        "Expected parse error, got: {}",
        error
    );

    Ok(())
}

/// Test: mcrctl config check rejects non-multicast input address
#[tokio::test]
async fn test_cli_config_check_non_multicast_input() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                input: {{ interface: "eth0", group: "192.168.1.1", port: 5000 }},
                outputs: []
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    // config check returns success with validation result in JSON
    let output = run_mcrctl(
        mcr.control_socket(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("\"valid\": false") || output.contains("\"valid\":false"),
        "Expected valid: false in response, got: {}",
        output
    );
    assert!(
        output.contains("multicast") && output.contains("192.168.1.1"),
        "Expected multicast address error, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config check rejects duplicate rules
#[tokio::test]
async fn test_cli_config_check_duplicate_rules() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                input: {{ interface: "eth0", group: "239.1.1.1", port: 5000 }},
                outputs: []
            }},
            {{
                input: {{ interface: "eth0", group: "239.1.1.1", port: 5000 }},
                outputs: []
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    let output = run_mcrctl(
        mcr.control_socket(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("\"valid\": false") || output.contains("\"valid\":false"),
        "Expected valid: false in response, got: {}",
        output
    );
    assert!(
        output.contains("duplicate"),
        "Expected duplicate rule error, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config check rejects invalid interface name
#[tokio::test]
async fn test_cli_config_check_invalid_interface() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                input: {{ interface: "this-interface-name-is-way-too-long", group: "239.1.1.1", port: 5000 }},
                outputs: []
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    let output = run_mcrctl(
        mcr.control_socket(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("\"valid\": false") || output.contains("\"valid\":false"),
        "Expected valid: false in response, got: {}",
        output
    );
    assert!(
        output.contains("interface") && output.contains("too long"),
        "Expected interface name error, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config check rejects port 0
#[tokio::test]
async fn test_cli_config_check_invalid_port() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                input: {{ interface: "eth0", group: "239.1.1.1", port: 0 }},
                outputs: []
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    let output = run_mcrctl(
        mcr.control_socket(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("\"valid\": false") || output.contains("\"valid\":false"),
        "Expected valid: false in response, got: {}",
        output
    );
    assert!(
        output.contains("port 0"),
        "Expected port error, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config check rejects non-multicast output address
#[tokio::test]
async fn test_cli_config_check_non_multicast_output() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                input: {{ interface: "eth0", group: "239.1.1.1", port: 5000 }},
                outputs: [{{ interface: "eth1", group: "10.0.0.1", port: 6000 }}]
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    let output = run_mcrctl(
        mcr.control_socket(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("\"valid\": false") || output.contains("\"valid\":false"),
        "Expected valid: false in response, got: {}",
        output
    );
    assert!(
        output.contains("multicast") && output.contains("10.0.0.1"),
        "Expected multicast address error for output, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config check rejects empty pinning
#[tokio::test]
async fn test_cli_config_check_empty_pinning() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        pinning: {{
            eth0: []
        }},
        rules: []
    }}"#
    )?;
    temp.flush()?;

    let output = run_mcrctl(
        mcr.control_socket(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("\"valid\": false") || output.contains("\"valid\":false"),
        "Expected valid: false in response, got: {}",
        output
    );
    assert!(
        output.contains("empty") && output.contains("eth0"),
        "Expected empty pinning error, got: {}",
        output
    );

    Ok(())
}

/// Test: mcrctl config check handles nonexistent file
#[tokio::test]
async fn test_cli_config_check_nonexistent_file() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    let error = run_mcrctl_expect_failure(
        mcr.control_socket(),
        &["config", "check", "--file", "/nonexistent/path/config.json"],
    )?;

    assert!(
        error.contains("No such file")
            || error.contains("not found")
            || error.contains("failed to read"),
        "Expected file not found error, got: {}",
        error
    );

    Ok(())
}

// =============================================================================
// CONFIG LOAD TESTS
// =============================================================================

/// Test: mcrctl config load loads valid configuration
#[tokio::test]
async fn test_cli_config_load() -> Result<()> {
    require_root!();

    // Enter a network namespace for isolation
    let _ns = NetworkNamespace::enter()?;

    // Create veth pair for the config
    let veth = VethPair::create("veth0a", "veth0b").await?;
    veth.up().await?;

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Verify no rules initially
    let initial_list = run_mcrctl(mcr.control_socket(), &["list"])?;
    assert!(
        initial_list.contains("[]"),
        "Should have no rules initially, got: {}",
        initial_list
    );

    // Create a config file with rules
    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                name: "loaded-rule",
                input: {{ interface: "veth0a", group: "239.5.5.1", port: 5050 }},
                outputs: [{{ interface: "veth0b", group: "239.5.5.2", port: 5051 }}]
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    // Load the config
    let load_output = run_mcrctl(
        mcr.control_socket(),
        &["config", "load", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        load_output.contains("Success") || load_output.contains("loaded"),
        "Expected success for config load, got: {}",
        load_output
    );

    // Verify the rule was loaded
    let list_output = run_mcrctl(mcr.control_socket(), &["list"])?;
    assert!(
        list_output.contains("239.5.5.1"),
        "Loaded rule should appear in list, got: {}",
        list_output
    );
    assert!(
        list_output.contains("loaded-rule"),
        "Rule name should appear in list, got: {}",
        list_output
    );

    Ok(())
}

/// Test: mcrctl config load with --replace replaces all rules
#[tokio::test]
async fn test_cli_config_load_replace() -> Result<()> {
    require_root!();

    // Enter a network namespace for isolation
    let _ns = NetworkNamespace::enter()?;

    // Create veth pairs for the configs
    let veth0 = VethPair::create("veth0a", "veth0b").await?;
    veth0.up().await?;

    let veth1 = VethPair::create("veth1a", "veth1b").await?;
    veth1.up().await?;

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Add an initial rule via CLI
    let add_output = run_mcrctl(
        mcr.control_socket(),
        &[
            "add",
            "--rule-id",
            "initial-rule",
            "--input-interface",
            "veth0a",
            "--input-group",
            "239.6.6.1",
            "--input-port",
            "6060",
            "--outputs",
            "239.6.6.2:6061:veth0b",
        ],
    )?;
    assert!(
        add_output.contains("Success"),
        "Should add initial rule, got: {}",
        add_output
    );

    // Verify initial rule exists
    let initial_list = run_mcrctl(mcr.control_socket(), &["list"])?;
    assert!(
        initial_list.contains("239.6.6.1"),
        "Initial rule should exist, got: {}",
        initial_list
    );

    // Create a config file with a different rule
    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                name: "replacement-rule",
                input: {{ interface: "veth1a", group: "239.7.7.1", port: 7070 }},
                outputs: [{{ interface: "veth1b", group: "239.7.7.2", port: 7071 }}]
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    // Load with --replace flag
    let load_output = run_mcrctl(
        mcr.control_socket(),
        &[
            "config",
            "load",
            "--file",
            temp.path().to_str().unwrap(),
            "--replace",
        ],
    )?;

    assert!(
        load_output.contains("Success") || load_output.contains("loaded"),
        "Expected success for config load --replace, got: {}",
        load_output
    );

    // Verify original rule is gone and new rule exists
    let final_list = run_mcrctl(mcr.control_socket(), &["list"])?;
    assert!(
        !final_list.contains("239.6.6.1"),
        "Original rule should be replaced, got: {}",
        final_list
    );
    assert!(
        final_list.contains("239.7.7.1"),
        "New rule should exist, got: {}",
        final_list
    );
    assert!(
        final_list.contains("replacement-rule"),
        "New rule name should appear, got: {}",
        final_list
    );

    Ok(())
}

/// Test: mcrctl config load without --replace merges rules
#[tokio::test]
async fn test_cli_config_load_merge() -> Result<()> {
    require_root!();

    // Enter a network namespace for isolation
    let _ns = NetworkNamespace::enter()?;

    // Create veth pairs for the configs
    let veth0 = VethPair::create("veth0a", "veth0b").await?;
    veth0.up().await?;

    let veth1 = VethPair::create("veth1a", "veth1b").await?;
    veth1.up().await?;

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Add an initial rule via CLI
    let add_output = run_mcrctl(
        mcr.control_socket(),
        &[
            "add",
            "--rule-id",
            "existing-rule",
            "--input-interface",
            "veth0a",
            "--input-group",
            "239.8.8.1",
            "--input-port",
            "8080",
            "--outputs",
            "239.8.8.2:8081:veth0b",
        ],
    )?;
    assert!(
        add_output.contains("Success"),
        "Should add initial rule, got: {}",
        add_output
    );

    // Create a config file with a different rule
    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                name: "merged-rule",
                input: {{ interface: "veth1a", group: "239.9.9.1", port: 9090 }},
                outputs: [{{ interface: "veth1b", group: "239.9.9.2", port: 9091 }}]
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    // Load without --replace (should merge)
    let load_output = run_mcrctl(
        mcr.control_socket(),
        &["config", "load", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        load_output.contains("Success") || load_output.contains("loaded"),
        "Expected success for config load (merge), got: {}",
        load_output
    );

    // Verify both rules exist
    let final_list = run_mcrctl(mcr.control_socket(), &["list"])?;
    assert!(
        final_list.contains("239.8.8.1"),
        "Original rule should still exist, got: {}",
        final_list
    );
    assert!(
        final_list.contains("239.9.9.1"),
        "New rule should be added, got: {}",
        final_list
    );

    Ok(())
}

/// Test: mcrctl config load rejects invalid config
#[tokio::test]
async fn test_cli_config_load_invalid() -> Result<()> {
    require_root!();

    let mcr = McrInstance::builder()
        .num_workers(1)
        .start_async()
        .await
        .context("Failed to start supervisor")?;

    sleep(Duration::from_millis(300)).await;

    // Create an invalid config file (non-multicast address)
    let mut temp = NamedTempFile::new()?;
    writeln!(
        temp,
        r#"{{
        rules: [
            {{
                input: {{ interface: "eth0", group: "192.168.1.1", port: 5000 }},
                outputs: []
            }}
        ]
    }}"#
    )?;
    temp.flush()?;

    // config load returns success with Error response in JSON
    let output = run_mcrctl(
        mcr.control_socket(),
        &["config", "load", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("Error"),
        "Expected Error response, got: {}",
        output
    );
    assert!(
        output.contains("multicast") && output.contains("192.168.1.1"),
        "Expected validation error message, got: {}",
        output
    );

    Ok(())
}
