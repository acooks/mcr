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

use crate::common::McrInstance;

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
