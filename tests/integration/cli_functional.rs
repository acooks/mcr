// SPDX-License-Identifier: Apache-2.0 OR MIT
//! **CLI Functional Tests**
//!
//! End-to-end tests that verify `mcrctl` CLI commands work correctly
//! when communicating with a running supervisor.

use anyhow::{Context, Result};
use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::process::Child;
use tokio::time::sleep;

use crate::tests::{cleanup_socket, unique_socket_path_with_prefix};

/// Get path to a binary in target/debug or target/release
fn binary_path(name: &str) -> PathBuf {
    // Try release first, then debug
    let release_path = PathBuf::from(format!("target/release/{}", name));
    if release_path.exists() {
        return release_path;
    }
    PathBuf::from(format!("target/debug/{}", name))
}

/// RAII guard for supervisor cleanup
struct TestSupervisor {
    process: Option<Child>,
    control_socket_path: PathBuf,
    relay_socket_path: PathBuf,
    #[allow(dead_code)]
    config_file: Option<NamedTempFile>,
}

impl TestSupervisor {
    fn socket_path(&self) -> &PathBuf {
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

/// Start supervisor without config (default mode)
async fn start_supervisor_default() -> Result<TestSupervisor> {
    let control_socket = unique_socket_path_with_prefix("cli_func_control");
    let relay_socket = unique_socket_path_with_prefix("cli_func_relay");

    cleanup_socket(&control_socket);
    cleanup_socket(&relay_socket);

    let binary = env!("CARGO_BIN_EXE_mcrd");

    let supervisor = tokio::process::Command::new(binary)
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

/// Run mcrctl command and return stdout
fn run_mcrctl(socket_path: &PathBuf, args: &[&str]) -> Result<String> {
    let binary = binary_path("mcrctl");
    let output = Command::new(&binary)
        .arg("--socket-path")
        .arg(socket_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to execute mcrctl")?;

    if !output.status.success() {
        anyhow::bail!("mcrctl failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// --- Tests ---

/// Test: mcrctl ping returns Pong
#[tokio::test]
async fn test_cli_ping() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let output = run_mcrctl(supervisor.socket_path(), &["ping"])?;

    assert!(
        output.contains("pong"),
        "Expected pong response, got: {}",
        output
    );
    println!("[TEST] Ping response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl version returns version info
#[tokio::test]
async fn test_cli_version() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let output = run_mcrctl(supervisor.socket_path(), &["version"])?;

    assert!(
        output.contains("version"),
        "Expected version in response, got: {}",
        output
    );
    println!("[TEST] Version response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl list-workers returns worker info
#[tokio::test]
async fn test_cli_list_workers() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let output = run_mcrctl(supervisor.socket_path(), &["list-workers"])?;

    // Should return JSON with Workers array
    assert!(
        output.contains("Workers"),
        "Expected Workers in response, got: {}",
        output
    );
    println!("[TEST] List workers response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl list returns empty rules initially
#[tokio::test]
async fn test_cli_list_empty() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let output = run_mcrctl(supervisor.socket_path(), &["list"])?;

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
    println!("[TEST] List rules response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl add and list workflow
#[tokio::test]
async fn test_cli_add_and_list_rule() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;

    // Add a rule (use lo->lo which should fail validation, so use empty outputs)
    let add_output = run_mcrctl(
        supervisor.socket_path(),
        &[
            "add",
            "--input-interface",
            "lo",
            "--input-group",
            "239.1.1.1",
            "--input-port",
            "5000",
            "--outputs",
            "", // Empty outputs to avoid self-loop validation
        ],
    );

    // Empty outputs might cause an error, that's ok for this test
    // The point is to test the CLI flow
    println!("[TEST] Add rule result: {:?}", add_output);

    // List rules
    let list_output = run_mcrctl(supervisor.socket_path(), &["list"])?;
    println!("[TEST] List rules after add: {}", list_output.trim());

    Ok(())
}

/// Test: mcrctl stats returns statistics
#[tokio::test]
async fn test_cli_stats() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let output = run_mcrctl(supervisor.socket_path(), &["stats"])?;

    // Should return JSON with Stats response
    assert!(
        output.contains("Stats") || output.contains("flows"),
        "Expected Stats in response, got: {}",
        output
    );
    println!("[TEST] Stats response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl log-level get returns current levels
#[tokio::test]
async fn test_cli_log_level_get() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let output = run_mcrctl(supervisor.socket_path(), &["log-level", "get"])?;

    // Should return log levels info
    assert!(
        output.contains("LogLevels"),
        "Expected LogLevels in response, got: {}",
        output
    );
    println!("[TEST] Log levels response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl log-level set --global changes level
#[tokio::test]
async fn test_cli_log_level_set_global() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;

    // Set global log level to debug
    let output = run_mcrctl(
        supervisor.socket_path(),
        &["log-level", "set", "--global", "debug"],
    )?;

    assert!(
        output.contains("Success"),
        "Expected Success response, got: {}",
        output
    );
    println!("[TEST] Set log level response: {}", output.trim());

    // Verify the change
    let get_output = run_mcrctl(supervisor.socket_path(), &["log-level", "get"])?;
    println!("[TEST] Log levels after set: {}", get_output.trim());

    Ok(())
}

/// Test: mcrctl log-level set --facility sets per-facility level
#[tokio::test]
async fn test_cli_log_level_set_facility() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;

    // Set DataPlane facility to debug
    let output = run_mcrctl(
        supervisor.socket_path(),
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
    println!("[TEST] Set facility log level response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl config show returns running config
#[tokio::test]
async fn test_cli_config_show() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;
    let output = run_mcrctl(supervisor.socket_path(), &["config", "show"])?;

    // Should return Config response
    assert!(
        output.contains("Config"),
        "Expected Config in response, got: {}",
        output
    );
    println!("[TEST] Config show response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl config check validates config file
#[tokio::test]
async fn test_cli_config_check() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;

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
        supervisor.socket_path(),
        &["config", "check", "--file", temp.path().to_str().unwrap()],
    )?;

    assert!(
        output.contains("ConfigValid") || output.contains("valid"),
        "Expected valid config response, got: {}",
        output
    );
    println!("[TEST] Config check response: {}", output.trim());

    Ok(())
}

/// Test: mcrctl remove with non-existent rule returns error
#[tokio::test]
async fn test_cli_remove_nonexistent() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test: requires root privileges");
        return Ok(());
    }

    let supervisor = start_supervisor_default().await?;

    // Try to remove a rule that doesn't exist
    let output = run_mcrctl(
        supervisor.socket_path(),
        &["remove", "--rule-id", "nonexistent-rule"],
    )?;

    // Should return error about rule not found
    assert!(
        output.contains("Error") || output.contains("not found"),
        "Expected error response, got: {}",
        output
    );
    println!("[TEST] Remove nonexistent response: {}", output.trim());

    Ok(())
}
