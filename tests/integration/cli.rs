// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration Test for the application main function.

use anyhow::Result;
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tokio::time::sleep;

/// **Passing Test:** Verifies the supervisor command runs without error.
#[tokio::test]
async fn test_main_supervisor_command() -> Result<()> {
    let mut child = TokioCommand::new(env!("CARGO_BIN_EXE_multicast_relay"))
        .arg("supervisor")
        .spawn()?;

    sleep(Duration::from_millis(500)).await; // Give it time to start.
    child.kill().await?;
    Ok(())
}

/// **Passing Test:** Verifies the control plane worker command runs without error.
#[tokio::test]
async fn test_main_worker_control_plane_command() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test_main_worker_control_plane_command: requires root privileges to drop to 'nobody'.");
        return Ok(());
    }

    let mut child = TokioCommand::new(env!("CARGO_BIN_EXE_multicast_relay"))
        .arg("worker")
        .arg("--user")
        .arg("nobody")
        .arg("--group")
        .arg("nobody")
        .arg("--relay-command-socket-path")
        .arg("/tmp/test_main_cp.sock")
        .spawn()?;

    sleep(Duration::from_millis(500)).await; // Give it time to start.
    child.kill().await?;
    Ok(())
}

/// **Passing Test:** Verifies the data plane worker command runs without error.
#[tokio::test]
async fn test_main_worker_data_plane_command() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping test_main_worker_data_plane_command: requires root privileges to create AF_PACKET socket and drop to 'nobody'.");
        return Ok(());
    }

    let mut child = TokioCommand::new(env!("CARGO_BIN_EXE_multicast_relay"))
        .arg("worker")
        .arg("--user")
        .arg("nobody")
        .arg("--group")
        .arg("nobody")
        .arg("--relay-command-socket-path")
        .arg("/tmp/test_main_dp.sock")
        .arg("--data-plane")
        .arg("--input-interface-name")
        .arg("lo")
        .arg("--input-group")
        .arg("224.0.0.1")
        .arg("--input-port")
        .arg("5000")
        .arg("--output-group")
        .arg("224.0.0.2")
        .arg("--output-port")
        .arg("5001")
        .arg("--output-interface")
        .arg("lo")
        .spawn()?;

    sleep(Duration::from_millis(500)).await; // Give it time to start.
    child.kill().await?;
    Ok(())
}
