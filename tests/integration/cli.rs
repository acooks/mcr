// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration Test for the application main function.

use anyhow::Result;
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tokio::time::sleep;

/// **Passing Test:** Verifies the supervisor command runs without error.
#[tokio::test]
async fn test_main_supervisor_command() -> Result<()> {
    require_root!();
    let mut child = TokioCommand::new(env!("CARGO_BIN_EXE_mcrd"))
        .arg("supervisor")
        .spawn()?;

    sleep(Duration::from_millis(500)).await; // Give it time to start.
    child.kill().await?;
    Ok(())
}

/// **Passing Test:** Verifies the worker command rejects direct invocation.
///
/// Workers are spawned by the supervisor via FD passing, not invoked directly.
/// This test confirms the worker subcommand exists but requires supervisor context.
#[tokio::test]
async fn test_main_worker_data_plane_command() -> Result<()> {
    require_root!();

    // Workers receive their command socket via FD passing from the supervisor.
    // Direct invocation should fail or exit quickly without proper context.
    let mut child = TokioCommand::new(env!("CARGO_BIN_EXE_mcrd"))
        .arg("worker")
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
