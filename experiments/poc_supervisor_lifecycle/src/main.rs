//! Proof-of-Concept: Robust Supervisor Process Lifecycle Management (Automated Test)
//!
//! This binary is a self-contained, automated test demonstrating the correct
//! and robust pattern for supervising multiple child processes concurrently
//! using Tokio. It has been refactored from an infinite loop into a test
//! that terminates upon meeting a specific success condition.
//!
//! ## Key Insight
//!
//! The crucial pattern for supervising child processes in Tokio is to use
//! `tokio::process::Command` and await the `child.wait()` future within a
//! `tokio::select!` loop.
//!
//! ## Test Logic
//!
//! This test will:
//! 1. Spawn three distinct child processes with different lifespans.
//! 2. Monitor them concurrently using `tokio::select!`.
//! 3. When a child exits, it is immediately restarted, and its restart counter is incremented.
//! 4. The test successfully completes and terminates when each child has been restarted
//!    at least `RESTART_GOAL` times.

use anyhow::Result;
use tokio::process::{Child, Command};

/// The number of times each child must be restarted for the test to pass.
const RESTART_GOAL: u32 = 2;

/// Spawns a simple child process that exits after a specified duration.
fn spawn_child(id: &str, exit_after_seconds: u64) -> Result<Child> {
    println!("[Supervisor] Spawning child '{}' (will exit in {}s)", id, exit_after_seconds);
    let child = Command::new("sleep")
        .arg(exit_after_seconds.to_string())
        .spawn()?;
    Ok(child)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("[Supervisor] Starting test. Goal: Restart each child {} times.", RESTART_GOAL);

    // Create the initial set of child processes.
    let mut control_plane = spawn_child("ControlPlane", 1)?;
    let mut data_plane_0 = spawn_child("DataPlane-0", 2)?;
    let mut data_plane_1 = spawn_child("DataPlane-1", 3)?;

    // Counters to track restarts for each process.
    let mut cp_restarts = 0;
    let mut dp0_restarts = 0;
    let mut dp1_restarts = 0;

    // Main monitoring loop.
    loop {
        // Concurrently wait for any of the child processes to exit.
        tokio::select! {
            // Branch 1: Monitor the control plane process.
            Ok(status) = control_plane.wait() => {
                println!("[Supervisor] Child 'ControlPlane' exited with status: {}. Restarting...", status);
                control_plane = spawn_child("ControlPlane", 1)?;
                cp_restarts += 1;
                println!("[Supervisor] 'ControlPlane' restart count: {}", cp_restarts);
            }

            // Branch 2: Monitor the first data plane process.
            Ok(status) = data_plane_0.wait() => {
                println!("[Supervisor] Child 'DataPlane-0' exited with status: {}. Restarting...", status);
                data_plane_0 = spawn_child("DataPlane-0", 2)?;
                dp0_restarts += 1;
                println!("[Supervisor] 'DataPlane-0' restart count: {}", dp0_restarts);
            }

            // Branch 3: Monitor the second data plane process.
            Ok(status) = data_plane_1.wait() => {
                println!("[Supervisor] Child 'DataPlane-1' exited with status: {}. Restarting...", status);
                data_plane_1 = spawn_child("DataPlane-1", 3)?;
                dp1_restarts += 1;
                println!("[Supervisor] 'DataPlane-1' restart count: {}", dp1_restarts);
            }
        }

        // Check for the termination condition.
        if cp_restarts >= RESTART_GOAL && dp0_restarts >= RESTART_GOAL && dp1_restarts >= RESTART_GOAL {
            println!("\n[Supervisor] SUCCESS: All children have been restarted at least {} times.", RESTART_GOAL);
            println!("[Supervisor] Test finished successfully.");
            // We must manually kill the last-spawned children to allow the program to exit.
            control_plane.kill().await?;
            data_plane_0.kill().await?;
            data_plane_1.kill().await?;
            break;
        }
    }

    Ok(())
}
