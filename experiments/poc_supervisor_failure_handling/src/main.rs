// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Proof-of-Concept: Supervisor Resilience with Exponential Backoff (Automated Test)
//!
//! This binary demonstrates a supervisor's ability to handle failing child
//! processes gracefully by implementing an exponential backoff strategy.
//!
//! ## Problem
//!
//! A supervisor that immediately restarts a persistently failing child can enter
//! a "busy-loop," consuming 100% CPU and potentially destabilizing the system.
//! A robust supervisor must introduce a delay before restarting a failed task,
//! and this delay should increase if the task continues to fail.
//!
//! ## Test Logic
//!
//! This test will:
//! 1. Spawn a "graceful" child and a "failing" child.
//! 2. When the graceful child exits, it is restarted immediately.
//! 3. When the failing child exits, the supervisor waits for a delay before
//!    restarting it. This delay doubles with each consecutive failure for that task.
//! 4. The test terminates successfully after observing a set number of restarts for both children.

use anyhow::Result;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration};

const GOAL: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 200; // Start with a 200ms delay

/// Spawns a child process that runs for 1 second and exits successfully.
fn spawn_graceful_child() -> Result<Child> {
    println!("[Supervisor] Spawning GRACEFUL child (sleep 1)");
    Command::new("sleep").arg("1").spawn().map_err(anyhow::Error::from)
}

/// Spawns a child process that exits immediately with a status code of 1.
fn spawn_failing_child() -> Result<Child> {
    println!("[Supervisor] Spawning FAILING child (exit 1)");
    Command::new("sh").arg("-c").arg("exit 1").spawn().map_err(anyhow::Error::from)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("[Supervisor] Starting test. Goal: Handle {} graceful and {} failing exits.", GOAL, GOAL);

    let mut graceful_child = spawn_graceful_child()?;
    let mut failing_child = spawn_failing_child()?;

    let mut graceful_restarts = 0;
    let mut failure_restarts = 0;
    let mut backoff_duration_ms = INITIAL_BACKOFF_MS;

    loop {
        tokio::select! {
            Ok(status) = graceful_child.wait() => {
                if status.success() {
                    println!("[Supervisor] GRACEFUL child exited successfully as expected.");
                    graceful_restarts += 1;
                } else {
                    println!("[Supervisor] ERROR: GRACEFUL child failed unexpectedly with status: {}", status);
                }
                println!("[Supervisor] Graceful restarts count: {}/{}", graceful_restarts, GOAL);
                graceful_child = spawn_graceful_child()?;
            }

            Ok(status) = failing_child.wait() => {
                if !status.success() {
                    println!("[Supervisor] FAILING child exited with failure as expected (status: {}).", status);
                    failure_restarts += 1;
                } else {
                    println!("[Supervisor] ERROR: FAILING child exited successfully unexpectedly.");
                }
                println!("[Supervisor] Failure restarts count: {}/{}", failure_restarts, GOAL);

                // Exponential backoff
                println!("[Supervisor] Waiting for {}ms before restarting failing child...", backoff_duration_ms);
                sleep(Duration::from_millis(backoff_duration_ms)).await;
                backoff_duration_ms *= 2; // Double the delay for the next failure

                failing_child = spawn_failing_child()?;
            }
        }

        if graceful_restarts >= GOAL && failure_restarts >= GOAL {
            println!("\n[Supervisor] SUCCESS: All restart goals met.");
            println!("[Supervisor] Test finished successfully.");
            graceful_child.kill().await?;
            failing_child.kill().await?;
            break;
        }
    }

    Ok(())
}
