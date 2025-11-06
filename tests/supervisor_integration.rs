//! Integration Test for the Supervisor Process Lifecycle

use anyhow::Result;
use multicast_relay::supervisor;
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tokio::time::{sleep, timeout};

/// Finds the PIDs of any child processes running a specific command.
async fn find_child_pids_by_command(command_name: &str) -> Result<Vec<u32>> {
    let output = TokioCommand::new("pgrep")
        .arg("-f") // Match against full command line
        .arg(command_name)
        .output()
        .await?;

    let stdout = String::from_utf8(output.stdout)?;
    let pids: Vec<u32> = stdout
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect();

    Ok(pids)
}

/// **Passing Test:** Verifies the supervisor's resilience by killing a worker and checking that it gets replaced.
#[tokio::test]
async fn test_supervisor_restarts_failed_worker() -> Result<()> {
    println!("--- Running test: test_supervisor_restarts_failed_worker ---");

    // 1. Setup: Run the supervisor logic in the background, injecting the dummy spawn functions.
    let supervisor_task = tokio::spawn(supervisor::run(
        supervisor::spawn_dummy_worker_async,
        supervisor::spawn_dummy_worker,
    ));
    sleep(Duration::from_millis(500)).await; // Give it time to spawn children.

    // The entire test is wrapped in a timeout to prevent hangs.
    let test_body = async {
        // 2. Verification (Initial State): Find the PIDs of the dummy `sleep` workers.
        let initial_worker_pids = find_child_pids_by_command("sleep 30").await?;
        println!("Initial worker PIDs: {:?}", initial_worker_pids);
        assert_eq!(
            initial_worker_pids.len(),
            2,
            "Supervisor should spawn two 'sleep' workers in test mode."
        );

        let worker_to_kill = initial_worker_pids[0];

        // 3. Action: Kill one of the worker processes.
        println!("Killing worker PID {}...", worker_to_kill);
        let kill_status = TokioCommand::new("kill")
            .arg("-9") // SIGKILL
            .arg(worker_to_kill.to_string())
            .status()
            .await?;
        assert!(kill_status.success(), "Failed to kill worker process.");

        // 4. Verification (Final State): Check that the worker is replaced.
        // Give the supervisor time to react.
        println!("Waiting for supervisor to restart the worker...");
        sleep(Duration::from_secs(1)).await;

        let final_worker_pids = find_child_pids_by_command("sleep 30").await?;
        println!("Final worker PIDs: {:?}", final_worker_pids);
        assert_eq!(
            final_worker_pids.len(),
            2,
            "Supervisor should still have two running workers."
        );

        // Verify that the killed worker's PID is no longer present.
        assert!(
            !final_worker_pids.contains(&worker_to_kill),
            "Killed worker PID should not be present after restart."
        );

        println!("SUCCESS: Worker was successfully restarted by the supervisor.");
        Ok(())
    };

    // Run the test body with a timeout.
    match timeout(Duration::from_secs(5), test_body).await {
        Ok(Ok(_)) => {
            // Test succeeded
            supervisor_task.abort();
            Ok(())
        }
        Ok(Err(e)) => {
            // Test logic failed
            supervisor_task.abort();
            Err(e)
        }
        Err(_) => {
            // Test timed out
            supervisor_task.abort();
            anyhow::bail!("Test timed out.")
        }
    }
}
