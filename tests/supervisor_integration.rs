//! Integration Test for the Supervisor Process Lifecycle

use anyhow::Result;
use multicast_relay::{supervisor, RelayCommand};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

/// **Passing Test:** Verifies the supervisor's resilience by killing a worker and checking that it gets replaced.
#[tokio::test]
async fn test_supervisor_restarts_failed_worker() -> Result<()> {
    println!("--- Running test: test_supervisor_restarts_failed_worker ---");

    // 1. Setup: Create a unique socket path and PID file for the test run.
    let socket_path = PathBuf::from(format!("/tmp/mcr-test-{}.sock", std::process::id()));
    let pid_file_path = PathBuf::from(format!("/tmp/mcr-pids-{}.txt", std::process::id()));
    let pid_file_path_clone = pid_file_path.clone();

    // The supervisor expects a channel, so we create a dummy one.
    let (_tx, rx) = mpsc::channel::<RelayCommand>(1);

    // Use an Arc<Mutex<>> to share the PID file path with the spawn closures.
    let pids = Arc::new(Mutex::new(Vec::new()));
    let pids_clone_cp = pids.clone();
    let pids_clone_dp = pids.clone();
    let cp_socket_path = socket_path.clone();
    let dp_socket_path = socket_path.clone();

    // Create FnMut closures that capture the necessary variables.
    let spawn_cp = move || -> anyhow::Result<tokio::process::Child> {
        let child = supervisor::spawn_dummy_worker(cp_socket_path.clone())?;
        pids_clone_cp.lock().unwrap().push(child.id().unwrap());
        Ok(child)
    };
    let spawn_dp = move || -> anyhow::Result<tokio::process::Child> {
        let child = supervisor::spawn_dummy_worker(dp_socket_path.clone())?;
        pids_clone_dp.lock().unwrap().push(child.id().unwrap());
        Ok(child)
    };

    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    // Run the supervisor logic in the background.
    let supervisor_task = tokio::spawn(supervisor::run_generic(
        spawn_cp,
        spawn_dp,
        rx,
        socket_path.clone(),
        master_rules.clone(),
    ));
    sleep(Duration::from_millis(500)).await; // Give it time to spawn children.

    // The entire test is wrapped in a timeout to prevent hangs.
    let test_body = async {
        // 2. Verification (Initial State): Get the PIDs from the shared Vec.
        let initial_worker_pids = pids.lock().unwrap().clone();
        println!("Initial worker PIDs: {:?}", initial_worker_pids);
        assert_eq!(
            initial_worker_pids.len(),
            2,
            "Supervisor should spawn two workers in test mode."
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
        println!("Waiting for supervisor to restart the worker...");
        sleep(Duration::from_secs(1)).await;

        let final_worker_pids = pids.lock().unwrap().clone();
        println!("Final worker PIDs: {:?}", final_worker_pids);
        assert_eq!(
            final_worker_pids.len(),
            3, // 2 initial + 1 replacement
            "Supervisor should have spawned a replacement worker."
        );

        // Verify that the killed worker's PID is no longer present in the list of *running* children.
        // This is a bit tricky since we're just recording PIDs. A better check is to see
        // that a *new* PID has been added.
        assert_ne!(
            initial_worker_pids, final_worker_pids,
            "The PID list should have changed after a restart."
        );

        println!("SUCCESS: Worker was successfully restarted by the supervisor.");
        Ok(())
    };

    // Run the test body with a timeout.
    match timeout(Duration::from_secs(5), test_body).await {
        Ok(Ok(_)) => {
            // Test succeeded
            supervisor_task.abort();
            fs::remove_file(&pid_file_path_clone).ok(); // Clean up PID file
            Ok(())
        }
        Ok(Err(e)) => {
            // Test logic failed
            supervisor_task.abort();
            fs::remove_file(&pid_file_path_clone).ok();
            Err(e)
        }
        Err(_) => {
            // Test timed out
            supervisor_task.abort();
            fs::remove_file(&pid_file_path_clone).ok();
            anyhow::bail!("Test timed out.")
        }
    }
}
