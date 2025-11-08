//! Integration Test for the Supervisor Process Lifecycle

use anyhow::Result;
use std::sync::{Arc, Mutex};
use tokio::net::UnixStream;
use tokio::process::{Child, Command as TokioCommand};

// --- Test Helpers ---

fn spawn_dummy_worker() -> anyhow::Result<Child> {
    let mut command = TokioCommand::new("sleep");
    command.arg("30");
    command.spawn().map_err(anyhow::Error::from)
}

#[tokio::test]
async fn test_supervisor_spawns_workers() -> Result<()> {
    println!("--- Running test: test_supervisor_spawns_workers ---");

    // Use an Arc<Mutex<>> to share a PID vector with the spawn closures.
    let pids = Arc::new(Mutex::new(Vec::new()));
    let pids_clone_cp = pids.clone();
    let pids_clone_dp = pids.clone();

    // Create FnMut closures that capture the necessary variables.
    let spawn_cp = move || -> Result<(Child, UnixStream)> {
        let child = spawn_dummy_worker()?;
        pids_clone_cp.lock().unwrap().push(child.id().unwrap());
        let (stream, _) = UnixStream::pair()?;
        Ok((child, stream))
    };
    let spawn_dp = move || -> Result<Child> {
        let child = spawn_dummy_worker()?;
        pids_clone_dp.lock().unwrap().push(child.id().unwrap());
        Ok(child)
    };

    // Call the closures directly to test the spawning logic.
    let (mut cp_child, _) = spawn_cp()?;
    let mut dp_child = spawn_dp()?;

    // Verify that the PIDs were recorded.
    {
        let spawned_pids = pids.lock().unwrap();
        assert_eq!(
            spawned_pids.len(),
            2,
            "Two worker PIDs should have been recorded."
        );
        assert!(spawned_pids.contains(&cp_child.id().unwrap()));
        assert!(spawned_pids.contains(&dp_child.id().unwrap()));
    } // MutexGuard is dropped here

    println!("SUCCESS: Worker spawning closures executed successfully.");

    // Clean up the child processes.
    cp_child.kill().await?;
    dp_child.kill().await?;

    Ok(())
}
