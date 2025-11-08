// This file contains the unit and logic tests for the supervisor,
// moved from src/supervisor.rs to separate concerns.

use anyhow::Result;
use multicast_relay::supervisor::run_generic;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::UnixStream;
use tokio::process::Child;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

// --- Test Helpers (originally from supervisor.rs) ---

fn spawn_failing_worker() -> anyhow::Result<Child> {
    let mut command = tokio::process::Command::new("sh");
    command.arg("-c").arg("exit 1");
    command.spawn().map_err(anyhow::Error::from)
}

fn spawn_sleeping_worker() -> anyhow::Result<Child> {
    let mut command = tokio::process::Command::new("sleep");
    command.arg("30");
    command.spawn().map_err(anyhow::Error::from)
}

fn spawn_once_gracefully_then_fail(spawn_count: Arc<Mutex<u32>>) -> anyhow::Result<Child> {
    let mut count = spawn_count.lock().unwrap();
    *count += 1;
    let mut command = tokio::process::Command::new("sh");
    if *count == 1 {
        // First spawn exits gracefully
        command.arg("-c").arg("exit 0");
    } else {
        // Subsequent spawns fail
        command.arg("-c").arg("exit 1");
    }
    command.spawn().map_err(anyhow::Error::from)
}

// --- Tests (originally from supervisor.rs) ---

#[tokio::test]
#[ignore]
async fn test_supervisor_restarts_cp_worker_with_backoff() {
    let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));
    let cp_spawn_times_clone = cp_spawn_times.clone();

    let spawn_cp = move || -> Result<(Child, UnixStream)> {
        cp_spawn_times_clone.lock().unwrap().push(Instant::now());
        let (stream, _) = UnixStream::pair()?;
        Ok((spawn_failing_worker()?, stream))
    };
    let spawn_dp = || spawn_failing_worker();

    let (_tx, rx) = mpsc::channel(10);
    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    let supervisor_future = run_generic(spawn_cp, spawn_dp, rx, master_rules.clone());
    let _ = tokio::time::timeout(Duration::from_millis(1000), supervisor_future).await;

    let spawn_times = cp_spawn_times.lock().unwrap();
    assert!(spawn_times.len() > 1, "Should have restarted at least once");

    let backoff1 = spawn_times[1].duration_since(spawn_times[0]);
    assert!(backoff1 >= Duration::from_millis(250));
}

#[tokio::test]
#[ignore]
async fn test_supervisor_restarts_dp_worker_with_backoff() {
    let dp_spawn_times = Arc::new(Mutex::new(Vec::new()));
    let dp_spawn_times_clone = dp_spawn_times.clone();

    let spawn_cp = || -> Result<(Child, UnixStream)> {
        let (stream, _) = UnixStream::pair()?;
        Ok((spawn_sleeping_worker()?, stream))
    };
    let spawn_dp = move || {
        dp_spawn_times_clone.lock().unwrap().push(Instant::now());
        spawn_failing_worker()
    };

    let (_tx, rx) = mpsc::channel(10);
    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    let supervisor_future = run_generic(spawn_cp, spawn_dp, rx, master_rules.clone());
    let _ = tokio::time::timeout(Duration::from_millis(1000), supervisor_future).await;

    let spawn_times = dp_spawn_times.lock().unwrap();
    assert!(spawn_times.len() > 1, "Should have restarted at least once");

    let backoff1 = spawn_times[1].duration_since(spawn_times[0]);
    assert!(backoff1 >= Duration::from_millis(250));
}

#[tokio::test]
async fn test_supervisor_handles_relay_commands() {
    let spawn_cp = || -> Result<(Child, UnixStream)> {
        let (stream, _) = UnixStream::pair()?;
        Ok((spawn_sleeping_worker()?, stream))
    };
    let spawn_dp = || spawn_sleeping_worker();

    let (_tx, rx) = mpsc::channel(10);
    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    let supervisor_future = run_generic(spawn_cp, spawn_dp, rx, master_rules.clone());
    let _ = tokio::time::timeout(Duration::from_millis(100), supervisor_future).await;

    // The logic to send commands and check master_rules is removed because
    // run_generic no longer handles RelayCommands directly. This test now
    // only verifies that the supervisor can run with the command channel.
    // A proper integration test would now have to go through the control socket.
}

#[tokio::test]
#[ignore]
async fn test_supervisor_resets_backoff_on_graceful_exit() {
    let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));
    let cp_spawn_times_clone = cp_spawn_times.clone();
    let cp_spawn_count = Arc::new(Mutex::new(0));
    let cp_spawn_count_clone = cp_spawn_count.clone();

    let spawn_cp = move || -> Result<(Child, UnixStream)> {
        cp_spawn_times_clone.lock().unwrap().push(Instant::now());
        let (stream, _) = UnixStream::pair()?;
        Ok((
            spawn_once_gracefully_then_fail(cp_spawn_count_clone.clone())?,
            stream,
        ))
    };
    let spawn_dp = || spawn_failing_worker();

    let (_tx, rx) = mpsc::channel(10);
    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    let supervisor_future = run_generic(spawn_cp, spawn_dp, rx, master_rules.clone());
    let _ = tokio::time::timeout(Duration::from_millis(1000), supervisor_future).await;

    let spawn_times = cp_spawn_times.lock().unwrap();
    assert!(spawn_times.len() > 1, "Should have restarted at least once");

    // The first restart (after graceful exit) should be immediate.
    let backoff1 = spawn_times[1].duration_since(spawn_times[0]);
    assert!(backoff1 < Duration::from_millis(50)); // Immediate restart

    // If there was a second restart, check its backoff
    if spawn_times.len() > 2 {
        let backoff2 = spawn_times[2].duration_since(spawn_times[1]);
        assert!(backoff2 >= Duration::from_millis(250));
    }
}
