// This file contains the unit and logic tests for the supervisor,
// moved from src/supervisor.rs to separate concerns.

use multicast_relay::supervisor::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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

async fn send_command_to_supervisor(
    socket_path: &PathBuf,
    command: multicast_relay::RelayCommand,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).await?;
    let command_bytes = serde_json::to_vec(&command)?;
    stream.write_all(&command_bytes).await?;
    Ok(())
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
async fn test_supervisor_restarts_cp_worker_with_backoff() {
    let cp_spawn_count = Arc::new(Mutex::new(0));
    let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));

    let cp_spawn_count_clone = cp_spawn_count.clone();
    let cp_spawn_times_clone = cp_spawn_times.clone();
    let spawn_cp = move || {
        *cp_spawn_count_clone.lock().unwrap() += 1;
        cp_spawn_times_clone.lock().unwrap().push(Instant::now());
        spawn_failing_worker()
    };

    let spawn_dp = || spawn_sleeping_worker();

    let socket_path = PathBuf::from(format!(
        "/tmp/test_supervisor_{}.sock",
        uuid::Uuid::new_v4()
    ));
    let (_tx, rx) = mpsc::channel(10);
    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    let supervisor_task = tokio::spawn(run_generic(
        spawn_cp,
        spawn_dp,
        rx,
        socket_path.clone(),
        master_rules.clone(),
    ));

    // Allow time for a few restarts
    tokio::time::sleep(Duration::from_millis(250 * 4)).await;

    supervisor_task.abort();
    let _ = std::fs::remove_file(&socket_path);

    // Verify spawn counts
    assert!(*cp_spawn_count.lock().unwrap() > 1);

    // Verify backoff
    let cp_times = cp_spawn_times.lock().unwrap();
    let cp_interval1 = cp_times[1].duration_since(cp_times[0]).as_millis() as u64;
    assert!(
        (250..250 * 2).contains(&cp_interval1),
        "CP backoff interval1 was {}",
        cp_interval1
    );
}

#[tokio::test]
async fn test_supervisor_restarts_dp_worker_with_backoff() {
    let dp_spawn_count = Arc::new(Mutex::new(0));
    let dp_spawn_times = Arc::new(Mutex::new(Vec::new()));

    let spawn_cp = || spawn_sleeping_worker();

    let dp_spawn_count_clone = dp_spawn_count.clone();
    let dp_spawn_times_clone = dp_spawn_times.clone();
    let spawn_dp = move || {
        *dp_spawn_count_clone.lock().unwrap() += 1;
        dp_spawn_times_clone.lock().unwrap().push(Instant::now());
        spawn_failing_worker()
    };

    let socket_path = PathBuf::from(format!(
        "/tmp/test_supervisor_{}.sock",
        uuid::Uuid::new_v4()
    ));
    let (_tx, rx) = mpsc::channel(10);
    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    let supervisor_task = tokio::spawn(run_generic(
        spawn_cp,
        spawn_dp,
        rx,
        socket_path.clone(),
        master_rules.clone(),
    ));

    // Allow time for a few restarts
    tokio::time::sleep(Duration::from_millis(250 * 4)).await;

    supervisor_task.abort();
    let _ = std::fs::remove_file(&socket_path);

    // Verify spawn counts
    assert!(*dp_spawn_count.lock().unwrap() > 1);

    // Verify backoff
    let dp_times = dp_spawn_times.lock().unwrap();
    let dp_interval1 = dp_times[1].duration_since(dp_times[0]).as_millis() as u64;
    assert!(
        (250..250 * 2).contains(&dp_interval1),
        "DP backoff interval1 was {}",
        dp_interval1
    );
}

#[tokio::test]
async fn test_supervisor_handles_relay_commands() {
    let spawn_cp = || spawn_sleeping_worker();
    let spawn_dp = || spawn_sleeping_worker();

    let socket_path = PathBuf::from(format!(
        "/tmp/test_supervisor_{}.sock",
        uuid::Uuid::new_v4()
    ));
    let (_tx, rx) = mpsc::channel(10);
    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    let supervisor_task = tokio::spawn(run_generic(
        spawn_cp,
        spawn_dp,
        rx,
        socket_path.clone(),
        master_rules.clone(),
    ));

    // Wait for the supervisor to start and bind the socket by trying to connect in a loop.
    let mut attempts = 0;
    while tokio::net::UnixStream::connect(&socket_path).await.is_err() {
        attempts += 1;
        if attempts > 10 {
            panic!("Supervisor did not start in time");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // --- Test AddRule ---
    let add_rule_cmd = multicast_relay::RelayCommand::AddRule(multicast_relay::ForwardingRule {
        rule_id: "test-rule".to_string(),
        input_interface: "lo".to_string(),
        input_group: "224.0.0.1".parse().unwrap(),
        input_port: 5000,
        outputs: vec![],
        dtls_enabled: false,
    });
    send_command_to_supervisor(&socket_path, add_rule_cmd)
        .await
        .unwrap();

    // Allow time for the supervisor to process the command
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify the rule was added
    assert_eq!(master_rules.lock().unwrap().len(), 1);
    assert!(master_rules.lock().unwrap().contains_key("test-rule"));

    // --- Test RemoveRule ---
    let remove_rule_cmd = multicast_relay::RelayCommand::RemoveRule {
        rule_id: "test-rule".to_string(),
    };
    send_command_to_supervisor(&socket_path, remove_rule_cmd)
        .await
        .unwrap();

    // Allow time for the supervisor to process the command
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify the rule was removed
    assert_eq!(master_rules.lock().unwrap().len(), 0);

    // Cleanup
    supervisor_task.abort();
    let _ = std::fs::remove_file(&socket_path);
}

#[tokio::test]
async fn test_supervisor_resets_backoff_on_graceful_exit() {
    let cp_spawn_count = Arc::new(Mutex::new(0));
    let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));

    let cp_spawn_count_clone = cp_spawn_count.clone();
    let cp_spawn_times_clone = cp_spawn_times.clone();
    let spawn_cp = move || {
        cp_spawn_times_clone.lock().unwrap().push(Instant::now());
        spawn_once_gracefully_then_fail(cp_spawn_count_clone.clone())
    };

    let spawn_dp = || spawn_sleeping_worker();

    let socket_path = PathBuf::from(format!(
        "/tmp/test_supervisor_{}.sock",
        uuid::Uuid::new_v4()
    ));
    let (_tx, rx) = mpsc::channel(10);
    let master_rules = Arc::new(Mutex::new(HashMap::new()));

    let supervisor_task = tokio::spawn(run_generic(
        spawn_cp,
        spawn_dp,
        rx,
        socket_path.clone(),
        master_rules.clone(),
    ));

    // Allow time for the graceful exit, immediate restart, and one backoff failure
    tokio::time::sleep(Duration::from_millis(250 * 2)).await;

    supervisor_task.abort();
    let _ = std::fs::remove_file(&socket_path);

    assert!(
        *cp_spawn_count.lock().unwrap() >= 3,
        "Should have spawned at least 3 times"
    );

    let cp_times = cp_spawn_times.lock().unwrap();
    // Interval after graceful exit should be very short (immediate restart)
    let immediate_restart_interval = cp_times[1].duration_since(cp_times[0]).as_millis() as u64;
    assert!(
        immediate_restart_interval < 250,
        "Restart after graceful exit should be immediate, but was {}ms",
        immediate_restart_interval
    );

    // Interval after the first failure (following the graceful one) should be the initial backoff
    let first_backoff_interval = cp_times[2].duration_since(cp_times[1]).as_millis() as u64;
    assert!(
        (250..250 * 2).contains(&first_backoff_interval),
        "First backoff interval after reset was incorrect: {}ms",
        first_backoff_interval
    );
}
