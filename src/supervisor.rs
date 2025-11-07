use anyhow::{Context, Result};
use nix::unistd::{Group, User};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::{ForwardingRule, RelayCommand};

const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 16000; // 16 seconds

// --- Production Spawning Logic ---

fn get_production_base_command() -> Command {
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");
    Command::new(current_exe)
}

pub fn spawn_control_plane_worker(
    uid: u32,
    gid: u32,
    relay_command_socket_path: PathBuf,
    prometheus_addr: Option<std::net::SocketAddr>,
) -> Result<Child> {
    println!("[Supervisor] Spawning Control Plane worker.");
    let mut command = get_production_base_command();
    command
        .arg("worker")
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path);

    if let Some(addr) = prometheus_addr {
        command.arg("--prometheus-addr").arg(addr.to_string());
    }

    command.spawn().map_err(anyhow::Error::from)
}

pub fn spawn_data_plane_worker(
    core_id: u32,
    uid: u32,
    gid: u32,
    relay_command_socket_path: PathBuf,
) -> Result<Child> {
    println!(
        "[Supervisor] Spawning Data Plane worker for core {}.",
        core_id
    );
    let mut command = get_production_base_command();
    command
        .arg("worker")
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .arg("--core-id")
        .arg(core_id.to_string())
        .arg("--data-plane")
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path);
    command.spawn().map_err(anyhow::Error::from)
}

// --- Supervisor Core Logic ---

pub async fn run(
    user: &str,
    group: &str,
    prometheus_addr: Option<std::net::SocketAddr>,
    _relay_command_rx: mpsc::Receiver<RelayCommand>,
    relay_command_socket_path: PathBuf,
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
) -> Result<()> {
    let uid = User::from_name(user)
        .with_context(|| format!("User '{}' not found", user))?
        .map(|u| u.uid.as_raw())
        .with_context(|| format!("User '{}' not found", user))?;
    let gid = Group::from_name(group)
        .with_context(|| format!("Group '{}' not found", group))?
        .map(|g| g.gid.as_raw())
        .with_context(|| format!("Group '{}' not found", group))?;

    let cp_socket_path = relay_command_socket_path.clone();
    let dp_socket_path = relay_command_socket_path.clone();

    run_generic(
        move || spawn_control_plane_worker(uid, gid, cp_socket_path.clone(), prometheus_addr),
        move || spawn_data_plane_worker(0, uid, gid, dp_socket_path.clone()),
        _relay_command_rx,
        relay_command_socket_path,
        master_rules,
    )
    .await
}

pub async fn run_generic<F, G>(
    mut spawn_cp: F,
    mut spawn_dp: G,
    _relay_command_rx: mpsc::Receiver<RelayCommand>,
    relay_command_socket_path: PathBuf,
    master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
) -> Result<()>
where
    F: FnMut() -> Result<Child>,
    G: FnMut() -> Result<Child>,
{
    println!("[Supervisor] Starting.");

    if relay_command_socket_path.exists() {
        std::fs::remove_file(&relay_command_socket_path)?;
    }

    let listener = UnixListener::bind(&relay_command_socket_path)?;

    let mut cp_child = spawn_cp()?;
    let mut dp_child = spawn_dp()?;

    let mut cp_backoff_ms = INITIAL_BACKOFF_MS;
    let mut dp_backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        tokio::select! {
            Ok(status) = cp_child.wait() => {
                if status.success() {
                    println!("[Supervisor] Control Plane worker exited gracefully. Restarting immediately.");
                    cp_backoff_ms = INITIAL_BACKOFF_MS;
                } else {
                    println!("[Supervisor] Control Plane worker failed (status: {}). Restarting after {}ms.", status, cp_backoff_ms);
                    sleep(Duration::from_millis(cp_backoff_ms)).await;
                    cp_backoff_ms = (cp_backoff_ms * 2).min(MAX_BACKOFF_MS);
                }
                cp_child = spawn_cp()?;
            }

            Ok(status) = dp_child.wait() => {
                if status.success() {
                    println!("[Supervisor] Data Plane worker exited gracefully. Restarting immediately.");
                    dp_backoff_ms = INITIAL_BACKOFF_MS;
                } else {
                    println!("[Supervisor] Data Plane worker failed (status: {}). Restarting after {}ms.", status, dp_backoff_ms);
                    sleep(Duration::from_millis(dp_backoff_ms)).await;
                    dp_backoff_ms = (dp_backoff_ms * 2).min(MAX_BACKOFF_MS);
                }
                dp_child = spawn_dp()?;
            }

            Ok((mut stream, _)) = listener.accept() => {
                let mut buffer = Vec::new();
                if stream.read_to_end(&mut buffer).await.is_err() {
                    eprintln!("[Supervisor] Failed to read command from control plane worker.");
                    continue;
                }
                let command: Result<RelayCommand, _> = serde_json::from_slice(&buffer);
                match command {
                    Ok(cmd) => {
                        match cmd {
                            RelayCommand::AddRule(rule) => {
                                println!("[Supervisor] Adding rule: {}", rule.rule_id);
                                master_rules.lock().unwrap().insert(rule.rule_id.clone(), rule);
                            }
                            RelayCommand::RemoveRule { rule_id } => {
                                println!("[Supervisor] Removing rule: {}", rule_id);
                                master_rules.lock().unwrap().remove(&rule_id);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Supervisor] Failed to deserialize RelayCommand: {}", e);
                    }
                }
            }
        }
    }
}

// --- Test-Specific Spawning Logic ---

#[cfg(feature = "integration_test")]
pub fn spawn_dummy_worker(_relay_command_socket_path: PathBuf) -> Result<Child> {
    let mut command = Command::new("sleep");
    command.arg("30");
    command.spawn().map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::time::Instant;

    fn spawn_failing_worker() -> Result<Child> {
        let mut command = Command::new("sh");
        command.arg("-c").arg("exit 1");
        command.spawn().map_err(anyhow::Error::from)
    }

    fn spawn_sleeping_worker() -> Result<Child> {
        let mut command = Command::new("sleep");
        command.arg("30");
        command.spawn().map_err(anyhow::Error::from)
    }

    #[tokio::test]
    async fn test_supervisor_restarts_cp_worker_with_backoff() {
        let cp_spawn_count = Arc::new(Mutex::new(0));
        let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));

        let cp_spawn_count_clone = cp_spawn_count.clone();
        let cp_spawn_times_clone = cp_spawn_times.clone();
        let _spawn_cp = move || {
            *cp_spawn_count_clone.lock().unwrap() += 1;
            cp_spawn_times_clone.lock().unwrap().push(Instant::now());
            spawn_failing_worker()
        };

        let _spawn_dp = || spawn_sleeping_worker();

        let socket_path = PathBuf::from(format!(
            "/tmp/test_supervisor_{}.sock",
            uuid::Uuid::new_v4()
        ));
        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));

        let supervisor_task = tokio::spawn(run_generic(
            _spawn_cp,
            _spawn_dp,
            rx,
            socket_path.clone(),
            master_rules.clone(),
        ));

        // Allow time for a few restarts
        tokio::time::sleep(Duration::from_millis(INITIAL_BACKOFF_MS * 4)).await;

        supervisor_task.abort();
        let _ = std::fs::remove_file(&socket_path);

        // Verify spawn counts
        assert!(*cp_spawn_count.lock().unwrap() > 1);

        // Verify backoff
        let cp_times = cp_spawn_times.lock().unwrap();
        let cp_interval1 = cp_times[1].duration_since(cp_times[0]).as_millis() as u64;
        assert!(
            (INITIAL_BACKOFF_MS..INITIAL_BACKOFF_MS * 2).contains(&cp_interval1),
            "CP backoff interval1 was {}",
            cp_interval1
        );
    }

    #[tokio::test]
    async fn test_supervisor_restarts_dp_worker_with_backoff() {
        let dp_spawn_count = Arc::new(Mutex::new(0));
        let dp_spawn_times = Arc::new(Mutex::new(Vec::new()));

        let _spawn_cp = || spawn_sleeping_worker();

        let dp_spawn_count_clone = dp_spawn_count.clone();
        let dp_spawn_times_clone = dp_spawn_times.clone();
        let _spawn_dp = move || {
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
            _spawn_cp,
            _spawn_dp,
            rx,
            socket_path.clone(),
            master_rules.clone(),
        ));

        // Allow time for a few restarts
        tokio::time::sleep(Duration::from_millis(INITIAL_BACKOFF_MS * 4)).await;

        supervisor_task.abort();
        let _ = std::fs::remove_file(&socket_path);

        // Verify spawn counts
        assert!(*dp_spawn_count.lock().unwrap() > 1);

        // Verify backoff
        let dp_times = dp_spawn_times.lock().unwrap();
        let dp_interval1 = dp_times[1].duration_since(dp_times[0]).as_millis() as u64;
        assert!(
            (INITIAL_BACKOFF_MS..INITIAL_BACKOFF_MS * 2).contains(&dp_interval1),
            "DP backoff interval1 was {}",
            dp_interval1
        );
    }

    #[tokio::test]
    async fn test_supervisor_handles_relay_commands() {
        let _spawn_cp = || spawn_sleeping_worker();
        let _spawn_dp = || spawn_sleeping_worker();

        let socket_path = PathBuf::from(format!(
            "/tmp/test_supervisor_{}.sock",
            uuid::Uuid::new_v4()
        ));
        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));

        let supervisor_task = tokio::spawn(run_generic(
            _spawn_cp,
            _spawn_dp,
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
        let add_rule_cmd = RelayCommand::AddRule(ForwardingRule {
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
        let remove_rule_cmd = RelayCommand::RemoveRule {
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

    async fn send_command_to_supervisor(
        socket_path: &PathBuf,
        command: RelayCommand,
    ) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;

        let mut stream = UnixStream::connect(socket_path).await?;
        let command_bytes = serde_json::to_vec(&command)?;
        stream.write_all(&command_bytes).await?;
        Ok(())
    }

    fn spawn_once_gracefully_then_fail(spawn_count: Arc<Mutex<u32>>) -> Result<Child> {
        let mut count = spawn_count.lock().unwrap();
        *count += 1;
        let mut command = Command::new("sh");
        if *count == 1 {
            // First spawn exits gracefully
            command.arg("-c").arg("exit 0");
        } else {
            // Subsequent spawns fail
            command.arg("-c").arg("exit 1");
        }
        command.spawn().map_err(anyhow::Error::from)
    }

    #[tokio::test]
    async fn test_supervisor_resets_backoff_on_graceful_exit() {
        let cp_spawn_count = Arc::new(Mutex::new(0));
        let cp_spawn_times = Arc::new(Mutex::new(Vec::new()));

        let cp_spawn_count_clone = cp_spawn_count.clone();
        let cp_spawn_times_clone = cp_spawn_times.clone();
        let _spawn_cp = move || {
            cp_spawn_times_clone.lock().unwrap().push(Instant::now());
            spawn_once_gracefully_then_fail(cp_spawn_count_clone.clone())
        };

        let _spawn_dp = || spawn_sleeping_worker();

        let socket_path = PathBuf::from(format!(
            "/tmp/test_supervisor_{}.sock",
            uuid::Uuid::new_v4()
        ));
        let (_tx, rx) = mpsc::channel(10);
        let master_rules = Arc::new(Mutex::new(HashMap::new()));

        let supervisor_task = tokio::spawn(run_generic(
            _spawn_cp,
            _spawn_dp,
            rx,
            socket_path.clone(),
            master_rules.clone(),
        ));

        // Allow time for the graceful exit, immediate restart, and one backoff failure
        tokio::time::sleep(Duration::from_millis(INITIAL_BACKOFF_MS * 2)).await;

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
            immediate_restart_interval < INITIAL_BACKOFF_MS,
            "Restart after graceful exit should be immediate, but was {}ms",
            immediate_restart_interval
        );

        // Interval after the first failure (following the graceful one) should be the initial backoff
        let first_backoff_interval = cp_times[2].duration_since(cp_times[1]).as_millis() as u64;
        assert!(
            (INITIAL_BACKOFF_MS..INITIAL_BACKOFF_MS * 2).contains(&first_backoff_interval),
            "First backoff interval after reset was incorrect: {}ms",
            first_backoff_interval
        );
    }
}
