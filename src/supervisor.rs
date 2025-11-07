use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::{ForwardingRule, RelayCommand};

const WORKER_USER: &str = "nobody";
const WORKER_GROUP: &str = "nogroup";
const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 16000; // 16 seconds

// --- Production Spawning Logic ---

fn get_production_base_command() -> Command {
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");
    Command::new(current_exe)
}

pub fn spawn_control_plane_worker(relay_command_socket_path: PathBuf) -> Result<Child> {
    println!("[Supervisor] Spawning Control Plane worker.");
    let mut command = get_production_base_command();
    command
        .arg("worker")
        .arg("--user")
        .arg(WORKER_USER)
        .arg("--group")
        .arg(WORKER_GROUP)
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path);
    command.spawn().map_err(anyhow::Error::from)
}

pub fn spawn_data_plane_worker(core_id: u32, relay_command_socket_path: PathBuf) -> Result<Child> {
    println!(
        "[Supervisor] Spawning Data Plane worker for core {}.",
        core_id
    );
    let mut command = get_production_base_command();
    command
        .arg("worker")
        .arg("--user")
        .arg(WORKER_USER)
        .arg("--group")
        .arg(WORKER_GROUP)
        .arg("--core-id")
        .arg(core_id.to_string())
        .arg("--data-plane")
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path);
    command.spawn().map_err(anyhow::Error::from)
}

// --- Supervisor Core Logic ---

pub async fn run<F, G>(
    mut spawn_cp: F,

    mut spawn_dp: G,

    _relay_command_rx: mpsc::Receiver<RelayCommand>, // This is now unused, will be removed

    relay_command_socket_path: PathBuf,
) -> Result<()>
where
    F: FnMut() -> Result<Child>,

    G: FnMut() -> Result<Child>,
{
    println!("[Supervisor] Starting.");

    let mut master_rules: HashMap<String, ForwardingRule> = HashMap::new();

    // Clean up old socket if it exists

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

            // Monitor the Control Plane worker

            Ok(status) = cp_child.wait() => {

                if status.success() {

                    println!("[Supervisor] Control Plane worker exited gracefully. Restarting immediately.");

                    cp_backoff_ms = INITIAL_BACKOFF_MS; // Reset backoff on success

                } else {

                    println!("[Supervisor] Control Plane worker failed (status: {}). Restarting after {}ms.", status, cp_backoff_ms);

                    sleep(Duration::from_millis(cp_backoff_ms)).await;

                    cp_backoff_ms = (cp_backoff_ms * 2).min(MAX_BACKOFF_MS); // Exponential backoff

                }

                cp_child = spawn_cp()?;

            }



            // Monitor the Data Plane worker

            Ok(status) = dp_child.wait() => {

                if status.success() {

                    println!("[Supervisor] Data Plane worker exited gracefully. Restarting immediately.");

                    dp_backoff_ms = INITIAL_BACKOFF_MS; // Reset backoff on success

                } else {

                    println!("[Supervisor] Data Plane worker failed (status: {}). Restarting after {}ms.", status, dp_backoff_ms);

                    sleep(Duration::from_millis(dp_backoff_ms)).await;

                    dp_backoff_ms = (dp_backoff_ms * 2).min(MAX_BACKOFF_MS); // Exponential backoff

                }

                dp_child = spawn_dp()?;

            }



            // Handle commands from the Control Plane worker via Unix socket

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

                                master_rules.insert(rule.rule_id.clone(), rule);

                                // TODO: Dispatch rule to appropriate worker

                            }

                            RelayCommand::RemoveRule { rule_id } => {

                                println!("[Supervisor] Removing rule: {}", rule_id);

                                master_rules.remove(&rule_id);

                                // TODO: Dispatch removal to appropriate worker

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
    command
        .arg("30");
    command.spawn().map_err(anyhow::Error::from)
}

#[cfg(feature = "integration_test")]
pub fn spawn_dummy_worker_async(_relay_command_socket_path: PathBuf) -> Result<Child> {
    let mut command = Command::new("sleep");
    command
        .arg("30");
    command.spawn().map_err(anyhow::Error::from)
}
