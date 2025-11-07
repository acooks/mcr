use anyhow::{Context, Result};
use nix::unistd::{chown, Gid, Group, Uid, User};
use std::collections::HashMap;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::PathBuf;
use std::process::Stdio;
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
    worker_socket_path: PathBuf,
    prometheus_addr: Option<std::net::SocketAddr>,
) -> Result<Child> {
    println!("[Supervisor] Spawning Control Plane worker.");

    // Create the listener socket for the worker before spawning it.
    let listener = StdUnixListener::bind(&worker_socket_path)
        .with_context(|| format!("Failed to bind worker socket at {:?}", worker_socket_path))?;
    listener.set_nonblocking(true)?;

    // Change ownership of the socket to the worker user/group.
    chown(
        worker_socket_path.as_os_str(),
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .with_context(|| format!("Failed to chown worker socket at {:?}", worker_socket_path))?;

    let listener_fd = listener.into_raw_fd();
    let worker_stdio = unsafe { Stdio::from_raw_fd(listener_fd) };

    let mut command = get_production_base_command();
    command
        .arg("worker")
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .arg("--relay-command-socket-path")
        .arg(relay_command_socket_path)
        .arg("--socket-fd") // Tell the worker to use the passed FD
        .arg(listener_fd.to_string())
        .stdin(worker_stdio);

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
    let worker_socket_path = PathBuf::from("/tmp/multicast_relay_control.sock");

    run_generic(
        move || {
            spawn_control_plane_worker(
                uid,
                gid,
                cp_socket_path.clone(),
                worker_socket_path.clone(),
                prometheus_addr,
            )
        },
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
