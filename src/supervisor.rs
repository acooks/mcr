use anyhow::{Context, Result};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::unistd::{Group, User};
use std::collections::HashMap;
use std::os::unix::io::IntoRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::{UnixListener, UnixStream};
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
) -> Result<(Child, UnixStream)> {
    println!("[Supervisor] Spawning Control Plane worker.");

    // Create a private socket pair for communication.
    let (supervisor_stream, worker_stream) = UnixStream::pair()?;

    // Remove the CLO_EXEC flag to allow inheritance.
    let flags = fcntl(&worker_stream, FcntlArg::F_GETFD)?;
    let mut new_flags = FdFlag::from_bits_truncate(flags);
    new_flags.remove(FdFlag::FD_CLOEXEC);
    fcntl(&worker_stream, FcntlArg::F_SETFD(new_flags))
        .context("Failed to remove CLO_EXEC flag from worker FD")?;

    // The worker no longer needs the listener object, just the FD.
    // We must convert to std stream to get ownership of the FD.
    let owned_worker_fd = worker_stream.into_std()?.into_raw_fd();

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
        .arg(owned_worker_fd.to_string());

    if let Some(addr) = prometheus_addr {
        command.arg("--prometheus-addr").arg(addr.to_string());
    }

    let child = command.spawn()?;
    Ok((child, supervisor_stream))
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
        master_rules,
    )
    .await
}

pub async fn run_generic<F, G>(
    mut spawn_cp: F,
    mut spawn_dp: G,
    _relay_command_rx: mpsc::Receiver<RelayCommand>,
    _master_rules: Arc<Mutex<HashMap<String, ForwardingRule>>>,
) -> Result<()>
where
    F: FnMut() -> Result<(Child, UnixStream)>,
    G: FnMut() -> Result<Child>,
{
    println!("[Supervisor] Starting.");

    let control_socket_path = PathBuf::from("/tmp/multicast_relay_control.sock");
    if control_socket_path.exists() {
        std::fs::remove_file(&control_socket_path)?;
    }
    let listener = UnixListener::bind(&control_socket_path)?;

    let (mut cp_child, mut cp_stream) = spawn_cp()?;
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
                (cp_child, cp_stream) = spawn_cp()?;
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

            Ok((mut client_stream, _)) = listener.accept() => {
                // We can't clone the stream, so we have to move it. This means the supervisor
                // can only handle one client at a time. This is a limitation of this design,
                // but acceptable for the current use case. A more complex implementation
                // would involve a pool of worker connections or a more sophisticated proxy.
                // For now, we will take the stream, and it will be replaced when the worker
                // restarts.
                let mut current_cp_stream = std::mem::replace(&mut cp_stream, UnixStream::pair()?.0);

                tokio::spawn(async move {
                    let (mut client_reader, mut client_writer) = client_stream.split();
                    let (mut cp_reader, mut cp_writer) = current_cp_stream.split();

                    // Forward client -> worker
                    let client_to_worker = tokio::io::copy(&mut client_reader, &mut cp_writer);
                    // Forward worker -> client
                    let worker_to_client = tokio::io::copy(&mut cp_reader, &mut client_writer);

                    tokio::select! {
                        _ = client_to_worker => {},
                        _ = worker_to_client => {},
                    }
                });
            }
        }
    }
}
