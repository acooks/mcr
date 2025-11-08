use anyhow::{Context, Result};
use log::info;
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::{getpid, Gid, Uid};
use privdrop::PrivDrop;
use std::collections::HashMap;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

pub mod buffer_pool;
pub mod control_plane;
pub mod data_plane;
pub mod data_plane_integrated;
pub mod egress;
pub mod ingress;
pub mod metrics;
pub mod packet_parser;
pub mod stats;

use crate::{ControlPlaneConfig, DataPlaneConfig, FlowStats, ForwardingRule, RelayCommand};
use control_plane::control_plane_task;
use data_plane_integrated::run_data_plane as data_plane_task;

// --- Common Worker Logic ---

fn drop_privileges(uid: Uid, gid: Gid) -> Result<()> {
    let privs = PrivDrop::default();
    privs
        .user(uid.to_string().as_str())
        .group(gid.to_string().as_str())
        .apply()
        .context("Failed to drop privileges")
}

fn set_cpu_affinity(core_id: usize) -> Result<()> {
    let mut cpu_set = CpuSet::new();
    cpu_set.set(core_id)?;
    sched_setaffinity(getpid(), &cpu_set).context("Failed to set CPU affinity")
}

// --- Relay Command Sender ---

pub struct UnixSocketRelayCommandSender<T> {
    stream: Mutex<T>,
}

impl<T: tokio::io::AsyncWrite + Unpin> UnixSocketRelayCommandSender<T> {
    pub fn new(stream: T) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }

    pub async fn send(&self, command: RelayCommand) -> Result<()> {
        let mut stream = self.stream.lock().await;
        let bytes = serde_json::to_vec(&command)?;
        stream.write_all(&bytes).await?;
        Ok(())
    }
}

// --- Worker Entrypoints ---

pub async fn run_control_plane(config: ControlPlaneConfig) -> Result<()> {
    info!(
        "Worker process started. Attempting to drop privileges to UID '{}' and GID '{}'.",
        config.uid, config.gid
    );
    drop_privileges(Uid::from_raw(config.uid), Gid::from_raw(config.gid))?;
    info!("Successfully dropped privileges.");

    let stream = UnixStream::from_std(unsafe {
        std::os::unix::net::UnixStream::from_raw_fd(config.socket_fd.unwrap())
    })?;
    let shared_flows = Arc::new(Mutex::new(
        HashMap::<String, (ForwardingRule, FlowStats)>::new(),
    ));

    // This sender is for relaying commands to the data plane.
    let data_plane_command_tx = Arc::new(UnixSocketRelayCommandSender::new(
        tokio::net::UnixStream::connect(&config.relay_command_socket_path).await?,
    ));

    control_plane_task(stream, data_plane_command_tx, shared_flows).await?;

    // Loop indefinitely to keep the worker alive.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

pub async fn run_data_plane(config: DataPlaneConfig) -> Result<()> {
    info!(
        "Worker process started. Attempting to drop privileges to UID '{}' and GID '{}'.",
        config.uid, config.gid
    );
    drop_privileges(Uid::from_raw(config.uid), Gid::from_raw(config.gid))?;
    info!("Successfully dropped privileges.");

    if let Some(core_id) = config.core_id {
        set_cpu_affinity(core_id as usize)?;
        info!("Successfully set CPU affinity to core {}.", core_id);
    }

    // The data plane task is synchronous and blocking.
    // We run it on a blocking thread to avoid starving the tokio scheduler.
    tokio::task::spawn_blocking(move || data_plane_task(config))
        .await?
        .context("Data plane task failed")?;

    // Loop indefinitely to keep the worker alive.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
