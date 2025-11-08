use anyhow::{Context, Result};
use log::info;
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::{getpid, Gid, Uid};

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

use caps::{CapSet, Capability};
use std::collections::HashSet;

// --- Common Worker Logic ---

fn drop_privileges(uid: Uid, gid: Gid, caps_to_keep: Option<&HashSet<Capability>>) -> Result<()> {
    let current_uid = nix::unistd::getuid();
    let current_gid = nix::unistd::getgid();

    // Skip privilege dropping if we're already running as the target uid/gid
    // In this case, we're not actually dropping privileges, so don't try to set capabilities
    // (which requires root privileges)
    if current_uid == uid && current_gid == gid {
        info!(
            "Already running as uid={}, gid={}, skipping privilege drop",
            uid, gid
        );
        return Ok(());
    }

    if let Some(caps) = caps_to_keep {
        caps::set(None, CapSet::Effective, caps)?;
        caps::set(None, CapSet::Permitted, caps)?;
        caps::set(None, CapSet::Inheritable, caps)?;
        info!("Successfully set capabilities.");
    }

    info!("Dropping privileges to uid={}, gid={}", uid, gid);
    nix::unistd::setgroups(&[gid]).context("Failed to set supplementary groups")?;
    nix::unistd::setgid(gid).context("Failed to set GID")?;
    nix::unistd::setuid(uid).context("Failed to set UID")?;
    info!("Successfully dropped privileges.");
    Ok(())
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
    drop_privileges(Uid::from_raw(config.uid), Gid::from_raw(config.gid), None)?;
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
    let mut caps_to_keep = HashSet::new();
    caps_to_keep.insert(Capability::CAP_NET_RAW);

    info!(
        "Worker process started. Attempting to drop privileges to UID '{}' and GID '{}'.",
        config.uid, config.gid
    );
    drop_privileges(
        Uid::from_raw(config.uid),
        Gid::from_raw(config.gid),
        Some(&caps_to_keep),
    )?;
    info!("Successfully dropped privileges and retained CAP_NET_RAW.");

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlPlaneConfig, DataPlaneConfig, ForwardingRule, RelayCommand};
    use std::os::unix::io::IntoRawFd;
    use std::path::PathBuf;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;
    use uuid::Uuid;

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify the serialization and transport of a `RelayCommand` over a Unix socket.
    /// - **Method:** A duplex channel (`tokio::io::duplex`) is used to create an in-memory Unix-like stream.
    ///   A `RelayCommand` is serialized to JSON, sent through the stream by the `UnixSocketRelayCommandSender`,
    ///   and then read and deserialized on the other end. The test asserts that the received command is
    ///   identical to the one that was sent.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    async fn test_unix_socket_relay_command_sender() {
        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        let sender = UnixSocketRelayCommandSender::new(server_stream);

        let command = RelayCommand::AddRule(ForwardingRule {
            rule_id: "test-rule-1".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![],
            dtls_enabled: false,
        });

        sender.send(command.clone()).await.unwrap();
        drop(sender); // Drop the sender to close the server_stream

        let mut buffer = Vec::new();
        client_stream.read_to_end(&mut buffer).await.unwrap();

        let received_command: RelayCommand = serde_json::from_slice(&buffer).unwrap();
        assert_eq!(command, received_command);
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify that the `run_control_plane` function can be invoked and enters its main loop
    ///   without panicking.
    /// - **Method:** The test sets up the necessary configuration, including a mock Unix socket for the supervisor
    ///   connection. It uses the current user's UID/GID to ensure the privilege-dropping logic doesn't fail
    ///   due to lack of permissions during the test run. The `run_control_plane` future is run with a short
    ///   timeout. The test passes if the future times out, which proves it has entered its infinite loop
    ///   and has not crashed.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    #[ignore]
    async fn test_run_control_plane_starts_successfully() -> anyhow::Result<()> {
        // Proposed Implementation:
        // 1.  **Refactor `run_control_plane`:** Modify the `run_control_plane` function
        //     to be generic over its `stream` argument, accepting any type that
        //     implements `tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin`.
        // 2.  **Use In-Memory Stream:** In this test, create an in-memory stream using
        //     `tokio::io::duplex(1024)`. Pass one half to the `run_control_plane`
        //     function.
        // 3.  **Remove File System Dependency:** The `relay_command_socket_path` is also
        //     a file system dependency. The `UnixSocketRelayCommandSender` should also be
        //     made generic to accept any `AsyncWrite` sink. This test can then provide
        //     another duplex stream for that.
        // 4.  **Assert Timeout:** Keep the existing logic that runs the function with a
        //     short timeout. The test passes if the future times out, which proves it
        //     has entered its main loop without crashing. This change makes the test
        //     fully self-contained and removes all side-effects.

        let socket_path = PathBuf::from(format!("/tmp/test_supervisor_{}.sock", Uuid::new_v4()));
        let _listener = UnixListener::bind(&socket_path)?;

        let (_client_stream, task_stream) = tokio::net::UnixStream::pair()?;

        // Use current process uid/gid to avoid permission errors when not running as root
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };

        let config = ControlPlaneConfig {
            uid: current_uid,
            gid: current_gid,
            relay_command_socket_path: socket_path.clone(),
            prometheus_addr: None,
            reporting_interval: 1,
            socket_fd: Some(task_stream.into_std()?.into_raw_fd()),
        };

        let run_future = run_control_plane(config);

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), run_future).await;

        assert!(
            result.is_err(),
            "run_control_plane should not exit and should time out"
        );

        std::fs::remove_file(&socket_path)?;
        Ok(())
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify that the `run_data_plane` function can be invoked and enters its main loop
    ///   without panicking, assuming the necessary capabilities are present.
    /// - **Method:** The test first checks if it is running with root privileges or has the `CAP_NET_RAW`
    ///   capability. If not, it skips the test. Otherwise, it configures and runs the `run_data_plane`
    ///   future with a short timeout. The test passes if the future times out, proving it has entered its
    ///   infinite loop and has not crashed during its complex initialization phase.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    #[ignore]
    async fn test_run_data_plane_starts_successfully() -> anyhow::Result<()> {
        // Proposed Implementation:
        // 1.  **Isolate `drop_privileges` and `set_cpu_affinity`:** These functions are the
        //     primary reason this test requires root. They should be refactored into a
        //     trait (e.g., `WorkerLifecycle`) that can be mocked.
        // 2.  **Mock Dependencies:** The `run_data_plane` function should be made generic
        //     over this new trait. In the test, a mock implementation of the trait would
        //     be provided that simply logs the calls to `drop_privileges` and
        //     `set_cpu_affinity` without actually executing them.
        // 3.  **Isolate `data_plane_task`:** The core data plane logic, which requires
        //     `CAP_NET_RAW`, should also be abstracted behind a trait so it can be
        //     replaced with a mock that does nothing.
        // 4.  **Assert Timeout:** With the privileged operations mocked out, the test can
        //     run as a normal user. The existing timeout assertion remains valid to
        //     ensure the main loop is entered. This change makes the test runnable in a
        //     standard, non-privileged CI environment.

        // This test requires root or CAP_NET_RAW to run the privilege drop and socket setup logic.
        if unsafe { libc::getuid() } != 0 {
            println!("[TEST] Skipping test_run_data_plane_starts_successfully: requires root");
            return Ok(());
        }

        // Use current process uid/gid to avoid permission errors when not running as root
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };

        let config = DataPlaneConfig {
            uid: current_uid,
            gid: current_gid,
            core_id: Some(0),
            prometheus_addr: "127.0.0.1:9002".parse().unwrap(),
            input_interface_name: Some("lo".to_string()),
            input_group: None,
            input_port: None,
            output_group: None,
            output_port: None,
            output_interface: None,
            reporting_interval: 1,
        };

        let run_future = run_data_plane(config);

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), run_future).await;

        assert!(
            result.is_err(),
            "run_data_plane should not exit and should time out"
        );

        Ok(())
    }
}
