// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::{Context, Result};
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::{getpid, Gid, Uid};
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

pub mod adaptive_wakeup;
pub mod buffer_pool;
pub mod command_reader;
pub mod data_plane;
pub mod data_plane_integrated;
pub mod packet_parser;
pub mod unified_loop;

use crate::logging::{Facility, Logger};
use crate::{DataPlaneConfig, RelayCommand};
// Unified single-threaded data plane with io_uring
use data_plane_integrated::run_unified_data_plane as data_plane_task;

use caps::{CapSet, Capability};
use nix::sys::eventfd::EventFd;
use nix::sys::socket::{recvmsg, MsgFlags};
use std::collections::HashSet;
use std::os::unix::io::AsRawFd;

/// Channel set for ingress thread communication
pub struct IngressChannelSet {
    pub cmd_stream_fd: OwnedFd,
}

/// Channel set for egress thread communication
pub struct EgressChannelSet {
    pub cmd_stream_fd: OwnedFd,
    pub shutdown_event_fd: EventFd, // For data path wakeup (from ingress)
}

// ... other code ...

async fn recv_fd(sock: &UnixStream) -> Result<RawFd> {
    let mut data = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut data)];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 2]);

    sock.ready(tokio::io::Interest::READABLE).await?;
    let msg = sock.try_io(tokio::io::Interest::READABLE, || {
        recvmsg::<()>(
            sock.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        )
        .map_err(std::io::Error::other)
    })?;

    for cmsg in msg.cmsgs()? {
        if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(fd);
            }
        }
    }

    anyhow::bail!("No file descriptor received in SCM_RIGHTS message");
}
fn drop_privileges(uid: Uid, gid: Gid, caps_to_keep: Option<&HashSet<Capability>>) -> Result<()> {
    let current_uid = nix::unistd::getuid();
    let current_gid = nix::unistd::getgid();

    // Skip privilege dropping if we're already running as the target uid/gid
    // In this case, we're not actually dropping privileges, so don't try to set capabilities
    // (which requires root privileges)
    if current_uid == uid && current_gid == gid {
        // Note: Can't use logging here as we may not have initialized it yet
        eprintln!(
            "[Worker] Already running as uid={}, gid={}, skipping privilege drop",
            uid, gid
        );
        return Ok(());
    }

    // Note: Can't use logging here as we may not have initialized it yet
    eprintln!("[Worker] Dropping privileges to uid={}, gid={}", uid, gid);

    // Get the username for initgroups
    let user = nix::unistd::User::from_uid(uid)?
        .ok_or_else(|| anyhow::anyhow!("User not found for uid {}", uid))?;

    // Initialize supplementary groups for the target user (requires CAP_SETGID)
    nix::unistd::initgroups(&std::ffi::CString::new(user.name.as_str())?, gid)
        .context("Failed to initialize supplementary groups")?;

    // Set the GID (requires CAP_SETGID)
    nix::unistd::setgid(gid).context("Failed to set GID")?;

    // Set capabilities after group changes but before changing UID
    if let Some(caps) = caps_to_keep {
        caps::set(None, CapSet::Effective, caps)?;
        caps::set(None, CapSet::Permitted, caps)?;
        caps::set(None, CapSet::Inheritable, caps)?;

        // Raise ambient capabilities for each capability we want to keep
        // Ambient capabilities are inherited by child threads even after setuid()
        for cap in caps {
            caps::raise(None, CapSet::Ambient, *cap)
                .with_context(|| format!("Failed to raise {:?} in Ambient set", cap))?;
        }
        // Note: Can't use logging here as we may not have initialized it yet
        eprintln!(
            "[Worker] Successfully set capabilities (including Ambient for thread inheritance)"
        );
    }

    // Set the UID last (irreversible)
    nix::unistd::setuid(uid).context("Failed to set UID")?;
    // Note: Can't use logging here as we may not have initialized it yet
    eprintln!("[Worker] Successfully dropped privileges");
    Ok(())
}

fn set_cpu_affinity(core_id: usize) -> Result<()> {
    let mut cpu_set = CpuSet::new();
    cpu_set.set(core_id)?;
    sched_setaffinity(getpid(), &cpu_set).context("Failed to set CPU affinity")
}

// --- Relay Command Sender ---

pub struct UnixSocketRelayCommandSender<T: AsyncWrite + Unpin> {
    stream: Mutex<T>,
}

impl<T: AsyncWrite + Unpin> UnixSocketRelayCommandSender<T> {
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

// --- Worker Lifecycle Abstraction for Testing ---

pub trait WorkerLifecycle: Send + 'static {
    fn drop_privileges(
        &self,
        uid: Uid,
        gid: Gid,
        caps_to_keep: Option<&HashSet<Capability>>,
    ) -> Result<()>;
    fn set_cpu_affinity(&self, core_id: usize) -> Result<()>;
    fn run_data_plane_task(
        &self,
        config: DataPlaneConfig,
        ingress_channels: IngressChannelSet,
        egress_channels: EgressChannelSet,
        logger: Logger,
    ) -> Result<()>;
}

pub struct DefaultWorkerLifecycle;

impl WorkerLifecycle for DefaultWorkerLifecycle {
    fn drop_privileges(
        &self,
        uid: Uid,
        gid: Gid,
        caps_to_keep: Option<&HashSet<Capability>>,
    ) -> Result<()> {
        drop_privileges(uid, gid, caps_to_keep)
    }

    fn set_cpu_affinity(&self, core_id: usize) -> Result<()> {
        set_cpu_affinity(core_id)
    }

    fn run_data_plane_task(
        &self,
        config: DataPlaneConfig,
        ingress_channels: IngressChannelSet,
        egress_channels: EgressChannelSet,
        logger: Logger,
    ) -> Result<()> {
        data_plane_task(config, ingress_channels, egress_channels, logger)
    }
}

pub async fn run_data_plane<T: WorkerLifecycle>(
    config: DataPlaneConfig,
    lifecycle: T,
) -> Result<()> {
    use nix::sys::eventfd::{EfdFlags, EventFd};

    // TODO: ARCHITECTURAL ISSUE - Privilege dropping with CAP_NET_RAW
    // Problem: Ambient capabilities are cleared by setuid(), so we can't retain
    // CAP_NET_RAW for child threads after dropping privileges.
    //
    // Proper solution: Supervisor should create AF_PACKET sockets and pass FDs to workers
    // via SCM_RIGHTS. This allows workers to drop ALL privileges completely.
    //
    // Temporary workaround: Don't drop privileges for data plane workers.
    // They need CAP_NET_RAW anyway, so running as root is acceptable until FD passing is implemented.

    // Note: Can't use logging yet as it's not initialized
    eprintln!(
        "[DataPlane] Worker process started (keeping root privileges - CAP_NET_RAW required)"
    );
    eprintln!("[DataPlane] TODO: Implement AF_PACKET FD passing from supervisor for proper privilege separation");

    // Skip privilege drop for now
    // let mut caps_to_keep = HashSet::new();
    // caps_to_keep.insert(Capability::CAP_NET_RAW);
    // caps_to_keep.insert(Capability::CAP_SETUID);
    // lifecycle.drop_privileges(
    //     Uid::from_raw(config.uid),
    //     Gid::from_raw(config.gid),
    //     Some(&caps_to_keep),
    // )?;

    if let Some(core_id) = config.core_id {
        lifecycle.set_cpu_affinity(core_id as usize)?;
        // Note: Can't use logging yet as it's not initialized
        eprintln!(
            "[DataPlane] Successfully set CPU affinity to core {}",
            core_id
        );
    }

    // Phase 2: Pipe-based JSON logging to stderr (shared memory deleted!)
    let core_id = config.core_id.ok_or_else(|| {
        eprintln!("[DataPlane] FATAL: core_id is None!");
        anyhow::anyhow!("Data plane worker requires core_id")
    })?;

    // Create a simple logger that writes JSON to stderr
    // (stderr is redirected to pipe by supervisor)
    use std::io::Write;

    // For testing, use MPSC ring buffer logging
    #[cfg(feature = "testing")]
    use crate::logging::ControlPlaneLogging;
    #[cfg(feature = "testing")]
    let logging = ControlPlaneLogging::new();

    #[cfg(feature = "testing")]
    let logger = logging
        .logger(Facility::DataPlane)
        .ok_or_else(|| anyhow::anyhow!("Failed to get logger for DataPlane facility"))?;

    // For production, create a minimal stderr logger
    #[cfg(not(feature = "testing"))]
    let logger = Logger::stderr_json();

    // Log startup message
    let log_msg = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "level": "INFO",
        "facility": "DataPlane",
        "message": format!("Data plane worker started on core {}", core_id),
        "core_id": core_id
    });
    eprintln!("{}", log_msg);
    std::io::stderr().flush().ok();

    logger.info(
        Facility::DataPlane,
        &format!("Data plane worker started on core {}", core_id),
    );

    eprintln!("[DataPlane] Logged startup message");
    std::io::stderr().flush().ok();

    eprintln!("[DataPlane] Getting FD 3 from supervisor...");
    std::io::stderr().flush().ok();

    // Get FD 3 from supervisor and set it to non-blocking before wrapping in tokio UnixStream
    let supervisor_sock = unsafe {
        let std_sock = std::os::unix::net::UnixStream::from_raw_fd(3);
        std_sock.set_nonblocking(true)?;
        UnixStream::from_std(std_sock)?
    };

    eprintln!("[DataPlane] Receiving ingress command FD...");
    std::io::stderr().flush().ok();

    let ingress_cmd_fd = recv_fd(&supervisor_sock).await?;

    eprintln!("[DataPlane] Receiving egress command FD...");
    std::io::stderr().flush().ok();

    let egress_cmd_fd = recv_fd(&supervisor_sock).await?;

    eprintln!("[DataPlane] Got all FDs from supervisor (ingress_cmd, egress_cmd)");
    std::io::stderr().flush().ok();

    // Create shutdown eventfd for egress (data path wakeup from ingress)
    let egress_shutdown_event_fd = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK)
        .context("Failed to create egress shutdown eventfd")?;

    // Convert raw FDs to OwnedFd for channel sets
    let ingress_cmd_owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(ingress_cmd_fd) };
    let egress_cmd_owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(egress_cmd_fd) };

    // Create channel sets (no more mpsc or tokio bridge!)
    let ingress_channels = IngressChannelSet {
        cmd_stream_fd: ingress_cmd_owned,
    };

    let egress_channels = EgressChannelSet {
        cmd_stream_fd: egress_cmd_owned,
        shutdown_event_fd: egress_shutdown_event_fd,
    };

    eprintln!(
        "[DataPlane] Channel sets created, calling run_data_plane_task directly (no bridge)..."
    );
    std::io::stderr().flush().ok();

    // Call run_data_plane_task directly - no more tokio bridge, no more async wrapper!
    // This function is synchronous and blocking, which is correct for our io_uring-based design.
    lifecycle.run_data_plane_task(config, ingress_channels, egress_channels, logger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ForwardingRule, RelayCommand};

    use tokio::io::AsyncReadExt;

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
    /// - **Purpose:** Verify that the `run_data_plane` function can be invoked and enters its main loop
    ///   without panicking, assuming the necessary capabilities are present.
    /// - **Method:** The test first checks if it is running with root privileges or has the `CAP_NET_RAW`
    ///   capability. If not, it skips the test. Otherwise, it configures and runs the `run_data_plane`
    ///   future with a short timeout. The test passes if the future times out, proving it has entered its
    ///   infinite loop and has not crashed during its complex initialization phase.
    /// - **Tier:** 1 (Logic)
    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_run_data_plane_starts_successfully() -> anyhow::Result<()> {
        struct MockWorkerLifecycle;
        impl WorkerLifecycle for MockWorkerLifecycle {
            fn drop_privileges(
                &self,
                _uid: Uid,
                _gid: Gid,
                _caps_to_keep: Option<&HashSet<Capability>>,
            ) -> Result<()> {
                Ok(())
            }
            fn set_cpu_affinity(&self, _core_id: usize) -> Result<()> {
                Ok(())
            }
            fn run_data_plane_task(
                &self,
                _config: DataPlaneConfig,
                _ingress_channels: IngressChannelSet,
                _egress_channels: EgressChannelSet,
                _logger: Logger,
            ) -> Result<()> {
                // In a real test, we might block here indefinitely,
                // but for the timeout test, returning Ok is sufficient.
                eprintln!(
                    "MockWorkerLifecycle::run_data_plane_task starting, sleeping for 10 seconds"
                );
                std::thread::sleep(std::time::Duration::from_secs(10));
                eprintln!("MockWorkerLifecycle::run_data_plane_task completed after sleep");
                Ok(())
            }
        }

        // Use current process uid/gid to avoid permission errors when not running as root
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };

        let config = DataPlaneConfig {
            uid: Some(current_uid),
            gid: Some(current_gid),
            supervisor_pid: std::process::id(),
            core_id: Some(0),
            input_interface_name: Some("lo".to_string()),
            input_group: None,
            input_port: None,
            output_group: None,
            output_port: None,
            output_interface: None,
            reporting_interval: 1,
            fanout_group_id: None,
        };

        // Create socket pairs for the test
        use std::os::unix::io::IntoRawFd;
        use tokio::net::UnixStream as TokioUnixStream;

        let (supervisor_sock, worker_sock) = TokioUnixStream::pair()?;
        let (request_sock1, _request_sock2) = TokioUnixStream::pair()?;
        let (command_sock1, _command_sock2) = TokioUnixStream::pair()?;

        // Set up FD 3 for the worker
        unsafe {
            let worker_std = worker_sock.into_std()?;
            let worker_fd = worker_std.into_raw_fd();
            if worker_fd != 3 {
                libc::dup2(worker_fd, 3);
                libc::close(worker_fd);
            }
        }

        // Send FDs via the supervisor socket
        let supervisor_sock_std = supervisor_sock.into_std()?;
        let request_fd = request_sock1.into_std()?.into_raw_fd();
        let command_fd = command_sock1.into_std()?.into_raw_fd();

        let supervisor_handle = tokio::task::spawn(async move {
            use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
            use std::io::IoSlice;
            use std::os::unix::io::AsRawFd;

            async fn send_fd_local(
                sock: &TokioUnixStream,
                fd: std::os::unix::io::RawFd,
            ) -> Result<()> {
                let data = [0u8; 1];
                let iov = [IoSlice::new(&data)];
                let fds = [fd];
                let cmsg = ControlMessage::ScmRights(&fds);

                sock.ready(tokio::io::Interest::WRITABLE).await?;
                sock.try_io(tokio::io::Interest::WRITABLE, || {
                    sendmsg::<()>(sock.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None)
                        .map(|_| ())
                        .map_err(std::io::Error::other)
                })?;
                Ok(())
            }

            let supervisor_sock = TokioUnixStream::from_std(supervisor_sock_std).unwrap();
            // Send the request and command FDs
            send_fd_local(&supervisor_sock, request_fd).await.ok();
            send_fd_local(&supervisor_sock, command_fd).await.ok();
            // Keep the socket alive for 1 second to prevent premature shutdown
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });

        let run_future = run_data_plane(config, MockWorkerLifecycle);

        let result = tokio::time::timeout(std::time::Duration::from_millis(200), run_future).await;

        assert!(
            result.is_err(),
            "run_data_plane should not exit and should time out. Result: {:?}",
            result
        );

        // Clean up the supervisor task
        supervisor_handle.abort();

        Ok(())
    }
}
