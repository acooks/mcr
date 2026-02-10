// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::{Context, Result};
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::{getpid, Gid, Uid};
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

pub mod buffer_pool;
pub mod command_reader;
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
    /// Pre-configured AF_PACKET socket received from supervisor.
    /// This socket is created and configured (bound, fanout set) by the supervisor
    /// with CAP_NET_RAW privileges, allowing the worker to drop all privileges.
    pub af_packet_fd: OwnedFd,
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

    // Retry loop to handle race condition where supervisor hasn't sent FD yet
    loop {
        sock.ready(tokio::io::Interest::READABLE).await?;
        match sock.try_io(tokio::io::Interest::READABLE, || {
            recvmsg::<()>(
                sock.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_buf),
                MsgFlags::empty(),
            )
            .map_err(|e| {
                // Convert nix::errno::Errno to std::io::Error properly
                // so that error kinds like WouldBlock are preserved
                std::io::Error::from_raw_os_error(e as i32)
            })
        }) {
            Ok(msg) => {
                for cmsg in msg.cmsgs()? {
                    if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                        if let Some(&fd) = fds.first() {
                            return Ok(fd);
                        }
                    }
                }
                anyhow::bail!("No file descriptor received in SCM_RIGHTS message");
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Socket not ready yet, wait and retry
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}
fn drop_privileges(uid: Uid, gid: Gid, caps_to_keep: Option<&HashSet<Capability>>) -> Result<()> {
    let current_uid = nix::unistd::getuid();
    let current_gid = nix::unistd::getgid();

    // Skip privilege dropping if we're already running as the target uid/gid
    // In this case, we're not actually dropping privileges, so don't try to set capabilities
    // (which requires root privileges)
    if current_uid == uid && current_gid == gid {
        return Ok(());
    }

    // Get the username for initgroups
    let user = nix::unistd::User::from_uid(uid)?
        .ok_or_else(|| anyhow::anyhow!("User not found for uid {}", uid))?;

    // Initialize supplementary groups for the target user (requires CAP_SETGID)
    nix::unistd::initgroups(&std::ffi::CString::new(user.name.as_str())?, gid)
        .context("Failed to initialize supplementary groups")?;

    // Set the GID (requires CAP_SETGID)
    nix::unistd::setgid(gid).context("Failed to set GID")?;

    if let Some(caps) = caps_to_keep {
        // PR_SET_KEEPCAPS preserves Permitted capabilities across setuid().
        // Without this, setuid(non-root) clears all capability sets.
        unsafe {
            if libc::prctl(libc::PR_SET_KEEPCAPS, 1) != 0 {
                return Err(anyhow::anyhow!("Failed to set PR_SET_KEEPCAPS"));
            }
        }

        // Set UID while keepcaps is active — Permitted set is preserved
        nix::unistd::setuid(uid).context("Failed to set UID")?;

        // Now restrict capabilities to only what we need.
        // After setuid, Effective is cleared but Permitted is kept (due to keepcaps).
        caps::set(None, CapSet::Permitted, caps)?;
        caps::set(None, CapSet::Effective, caps)?;
        caps::set(None, CapSet::Inheritable, caps)?;

        for cap in caps {
            caps::raise(None, CapSet::Ambient, *cap)
                .with_context(|| format!("Failed to raise {:?} in Ambient set", cap))?;
        }

        // Clear keepcaps flag (no longer needed)
        unsafe {
            libc::prctl(libc::PR_SET_KEEPCAPS, 0);
        }
    } else {
        // No capabilities to keep — just drop to target UID
        nix::unistd::setuid(uid).context("Failed to set UID")?;
    }

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

    // AF_PACKET socket is created by the supervisor and passed to us via SCM_RIGHTS.
    // This allows workers to drop ALL privileges after receiving the pre-configured socket.
    // Privilege dropping happens after we receive all FDs from the supervisor.

    if let Some(core_id) = config.core_id {
        lifecycle.set_cpu_affinity(core_id as usize)?;
    }

    let core_id = config
        .core_id
        .ok_or_else(|| anyhow::anyhow!("Data plane worker requires core_id"))?;

    // For testing, use MPSC ring buffer logging
    #[cfg(feature = "testing")]
    use crate::logging::TestLogging;
    #[cfg(feature = "testing")]
    let logging = TestLogging::new();

    #[cfg(feature = "testing")]
    let logger = logging
        .logger(Facility::DataPlane)
        .ok_or_else(|| anyhow::anyhow!("Failed to get logger for DataPlane facility"))?;

    // For production, create a minimal stderr logger
    #[cfg(not(feature = "testing"))]
    let logger = Logger::stderr_json();

    logger.debug(
        Facility::DataPlane,
        &format!("Worker started on core {}", core_id),
    );

    // Get FD 3 from supervisor and set it to non-blocking before wrapping in tokio UnixStream
    let supervisor_sock = unsafe {
        let std_sock = std::os::unix::net::UnixStream::from_raw_fd(3);
        std_sock.set_nonblocking(true)?;
        UnixStream::from_std(std_sock)?
    };

    // Receive FDs from supervisor
    let ingress_cmd_fd = recv_fd(&supervisor_sock).await?;
    let egress_cmd_fd = recv_fd(&supervisor_sock).await?;
    let af_packet_fd = recv_fd(&supervisor_sock).await?;

    // Now that we have the pre-configured AF_PACKET socket from the supervisor,
    // we can safely drop all privileges. The socket is already bound to the
    // interface and has PACKET_FANOUT configured.
    //
    // Always drop privileges to nobody:nobody (uid=65534, gid=65534)
    // This is a standard Linux pattern for unprivileged daemons.
    const NOBODY_UID: u32 = 65534;
    const NOBODY_GID: u32 = 65534;

    // Drop privileges but retain CAP_NET_RAW — needed for ESP egress sockets
    // (create_raw_esp_socket creates SOCK_RAW for protocol 50 on demand).
    // The pre-configured AF_PACKET ingress socket doesn't need capabilities,
    // but ESP rules require creating new raw sockets at runtime.
    let caps_to_keep: HashSet<Capability> =
        [Capability::CAP_NET_RAW, Capability::CAP_NET_BIND_SERVICE]
            .into_iter()
            .collect();
    lifecycle.drop_privileges(
        Uid::from_raw(NOBODY_UID),
        Gid::from_raw(NOBODY_GID),
        Some(&caps_to_keep),
    )?;

    logger.debug(Facility::DataPlane, "Privileges dropped");

    // Create shutdown eventfd for egress (data path wakeup from ingress)
    let egress_shutdown_event_fd = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK)
        .context("Failed to create egress shutdown eventfd")?;

    // Convert raw FDs to OwnedFd for channel sets
    let ingress_cmd_owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(ingress_cmd_fd) };
    let egress_cmd_owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(egress_cmd_fd) };
    let af_packet_owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(af_packet_fd) };

    // Create channel sets (no more mpsc or tokio bridge!)
    let ingress_channels = IngressChannelSet {
        cmd_stream_fd: ingress_cmd_owned,
        af_packet_fd: af_packet_owned,
    };

    let egress_channels = EgressChannelSet {
        cmd_stream_fd: egress_cmd_owned,
        shutdown_event_fd: egress_shutdown_event_fd,
    };

    // Call run_data_plane_task directly - synchronous and blocking (io_uring-based design)
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
            name: None,
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            input_protocol: 17,
            input_source: None,
            outputs: vec![],
            source: crate::RuleSource::Static,
        });

        sender.send(command.clone()).await.unwrap();
        drop(sender); // Drop the sender to close the server_stream

        let mut buffer = Vec::new();
        client_stream.read_to_end(&mut buffer).await.unwrap();

        let received_command: RelayCommand = serde_json::from_slice(&buffer).unwrap();
        assert_eq!(command, received_command);
    }
}
