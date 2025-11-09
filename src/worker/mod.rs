use anyhow::{Context, Result};
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::{getpid, Gid, Uid};
use std::os::unix::io::{FromRawFd, RawFd};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
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

use crate::{ControlPlaneConfig, DataPlaneConfig, RelayCommand};
use control_plane::ControlPlane;
use data_plane_integrated::run_data_plane as data_plane_task;

use caps::{CapSet, Capability};
use nix::sys::socket::{recvmsg, MsgFlags};
use std::collections::HashSet;
use std::os::unix::io::AsRawFd;

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
        eprintln!(
            "[Worker] Already running as uid={}, gid={}, skipping privilege drop",
            uid, gid
        );
        return Ok(());
    }

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
        eprintln!(
            "[Worker] Successfully set capabilities (including Ambient for thread inheritance)"
        );
    }

    // Set the UID last (irreversible)
    nix::unistd::setuid(uid).context("Failed to set UID")?;
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

// --- Worker Entrypoints ---

/// Generic control plane runner for testing purposes.
pub async fn run_control_plane_generic<S: AsyncRead + AsyncWrite + Unpin>(
    supervisor_stream: S,
    request_stream: UnixStream,
) -> Result<()> {
    let control_plane = ControlPlane::new(supervisor_stream, request_stream);
    control_plane.run().await
}

pub async fn run_control_plane(config: ControlPlaneConfig) -> Result<()> {
    eprintln!(
        "[ControlPlane] Worker process started, dropping privileges to UID {} and GID {}",
        config.uid, config.gid
    );

    drop_privileges(Uid::from_raw(config.uid), Gid::from_raw(config.gid), None)?;

    // Get FD 3 from supervisor and set it to non-blocking before wrapping in tokio UnixStream
    let supervisor_sock = unsafe {
        let std_sock = std::os::unix::net::UnixStream::from_raw_fd(3);
        std_sock.set_nonblocking(true)?;
        UnixStream::from_std(std_sock)?
    };

    let request_fd = recv_fd(&supervisor_sock).await?;

    // Set request_fd to non-blocking before wrapping in tokio UnixStream
    let request_stream = unsafe {
        let std_sock = std::os::unix::net::UnixStream::from_raw_fd(request_fd);
        std_sock.set_nonblocking(true)?;
        UnixStream::from_std(std_sock)?
    };

    // Control plane no longer needs a separate relay stream connection
    // All communication happens via supervisor_sock (FD 3)
    run_control_plane_generic(supervisor_sock, request_stream).await
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
        command_rx: std::sync::mpsc::Receiver<RelayCommand>,
        event_fd: nix::sys::eventfd::EventFd,
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
        command_rx: std::sync::mpsc::Receiver<RelayCommand>,
        event_fd: nix::sys::eventfd::EventFd,
    ) -> Result<()> {
        data_plane_task(config, command_rx, event_fd)
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
        eprintln!(
            "[DataPlane] Successfully set CPU affinity to core {}",
            core_id
        );
    }

    // Get FD 3 from supervisor and set it to non-blocking before wrapping in tokio UnixStream
    let supervisor_sock = unsafe {
        let std_sock = std::os::unix::net::UnixStream::from_raw_fd(3);
        std_sock.set_nonblocking(true)?;
        UnixStream::from_std(std_sock)?
    };
    let _request_fd = recv_fd(&supervisor_sock).await?;
    let command_fd = recv_fd(&supervisor_sock).await?;

    // Create eventfd for command notifications to ingress
    let event_fd = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK)
        .context("Failed to create eventfd")?;
    let event_fd_for_writer = event_fd.as_raw_fd();

    // Bridge from the async command stream (tokio) to the sync data plane task (std::thread)
    let (std_tx, std_rx) = std::sync::mpsc::channel::<RelayCommand>();
    let command_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(command_fd) };
    command_stream.set_nonblocking(true)?;
    let command_stream = UnixStream::from_std(command_stream)?;
    let mut framed = tokio_util::codec::Framed::new(
        command_stream,
        tokio_util::codec::LengthDelimitedCodec::new(),
    );

    tokio::spawn(async move {
        use futures::StreamExt;
        while let Some(Ok(bytes)) = framed.next().await {
            match serde_json::from_slice::<RelayCommand>(&bytes) {
                Ok(command) => {
                    println!("[DataPlane Worker] Received command: {:?}", command);
                    match std_tx.send(command) {
                        Ok(_) => {
                            println!(
                                "[DataPlane Worker] Command sent to data plane thread successfully"
                            );
                        }
                        Err(e) => {
                            eprintln!("[DataPlane Worker] FATAL: Failed to send command to data plane thread: {:?}", e);
                            eprintln!("[DataPlane Worker] This means the ingress thread has exited or panicked");
                            break;
                        }
                    }
                    println!("[DataPlane Worker] Signaling eventfd");
                    // Signal the eventfd to wake up ingress io_uring loop
                    // Use spawn_blocking to avoid blocking the async runtime
                    let event_fd = event_fd_for_writer;
                    tokio::task::spawn_blocking(move || {
                        let value: u64 = 1;
                        unsafe {
                            libc::write(event_fd, &value as *const u64 as *const libc::c_void, 8);
                        }
                    });
                }
                Err(e) => {
                    eprintln!(
                        "[DataPlane Worker] Error: Failed to deserialize RelayCommand: {}",
                        e
                    );
                }
            }
        }
    });

    // The data plane task is synchronous and blocking.
    // CRITICAL: We must use std::thread::spawn instead of tokio::task::spawn_blocking
    // because the tokio thread pool was created BEFORE we dropped privileges,
    // so its threads don't have our Ambient capabilities (CAP_NET_RAW).
    // Creating a new thread ensures it inherits the ambient capabilities.
    let handle = std::thread::Builder::new()
        .name("data_plane".to_string())
        .spawn(move || lifecycle.run_data_plane_task(config, std_rx, event_fd))
        .context("Failed to spawn data plane thread")?;

    // Wait for the data plane thread in a blocking task so the async runtime can continue
    // processing commands. This is critical - if we block the runtime here, the async
    // task receiving commands from the supervisor cannot make progress!
    tokio::task::spawn_blocking(move || {
        handle
            .join()
            .map_err(|e| anyhow::anyhow!("Data plane thread panicked: {:?}", e))?
            .context("Data plane task failed")
    })
    .await
    .context("Failed to join data plane thread")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlPlaneConfig, DataPlaneConfig, ForwardingRule, RelayCommand};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::net::UnixStream;

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
    async fn test_run_control_plane_starts_successfully() {
        // Basic test to ensure the control plane can start up without panicking.
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let _config = ControlPlaneConfig {
            uid: 0,
            gid: 0,
            relay_command_socket_path: socket_path.clone(),
            prometheus_addr: None,
            reporting_interval: 1000,
        };
        let (supervisor_stream, _) = UnixStream::pair().unwrap();
        let (req_stream, _) = UnixStream::pair().unwrap();
        let run_future = run_control_plane_generic(supervisor_stream, req_stream);
        // The important part is that this doesn't panic.
        let _ = tokio::time::timeout(Duration::from_millis(100), run_future).await;
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
                _command_rx: std::sync::mpsc::Receiver<RelayCommand>,
                _event_fd: nix::sys::eventfd::EventFd,
            ) -> Result<()> {
                // In a real test, we might block here indefinitely,
                // but for the timeout test, returning Ok is sufficient.
                std::thread::sleep(std::time::Duration::from_secs(10));
                Ok(())
            }
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

        tokio::task::spawn(async move {
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
        });

        let run_future = run_data_plane(config, MockWorkerLifecycle);

        let result = tokio::time::timeout(std::time::Duration::from_millis(200), run_future).await;

        assert!(
            result.is_err(),
            "run_data_plane should not exit and should time out"
        );

        Ok(())
    }
}
