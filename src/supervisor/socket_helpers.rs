// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Socket creation and file descriptor passing helpers.
//!
//! These functions create AF_PACKET sockets with CAP_NET_RAW privileges
//! and pass file descriptors to worker processes via SCM_RIGHTS.

use anyhow::{Context, Result};
use nix::sys::socket::{
    sendmsg, socketpair, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use tokio::net::UnixStream;

use crate::logging::{Facility, Logger};

/// Create and configure an AF_PACKET socket bound to a specific interface.
///
/// This function creates the socket with CAP_NET_RAW privileges in the supervisor,
/// then the socket FD can be passed to unprivileged workers via SCM_RIGHTS.
///
/// # Arguments
/// * `interface_name` - Network interface to bind to (e.g., "eth0")
/// * `fanout_group_id` - PACKET_FANOUT group ID for load balancing (0 = disabled)
/// * `logger` - Logger instance for status messages
///
/// # Returns
/// An owned file descriptor for the configured AF_PACKET socket
pub(crate) fn create_af_packet_socket(
    interface_name: &str,
    fanout_group_id: u16,
    logger: &Logger,
) -> Result<std::os::fd::OwnedFd> {
    use socket2::{Domain, Protocol, Socket, Type};

    logger.debug(
        Facility::Supervisor,
        &format!(
            "Creating AF_PACKET socket for interface {} (fanout_group_id={})",
            interface_name, fanout_group_id
        ),
    );

    // Create AF_PACKET socket for receiving
    let recv_socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0x0003)))
        .context("Failed to create AF_PACKET socket")?;

    // Set large receive buffer to prevent drops during traffic bursts.
    // Default system buffer (~212KB) can only hold ~150 packets at 1400 bytes each.
    // At 100k pps, that's only 1.5ms of buffering - not enough for io_uring latency.
    // We request 16MB which gives ~11k packets / ~110ms of burst tolerance.
    // Note: Actual size may be limited by net.core.rmem_max sysctl.
    const RECV_BUFFER_SIZE: i32 = 16 * 1024 * 1024; // 16MB
    unsafe {
        let ret = libc::setsockopt(
            recv_socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &RECV_BUFFER_SIZE as *const _ as *const _,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret < 0 {
            // Log warning but don't fail - system may have lower limits
            logger.warning(
                Facility::Supervisor,
                &format!(
                    "Failed to set SO_RCVBUF to {}MB, using system default",
                    RECV_BUFFER_SIZE / 1024 / 1024
                ),
            );
        } else {
            // Read back actual size (kernel may have adjusted it)
            let mut actual_size: i32 = 0;
            let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;
            libc::getsockopt(
                recv_socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &mut actual_size as *mut _ as *mut _,
                &mut len,
            );
            logger.debug(
                Facility::Supervisor,
                &format!(
                    "AF_PACKET SO_RCVBUF set to {}KB (requested {}MB)",
                    actual_size / 1024,
                    RECV_BUFFER_SIZE / 1024 / 1024
                ),
            );
        }
    }

    // Get interface index
    let iface_index = get_interface_index(interface_name)?;

    // Bind to interface using raw libc bind
    unsafe {
        let sockaddr_ll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: iface_index,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let ret = libc::bind(
            recv_socket.as_raw_fd(),
            &sockaddr_ll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "Failed to bind AF_PACKET socket to {}: {}",
                interface_name,
                std::io::Error::last_os_error()
            ));
        }
    }

    // Configure PACKET_FANOUT if fanout_group_id is non-zero
    if fanout_group_id > 0 {
        let fanout_arg: u32 = (fanout_group_id as u32) | (libc::PACKET_FANOUT_CPU << 16);

        unsafe {
            if libc::setsockopt(
                recv_socket.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_FANOUT,
                &fanout_arg as *const _ as *const _,
                std::mem::size_of::<u32>() as _,
            ) < 0
            {
                return Err(anyhow::anyhow!(
                    "PACKET_FANOUT failed for {}: {}",
                    interface_name,
                    std::io::Error::last_os_error()
                ));
            }
        }
        logger.debug(
            Facility::Supervisor,
            &format!(
                "PACKET_FANOUT configured for {} (group_id={}, mode=CPU)",
                interface_name, fanout_group_id
            ),
        );
    }

    // Set non-blocking
    recv_socket.set_nonblocking(true)?;

    // Convert to OwnedFd
    Ok(std::os::fd::OwnedFd::from(recv_socket))
}

/// Get network interface index by name
pub(crate) fn get_interface_index(interface_name: &str) -> Result<i32> {
    for iface in pnet::datalink::interfaces() {
        if iface.name == interface_name {
            return Ok(iface.index as i32);
        }
    }
    Err(anyhow::anyhow!("Interface not found: {}", interface_name))
}

/// Send a file descriptor to a worker process via SCM_RIGHTS
///
/// # Safety
/// This function uses unsafe FFI to send file descriptors. The caller must ensure:
/// - `sock` is a valid Unix domain socket
/// - `fd` is a valid open file descriptor
pub(crate) async fn send_fd(sock: &UnixStream, fd: RawFd) -> Result<()> {
    let data = [0u8; 1];
    let iov = [std::io::IoSlice::new(&data)];
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    sock.ready(tokio::io::Interest::WRITABLE).await?;
    sock.try_io(tokio::io::Interest::WRITABLE, || {
        sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .map_err(std::io::Error::other)
    })?;

    Ok(())
}

/// Create a socketpair and send one end to the worker, returning the supervisor's end
///
/// This helper reduces duplication when setting up IPC channels with workers.
/// Creates a Unix domain socket pair with CLOEXEC and NONBLOCK flags, then
/// sends the worker's end via file descriptor passing.
pub(crate) async fn create_and_send_socketpair(supervisor_sock: &UnixStream) -> Result<UnixStream> {
    let (supervisor_fd, worker_fd) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )?;

    send_fd(supervisor_sock, worker_fd.into_raw_fd()).await?;

    Ok(UnixStream::from_std(unsafe {
        std::os::unix::net::UnixStream::from_raw_fd(supervisor_fd.into_raw_fd())
    })?)
}
