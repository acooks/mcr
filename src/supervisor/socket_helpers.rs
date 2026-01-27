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
    set_recv_buffer_size(recv_socket.as_raw_fd(), RECV_BUFFER_SIZE, Some(logger));

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

/// Linux interface flags (from if.h)
#[allow(dead_code)]
pub mod interface_flags {
    pub const IFF_UP: u32 = 0x1;
    pub const IFF_BROADCAST: u32 = 0x2;
    pub const IFF_LOOPBACK: u32 = 0x8;
    pub const IFF_POINTOPOINT: u32 = 0x10;
    pub const IFF_RUNNING: u32 = 0x40;
    pub const IFF_MULTICAST: u32 = 0x1000;
}

/// Information about an interface's multicast capability
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InterfaceCapability {
    pub name: String,
    pub index: u32,
    pub flags: u32,
    pub is_up: bool,
    pub is_running: bool,
    pub is_multicast: bool,
    pub is_loopback: bool,
    pub is_point_to_point: bool,
}

impl InterfaceCapability {
    /// Check if interface is suitable for multicast forwarding
    #[allow(dead_code)]
    pub fn is_multicast_capable(&self) -> bool {
        self.is_up && self.is_multicast
    }

    /// Get a human-readable reason why multicast is not supported
    pub fn multicast_unsupported_reason(&self) -> Option<String> {
        if !self.is_up {
            Some("interface is down".to_string())
        } else if !self.is_multicast {
            if self.is_point_to_point {
                Some("point-to-point interface without multicast support".to_string())
            } else {
                Some("interface lacks IFF_MULTICAST flag".to_string())
            }
        } else {
            None
        }
    }
}

impl std::fmt::Display for InterfaceCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::new();
        if self.is_up {
            flags.push("UP");
        }
        if self.is_running {
            flags.push("RUNNING");
        }
        if self.is_multicast {
            flags.push("MULTICAST");
        }
        if self.is_loopback {
            flags.push("LOOPBACK");
        }
        if self.is_point_to_point {
            flags.push("POINTOPOINT");
        }
        write!(f, "{}: <{}>", self.name, flags.join(","))
    }
}

/// Get capability information for a specific interface
pub fn get_interface_capability(interface_name: &str) -> Option<InterfaceCapability> {
    use interface_flags::*;

    for iface in pnet::datalink::interfaces() {
        if iface.name == interface_name {
            return Some(InterfaceCapability {
                name: iface.name,
                index: iface.index,
                flags: iface.flags,
                is_up: iface.flags & IFF_UP != 0,
                is_running: iface.flags & IFF_RUNNING != 0,
                is_multicast: iface.flags & IFF_MULTICAST != 0,
                is_loopback: iface.flags & IFF_LOOPBACK != 0,
                is_point_to_point: iface.flags & IFF_POINTOPOINT != 0,
            });
        }
    }
    None
}

/// Check if an interface supports multicast
///
/// Returns Ok(()) if multicast is supported, or an error with details if not.
pub fn check_multicast_capability(interface_name: &str) -> Result<()> {
    match get_interface_capability(interface_name) {
        Some(cap) => {
            if let Some(reason) = cap.multicast_unsupported_reason() {
                Err(anyhow::anyhow!(
                    "Interface {} does not support multicast: {}",
                    interface_name,
                    reason
                ))
            } else {
                Ok(())
            }
        }
        None => Err(anyhow::anyhow!("Interface not found: {}", interface_name)),
    }
}

/// Get all multicast-capable interfaces
#[allow(dead_code)]
pub fn get_multicast_capable_interfaces() -> Vec<InterfaceCapability> {
    use interface_flags::*;

    pnet::datalink::interfaces()
        .into_iter()
        .map(|iface| InterfaceCapability {
            name: iface.name,
            index: iface.index,
            flags: iface.flags,
            is_up: iface.flags & IFF_UP != 0,
            is_running: iface.flags & IFF_RUNNING != 0,
            is_multicast: iface.flags & IFF_MULTICAST != 0,
            is_loopback: iface.flags & IFF_LOOPBACK != 0,
            is_point_to_point: iface.flags & IFF_POINTOPOINT != 0,
        })
        .filter(|cap| cap.is_multicast_capable())
        .collect()
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

// ============================================================================
// Safe socket creation and configuration wrappers
// ============================================================================
//
// These wrappers encapsulate unsafe libc socket operations to:
// - Centralize error handling with consistent messages
// - Eliminate repetitive unsafe blocks throughout the codebase
// - Provide type-safe interfaces for socket configuration
// ============================================================================

/// Socket flags for creation
#[derive(Clone, Copy, Default)]
pub struct SocketFlags {
    pub cloexec: bool,
    pub nonblock: bool,
}

impl SocketFlags {
    pub fn cloexec_nonblock() -> Self {
        Self {
            cloexec: true,
            nonblock: true,
        }
    }

    fn to_libc_flags(self) -> i32 {
        let mut flags = 0;
        if self.cloexec {
            flags |= libc::SOCK_CLOEXEC;
        }
        if self.nonblock {
            flags |= libc::SOCK_NONBLOCK;
        }
        flags
    }
}

/// Create a raw IP socket for a specific protocol (e.g., IGMP=2, PIM=103)
///
/// Returns an OwnedFd that automatically closes on drop.
pub fn create_raw_ip_socket(protocol: i32, flags: SocketFlags) -> Result<std::os::fd::OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | flags.to_libc_flags(),
            protocol,
        )
    };

    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create raw IP socket (protocol {}): {}",
            protocol,
            std::io::Error::last_os_error()
        ));
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Create an AF_PACKET socket for L2 packet capture
///
/// - `sock_type`: Use SOCK_DGRAM to skip ethernet header, SOCK_RAW for full frame
/// - `protocol`: Ethernet protocol (e.g., ETH_P_IP=0x0800, ETH_P_ALL=0x0003)
pub fn create_packet_socket(
    sock_type: i32,
    protocol: u16,
    flags: SocketFlags,
) -> Result<std::os::fd::OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            sock_type | flags.to_libc_flags(),
            protocol.to_be() as i32,
        )
    };

    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create AF_PACKET socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Create a temporary DGRAM socket for ioctl operations
///
/// This socket is typically used for interface configuration (SIOCGIFFLAGS, etc.)
/// and should be closed after the ioctl completes.
pub fn create_ioctl_socket() -> Result<std::os::fd::OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };

    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create DGRAM socket for ioctl: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Set IP_HDRINCL on a raw socket to craft our own IP headers
pub fn set_ip_hdrincl(fd: RawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(anyhow::anyhow!(
            "Failed to set IP_HDRINCL: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Set IP_PKTINFO to receive interface information on incoming packets
pub fn set_ip_pktinfo(fd: RawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(anyhow::anyhow!(
            "Failed to set IP_PKTINFO: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Set PACKET_AUXDATA on an AF_PACKET socket to receive metadata
pub fn set_packet_auxdata(fd: RawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_AUXDATA,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(anyhow::anyhow!(
            "Failed to set PACKET_AUXDATA: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Join a multicast group on a specific interface
///
/// Uses ip_mreqn to specify the interface by index.
pub fn join_multicast_group(
    fd: RawFd,
    group: std::net::Ipv4Addr,
    interface_index: i32,
) -> Result<()> {
    let mreqn = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from(group).to_be(),
        },
        imr_address: libc::in_addr { s_addr: 0 },
        imr_ifindex: interface_index,
    };

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_ADD_MEMBERSHIP,
            &mreqn as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(anyhow::anyhow!(
            "Failed to join multicast group {}: {}",
            group,
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Bind socket to a specific network device
#[allow(dead_code)]
pub fn set_bind_to_device(fd: RawFd, interface: &str) -> Result<()> {
    use std::ffi::CString;

    let iface_cstr = CString::new(interface)
        .map_err(|_| anyhow::anyhow!("Invalid interface name: {}", interface))?;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_cstr.as_ptr() as *const libc::c_void,
            iface_cstr.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(anyhow::anyhow!(
            "Failed to bind to device {}: {}",
            interface,
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Set TCP_NODELAY on a TCP socket
#[allow(dead_code)]
pub fn set_tcp_nodelay(fd: RawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(anyhow::anyhow!(
            "Failed to set TCP_NODELAY: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Set receive buffer size on a socket
///
/// Returns the actual buffer size set by the kernel (may be different from requested).
/// Logs a warning if the requested size couldn't be set.
pub fn set_recv_buffer_size(
    fd: RawFd,
    requested_size: i32,
    logger: Option<&crate::logging::Logger>,
) -> i32 {
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &requested_size as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if result < 0 {
        if let Some(log) = logger {
            log.warning(
                crate::logging::Facility::Supervisor,
                &format!(
                    "Failed to set SO_RCVBUF to {}MB, using system default",
                    requested_size / 1024 / 1024
                ),
            );
        }
        return 0;
    }

    // Read back actual size (kernel may have adjusted it)
    let mut actual_size: i32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut actual_size as *mut _ as *mut libc::c_void,
            &mut len,
        );
    }

    if let Some(log) = logger {
        log.debug(
            crate::logging::Facility::Supervisor,
            &format!(
                "SO_RCVBUF set to {}KB (requested {}MB)",
                actual_size / 1024,
                requested_size / 1024 / 1024
            ),
        );
    }

    actual_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_flags_constants() {
        // Verify flag constants match Linux kernel values
        assert_eq!(interface_flags::IFF_UP, 0x1);
        assert_eq!(interface_flags::IFF_BROADCAST, 0x2);
        assert_eq!(interface_flags::IFF_LOOPBACK, 0x8);
        assert_eq!(interface_flags::IFF_POINTOPOINT, 0x10);
        assert_eq!(interface_flags::IFF_RUNNING, 0x40);
        assert_eq!(interface_flags::IFF_MULTICAST, 0x1000);
    }

    #[test]
    fn test_interface_capability_multicast_capable() {
        use interface_flags::*;

        // UP + MULTICAST = capable
        let cap = InterfaceCapability {
            name: "eth0".to_string(),
            index: 1,
            flags: IFF_UP | IFF_MULTICAST | IFF_RUNNING,
            is_up: true,
            is_running: true,
            is_multicast: true,
            is_loopback: false,
            is_point_to_point: false,
        };
        assert!(cap.is_multicast_capable());
        assert!(cap.multicast_unsupported_reason().is_none());

        // DOWN = not capable
        let cap_down = InterfaceCapability {
            name: "eth1".to_string(),
            index: 2,
            flags: IFF_MULTICAST,
            is_up: false,
            is_running: false,
            is_multicast: true,
            is_loopback: false,
            is_point_to_point: false,
        };
        assert!(!cap_down.is_multicast_capable());
        assert!(cap_down
            .multicast_unsupported_reason()
            .unwrap()
            .contains("down"));

        // UP but no MULTICAST flag = not capable
        let cap_no_mcast = InterfaceCapability {
            name: "tun0".to_string(),
            index: 3,
            flags: IFF_UP | IFF_RUNNING | IFF_POINTOPOINT,
            is_up: true,
            is_running: true,
            is_multicast: false,
            is_loopback: false,
            is_point_to_point: true,
        };
        assert!(!cap_no_mcast.is_multicast_capable());
        assert!(cap_no_mcast
            .multicast_unsupported_reason()
            .unwrap()
            .contains("point-to-point"));
    }

    #[test]
    fn test_interface_capability_display() {
        use interface_flags::*;

        let cap = InterfaceCapability {
            name: "eth0".to_string(),
            index: 1,
            flags: IFF_UP | IFF_MULTICAST | IFF_RUNNING,
            is_up: true,
            is_running: true,
            is_multicast: true,
            is_loopback: false,
            is_point_to_point: false,
        };
        let display = format!("{}", cap);
        assert!(display.contains("eth0"));
        assert!(display.contains("UP"));
        assert!(display.contains("MULTICAST"));
    }

    #[test]
    fn test_get_interface_capability_loopback() {
        // Loopback should always exist
        if let Some(cap) = get_interface_capability("lo") {
            assert!(cap.is_loopback);
            assert!(cap.is_up);
            // Note: Loopback may or may not have IFF_MULTICAST depending on the system
        }
        // If loopback doesn't exist (unlikely), test passes silently
    }

    #[test]
    fn test_get_interface_capability_nonexistent() {
        assert!(get_interface_capability("nonexistent_interface_xyz123").is_none());
    }

    #[test]
    fn test_check_multicast_capability_nonexistent() {
        let result = check_multicast_capability("nonexistent_interface_xyz123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_get_multicast_capable_interfaces() {
        let interfaces = get_multicast_capable_interfaces();
        // All returned interfaces should be multicast capable
        for iface in &interfaces {
            assert!(iface.is_multicast_capable());
        }
    }
}
