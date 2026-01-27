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

// ============================================================================
// Interface Cache for O(1) lookups
// ============================================================================

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Default TTL for interface cache (30 seconds)
pub const DEFAULT_INTERFACE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Cached interface information for O(1) lookups
///
/// This cache stores interface information from `pnet::datalink::interfaces()`
/// and provides fast lookups by name or index. The cache automatically refreshes
/// when the TTL expires.
///
/// # Thread Safety
/// The cache uses interior mutability with `RwLock` for thread-safe access.
/// Multiple readers can access the cache concurrently, and writes (refresh)
/// are exclusive.
///
/// # Example
/// ```ignore
/// let cache = InterfaceCache::new();
/// let index = cache.get_index("eth0")?;
/// let cap = cache.get_capability("eth0");
/// ```
pub struct InterfaceCache {
    /// Map from interface name to capability info
    by_name: RwLock<HashMap<String, InterfaceCapability>>,
    /// Map from interface index to interface name
    index_to_name: RwLock<HashMap<u32, String>>,
    /// When the cache was last refreshed
    last_refresh: RwLock<Instant>,
    /// Time-to-live for cached data
    ttl: Duration,
}

impl InterfaceCache {
    /// Create a new interface cache with default TTL (30 seconds)
    pub fn new() -> Self {
        let cache = Self {
            by_name: RwLock::new(HashMap::new()),
            index_to_name: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(Instant::now() - DEFAULT_INTERFACE_CACHE_TTL * 2), // Force initial refresh
            ttl: DEFAULT_INTERFACE_CACHE_TTL,
        };
        cache.refresh_if_stale();
        cache
    }

    /// Create a new interface cache with custom TTL
    pub fn with_ttl(ttl: Duration) -> Self {
        let cache = Self {
            by_name: RwLock::new(HashMap::new()),
            index_to_name: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(Instant::now() - ttl * 2), // Force initial refresh
            ttl,
        };
        cache.refresh_if_stale();
        cache
    }

    /// Check if the cache is stale and needs refresh
    fn is_stale(&self) -> bool {
        let last = self.last_refresh.read().unwrap();
        last.elapsed() >= self.ttl
    }

    /// Refresh the cache if it's stale
    fn refresh_if_stale(&self) {
        if !self.is_stale() {
            return;
        }
        self.refresh();
    }

    /// Force refresh the cache from system interfaces
    pub fn refresh(&self) {
        use interface_flags::*;

        let interfaces = pnet::datalink::interfaces();

        let mut by_name = self.by_name.write().unwrap();
        let mut index_to_name = self.index_to_name.write().unwrap();
        let mut last_refresh = self.last_refresh.write().unwrap();

        by_name.clear();
        index_to_name.clear();

        for iface in interfaces {
            let cap = InterfaceCapability {
                name: iface.name.clone(),
                index: iface.index,
                flags: iface.flags,
                is_up: iface.flags & IFF_UP != 0,
                is_running: iface.flags & IFF_RUNNING != 0,
                is_multicast: iface.flags & IFF_MULTICAST != 0,
                is_loopback: iface.flags & IFF_LOOPBACK != 0,
                is_point_to_point: iface.flags & IFF_POINTOPOINT != 0,
            };

            index_to_name.insert(iface.index, iface.name.clone());
            by_name.insert(iface.name, cap);
        }

        *last_refresh = Instant::now();
    }

    /// Get interface index by name (O(1) lookup)
    ///
    /// Automatically refreshes the cache if stale.
    pub fn get_index(&self, interface_name: &str) -> Result<i32> {
        self.refresh_if_stale();
        let by_name = self.by_name.read().unwrap();
        by_name
            .get(interface_name)
            .map(|cap| cap.index as i32)
            .ok_or_else(|| anyhow::anyhow!("Interface not found: {}", interface_name))
    }

    /// Get interface capability by name (O(1) lookup)
    ///
    /// Automatically refreshes the cache if stale.
    pub fn get_capability(&self, interface_name: &str) -> Option<InterfaceCapability> {
        self.refresh_if_stale();
        let by_name = self.by_name.read().unwrap();
        by_name.get(interface_name).cloned()
    }

    /// Get interface name by index (O(1) lookup)
    ///
    /// Automatically refreshes the cache if stale.
    pub fn get_name_by_index(&self, index: u32) -> Option<String> {
        self.refresh_if_stale();
        let index_to_name = self.index_to_name.read().unwrap();
        index_to_name.get(&index).cloned()
    }

    /// Get all multicast-capable interfaces
    ///
    /// Automatically refreshes the cache if stale.
    pub fn get_multicast_capable(&self) -> Vec<InterfaceCapability> {
        self.refresh_if_stale();
        let by_name = self.by_name.read().unwrap();
        by_name
            .values()
            .filter(|cap| cap.is_multicast_capable())
            .cloned()
            .collect()
    }

    /// Get all cached interfaces
    pub fn get_all(&self) -> Vec<InterfaceCapability> {
        self.refresh_if_stale();
        let by_name = self.by_name.read().unwrap();
        by_name.values().cloned().collect()
    }

    /// Get the number of cached interfaces
    pub fn len(&self) -> usize {
        let by_name = self.by_name.read().unwrap();
        by_name.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the configured TTL
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Get time since last refresh
    pub fn age(&self) -> Duration {
        let last = self.last_refresh.read().unwrap();
        last.elapsed()
    }
}

impl Default for InterfaceCache {
    fn default() -> Self {
        Self::new()
    }
}

// Global interface cache singleton
use std::sync::OnceLock;

static INTERFACE_CACHE: OnceLock<InterfaceCache> = OnceLock::new();

/// Get the global interface cache
///
/// This provides a singleton interface cache that can be used throughout the application.
/// The cache is initialized lazily on first access with the default TTL.
pub fn global_interface_cache() -> &'static InterfaceCache {
    INTERFACE_CACHE.get_or_init(InterfaceCache::new)
}

// ============================================================================
// Interface lookup functions (now with optional caching)
// ============================================================================

/// Get capability information for a specific interface
pub fn get_interface_capability(interface_name: &str) -> Option<InterfaceCapability> {
    pnet::datalink::interfaces()
        .iter()
        .find(|iface| iface.name == interface_name)
        .map(extract_interface_capability)
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
    pnet::datalink::interfaces()
        .iter()
        .map(extract_interface_capability)
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

// ============================================================================
// Error handling helpers (M1 from refactoring roadmap)
// ============================================================================

/// Check a libc function result and convert to anyhow::Result
///
/// This helper reduces repetitive error handling boilerplate across socket
/// option functions. It checks if the result is negative (indicating error)
/// and returns an appropriate error with the OS error message.
///
/// # Arguments
/// * `result` - The return value from a libc function
/// * `context` - Description of the operation for the error message
///
/// # Example
/// ```ignore
/// let result = unsafe { libc::setsockopt(...) };
/// check_libc_result(result, "set IP_HDRINCL")?;
/// ```
fn check_libc_result(result: i32, context: &str) -> Result<()> {
    if result < 0 {
        Err(anyhow::anyhow!(
            "Failed to {}: {}",
            context,
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

// ============================================================================
// Interface capability helper (M2 from refactoring roadmap)
// ============================================================================

/// Extract InterfaceCapability from a pnet NetworkInterface
///
/// This helper centralizes the flag extraction logic that was duplicated
/// in `get_interface_capability()` and `get_multicast_capable_interfaces()`.
fn extract_interface_capability(iface: &pnet::datalink::NetworkInterface) -> InterfaceCapability {
    use interface_flags::*;

    InterfaceCapability {
        name: iface.name.clone(),
        index: iface.index,
        flags: iface.flags,
        is_up: iface.flags & IFF_UP != 0,
        is_running: iface.flags & IFF_RUNNING != 0,
        is_multicast: iface.flags & IFF_MULTICAST != 0,
        is_loopback: iface.flags & IFF_LOOPBACK != 0,
        is_point_to_point: iface.flags & IFF_POINTOPOINT != 0,
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
    check_libc_result(result, "set IP_HDRINCL")
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
    check_libc_result(result, "set IP_PKTINFO")
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
    check_libc_result(result, "set PACKET_AUXDATA")
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
    check_libc_result(result, &format!("join multicast group {}", group))
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
    check_libc_result(result, &format!("bind to device {}", interface))
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
    check_libc_result(result, "set TCP_NODELAY")
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

// ============================================================================
// Eventfd creation
// ============================================================================

/// Create an eventfd for signaling between threads/processes
///
/// Flags:
/// - `nonblock`: Set EFD_NONBLOCK for non-blocking reads
/// - `cloexec`: Set EFD_CLOEXEC to close on exec (recommended)
pub fn create_eventfd(nonblock: bool, cloexec: bool) -> Result<std::os::fd::OwnedFd> {
    let mut flags = 0;
    if nonblock {
        flags |= libc::EFD_NONBLOCK;
    }
    if cloexec {
        flags |= libc::EFD_CLOEXEC;
    }

    let fd = unsafe { libc::eventfd(0, flags) };

    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create eventfd: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

// ============================================================================
// Multicast socket options
// ============================================================================

/// Set the outgoing interface for multicast packets by interface index
///
/// Uses ip_mreqn which allows specifying the interface by index rather than address.
pub fn set_multicast_if_by_index(fd: RawFd, interface_index: i32) -> Result<()> {
    let mreqn = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr { s_addr: 0 },
        imr_address: libc::in_addr { s_addr: 0 },
        imr_ifindex: interface_index,
    };

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &mreqn as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };
    check_libc_result(result, "set IP_MULTICAST_IF")
}

/// Set the outgoing interface for multicast packets by source IP address
///
/// Uses in_addr which specifies the interface by its IP address.
pub fn set_multicast_if_by_addr(fd: RawFd, source_ip: std::net::Ipv4Addr) -> Result<()> {
    let mcast_if = libc::in_addr {
        s_addr: u32::from_ne_bytes(source_ip.octets()),
    };

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &mcast_if as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::in_addr>() as libc::socklen_t,
        )
    };
    check_libc_result(result, &format!("set IP_MULTICAST_IF to {}", source_ip))
}

/// Set the TTL for outgoing multicast packets
pub fn set_multicast_ttl(fd: RawFd, ttl: u8) -> Result<()> {
    let ttl_val: libc::c_int = ttl as libc::c_int;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_TTL,
            &ttl_val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    check_libc_result(result, &format!("set IP_MULTICAST_TTL to {}", ttl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    // ========================================================================
    // SocketFlags tests
    // ========================================================================

    #[test]
    fn test_socket_flags_default() {
        let flags = SocketFlags::default();
        assert!(!flags.cloexec);
        assert!(!flags.nonblock);
        assert_eq!(flags.to_libc_flags(), 0);
    }

    #[test]
    fn test_socket_flags_cloexec_nonblock() {
        let flags = SocketFlags::cloexec_nonblock();
        assert!(flags.cloexec);
        assert!(flags.nonblock);
        let libc_flags = flags.to_libc_flags();
        assert_ne!(libc_flags & libc::SOCK_CLOEXEC, 0);
        assert_ne!(libc_flags & libc::SOCK_NONBLOCK, 0);
    }

    #[test]
    fn test_socket_flags_individual() {
        let cloexec_only = SocketFlags {
            cloexec: true,
            nonblock: false,
        };
        assert_ne!(cloexec_only.to_libc_flags() & libc::SOCK_CLOEXEC, 0);
        assert_eq!(cloexec_only.to_libc_flags() & libc::SOCK_NONBLOCK, 0);

        let nonblock_only = SocketFlags {
            cloexec: false,
            nonblock: true,
        };
        assert_eq!(nonblock_only.to_libc_flags() & libc::SOCK_CLOEXEC, 0);
        assert_ne!(nonblock_only.to_libc_flags() & libc::SOCK_NONBLOCK, 0);
    }

    // ========================================================================
    // Socket creation tests (non-privileged where possible)
    // ========================================================================

    #[test]
    fn test_create_ioctl_socket_success() {
        // create_ioctl_socket doesn't require special privileges
        let result = create_ioctl_socket();
        assert!(
            result.is_ok(),
            "create_ioctl_socket should succeed: {:?}",
            result.err()
        );
        let fd = result.unwrap();
        // Verify it's a valid file descriptor
        assert!(fd.as_raw_fd() >= 0);
    }

    #[test]
    fn test_create_ioctl_socket_returns_owned_fd() {
        // Verify the OwnedFd is properly closed on drop
        let fd_raw;
        {
            let fd = create_ioctl_socket().unwrap();
            fd_raw = fd.as_raw_fd();
            // fd is valid here
            assert!(fd_raw >= 0);
        }
        // After drop, trying to use fd_raw would be invalid
        // We can't easily test this without undefined behavior, but the OwnedFd
        // should have closed it automatically
    }

    // Note: create_raw_ip_socket and create_packet_socket require CAP_NET_RAW
    // These tests are skipped unless running as root
    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_create_raw_ip_socket_igmp() {
        let result = create_raw_ip_socket(libc::IPPROTO_IGMP, SocketFlags::cloexec_nonblock());
        assert!(
            result.is_ok(),
            "create_raw_ip_socket(IGMP) failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_create_raw_ip_socket_pim() {
        let result = create_raw_ip_socket(103, SocketFlags::cloexec_nonblock()); // PIM = 103
        assert!(
            result.is_ok(),
            "create_raw_ip_socket(PIM) failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_create_packet_socket_dgram() {
        let result = create_packet_socket(
            libc::SOCK_DGRAM,
            libc::ETH_P_IP as u16,
            SocketFlags::cloexec_nonblock(),
        );
        assert!(
            result.is_ok(),
            "create_packet_socket(DGRAM) failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_create_packet_socket_raw() {
        let result = create_packet_socket(
            libc::SOCK_RAW,
            libc::ETH_P_ALL as u16,
            SocketFlags::cloexec_nonblock(),
        );
        assert!(
            result.is_ok(),
            "create_packet_socket(RAW) failed: {:?}",
            result.err()
        );
    }

    // ========================================================================
    // Eventfd tests
    // ========================================================================

    #[test]
    fn test_create_eventfd_default() {
        let result = create_eventfd(false, false);
        assert!(result.is_ok(), "create_eventfd failed: {:?}", result.err());
        let fd = result.unwrap();
        assert!(fd.as_raw_fd() >= 0);
    }

    #[test]
    fn test_create_eventfd_nonblock() {
        let result = create_eventfd(true, false);
        assert!(result.is_ok());
        let fd = result.unwrap();

        // Verify nonblock by trying to read - should return EAGAIN
        let mut buf = [0u8; 8];
        let read_result =
            unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, 8) };
        assert_eq!(read_result, -1);
        let err = std::io::Error::last_os_error();
        assert!(
            err.kind() == std::io::ErrorKind::WouldBlock,
            "Expected WouldBlock, got: {:?}",
            err
        );
    }

    #[test]
    fn test_create_eventfd_cloexec() {
        let result = create_eventfd(false, true);
        assert!(result.is_ok());
        // Can't easily verify CLOEXEC without fork/exec, but at least verify success
    }

    #[test]
    fn test_create_eventfd_both_flags() {
        let result = create_eventfd(true, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_eventfd_signal_and_read() {
        let fd = create_eventfd(true, true).expect("create_eventfd failed");

        // Write a value
        let value: u64 = 42;
        let write_result =
            unsafe { libc::write(fd.as_raw_fd(), &value as *const _ as *const libc::c_void, 8) };
        assert_eq!(write_result, 8);

        // Read the value back
        let mut read_value: u64 = 0;
        let read_result = unsafe {
            libc::read(
                fd.as_raw_fd(),
                &mut read_value as *mut _ as *mut libc::c_void,
                8,
            )
        };
        assert_eq!(read_result, 8);
        assert_eq!(read_value, 42);
    }

    #[test]
    fn test_eventfd_semaphore_behavior() {
        // Eventfd without EFD_SEMAPHORE adds values
        let fd = create_eventfd(true, true).expect("create_eventfd failed");

        // Write twice
        let value: u64 = 1;
        unsafe {
            libc::write(fd.as_raw_fd(), &value as *const _ as *const libc::c_void, 8);
            libc::write(fd.as_raw_fd(), &value as *const _ as *const libc::c_void, 8);
        }

        // Read should give sum
        let mut read_value: u64 = 0;
        unsafe {
            libc::read(
                fd.as_raw_fd(),
                &mut read_value as *mut _ as *mut libc::c_void,
                8,
            );
        }
        assert_eq!(read_value, 2); // 1 + 1 = 2
    }

    // ========================================================================
    // Socket option tests (using ioctl socket which doesn't need privileges)
    // ========================================================================

    #[test]
    fn test_set_recv_buffer_size() {
        let fd = create_ioctl_socket().unwrap();
        let actual = set_recv_buffer_size(fd.as_raw_fd(), 1024 * 1024, None);
        // Should return a non-zero value (kernel may adjust the size)
        assert!(actual > 0, "Expected positive buffer size, got {}", actual);
    }

    #[test]
    fn test_set_recv_buffer_size_invalid_fd() {
        // Using invalid fd should return 0 (failure)
        let actual = set_recv_buffer_size(-1, 1024 * 1024, None);
        assert_eq!(actual, 0);
    }

    // Note: Most socket option tests require specific socket types
    // These are skipped unless running with privileges

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_set_ip_hdrincl() {
        let fd = create_raw_ip_socket(libc::IPPROTO_IGMP, SocketFlags::default()).unwrap();
        let result = set_ip_hdrincl(fd.as_raw_fd());
        assert!(result.is_ok(), "set_ip_hdrincl failed: {:?}", result.err());
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_set_ip_pktinfo() {
        let fd = create_raw_ip_socket(libc::IPPROTO_IGMP, SocketFlags::default()).unwrap();
        let result = set_ip_pktinfo(fd.as_raw_fd());
        assert!(result.is_ok(), "set_ip_pktinfo failed: {:?}", result.err());
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_set_packet_auxdata() {
        let fd = create_packet_socket(
            libc::SOCK_DGRAM,
            libc::ETH_P_IP as u16,
            SocketFlags::default(),
        )
        .unwrap();
        let result = set_packet_auxdata(fd.as_raw_fd());
        assert!(
            result.is_ok(),
            "set_packet_auxdata failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_set_multicast_ttl() {
        let fd = create_raw_ip_socket(libc::IPPROTO_IGMP, SocketFlags::default()).unwrap();
        let result = set_multicast_ttl(fd.as_raw_fd(), 1);
        assert!(
            result.is_ok(),
            "set_multicast_ttl failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_set_multicast_if_by_index() {
        let fd = create_raw_ip_socket(libc::IPPROTO_IGMP, SocketFlags::default()).unwrap();
        // Use loopback index (usually 1)
        let lo_index = get_interface_index("lo").unwrap_or(1);
        let result = set_multicast_if_by_index(fd.as_raw_fd(), lo_index);
        assert!(
            result.is_ok(),
            "set_multicast_if_by_index failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_set_multicast_if_by_addr() {
        let fd = create_raw_ip_socket(libc::IPPROTO_IGMP, SocketFlags::default()).unwrap();
        let result = set_multicast_if_by_addr(fd.as_raw_fd(), std::net::Ipv4Addr::LOCALHOST);
        assert!(
            result.is_ok(),
            "set_multicast_if_by_addr failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW (run with: cargo test -- --ignored)"]
    fn test_join_multicast_group() {
        let fd = create_raw_ip_socket(libc::IPPROTO_IGMP, SocketFlags::default()).unwrap();
        let lo_index = get_interface_index("lo").unwrap_or(1);
        // Join 224.0.0.1 (all hosts)
        let result = join_multicast_group(
            fd.as_raw_fd(),
            std::net::Ipv4Addr::new(224, 0, 0, 1),
            lo_index,
        );
        assert!(
            result.is_ok(),
            "join_multicast_group failed: {:?}",
            result.err()
        );
    }

    // ========================================================================
    // Interface lookup tests
    // ========================================================================

    #[test]
    fn test_get_interface_index_loopback() {
        // Loopback should always exist
        let result = get_interface_index("lo");
        assert!(
            result.is_ok(),
            "get_interface_index(lo) failed: {:?}",
            result.err()
        );
        let index = result.unwrap();
        assert!(
            index > 0,
            "Loopback index should be positive, got {}",
            index
        );
    }

    #[test]
    fn test_get_interface_index_nonexistent() {
        let result = get_interface_index("nonexistent_iface_xyz123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

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

    // ========================================================================
    // InterfaceCache tests
    // ========================================================================

    #[test]
    fn test_interface_cache_new() {
        let cache = InterfaceCache::new();
        // Should have at least loopback
        assert!(!cache.is_empty(), "Cache should not be empty");
    }

    #[test]
    fn test_interface_cache_default_ttl() {
        let cache = InterfaceCache::new();
        assert_eq!(cache.ttl(), DEFAULT_INTERFACE_CACHE_TTL);
    }

    #[test]
    fn test_interface_cache_custom_ttl() {
        let custom_ttl = Duration::from_secs(60);
        let cache = InterfaceCache::with_ttl(custom_ttl);
        assert_eq!(cache.ttl(), custom_ttl);
    }

    #[test]
    fn test_interface_cache_get_index_loopback() {
        let cache = InterfaceCache::new();
        let result = cache.get_index("lo");
        assert!(result.is_ok(), "get_index(lo) failed: {:?}", result.err());
        let index = result.unwrap();
        assert!(index > 0, "Loopback index should be positive");
    }

    #[test]
    fn test_interface_cache_get_index_nonexistent() {
        let cache = InterfaceCache::new();
        let result = cache.get_index("nonexistent_xyz123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_interface_cache_get_capability_loopback() {
        let cache = InterfaceCache::new();
        let cap = cache.get_capability("lo");
        assert!(cap.is_some(), "Loopback should exist");
        let cap = cap.unwrap();
        assert!(cap.is_loopback);
        assert!(cap.is_up);
    }

    #[test]
    fn test_interface_cache_get_capability_nonexistent() {
        let cache = InterfaceCache::new();
        let cap = cache.get_capability("nonexistent_xyz123");
        assert!(cap.is_none());
    }

    #[test]
    fn test_interface_cache_get_name_by_index() {
        let cache = InterfaceCache::new();
        // Get loopback index first
        let lo_index = cache.get_index("lo").unwrap() as u32;
        // Then look up by index
        let name = cache.get_name_by_index(lo_index);
        assert!(name.is_some(), "Should find loopback by index");
        assert_eq!(name.unwrap(), "lo");
    }

    #[test]
    fn test_interface_cache_get_name_by_index_nonexistent() {
        let cache = InterfaceCache::new();
        let name = cache.get_name_by_index(99999);
        assert!(name.is_none());
    }

    #[test]
    fn test_interface_cache_get_all() {
        let cache = InterfaceCache::new();
        let all = cache.get_all();
        assert!(!all.is_empty(), "Should have at least loopback");
        // Verify loopback is in the list
        assert!(all.iter().any(|cap| cap.name == "lo"));
    }

    #[test]
    fn test_interface_cache_get_multicast_capable() {
        let cache = InterfaceCache::new();
        let mc_capable = cache.get_multicast_capable();
        // All returned should be multicast capable
        for cap in &mc_capable {
            assert!(cap.is_multicast_capable());
        }
    }

    #[test]
    fn test_interface_cache_refresh() {
        let cache = InterfaceCache::new();
        let initial_age = cache.age();
        // Force refresh
        cache.refresh();
        // Age should be reset (less than initial)
        assert!(
            cache.age() < initial_age || cache.age() < Duration::from_millis(100),
            "Age should be reset after refresh"
        );
    }

    #[test]
    fn test_interface_cache_consistency() {
        let cache = InterfaceCache::new();
        // Multiple calls should return consistent results
        let index1 = cache.get_index("lo").unwrap();
        let index2 = cache.get_index("lo").unwrap();
        assert_eq!(index1, index2, "Index should be consistent");

        let cap1 = cache.get_capability("lo").unwrap();
        let cap2 = cache.get_capability("lo").unwrap();
        assert_eq!(cap1.index, cap2.index);
        assert_eq!(cap1.name, cap2.name);
    }

    #[test]
    fn test_global_interface_cache() {
        // Test the global singleton
        let cache = global_interface_cache();
        assert!(!cache.is_empty());

        // Multiple calls should return the same instance
        let cache2 = global_interface_cache();
        // Can't directly compare addresses, but we can verify behavior is consistent
        let index1 = cache.get_index("lo").unwrap();
        let index2 = cache2.get_index("lo").unwrap();
        assert_eq!(index1, index2);
    }

    #[test]
    fn test_interface_cache_default_impl() {
        let cache = InterfaceCache::default();
        assert!(!cache.is_empty());
        assert_eq!(cache.ttl(), DEFAULT_INTERFACE_CACHE_TTL);
    }
}
