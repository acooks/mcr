// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Netlink-based interface change monitoring
//!
//! This module provides real-time detection of network interface changes
//! (add, remove, up, down) using Linux netlink sockets. When changes are
//! detected, the global interface cache is refreshed immediately rather
//! than waiting for the TTL to expire.
//!
//! Interface events are also sent to the supervisor via a channel, enabling
//! immediate retry of pending worker spawns when interfaces come up.
//!
//! Uses raw netlink via `libc` + `tokio::io::unix::AsyncFd` — no rtnetlink
//! dependency.
//!
//! # Usage
//!
//! ```ignore
//! // In supervisor startup:
//! let (handle, mut rx) = spawn_netlink_monitor(logger.clone());
//!
//! // In select! loop:
//! Some(event) = rx.recv() => { ... }
//!
//! // On shutdown:
//! handle.abort();
//! ```

use std::os::unix::io::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::logging::{Facility, Logger};

use super::socket_helpers::global_interface_cache;

// Netlink constants not exposed by libc
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const IFLA_IFNAME: u16 = 3;

/// Kernel `struct ifinfomsg` — payload of RTM_NEWLINK / RTM_DELLINK.
#[repr(C)]
struct IfInfoMsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

const NLMSGHDR_SIZE: usize = std::mem::size_of::<libc::nlmsghdr>(); // 16
const IFINFOMSG_SIZE: usize = std::mem::size_of::<IfInfoMsg>(); // 16

// Compile-time verification that our struct matches the kernel's layout.
const _: () = assert!(IFINFOMSG_SIZE == 16);
const _: () = assert!(NLMSGHDR_SIZE == 16);

/// Align to 4-byte boundary (NLMSG_ALIGN / NLA_ALIGN).
const fn align4(len: usize) -> usize {
    (len + 3) & !3
}

/// Events from the netlink monitor to the supervisor
#[derive(Debug, Clone)]
pub enum InterfaceEvent {
    /// Interface has come up or been added
    Up(String),
    /// Interface has gone down or been removed
    Down(String),
}

/// Newtype so we can impl `AsRawFd` for `AsyncFd`.
struct NetlinkSocket(RawFd);

impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Spawn a background task that monitors netlink for interface changes.
///
/// Returns a tuple of:
/// - `JoinHandle` that can be used to abort the monitor on shutdown
/// - `Receiver` for interface events to be processed by the supervisor
pub fn spawn_netlink_monitor(
    logger: Logger,
) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<InterfaceEvent>) {
    let (tx, rx) = mpsc::channel::<InterfaceEvent>(32);

    let handle = tokio::spawn(async move {
        if let Err(e) = run_netlink_monitor(&logger, tx).await {
            logger.warning(
                Facility::Supervisor,
                &format!("Netlink monitor exited with error: {}", e),
            );
        }
    });

    (handle, rx)
}

/// Create a non-blocking netlink socket bound to RTMGRP_LINK.
fn create_netlink_socket() -> std::io::Result<NetlinkSocket> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = libc::RTMGRP_LINK as u32;

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    Ok(NetlinkSocket(fd))
}

/// Extract the interface name (IFLA_IFNAME) from a single netlink message payload.
///
/// `payload` starts right after the nlmsghdr and must contain at least
/// `IFINFOMSG_SIZE` bytes (the ifinfomsg struct) followed by nlattr TLVs.
/// Returns `None` if IFLA_IFNAME is not found.
fn parse_ifname_from_nlmsg(payload: &[u8]) -> Option<String> {
    if payload.len() < IFINFOMSG_SIZE {
        return None;
    }

    // Skip past ifinfomsg to reach the attribute chain
    let attrs = &payload[IFINFOMSG_SIZE..];
    let mut offset = 0;

    // Each nlattr: u16 nla_len, u16 nla_type, then payload
    while offset + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[offset], attrs[offset + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[offset + 2], attrs[offset + 3]]);

        if nla_len < 4 || offset + nla_len > attrs.len() {
            break;
        }

        if nla_type == IFLA_IFNAME {
            // Payload starts at offset+4, length is nla_len-4, null-terminated
            let name_bytes = &attrs[offset + 4..offset + nla_len];
            let name = name_bytes
                .split(|&b| b == 0)
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
                .map(|s| s.to_string());
            return name;
        }

        offset += align4(nla_len);
    }

    None
}

/// Extract ifi_index from the ifinfomsg in a netlink message payload.
///
/// ifi_index is at offset 4 within ifinfomsg (after ifi_family, _pad, ifi_type).
fn parse_ifindex_from_nlmsg(payload: &[u8]) -> Option<i32> {
    if payload.len() < IFINFOMSG_SIZE {
        return None;
    }
    Some(i32::from_ne_bytes([
        payload[4], payload[5], payload[6], payload[7],
    ]))
}

/// Read nlmsg_len (u32 at offset 0) and nlmsg_type (u16 at offset 4) from nlmsghdr bytes.
fn read_nlmsghdr(data: &[u8], offset: usize) -> (usize, u16) {
    let msg_len = u32::from_ne_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let msg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);
    (msg_len, msg_type)
}

/// Parse all netlink messages in `data` and return interface events.
///
/// A single `recv()` can deliver multiple netlink messages back-to-back.
/// This walks the nlmsghdr chain, extracting interface names from
/// RTM_NEWLINK and RTM_DELLINK messages.
fn parse_netlink_events(data: &[u8]) -> Vec<InterfaceEvent> {
    let n = data.len();
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + NLMSGHDR_SIZE <= n {
        let (msg_len, msg_type) = read_nlmsghdr(data, offset);

        if msg_len < NLMSGHDR_SIZE || msg_len > n - offset {
            break;
        }

        let payload = &data[offset + NLMSGHDR_SIZE..offset + msg_len];

        let event = match msg_type {
            RTM_NEWLINK => {
                let name = parse_ifname_from_nlmsg(payload).unwrap_or_else(|| {
                    let idx = parse_ifindex_from_nlmsg(payload).unwrap_or(0);
                    format!("index {}", idx)
                });
                Some(InterfaceEvent::Up(name))
            }
            RTM_DELLINK => {
                let name = parse_ifname_from_nlmsg(payload).unwrap_or_else(|| {
                    let idx = parse_ifindex_from_nlmsg(payload).unwrap_or(0);
                    format!("index {}", idx)
                });
                Some(InterfaceEvent::Down(name))
            }
            _ => None,
        };

        if let Some(ev) = event {
            events.push(ev);
        }

        offset += align4(msg_len);
    }

    events
}

/// Internal function that runs the netlink monitoring loop.
async fn run_netlink_monitor(
    logger: &Logger,
    tx: mpsc::Sender<InterfaceEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sock = create_netlink_socket()?;
    let async_fd = AsyncFd::new(sock)?;

    logger.info(
        Facility::Supervisor,
        "Netlink monitor started - watching for interface changes",
    );

    let mut buf = vec![0u8; 16384];

    loop {
        // Wait for the socket to become readable
        let mut guard = async_fd.readable().await?;

        match guard.try_io(|inner| {
            let n = unsafe {
                libc::recv(
                    inner.get_ref().as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_TRUNC,
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) => {
                // EOF — treat like WouldBlock, re-register
                continue;
            }
            Ok(Ok(n)) => {
                // MSG_TRUNC: if n > buf.len(), the message was truncated.
                // Discard this batch rather than parsing partial data.
                if n > buf.len() {
                    logger.warning(
                        Facility::Supervisor,
                        &format!(
                            "Netlink message truncated ({} bytes, buffer {}), skipping",
                            n,
                            buf.len()
                        ),
                    );
                    continue;
                }
                for event in parse_netlink_events(&buf[..n]) {
                    match &event {
                        InterfaceEvent::Up(name) => {
                            logger.debug(
                                Facility::Supervisor,
                                &format!(
                                    "Netlink: interface {} added/changed, refreshing cache",
                                    name
                                ),
                            );
                        }
                        InterfaceEvent::Down(name) => {
                            logger.debug(
                                Facility::Supervisor,
                                &format!("Netlink: interface {} removed, refreshing cache", name),
                            );
                        }
                    }
                    global_interface_cache().refresh();
                    let _ = tx.send(event).await;
                }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                // EINTR — signal interrupted recv(), just retry
                continue;
            }
            Ok(Err(e)) => {
                return Err(Box::new(e));
            }
            Err(_would_block) => {
                // Spurious wakeup — loop back and re-register
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netlink_socket_creation() {
        let sock = create_netlink_socket();
        assert!(
            sock.is_ok(),
            "Failed to create netlink socket: {:?}",
            sock.err()
        );
        // Socket is closed on drop
    }

    #[test]
    fn test_parse_ifname_from_nlmsg() {
        // Build a minimal netlink message payload:
        // ifinfomsg (16 bytes) + nlattr IFLA_IFNAME with "eth0\0"

        let mut payload = vec![0u8; IFINFOMSG_SIZE];

        // ifinfomsg: family=AF_UNSPEC, pad=0, type=0, index=2, flags=0, change=0
        payload[0] = 0; // ifi_family
                        // bytes 1..16 are zero (pad, type, index, flags, change)
                        // Set ifi_index = 2
        payload[4..8].copy_from_slice(&2i32.to_ne_bytes());

        // IFLA_IFNAME attribute: nla_len=9 (4 header + 5 "eth0\0"), nla_type=3
        let name = b"eth0\0";
        let nla_len: u16 = 4 + name.len() as u16; // 9
        payload.extend_from_slice(&nla_len.to_ne_bytes());
        payload.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
        payload.extend_from_slice(name);
        // Pad to 4-byte alignment (9 → 12, need 3 padding bytes)
        payload.extend_from_slice(&[0, 0, 0]);

        let result = parse_ifname_from_nlmsg(&payload);
        assert_eq!(result, Some("eth0".to_string()));
    }

    #[test]
    fn test_parse_ifname_missing() {
        // Payload with only ifinfomsg, no attributes
        let payload = vec![0u8; IFINFOMSG_SIZE];
        let result = parse_ifname_from_nlmsg(&payload);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_ifname_skips_other_attrs() {
        // Build payload with a non-IFLA_IFNAME attr first, then IFLA_IFNAME
        let mut payload = vec![0u8; IFINFOMSG_SIZE];

        // First attr: IFLA_MTU (type=4), value=1500 (4 bytes)
        let mtu_nla_len: u16 = 4 + 4; // header + 4-byte u32
        payload.extend_from_slice(&mtu_nla_len.to_ne_bytes());
        payload.extend_from_slice(&4u16.to_ne_bytes()); // IFLA_MTU
        payload.extend_from_slice(&1500u32.to_ne_bytes());

        // Second attr: IFLA_IFNAME with "veth1\0"
        let name = b"veth1\0";
        let name_nla_len: u16 = 4 + name.len() as u16;
        payload.extend_from_slice(&name_nla_len.to_ne_bytes());
        payload.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
        payload.extend_from_slice(name);
        // Pad to 4-byte alignment (10 → 12)
        payload.extend_from_slice(&[0, 0]);

        let result = parse_ifname_from_nlmsg(&payload);
        assert_eq!(result, Some("veth1".to_string()));
    }

    #[test]
    fn test_parse_ifname_too_short() {
        let payload = vec![0u8; 4]; // Shorter than ifinfomsg
        assert_eq!(parse_ifname_from_nlmsg(&payload), None);
    }

    #[test]
    fn test_parse_ifindex() {
        let mut payload = vec![0u8; IFINFOMSG_SIZE];
        payload[4..8].copy_from_slice(&42i32.to_ne_bytes());
        assert_eq!(parse_ifindex_from_nlmsg(&payload), Some(42));
    }

    #[test]
    fn test_align4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(9), 12);
        assert_eq!(align4(16), 16);
    }

    /// Build a complete netlink message (nlmsghdr + ifinfomsg + optional IFLA_IFNAME attr).
    fn build_nlmsg(msg_type: u16, ifindex: i32, ifname: Option<&str>) -> Vec<u8> {
        // Build payload: ifinfomsg + attributes
        let mut payload = vec![0u8; IFINFOMSG_SIZE];
        payload[4..8].copy_from_slice(&ifindex.to_ne_bytes());

        if let Some(name) = ifname {
            let mut name_bytes = name.as_bytes().to_vec();
            name_bytes.push(0); // null terminator
            let nla_len = 4 + name_bytes.len() as u16;
            payload.extend_from_slice(&nla_len.to_ne_bytes());
            payload.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
            payload.extend_from_slice(&name_bytes);
            // Pad to 4-byte alignment
            while !payload.len().is_multiple_of(4) {
                payload.push(0);
            }
        }

        // Build nlmsghdr (16 bytes) + payload
        let total_len = (NLMSGHDR_SIZE + payload.len()) as u32;
        let mut msg = Vec::with_capacity(total_len as usize);
        msg.extend_from_slice(&total_len.to_ne_bytes()); // nlmsg_len
        msg.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
        msg.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
        msg.extend_from_slice(&payload);

        // Pad full message to 4-byte alignment
        while msg.len() % 4 != 0 {
            msg.push(0);
        }

        msg
    }

    #[test]
    fn test_parse_single_newlink_event() {
        let msg = build_nlmsg(RTM_NEWLINK, 3, Some("eth0"));
        let events = parse_netlink_events(&msg);
        assert_eq!(events.len(), 1);
        match &events[0] {
            InterfaceEvent::Up(name) => assert_eq!(name, "eth0"),
            other => panic!("Expected Up, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_single_dellink_event() {
        let msg = build_nlmsg(RTM_DELLINK, 5, Some("wlan0"));
        let events = parse_netlink_events(&msg);
        assert_eq!(events.len(), 1);
        match &events[0] {
            InterfaceEvent::Down(name) => assert_eq!(name, "wlan0"),
            other => panic!("Expected Down, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_multi_message_buffer() {
        // Two messages back-to-back in one recv() buffer
        let mut buf = build_nlmsg(RTM_NEWLINK, 2, Some("eth0"));
        buf.extend_from_slice(&build_nlmsg(RTM_DELLINK, 3, Some("eth1")));

        let events = parse_netlink_events(&buf);
        assert_eq!(events.len(), 2);
        match &events[0] {
            InterfaceEvent::Up(name) => assert_eq!(name, "eth0"),
            other => panic!("Expected Up(eth0), got {:?}", other),
        }
        match &events[1] {
            InterfaceEvent::Down(name) => assert_eq!(name, "eth1"),
            other => panic!("Expected Down(eth1), got {:?}", other),
        }
    }

    #[test]
    fn test_parse_ignores_unknown_message_types() {
        // RTM_NEWADDR = 20, should be ignored
        let mut buf = build_nlmsg(20, 1, Some("lo"));
        buf.extend_from_slice(&build_nlmsg(RTM_NEWLINK, 4, Some("br0")));

        let events = parse_netlink_events(&buf);
        assert_eq!(events.len(), 1);
        match &events[0] {
            InterfaceEvent::Up(name) => assert_eq!(name, "br0"),
            other => panic!("Expected Up(br0), got {:?}", other),
        }
    }

    #[test]
    fn test_parse_fallback_to_ifindex() {
        // Message with no IFLA_IFNAME attribute — should fall back to "index N"
        let msg = build_nlmsg(RTM_NEWLINK, 42, None);
        let events = parse_netlink_events(&msg);
        assert_eq!(events.len(), 1);
        match &events[0] {
            InterfaceEvent::Up(name) => assert_eq!(name, "index 42"),
            other => panic!("Expected Up(index 42), got {:?}", other),
        }
    }

    #[test]
    fn test_parse_max_length_ifname() {
        // Linux IFNAMSIZ = 16, max name is 15 chars + null
        let long_name = "a]bcdefghijklmn"; // 15 chars
        let msg = build_nlmsg(RTM_NEWLINK, 1, Some(long_name));
        let events = parse_netlink_events(&msg);
        assert_eq!(events.len(), 1);
        match &events[0] {
            InterfaceEvent::Up(name) => assert_eq!(name, long_name),
            other => panic!("Expected Up, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_empty_buffer() {
        let events = parse_netlink_events(&[]);
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_truncated_header() {
        // Less than NLMSGHDR_SIZE bytes
        let events = parse_netlink_events(&[0u8; 12]);
        assert!(events.is_empty());
    }
}
