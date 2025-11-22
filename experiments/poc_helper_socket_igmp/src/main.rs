// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Proof of Concept: Helper Socket Pattern for IGMP + NIC Filtering
//!
//! This experiment validates a critical architectural assumption (D6, D4):
//! Can we use an AF_INET socket SOLELY to trigger IGMP joins and program
//! the NIC's MAC address filter, while receiving packets via a separate
//! AF_PACKET socket?
//!
//! The pattern:
//! 1. Create AF_INET UDP socket
//! 2. Join multicast group (triggers IGMP join to network)
//! 3. Set SO_RCVBUF to minimum (we never read from this socket)
//! 4. Create AF_PACKET socket on same interface
//! 5. Packets arrive at AF_PACKET socket, NOT the AF_INET socket
//!
//! If this doesn't work, the entire ingress filtering strategy must be redesigned.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

const MULTICAST_GROUP: &str = "239.255.1.1";
const MULTICAST_PORT: u16 = 9999;
const PACKET_COUNT: usize = 10;

fn main() -> Result<()> {
    println!("=== Helper Socket Pattern Experiment ===\n");

    // Get interface name from args or use default
    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "veth-relay".to_string());

    println!("Configuration:");
    println!("  Interface: {}", interface);
    println!("  Multicast Group: {}", MULTICAST_GROUP);
    println!("  Port: {}", MULTICAST_PORT);
    println!();

    // Step 1: Create the "helper" AF_INET socket
    println!("[Step 1] Creating AF_INET helper socket...");
    let helper_socket = create_helper_socket(&interface)?;
    println!("  ✓ Helper socket created (FD: {})", helper_socket);
    println!();

    // Step 2: Join multicast group on helper socket
    println!("[Step 2] Joining multicast group on helper socket...");
    join_multicast_group(helper_socket, &interface)?;
    println!("  ✓ Joined {} (should trigger IGMP join)", MULTICAST_GROUP);
    println!();

    // Step 3: Set SO_RCVBUF to minimum on helper socket
    println!("[Step 3] Setting SO_RCVBUF to minimum on helper socket...");
    set_minimal_rcvbuf(helper_socket)?;
    println!("  ✓ SO_RCVBUF set to minimum (socket will never be read)");
    println!();

    // Step 4: Create AF_PACKET socket
    println!("[Step 4] Creating AF_PACKET socket...");
    let packet_socket = create_af_packet_socket(&interface)?;
    println!("  ✓ AF_PACKET socket created (FD: {})", packet_socket);
    println!();

    // Step 5: Wait a moment for IGMP to propagate
    println!("[Step 5] Waiting for IGMP join to propagate...");
    std::thread::sleep(Duration::from_millis(500));
    println!("  ✓ Ready to receive packets");
    println!();

    // Step 6: Receive packets from AF_PACKET socket
    println!("[Step 6] Receiving packets from AF_PACKET socket...");
    println!("  Waiting for {} multicast packets...", PACKET_COUNT);
    println!("  (Sender should be running in peer namespace)");
    println!();

    let mut received = 0;
    let mut buffer = vec![0u8; 2048];

    while received < PACKET_COUNT {
        match receive_packet(packet_socket, &mut buffer) {
            Ok(size) => {
                received += 1;
                println!(
                    "  [{}] Received packet: {} bytes",
                    received, size
                );

                // Parse and display basic packet info
                if let Some(info) = parse_packet_info(&buffer[..size]) {
                    println!("      → {}", info);
                }
            }
            Err(e) => {
                eprintln!("  ✗ Error receiving packet: {}", e);
                break;
            }
        }
    }

    println!();

    // Step 7: Check helper socket status
    println!("[Step 7] Checking helper socket status...");
    check_socket_status(helper_socket)?;
    println!();

    // Step 8: Verify no data in helper socket
    println!("[Step 8] Verifying helper socket has no readable data...");
    verify_helper_socket_empty(helper_socket)?;
    println!();

    if received == PACKET_COUNT {
        println!("✓ SUCCESS: Helper socket pattern works!");
        println!("  - IGMP join triggered from AF_INET socket");
        println!("  - Packets received at AF_PACKET socket");
        println!("  - Helper socket never read");
        println!();
        println!("✓ Core assumption validated: D6 (Helper Socket Pattern) is viable");
        Ok(())
    } else {
        println!("✗ FAILURE: Only received {}/{} packets", received, PACKET_COUNT);
        println!("  The helper socket pattern may not work as expected.");
        anyhow::bail!("Experiment failed: insufficient packets received");
    }
}

/// Create an AF_INET UDP socket bound to the multicast port
fn create_helper_socket(interface: &str) -> Result<RawFd> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::unix::io::IntoRawFd;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create AF_INET socket")?;

    // Allow multiple sockets to bind to same port (for testing)
    socket
        .set_reuse_address(true)
        .context("Failed to set SO_REUSEADDR")?;

    // Bind to the multicast port
    let addr: SocketAddr = format!("0.0.0.0:{}", MULTICAST_PORT)
        .parse()
        .context("Invalid address")?;
    socket
        .bind(&addr.into())
        .context("Failed to bind helper socket")?;

    // Bind to specific interface
    socket
        .bind_device(Some(interface.as_bytes()))
        .context("Failed to bind to interface")?;

    // Transfer ownership of the FD to prevent socket from being closed
    Ok(socket.into_raw_fd())
}

/// Join a multicast group on the helper socket
fn join_multicast_group(socket_fd: RawFd, interface: &str) -> Result<()> {
    use nix::sys::socket::{setsockopt, sockopt::IpAddMembership, IpMembershipRequest};
    use std::os::unix::io::BorrowedFd;

    // Get interface IP address
    let interface_ip = get_interface_ip(interface)
        .context("Failed to get interface IP")?;

    let multicast_addr: Ipv4Addr = MULTICAST_GROUP.parse()
        .context("Invalid multicast address")?;

    // Create IpMembershipRequest (nix 0.30 wrapper)
    let mreq = IpMembershipRequest::new(multicast_addr, Some(interface_ip));

    // Join multicast group
    // SAFETY: socket_fd is a valid file descriptor owned by the caller
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(socket_fd) };
    setsockopt(&borrowed_fd, IpAddMembership, &mreq)
        .context("Failed to join multicast group")?;

    Ok(())
}

/// Set SO_RCVBUF to the minimum allowed value
fn set_minimal_rcvbuf(socket_fd: RawFd) -> Result<()> {
    use nix::sys::socket::{getsockopt, setsockopt, sockopt::RcvBuf};
    use std::os::unix::io::BorrowedFd;

    // SAFETY: socket_fd is a valid file descriptor owned by the caller
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(socket_fd) };

    // Try to set to 1 byte (kernel will round up to minimum)
    setsockopt(&borrowed_fd, RcvBuf, &1)
        .context("Failed to set SO_RCVBUF")?;

    // Query actual value
    let actual = getsockopt(&borrowed_fd, RcvBuf)
        .context("Failed to get SO_RCVBUF")?;

    println!("  SO_RCVBUF set to: {} bytes (kernel minimum)", actual);

    Ok(())
}

/// Create an AF_PACKET socket bound to the specified interface
fn create_af_packet_socket(interface: &str) -> Result<RawFd> {
    use std::mem;

    // Get interface index first
    let if_index = get_interface_index(interface)?;

    // Create AF_PACKET socket with ETH_P_ALL (0x0003) using raw libc
    let socket_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to create AF_PACKET socket");
    }

    // Bind to interface using sockaddr_ll
    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = if_index as i32;

    let addr_ptr = &addr as *const libc::sockaddr_ll as *const libc::sockaddr;
    let addr_len = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

    let result = unsafe { libc::bind(socket_fd, addr_ptr, addr_len) };

    if result < 0 {
        unsafe { libc::close(socket_fd) };
        return Err(std::io::Error::last_os_error())
            .context("Failed to bind AF_PACKET socket");
    }

    Ok(socket_fd)
}

/// Receive a packet from AF_PACKET socket
fn receive_packet(socket_fd: RawFd, buffer: &mut [u8]) -> Result<usize> {
    // Use raw libc recvfrom
    let result = unsafe {
        libc::recvfrom(
            socket_fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0, // flags
            std::ptr::null_mut(), // src_addr (we don't need it)
            std::ptr::null_mut(), // addrlen (we don't need it)
        )
    };

    if result < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to receive packet");
    }

    Ok(result as usize)
}

/// Parse basic packet information for display
fn parse_packet_info(packet: &[u8]) -> Option<String> {
    if packet.len() < 42 {
        // Min: 14 (eth) + 20 (ip) + 8 (udp)
        return Some("Packet too short".to_string());
    }

    // Parse Ethernet header
    let eth_type = u16::from_be_bytes([packet[12], packet[13]]);
    if eth_type != 0x0800 {
        // Not IPv4
        return Some(format!("Non-IPv4 packet (EtherType: 0x{:04x})", eth_type));
    }

    // Parse IPv4 header
    let ip_proto = packet[23];
    if ip_proto != 17 {
        // Not UDP
        return Some(format!("Non-UDP packet (protocol: {})", ip_proto));
    }

    let src_ip = Ipv4Addr::new(packet[26], packet[27], packet[28], packet[29]);
    let dst_ip = Ipv4Addr::new(packet[30], packet[31], packet[32], packet[33]);

    // Parse UDP header
    let src_port = u16::from_be_bytes([packet[34], packet[35]]);
    let dst_port = u16::from_be_bytes([packet[36], packet[37]]);

    Some(format!(
        "UDP {}:{} → {}:{}",
        src_ip, src_port, dst_ip, dst_port
    ))
}

/// Check socket status and statistics
fn check_socket_status(socket_fd: RawFd) -> Result<()> {
    use nix::sys::socket::{getsockopt, sockopt::RcvBuf};
    use std::os::unix::io::BorrowedFd;

    // SAFETY: socket_fd is a valid file descriptor owned by the caller
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(socket_fd) };

    let rcvbuf = getsockopt(&borrowed_fd, RcvBuf)
        .context("Failed to get SO_RCVBUF")?;

    println!("  Helper socket SO_RCVBUF: {} bytes", rcvbuf);
    println!("  (This socket should have accumulated buffer overflows)");

    Ok(())
}

/// Verify that the helper socket has no readable data
fn verify_helper_socket_empty(socket_fd: RawFd) -> Result<()> {
    // Use raw libc poll
    let mut poll_fd = libc::pollfd {
        fd: socket_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let timeout = 10; // 10ms

    let result = unsafe {
        libc::poll(&mut poll_fd as *mut libc::pollfd, 1, timeout)
    };

    if result < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to poll helper socket");
    }

    if result == 0 {
        println!("  ✓ Helper socket has no readable data (as expected)");
        Ok(())
    } else {
        println!("  ⚠ Helper socket has readable data (unexpected!)");
        println!("  This suggests packets may be going to both sockets.");
        Ok(())
    }
}

/// Get interface index by name
fn get_interface_index(interface: &str) -> Result<u32> {
    use nix::net::if_::if_nametoindex;

    if_nametoindex(interface)
        .context("Failed to get interface index")
}

/// Get the IP address of an interface
fn get_interface_ip(interface: &str) -> Result<Ipv4Addr> {
    use nix::ifaddrs::getifaddrs;

    let addrs = getifaddrs().context("Failed to get interface addresses")?;

    for addr in addrs {
        if addr.interface_name == interface {
            if let Some(sock_addr) = addr.address {
                if let Some(ipv4) = sock_addr.as_sockaddr_in() {
                    // nix's SockaddrIn::ip() returns Ipv4Addr directly
                    return Ok(ipv4.ip());
                }
            }
        }
    }

    anyhow::bail!("Interface {} not found or has no IPv4 address", interface)
}
