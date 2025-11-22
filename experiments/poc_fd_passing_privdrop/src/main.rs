// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Proof of Concept: File Descriptor Passing with Privilege Drop
//!
//! This experiment validates a critical security architecture assumption (D24):
//! Can AF_PACKET sockets created with CAP_NET_RAW be passed to unprivileged
//! worker processes and still function correctly?
//!
//! The pattern:
//! 1. Privileged parent creates AF_PACKET socket (requires CAP_NET_RAW)
//! 2. Parent passes socket FD to child via Unix domain socket + SCM_RIGHTS
//! 3. Child drops ALL privileges
//! 4. Child attempts to receive packets using the passed socket
//!
//! If this doesn't work, the entire privilege separation architecture fails.

use anyhow::{Context, Result};
use nix::unistd::{fork, ForkResult, Uid, Gid};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const PACKET_COUNT: usize = 5;

fn main() -> Result<()> {
    println!("=== File Descriptor Passing with Privilege Drop Experiment ===\n");

    // Check if running as root
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!("This experiment must be run as root (use sudo)");
    }

    // Get interface name from args or use default
    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "veth-relay".to_string());

    println!("Configuration:");
    println!("  Interface: {}", interface);
    println!("  Running as: root (UID {})", nix::unistd::geteuid());
    println!();

    // Step 1: Create AF_PACKET socket (privileged operation)
    println!("[Parent/Privileged] Creating AF_PACKET socket...");
    let packet_socket = create_af_packet_socket(&interface)?;
    println!("  ✓ AF_PACKET socket created (FD: {})", packet_socket);
    println!("  ✓ Socket has CAP_NET_RAW privileges");
    println!();

    // Step 2: Create Unix domain socketpair for IPC
    println!("[Parent/Privileged] Creating Unix domain socketpair for FD passing...");
    let (parent_sock, child_sock) = UnixStream::pair()
        .context("Failed to create Unix domain socketpair")?;
    println!("  ✓ Socketpair created for IPC");
    println!();

    // Step 3: Fork child process
    println!("[Parent/Privileged] Forking child process...");

    match unsafe { fork() }.context("Failed to fork")? {
        ForkResult::Parent { child } => {
            println!("  ✓ Forked child process (PID: {})", child);
            println!();

            // Close child's socket in parent
            drop(child_sock);

            run_parent(parent_sock, packet_socket)
        }
        ForkResult::Child => {
            // Close parent's socket in child
            drop(parent_sock);

            run_child(child_sock, &interface)
        }
    }
}

/// Parent process: passes the AF_PACKET socket FD to child
fn run_parent(sock: UnixStream, packet_fd: RawFd) -> Result<()> {
    println!("[Parent/Privileged] Passing AF_PACKET socket FD to child...");

    // Send FD via SCM_RIGHTS
    send_fd(&sock, packet_fd)?;

    println!("  ✓ FD passed to child via SCM_RIGHTS");
    println!();

    println!("[Parent/Privileged] Waiting for child to complete test...");

    // Wait for child to signal completion
    let mut buf = [0u8; 1];
    use std::io::Read;
    let _ = (&sock).read(&mut buf);

    println!();
    println!("[Parent/Privileged] Child completed. Parent exiting.");

    Ok(())
}

/// Child process: drops privileges and attempts to use the passed socket
fn run_child(sock: UnixStream, interface: &str) -> Result<()> {
    println!("[Child/Privileged] Child process started");
    println!("  Current UID: {}", nix::unistd::geteuid());
    println!("  Current GID: {}", nix::unistd::getegid());
    println!();

    // Step 4: Receive FD from parent
    println!("[Child/Privileged] Receiving AF_PACKET socket FD from parent...");
    let received_fd = recv_fd(&sock)?;
    println!("  ✓ Received FD: {}", received_fd);
    println!();

    // Step 5: Drop ALL privileges
    println!("[Child/Privileged] Dropping all privileges...");
    drop_privileges()?;
    println!("  ✓ Privileges dropped!");
    println!("  New UID: {} (unprivileged)", nix::unistd::geteuid());
    println!("  New GID: {} (unprivileged)", nix::unistd::getegid());
    println!();

    // Verify we can't create new AF_PACKET sockets
    println!("[Child/Unprivileged] Verifying CAP_NET_RAW is gone...");
    match create_af_packet_socket(interface) {
        Ok(_) => {
            println!("  ✗ ERROR: Still have CAP_NET_RAW! Privilege drop failed!");
            anyhow::bail!("Privilege drop validation failed");
        }
        Err(_) => {
            println!("  ✓ Cannot create new AF_PACKET sockets (CAP_NET_RAW dropped)");
            println!();
        }
    }

    // Step 6: Attempt to use the passed socket
    println!("[Child/Unprivileged] Attempting to receive packets using passed socket...");
    println!("  Waiting for {} packets...", PACKET_COUNT);
    println!();

    let mut received = 0;
    let mut buffer = vec![0u8; 2048];

    while received < PACKET_COUNT {
        match receive_packet_with_timeout(received_fd, &mut buffer, Duration::from_secs(2)) {
            Ok(size) => {
                received += 1;
                println!("  [{}] Received packet: {} bytes", received, size);

                if let Some(info) = parse_packet_info(&buffer[..size]) {
                    println!("      → {}", info);
                }
            }
            Err(e) => {
                println!("  ⚠ Timeout or error receiving packet: {}", e);
                break;
            }
        }
    }

    println!();

    // Step 7: Report results
    println!("[Child/Unprivileged] Test Results:");
    println!("  Packets received: {}/{}", received, PACKET_COUNT);
    println!();

    if received >= 1 {
        println!("✓ SUCCESS: File descriptor passing works!");
        println!("  - AF_PACKET socket created with CAP_NET_RAW");
        println!("  - Socket FD passed via SCM_RIGHTS");
        println!("  - Unprivileged child can use the socket");
        println!("  - Received {} packet(s) without privileges", received);
        println!();
        println!("✓ Core assumption validated: D24 (Privilege Separation) is viable");

        // Signal parent we're done
        use std::io::Write;
        let _ = (&sock).write(&[1u8]);

        Ok(())
    } else {
        println!("✗ FAILURE: Could not receive packets");
        println!("  The passed socket FD may not work correctly in unprivileged process.");
        anyhow::bail!("Experiment failed: no packets received");
    }
}

/// Create an AF_PACKET socket (requires CAP_NET_RAW)
fn create_af_packet_socket(interface: &str) -> Result<RawFd> {
    use nix::net::if_::if_nametoindex;
    use std::mem;

    // Get interface index
    let if_index = if_nametoindex(interface)
        .context("Failed to get interface index")?;

    // Create AF_PACKET socket
    let socket_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    if socket_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to create AF_PACKET socket (need CAP_NET_RAW)");
    }

    // Bind to interface
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

/// Send a file descriptor via Unix domain socket (SCM_RIGHTS)
fn send_fd(sock: &UnixStream, fd: RawFd) -> Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    use std::os::unix::io::AsRawFd;

    let data = [0u8; 1]; // Dummy data
    let iov = [std::io::IoSlice::new(&data)];

    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    sendmsg::<()>(
        sock.as_raw_fd(),
        &iov,
        &cmsg,
        MsgFlags::empty(),
        None,
    )
    .context("Failed to send FD via SCM_RIGHTS")?;

    Ok(())
}

/// Receive a file descriptor via Unix domain socket (SCM_RIGHTS)
fn recv_fd(sock: &UnixStream) -> Result<RawFd> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::os::unix::io::AsRawFd;

    let mut data = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut data)];

    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .context("Failed to receive message")?;

    let mut cmsgs = msg.cmsgs().context("Failed to get control messages")?;
    while let Some(cmsg) = cmsgs.next() {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(fd);
            }
        }
    }

    anyhow::bail!("No file descriptor received in SCM_RIGHTS message");
}

/// Drop all privileges to become unprivileged user
fn drop_privileges() -> Result<()> {
    // Get nobody user (typically UID 65534)
    let nobody_uid = Uid::from_raw(65534);
    let nobody_gid = Gid::from_raw(65534);

    // Drop to nobody:nobody
    nix::unistd::setgid(nobody_gid)
        .context("Failed to setgid")?;
    nix::unistd::setuid(nobody_uid)
        .context("Failed to setuid")?;

    // Verify we can't regain privileges
    if nix::unistd::geteuid().is_root() {
        anyhow::bail!("Still root after privilege drop!");
    }

    Ok(())
}

/// Receive a packet with timeout
fn receive_packet_with_timeout(socket_fd: RawFd, buffer: &mut [u8], timeout: Duration) -> Result<usize> {
    // Set receive timeout
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };

    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeval as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };

    if result < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to set socket timeout");
    }

    // Receive packet
    let result = unsafe {
        libc::recvfrom(
            socket_fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if result < 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to receive packet");
    }

    Ok(result as usize)
}

/// Parse basic packet information
fn parse_packet_info(packet: &[u8]) -> Option<String> {
    if packet.len() < 14 {
        return Some("Packet too short".to_string());
    }

    let eth_type = u16::from_be_bytes([packet[12], packet[13]]);

    match eth_type {
        0x0800 => {
            // IPv4
            if packet.len() < 34 {
                return Some("IPv4 packet (truncated)".to_string());
            }
            let proto = packet[23];
            Some(format!("IPv4 (protocol: {})", proto))
        }
        0x86dd => Some("IPv6".to_string()),
        0x0806 => Some("ARP".to_string()),
        _ => Some(format!("EtherType: 0x{:04x}", eth_type)),
    }
}
