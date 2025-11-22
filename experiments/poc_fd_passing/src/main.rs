// SPDX-License-Identifier: Apache-2.0 OR MIT
//! File Descriptor Passing Demonstration
//!
//! This experiment demonstrates how to pass file descriptors between processes
//! using Unix domain sockets and the SCM_RIGHTS ancillary data mechanism.
//!
//! ## What is File Descriptor Passing?
//!
//! File descriptor passing allows one process to transfer ownership of an open
//! file descriptor to another process. This is crucial for privilege separation
//! architectures like multicast_relay, where:
//!
//! 1. A privileged supervisor process opens raw sockets (requires CAP_NET_RAW)
//! 2. The supervisor passes these FDs to unprivileged worker processes
//! 3. Workers can use the sockets without needing elevated privileges
//!
//! ## How It Works (SCM_RIGHTS)
//!
//! The kernel provides a special mechanism called SCM_RIGHTS (Socket Control Message - Rights):
//!
//! ```text
//! ┌─────────────┐                    ┌─────────────┐
//! │  Supervisor │                    │   Worker    │
//! │  Process    │                    │   Process   │
//! └──────┬──────┘                    └──────┬──────┘
//!        │                                  │
//!        │ 1. Opens socket (needs privilege)│
//!        │    fd = socket(AF_PACKET, ...)   │
//!        │                                  │
//!        │ 2. Sends FD via Unix socket      │
//!        │    sendmsg(sock, SCM_RIGHTS, fd) │
//!        ├─────────────────────────────────>│
//!        │                                  │
//!        │                                  │ 3. Receives FD
//!        │                                  │    recvmsg(sock, SCM_RIGHTS)
//!        │                                  │
//!        │                                  │ 4. Uses socket without privilege
//!        │                                  │    send(fd, packet)
//!        │                                  │
//! ```
//!
//! ## Safety Considerations
//!
//! - The receiving process gets a NEW file descriptor number (not the same number)
//! - Both processes share the same underlying kernel file description
//! - The sender can close their FD; receiver still has access
//! - This requires `unsafe` code due to FFI and raw libc operations

use nix::cmsg_space;
use nix::sys::socket::{
    recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags,
    SockFlag, SockType,
};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult};
use std::fs::File;
use std::io::Write as IoWrite;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Sends a file descriptor to another process via a Unix domain socket
///
/// # Arguments
/// * `socket_fd` - The Unix domain socket to send through
/// * `fd_to_send` - The file descriptor to transfer
///
/// # Safety
/// This function uses unsafe FFI to send file descriptors. The caller must ensure:
/// - `socket_fd` is a valid Unix domain socket
/// - `fd_to_send` is a valid open file descriptor
/// - The receiving end is ready to receive
fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> Result<(), Box<dyn std::error::Error>> {
    println!("[SENDER] Sending file descriptor {} via socket {}", fd_to_send, socket_fd);

    // Prepare a dummy byte to send (sendmsg requires some data)
    let data = [1u8];
    let iov = [std::io::IoSlice::new(&data)];

    // Construct the control message with SCM_RIGHTS containing our FD
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    // Send the message with the file descriptor in ancillary data
    let bytes_sent = sendmsg::<()>(
        socket_fd,
        &iov,
        &cmsg,
        MsgFlags::empty(),
        None,
    )?;

    println!("[SENDER] Sent {} bytes with FD in ancillary data", bytes_sent);
    Ok(())
}

/// Receives a file descriptor from another process via a Unix domain socket
///
/// # Arguments
/// * `socket_fd` - The Unix domain socket to receive from
///
/// # Returns
/// The received file descriptor
///
/// # Safety
/// This function uses unsafe FFI to receive file descriptors. The caller must ensure:
/// - `socket_fd` is a valid Unix domain socket
/// - There is a sender ready to send an FD
fn recv_fd(socket_fd: RawFd) -> Result<RawFd, Box<dyn std::error::Error>> {
    println!("[RECEIVER] Waiting to receive file descriptor via socket {}...", socket_fd);

    // Prepare buffer for the dummy data
    let mut data = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut data)];

    // Allocate space for control message (ancillary data)
    // cmsg_space! calculates the required buffer size for SCM_RIGHTS with 1 FD
    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);

    // Receive the message
    let msg = recvmsg::<()>(
        socket_fd,
        &mut iov,
        Some(&mut cmsg_buffer),
        MsgFlags::empty(),
    )?;

    println!("[RECEIVER] Received {} bytes, parsing ancillary data...", msg.bytes);

    // Extract the file descriptor from control messages
    let mut received_fd = None;
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            println!("[RECEIVER] Found SCM_RIGHTS with {} file descriptor(s)", fds.len());
            if let Some(&fd) = fds.first() {
                received_fd = Some(fd);
                println!("[RECEIVER] Extracted FD: {}", fd);
            }
        }
    }

    received_fd.ok_or_else(|| "No file descriptor received".into())
}

/// Demonstrates passing a file descriptor from parent to child process
fn demonstrate_fd_passing() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== File Descriptor Passing Demonstration ===\n");

    // Step 1: Create a Unix domain socket pair for IPC
    println!("[PARENT] Creating Unix domain socket pair for communication...");
    let (parent_sock, child_sock) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )?;

    let parent_fd = parent_sock.as_raw_fd();
    let child_fd = child_sock.as_raw_fd();
    println!("[PARENT] Socket pair created: parent_fd={}, child_fd={}", parent_fd, child_fd);

    // Step 2: Create a file that we'll pass to the child
    println!("[PARENT] Creating a test file to pass to child...");
    let test_file = File::create("/tmp/fd_passing_demo.txt")?;
    let file_fd = test_file.as_raw_fd();
    println!("[PARENT] Created file with FD: {}", file_fd);

    // Write some initial content
    let mut file = test_file;
    writeln!(file, "This file was created by the parent process (PID: {})", std::process::id())?;
    writeln!(file, "Original file descriptor: {}", file_fd)?;
    file.flush()?;

    // Step 3: Fork to create child process
    println!("\n[PARENT] Forking child process...");
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            println!("[PARENT] Forked child with PID: {}", child);

            // Parent doesn't need child's socket end
            drop(child_sock);

            // Step 4: Send the file descriptor to child
            println!("[PARENT] Sending file descriptor to child...");
            send_fd(parent_fd, file_fd)?;
            println!("[PARENT] File descriptor sent successfully!");

            // Parent can close its FD now - child has its own reference
            println!("[PARENT] Closing parent's file descriptor...");
            drop(file); // Close the file in parent

            // Step 5: Wait for child to finish
            println!("[PARENT] Waiting for child to complete...");
            waitpid(child, None)?;
            println!("[PARENT] Child process completed");

            // Cleanup
            drop(parent_sock);

            // Read and display the final file content
            println!("\n[PARENT] Final file content:");
            let content = std::fs::read_to_string("/tmp/fd_passing_demo.txt")?;
            for line in content.lines() {
                println!("  {}", line);
            }

            println!("\n✅ Demonstration complete!");
        }
        ForkResult::Child => {
            // Parent doesn't need parent's socket end
            drop(parent_sock);

            println!("\n[CHILD] Child process started (PID: {})", std::process::id());

            // Step 6: Receive the file descriptor from parent
            println!("[CHILD] Receiving file descriptor from parent...");
            let received_fd = recv_fd(child_fd)?;
            println!("[CHILD] Successfully received FD: {}", received_fd);

            // Step 7: Use the received file descriptor
            println!("[CHILD] Using received file descriptor to write to file...");

            // SAFETY: We know this FD is valid because we just received it from parent
            let mut received_file = unsafe { File::from_raw_fd(received_fd) };

            writeln!(received_file, "This line was written by the child process (PID: {})", std::process::id())?;
            writeln!(received_file, "Received file descriptor: {}", received_fd)?;
            writeln!(received_file, "Note: FD number changed from parent's {} to child's {}",
                     file_fd, received_fd)?;
            received_file.flush()?;

            println!("[CHILD] Successfully wrote to file using received FD");

            // Cleanup
            drop(received_file);
            drop(child_sock);

            println!("[CHILD] Child process exiting\n");
            std::process::exit(0);
        }
    }

    Ok(())
}

/// Advanced example: Demonstrates how the supervisor pattern works
fn demonstrate_supervisor_pattern() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Supervisor Pattern Demonstration ===\n");
    println!("This simulates how multicast_relay's supervisor passes sockets to workers.\n");

    // Create socket pair for command channel (like supervisor <-> worker)
    let (supervisor_sock, worker_sock) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )?;

    let supervisor_fd = supervisor_sock.as_raw_fd();
    let worker_fd = worker_sock.as_raw_fd();

    println!("[SUPERVISOR] Created command channel: supervisor_fd={}, worker_fd={}",
             supervisor_fd, worker_fd);

    // Simulate creating a "privileged" socket (in reality this would be AF_PACKET)
    println!("[SUPERVISOR] Opening privileged socket (simulated with temp file)...");
    let privileged_socket = File::create("/tmp/privileged_socket_sim.txt")?;
    let socket_fd = privileged_socket.as_raw_fd();

    let mut file = privileged_socket;
    writeln!(file, "Simulated privileged socket created by supervisor")?;
    file.flush()?;

    println!("[SUPERVISOR] Privileged socket FD: {}", socket_fd);

    // Fork worker
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            drop(worker_sock);

            println!("\n[SUPERVISOR] Worker spawned with PID: {}", child);
            println!("[SUPERVISOR] Transferring socket ownership to worker...");

            // Transfer socket to worker
            send_fd(supervisor_fd, socket_fd)?;
            println!("[SUPERVISOR] Socket transferred!");

            // Supervisor can drop privileges and close the socket now
            println!("[SUPERVISOR] Closing socket in supervisor (worker owns it now)");
            drop(file);

            // Wait for worker
            waitpid(child, None)?;
            drop(supervisor_sock);

            println!("\n[SUPERVISOR] Worker completed. Pattern demonstration successful!");
        }
        ForkResult::Child => {
            drop(supervisor_sock);

            println!("\n[WORKER] Worker started (PID: {})", std::process::id());
            println!("[WORKER] Waiting to receive socket from supervisor...");

            // Receive the privileged socket
            let worker_socket_fd = recv_fd(worker_fd)?;
            println!("[WORKER] Received socket FD: {}", worker_socket_fd);
            println!("[WORKER] Worker can now use this socket without privileges!");

            // Use the socket
            let mut sock = unsafe { File::from_raw_fd(worker_socket_fd) };
            writeln!(sock, "Worker (PID: {}) is now using the privileged socket",
                     std::process::id())?;
            writeln!(sock, "Worker received FD: {}", worker_socket_fd)?;
            sock.flush()?;

            println!("[WORKER] Successfully used the privileged socket");

            drop(sock);
            drop(worker_sock);

            println!("[WORKER] Worker exiting\n");
            std::process::exit(0);
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║   File Descriptor Passing - Educational Demonstration  ║");
    println!("║   Showing SCM_RIGHTS mechanism used in multicast_relay ║");
    println!("╚════════════════════════════════════════════════════════╝");

    // Run basic demonstration
    demonstrate_fd_passing()?;

    // Show how it applies to supervisor pattern
    demonstrate_supervisor_pattern()?;

    println!("\n📚 Key Takeaways:");
    println!("  1. File descriptors can be transferred between processes");
    println!("  2. Uses Unix domain sockets + SCM_RIGHTS control message");
    println!("  3. FD number changes, but refers to same kernel object");
    println!("  4. Enables privilege separation (supervisor opens, worker uses)");
    println!("  5. Both processes have independent references (can close separately)");
    println!("\n🔍 See /tmp/fd_passing_demo.txt and /tmp/privileged_socket_sim.txt");

    Ok(())
}
