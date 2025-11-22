// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Proof-of-Concept: io_uring with AF_PACKET Sockets
//!
//! This binary is a minimal, self-contained example demonstrating how to use the
//! `tokio-uring` runtime to asynchronously read raw packets from an `AF_PACKET`
//! socket.
//!
//! It establishes the correct pattern for integrating a raw file descriptor,
//! obtained via `libc` calls, into the `tokio-uring` ecosystem.
//!
//! ## Usage:
//!
//! ```sh
//! sudo target/debug/poc_io_uring_af_packet <INTERFACE_NAME>
//! ```
//! e.g.
//! ```sh
//! sudo target/debug/poc_io_uring_af_packet eth0
//! ```

use anyhow::Result;
use std::ffi::CString;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

/// Creates and binds an AF_PACKET socket using direct libc calls.
/// This function is a self-contained copy of the logic in `worker::data_plane`.
/// It requires root privileges to execute successfully.
fn setup_ingress_socket(interface_name: &str) -> Result<OwnedFd> {
    // 1. Convert the interface name to a CString for libc.
    let if_name = CString::new(interface_name)?;
    // 2. Get the interface index.
    let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
    if if_index == 0 {
        return Err(anyhow::anyhow!(
            "Interface '{}' not found (errno: {})",
            interface_name,
            std::io::Error::last_os_error()
        ));
    }

    // 3. Create an AF_PACKET, SOCK_RAW socket.
    // We convert ETH_P_ALL to network byte order.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create AF_PACKET socket (errno: {})",
            std::io::Error::last_os_error()
        ));
    }

    // 4. Construct the sockaddr_ll struct for binding.
    let mut sockaddr_ll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sockaddr_ll.sll_family = libc::AF_PACKET as u16;
    sockaddr_ll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sockaddr_ll.sll_ifindex = if_index as i32;

    // 5. Bind the socket to the specified interface.
    let bind_result = unsafe {
        libc::bind(
            fd,
            &sockaddr_ll as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if bind_result < 0 {
        return Err(anyhow::anyhow!(
            "Failed to bind to interface '{}' (errno: {})",
            interface_name,
            std::io::Error::last_os_error()
        ));
    }

    println!(
        "Successfully created and bound AF_PACKET socket (fd: {}) to interface '{}' (index: {}).",
        fd, interface_name, if_index
    );

    // 6. Safely wrap the raw file descriptor in an OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn main() -> Result<()> {
    // Get the interface name from the command line arguments.
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <INTERFACE_NAME>", args[0]);
        std::process::exit(1);
    }
    let interface_name = &args[1];

    // Use tokio_uring::start to run an async main function on a tokio-uring runtime.
    tokio_uring::start(async {
        // --- Setup Phase ---
        // Create the raw socket. This part requires privileges.
        let socket_fd = setup_ingress_socket(interface_name).expect("Failed to setup socket");

        // Convert the `OwnedFd` into a `tokio_uring::fs::File`. This is the
        // critical step that allows `tokio-uring` to manage the raw file descriptor.
        // We must wrap this in an `unsafe` block because we are responsible for
        // ensuring the file descriptor is valid.
        let uring_file = unsafe { tokio_uring::fs::File::from_raw_fd(socket_fd.as_raw_fd()) };

        // Pre-allocate a buffer for reading packets.
        // The `read_at` operation in tokio-uring takes ownership of the buffer and
        // returns it, so we need to re-assign it in the loop.
        let mut buffer = vec![0u8; 2048]; // A common MTU size

        println!("Starting to read packets using io_uring...");

        // --- I/O Loop ---
        loop {
            // Submit a `read_at` operation to the io_uring at offset 0.
            // For a raw socket, the offset is ignored, but the API requires it.
            // This does not block the thread. It submits the request to the kernel
            // and returns a Future.
            let read_future = uring_file.read_at(buffer, 0);

            // `await` the future. The runtime will suspend this task and work on
            // other things until the kernel signals that the read operation is complete.
            let (res, b) = read_future.await;

            // The buffer is returned along with the result. We take it back.
            buffer = b;
            let bytes_read = res.expect("Read operation failed");

            if bytes_read > 0 {
                // For this PoC, we just print the number of bytes read.
                // In the real application, this is where we would parse the
                // Ethernet frame and process the packet.
                println!("Read {} bytes from the wire.", bytes_read);
            }
        }
    })
}
