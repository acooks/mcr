# File Descriptor Passing PoC

## Overview

This experiment demonstrates **file descriptor passing** between processes using Unix domain sockets and the `SCM_RIGHTS` ancillary data mechanism. This is a fundamental technique used in the multicast_relay supervisor architecture for privilege separation.

## What Problem Does This Solve?

In multicast_relay, we need to:

1. **Open privileged sockets** (AF_PACKET raw sockets require `CAP_NET_RAW`)
2. **Drop privileges** for security (workers shouldn't run with elevated rights)
3. **Allow workers to use** these privileged sockets

**Solution**: The supervisor opens sockets with privileges, then transfers ownership to unprivileged workers via file descriptor passing.

## How It Works

### The SCM_RIGHTS Mechanism

`SCM_RIGHTS` (Socket Control Message - Rights) is a kernel mechanism for transferring file descriptors between processes through Unix domain sockets.

```
┌──────────────────────────────────────────────────────────────┐
│  Process A (Supervisor)         Process B (Worker)           │
│                                                               │
│  1. Opens privileged socket                                  │
│     fd_socket = socket(AF_PACKET, ...)                       │
│                                                               │
│  2. Sends FD through Unix socket                             │
│     sendmsg(unix_sock, {                                     │
│       .msg_control = SCM_RIGHTS,                             │
│       .msg_controllen = CMSG_LEN(sizeof(fd_socket)),         │
│       .cmsg_data = [fd_socket]                               │
│     })                                                        │
│                        │                                      │
│                        ├────────────────────>                │
│                        │                                      │
│                        │                      3. Receives FD  │
│                        │                         recvmsg()   │
│                        │                         → new_fd    │
│                        │                                      │
│  4. Can close its FD   │                      5. Uses socket │
│     close(fd_socket)   │                         send(new_fd)│
│     (worker still OK)  │                                      │
└──────────────────────────────────────────────────────────────┘
```

### Key Properties

1. **Different FD numbers**: The FD number changes between processes, but both refer to the same underlying kernel file description

2. **Independent lifetime**: Either process can close its FD without affecting the other's access

3. **Shared state**: Both FDs share the same file offset, flags, and kernel state

4. **Requires Unix sockets**: Only works over Unix domain sockets (AF_UNIX), not TCP/IP

## Code Structure

### `send_fd(socket_fd, fd_to_send)`

Sends a file descriptor through a Unix domain socket:

```rust
fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> Result<(), Error> {
    let data = [1u8];  // Dummy byte (sendmsg requires data)
    let iov = [IoSlice::new(&data)];

    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];  // <-- THE MAGIC

    sendmsg(socket_fd, &iov, &cmsg, MsgFlags::empty(), None)?;
    Ok(())
}
```

**Key components**:
- `iov`: I/O vector with at least one byte of data
- `cmsg`: Control message array containing `SCM_RIGHTS` with the FD(s)
- The kernel handles the FD translation and security checks

### `recv_fd(socket_fd)`

Receives a file descriptor from a Unix domain socket:

```rust
fn recv_fd(socket_fd: RawFd) -> Result<RawFd, Error> {
    let mut data = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut data)];

    // Allocate buffer for control message
    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);

    let msg = recvmsg(socket_fd, &mut iov, Some(&mut cmsg_buffer), MsgFlags::empty())?;

    // Extract FD from control messages
    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            return Ok(fds[0]);
        }
    }

    Err("No FD received".into())
}
```

**Key components**:
- `cmsg_buffer`: Pre-allocated buffer sized by `cmsg_space!` macro
- `msg.cmsgs()`: Iterator over received control messages
- `ScmRights`: Extracted file descriptors

## Demonstrations

### Demo 1: Basic FD Passing

Shows parent process creating a file, then passing the FD to a child process:

1. Parent creates file and writes to it
2. Parent sends FD to child via Unix socket
3. Parent closes its FD
4. Child receives different FD number (same file)
5. Child writes to file using received FD

**Result**: Both parent and child successfully wrote to the same file with different FD numbers.

### Demo 2: Supervisor Pattern

Simulates the multicast_relay architecture:

1. **Supervisor** (privileged) opens "socket"
2. **Supervisor** spawns worker process
3. **Supervisor** transfers socket FD to worker
4. **Supervisor** closes socket and drops privileges
5. **Worker** (unprivileged) uses the socket

**Result**: Worker can use privileged socket without ever having privileges itself.

## Running the Demonstration

```bash
cd experiments/poc_fd_passing

# Build
cargo build

# Run
cargo run

# You'll see detailed output showing:
# - FD numbers in parent vs child
# - Sending and receiving operations
# - Both processes using the same underlying file
```

### Expected Output

```
╔════════════════════════════════════════════════════════╗
║   File Descriptor Passing - Educational Demonstration  ║
║   Showing SCM_RIGHTS mechanism used in multicast_relay ║
╚════════════════════════════════════════════════════════╝

=== File Descriptor Passing Demonstration ===

[PARENT] Creating Unix domain socket pair for communication...
[PARENT] Socket pair created: parent_fd=3, child_fd=4
[PARENT] Creating a test file to pass to child...
[PARENT] Created file with FD: 5
[PARENT] Forking child process...
[PARENT] Forked child with PID: 12345
[PARENT] Sending file descriptor to child...
[SENDER] Sending file descriptor 5 via socket 3
[SENDER] Sent 1 bytes with FD in ancillary data
[PARENT] File descriptor sent successfully!

[CHILD] Child process started (PID: 12345)
[CHILD] Receiving file descriptor from parent...
[RECEIVER] Waiting to receive file descriptor via socket 4...
[RECEIVER] Received 1 bytes, parsing ancillary data...
[RECEIVER] Found SCM_RIGHTS with 1 file descriptor(s)
[RECEIVER] Extracted FD: 3
[CHILD] Successfully received FD: 3
[CHILD] Using received file descriptor to write to file...
[CHILD] Successfully wrote to file using received FD
[CHILD] Child process exiting

[PARENT] Final file content:
  This file was created by the parent process (PID: 12344)
  Original file descriptor: 5
  This line was written by the child process (PID: 12345)
  Received file descriptor: 3
  Note: FD number changed from parent's 5 to child's 3

✅ Demonstration complete!
```

## Safety Considerations

### Why `unsafe` is Required

File descriptor passing requires `unsafe` code because:

1. **FFI boundary**: Uses raw libc system calls (`sendmsg`/`recvmsg`)
2. **Raw file descriptors**: Operating on `RawFd` (just integers)
3. **Kernel contracts**: Relies on kernel guarantees not expressible in Rust's type system
4. **Resource management**: Manual lifetime management of kernel resources

### Safety Invariants

When using FD passing, you must ensure:

```rust
// ✅ SAFE: Proper usage
let (sock_a, sock_b) = socketpair(...)?;
let file = File::open("test.txt")?;
send_fd(sock_a, file.as_raw_fd())?;
// file is still valid here

// ❌ UNSAFE: Use after close
let fd = file.as_raw_fd();
drop(file);  // Closes the FD
send_fd(sock, fd)?;  // BUG: Sending invalid FD!

// ❌ UNSAFE: Double close
let received_fd = recv_fd(sock)?;
close(received_fd)?;
close(received_fd)?;  // BUG: Double close!

// ✅ SAFE: Using File wrapper for RAII
let received_fd = recv_fd(sock)?;
let file = unsafe { File::from_raw_fd(received_fd) };
// file automatically closed on drop
```

## How multicast_relay Uses This

In the multicast_relay architecture:

```rust
// Supervisor (privileged)
fn supervisor_main() {
    // 1. Open privileged sockets
    let ingress_socket = create_af_packet_socket()?;  // Needs CAP_NET_RAW
    let egress_socket = create_af_packet_socket()?;

    // 2. Create Unix socket pair for worker communication
    let (supervisor_sock, worker_sock) = socketpair(...)?;

    // 3. Spawn worker process
    match fork()? {
        Parent { child } => {
            // 4. Send sockets to worker
            send_fd(supervisor_sock, ingress_socket.as_raw_fd())?;
            send_fd(supervisor_sock, egress_socket.as_raw_fd())?;

            // 5. Drop privileges
            drop_capabilities()?;

            // 6. Supervise worker
            monitor_worker(child)?;
        }
        Child => {
            // Worker process runs unprivileged from birth
            worker_main(worker_sock)?;
        }
    }
}

// Worker (unprivileged)
fn worker_main(command_sock: RawFd) {
    // Receive sockets from supervisor
    let ingress_fd = recv_fd(command_sock)?;
    let egress_fd = recv_fd(command_sock)?;

    // Use them without needing privileges
    let ingress = unsafe { Socket::from_raw_fd(ingress_fd) };
    let egress = unsafe { Socket::from_raw_fd(egress_fd) };

    // Run data plane with received sockets
    run_data_plane(ingress, egress)?;
}
```

## References

### Man Pages
- `unix(7)` - Unix domain sockets
- `cmsg(3)` - Control message ancillary data
- `sendmsg(2)` - Send message with ancillary data
- `recvmsg(2)` - Receive message with ancillary data

### Kernel Documentation
- [SCM_RIGHTS implementation](https://elixir.bootlin.com/linux/latest/source/net/unix/af_unix.c)
- [File descriptor passing in Unix sockets](https://man7.org/linux/man-pages/man7/unix.7.html)

### Rust Crates
- [`nix`](https://docs.rs/nix/) - Safe Rust bindings to Unix APIs
- Provides `sendmsg`, `recvmsg`, `ControlMessage`, etc.

## Learning Outcomes

After running this experiment, you should understand:

✅ How file descriptors can be transferred between processes
✅ The role of `SCM_RIGHTS` in ancillary data
✅ Why FD numbers differ between processes
✅ How this enables privilege separation architectures
✅ Safety considerations when working with raw FDs
✅ The connection to multicast_relay's supervisor design

## Next Steps

- Read `src/supervisor.rs` - See real FD passing in production code
- Read `src/worker/mod.rs` - See worker receiving FDs
- Read `ARCHITECTURE_DIAGRAMS.md` - See how this fits the big picture
- Experiment: Try passing multiple FDs at once
- Experiment: Try passing socket FDs instead of file FDs
