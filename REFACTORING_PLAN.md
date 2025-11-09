# Supervisor-Worker Refactoring Plan

## Current State (Broken)

### Problems Identified

1. **Control Plane Relay Stream Inconsistency**
   - Supervisor creates `_relay_command_listener` but doesn't use it
   - Control plane tries to `connect()` to a socket with no listener
   - Result: Connection failure

2. **EventFD Not Signaled**
   - Ingress loop waits for eventfd via io_uring
   - No code writes to eventfd when commands arrive
   - Result: Ingress blocks forever

3. **FD Lifecycle Violations**
   - File descriptors closed multiple times
   - Result: "IO Safety violation" crash

## Proposed Consistent Architecture

### FD Passing Flow

```
Supervisor Process
  │
  ├─> Control Plane Worker Process
  │     ├─ FD 3: supervisor_sock (passed via dup2)
  │     ├─ FD N: request_sock (passed via SCM_RIGHTS)
  │     └─ NO relay_command_socket connection needed!
  │
  └─> Data Plane Worker Process (one per core)
        ├─ FD 3: supervisor_sock (passed via dup2)
        ├─ FD N: request_sock (passed via SCM_RIGHTS)
        └─ FD M: command_sock (passed via SCM_RIGHTS)
```

### Socket Purposes

1. **supervisor_sock** (FD 3)
   - Supervisor → Worker commands (one-way)
   - Worker receives commands via this stream

2. **request_sock**
   - Bi-directional request/response
   - Used for `ListRules`, `GetStats`, etc.

3. **command_sock** (Data plane only)
   - Supervisor → Data plane commands
   - Used to dispatch `AddRule`, `RemoveRule` to specific workers
   - Framed with LengthDelimitedCodec

### Removed: relay_command_socket_path for Internal Use

- **OLD**: Control plane connected to `relay_command_socket_path`
- **NEW**: Control plane doesn't need this socket at all!
- **Rationale**: All communication is via FD passing, no need for filesystem sockets

The `relay_command_socket_path` can be removed from `ControlPlaneConfig` entirely.

## Implementation Changes

### 1. Fix Control Plane Initialization

**File**: `src/worker/mod.rs`

```rust
pub async fn run_control_plane(config: ControlPlaneConfig) -> Result<()> {
    drop_privileges(Uid::from_raw(config.uid), Gid::from_raw(config.gid), None)?;

    // Get FD 3 from supervisor
    let supervisor_sock = unsafe {
        let std_sock = std::os::unix::net::UnixStream::from_raw_fd(3);
        std_sock.set_nonblocking(true)?;
        UnixStream::from_std(std_sock)?
    };

    // Receive request socket via SCM_RIGHTS
    let request_fd = recv_fd(&supervisor_sock).await?;
    let request_stream = unsafe {
        let std_sock = std::os::unix::net::UnixStream::from_raw_fd(request_fd);
        std_sock.set_nonblocking(true)?;
        UnixStream::from_std(std_sock)?
    };

    // Use supervisor_sock as the command stream (no separate relay socket needed!)
    run_control_plane_generic(supervisor_sock, request_stream).await
}
```

**Changes**:
- Remove connection to `relay_command_socket_path`
- Use `supervisor_sock` directly for commands
- Simplify control plane to only receive via FD passing

### 2. Fix Control Plane Struct

**File**: `src/worker/control_plane.rs`

```rust
pub struct ControlPlane<S, R> {
    supervisor_stream: S,         // Commands from supervisor
    request_stream: R,            // Request/response channel
    shared_flows: SharedFlows,
}

impl<S: AsyncRead + AsyncWrite + Unpin, R: AsyncRead + AsyncWrite + Unpin>
    ControlPlane<S, R>
{
    pub fn new(supervisor_stream: S, request_stream: R) -> Self {
        let shared_flows = Arc::new(Mutex::new(HashMap::new()));
        Self {
            supervisor_stream,
            request_stream,
            shared_flows,
        }
    }
}
```

**Changes**:
- Remove `relay_command_tx` field (not needed)
- Control plane doesn't send relay commands, it handles supervisor commands
- Supervisor handles command distribution to data plane workers

### 3. Remove Unused Relay Socket Creation

**File**: `src/supervisor.rs`

```rust
pub async fn run(...) -> Result<()> {
    // ... existing code ...

    // REMOVE these lines (167-180):
    // if relay_command_socket_path.exists() { ... }
    // let _relay_command_listener = { ... };

    // The relay_command_socket_path is not needed for internal communication!
    // All worker communication uses FD passing.
}
```

### 4. Fix EventFD Integration in Data Plane

**File**: `src/worker/mod.rs`

The data plane command reception needs to signal the eventfd:

```rust
pub async fn run_data_plane<T: WorkerLifecycle>(
    config: DataPlaneConfig,
    lifecycle: T,
) -> Result<()> {
    // ... existing privilege drop code ...

    let supervisor_sock = /* ... get FD 3 ... */;
    let _request_fd = recv_fd(&supervisor_sock).await?;
    let command_fd = recv_fd(&supervisor_sock).await?;

    // Create eventfd for waking ingress loop
    let event_fd = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK)?;
    let event_fd_for_writer = event_fd.as_raw_fd();

    let (std_tx, std_rx) = std::sync::mpsc::channel::<RelayCommand>();
    let command_stream = /* ... setup command stream ... */;
    let mut framed = /* ... setup framed codec ... */;

    tokio::spawn(async move {
        use futures::StreamExt;
        while let Some(Ok(bytes)) = framed.next().await {
            match serde_json::from_slice::<RelayCommand>(&bytes) {
                Ok(command) => {
                    if std_tx.send(command).is_err() {
                        break;
                    }
                    // SIGNAL THE EVENTFD TO WAKE INGRESS!
                    let value: u64 = 1;
                    unsafe {
                        libc::write(
                            event_fd_for_writer,
                            &value as *const u64 as *const libc::c_void,
                            8
                        );
                    }
                }
                Err(e) => {
                    error!("Failed to deserialize RelayCommand: {}", e);
                }
            }
        }
    });

    // Pass event_fd to data plane task
    tokio::task::spawn_blocking(move || {
        lifecycle.run_data_plane_task(config, std_rx, event_fd)
    })
    .await?
    .context("Data plane task failed")
}
```

### 5. Update Data Plane Task Signature

The ingress loop needs to receive the eventfd:

```rust
pub trait WorkerLifecycle: Send + 'static {
    fn run_data_plane_task(
        &self,
        config: DataPlaneConfig,
        command_rx: std::sync::mpsc::Receiver<RelayCommand>,
        event_fd: EventFd,  // ADD THIS
    ) -> Result<()>;
}
```

## Testing Strategy

### Unit Tests to Add

1. **FD Passing Test** (`src/supervisor.rs`)
   - Verify FDs are passed correctly to workers
   - Verify no double-close violations
   - Verify FDs are usable after passing

2. **EventFD Signaling Test** (`src/worker/mod.rs`)
   - Verify eventfd is signaled when command arrives
   - Verify ingress loop wakes up on signal

3. **Control Plane Communication Test**
   - Verify control plane receives commands via supervisor_sock
   - Verify no connection attempt to relay_command_socket_path

### E2E Test Flow

1. Start supervisor
2. Supervisor spawns control plane worker
3. Supervisor spawns data plane worker
4. External client sends AddRule command
5. Supervisor receives command
6. Supervisor dispatches to data plane worker
7. Data plane worker adds rule
8. Verify rule is active

## CRITICAL DATA PLANE BUGS (Not in Original Plan)

### Bug 1: Ingress Buffer Mapping Corruption 🔴 SEVERE

**Location**: `src/worker/ingress.rs:269`

**Problem**:
```rust
// WRONG: Always processes recv_buffers[0] regardless of which buffer received data!
self.process_packet(&recv_buffers[0][..bytes_received])?;
```

The ingress loop processes multiple io_uring completions in a batch, but **always reads from the first buffer** (`recv_buffers[0]`). This means:
- Only the first packet in each batch is processed correctly
- All other packets use corrupted/stale data from buffer[0]
- Silent packet loss and data corruption under load

**Root Cause**: No mapping from `cqe` (completion queue entry) back to the buffer that was actually used for that recv operation.

**Fix**: Use io_uring `user_data` field to track buffer indices:

```rust
// In submit loop:
for (i, buf) in recv_buffers.iter_mut().enumerate().take(available_buffers) {
    let recv_op = opcode::Recv::new(
        types::Fd(self.af_packet_socket.as_raw_fd()),
        buf.as_mut_ptr(),
        buf.len() as u32,
    )
    .build()
    .user_data(PACKET_RECV_BASE + i as u64);  // Encode buffer index
    // ...
}

// In completion processing:
match cqe.user_data() {
    ud if ud >= PACKET_RECV_BASE && ud < PACKET_RECV_BASE + batch_size as u64 => {
        let buffer_idx = (ud - PACKET_RECV_BASE) as usize;
        let bytes_received = cqe.result();
        if bytes_received > 0 {
            self.process_packet(&recv_buffers[buffer_idx][..bytes_received as usize])?;
        }
    }
    COMMAND_NOTIFY => { /* ... */ }
    _ => { /* ... */ }
}
```

**Constants**:
```rust
const COMMAND_NOTIFY: u64 = 0;
const PACKET_RECV_BASE: u64 = 1;  // Buffer 0 = user_data 1, buffer 1 = user_data 2, etc.
```

### Bug 2: Unsound `unsafe` in Egress BufferPool 🔴 CRITICAL

**Location**: `src/worker/egress.rs:295-300` (approximately)

**Problem**:
```rust
// UNSOUND: Creates mutable alias to Arc-wrapped BufferPool!
let pool_ptr = Arc::as_ptr(&self.buffer_pool) as *mut BufferPool;
unsafe {
    (*pool_ptr).deallocate(buffer);
}
```

This violates Rust's aliasing rules:
- `BufferPool` is shared via `Arc` (immutable shared ownership)
- Code creates a **mutable raw pointer** and dereferences it
- No synchronization (mutex/atomic) protects this access
- Data race risk if BufferPool is accessed from multiple contexts

**Why it "works" now**: Pure luck. The egress loop is currently single-threaded and happens to have exclusive access. But this is **unsound** and a future time bomb.

**Fix Option 1 - Proper Ownership** (Recommended):
Don't share BufferPool via Arc. Each egress loop should **own** its BufferPool:

```rust
pub struct EgressLoop {
    buffer_pool: BufferPool,  // Owned, not Arc<BufferPool>
    // ...
}

// In completion handling:
self.buffer_pool.deallocate(buffer);  // Safe! No unsafe needed
```

**Fix Option 2 - Interior Mutability** (If sharing is truly needed):
```rust
pub struct EgressLoop {
    buffer_pool: Arc<Mutex<BufferPool>>,  // Proper synchronization
    // ...
}

// In completion handling:
self.buffer_pool.lock().unwrap().deallocate(buffer);
```

**Recommendation**: Use Option 1. The egress loop doesn't actually need to share the BufferPool. Each worker core should have its own isolated pool (as per D15 design decision).

### Bug 3: Blocking Syscall in Async Context ⚠️ ANTI-PATTERN

**Location**: Proposed eventfd signaling code

**Problem**:
```rust
// DON'T DO THIS:
tokio::spawn(async move {
    // ...
    unsafe {
        libc::write(event_fd_for_writer, ...);  // BLOCKING syscall in async task!
    }
});
```

While `write()` to an eventfd is typically fast, it's still a blocking syscall that can stall the Tokio scheduler.

**Fix**: Use `spawn_blocking` for the write:
```rust
tokio::spawn(async move {
    while let Some(Ok(bytes)) = framed.next().await {
        match serde_json::from_slice::<RelayCommand>(&bytes) {
            Ok(command) => {
                if std_tx.send(command).is_err() {
                    break;
                }
                // Spawn blocking task for eventfd write
                let event_fd = event_fd_for_writer;
                tokio::task::spawn_blocking(move || {
                    let value: u64 = 1;
                    unsafe {
                        libc::write(
                            event_fd,
                            &value as *const u64 as *const libc::c_void,
                            8
                        );
                    }
                });
            }
            Err(e) => { /* ... */ }
        }
    }
});
```

**Alternative**: Use async-compatible eventfd crate (e.g., `tokio-eventfd`) if available.

### Observation: Complex Command Pipeline

**Current Proposed Chain**:
```
UnixStream → Framed → tokio::spawn → serde_json →
std::sync::mpsc → eventfd → ingress loop → mpsc::try_recv
```

This is complex and crosses multiple synchronization boundaries. While workable, it introduces:
- Multiple points of failure
- Complex error propagation
- Difficult debugging

**Recommendation**: Accept this complexity for now, but ensure:
1. Comprehensive error logging at each stage
2. Unit tests for each component in isolation
3. Integration tests for the full pipeline
4. Consider future simplification with async-aware channels

## Migration Path

### Phase 1: Fix Critical Data Plane Bugs ⭐ HIGHEST PRIORITY

1. ✅ Identify ingress buffer mapping bug
2. ⏳ Fix ingress buffer mapping bug
3. ⏳ Add unit test for ingress multi-packet processing
4. ✅ Identify egress unsafe block bug
5. ⏳ Fix egress BufferPool ownership (remove Arc or add Mutex)
6. ⏳ Add unit test for egress buffer lifecycle
7. ⏳ Run unit tests to verify data plane correctness

### Phase 2: Fix IPC Architecture

1. ⏳ Write unit tests for FD passing lifecycle
2. ⏳ Fix control plane initialization (remove relay socket)
3. ⏳ Fix eventfd signaling with spawn_blocking
4. ⏳ Update control plane struct (remove relay_command_tx)
5. ⏳ Remove unused relay socket creation in supervisor
6. ⏳ Run unit tests to verify IPC correctness

### Phase 3: Integration and Cleanup

1. ⏳ Remove debug print statements
2. ⏳ Run all unit tests
3. ⏳ Run E2E tests
4. ⏳ Update documentation
5. ⏳ Code review for any remaining unsafe blocks

## Critical Success Criteria

Before considering the refactoring complete:

1. ✅ **Data Correctness**: Ingress can process multiple packets per batch correctly
2. ✅ **Memory Safety**: No unsound `unsafe` blocks remain
3. ✅ **IPC Reliability**: Workers communicate via FD passing without filesystem sockets
4. ✅ **Non-Blocking**: No blocking syscalls in async contexts
5. ✅ **Test Coverage**: Unit tests for all critical paths
6. ✅ **E2E Validation**: Full system test passes with traffic load
