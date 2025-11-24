# MCR Refactoring Plan: Three-Phase Pragmatic Simplification

**Status**: Planning Complete - Ready for Implementation
**Last Updated**: 2025-11-14
**Expected Impact**: -1,531 lines of code, eliminates 5 bug classes, +4.8% performance improvement

---

## Executive Summary

This refactoring addresses three core pain points in the MCR architecture:

1. **Complexity**: Impedance mismatch between concurrency models (tokio ↔ std::thread ↔ io_uring)
2. **Fragility**: Race conditions from custom adapter code (startup deadlock, shutdown hangs, logging bugs)
3. **Performance**: Unnecessary syscalls on the data path (100,000 eventfd writes/sec)

The plan consists of three independent phases that eliminate custom "adapter" code and replace it with standard kernel primitives managed directly by io_uring.

---

## Phase 1: Eliminate the Command Bridge

**Goal**: Remove the "Three-Primitive Bridge" (UnixStream → tokio task → mpsc → eventfd → io_uring)

**Impact**:
- ✅ Eliminates tokio runtime dependency from data plane worker
- ✅ Fixes startup deadlock bug (commit 21961ac)
- ✅ Fixes shutdown hang bugs
- ✅ Simplifies architecture (single threading model)

**Code Changes**:
- Lines deleted: ~200
- Lines added: ~230
- Net change: +30 lines (but much simpler)

### 1.1 Supervisor Side Modification

**File**: `src/supervisor.rs`

**Change**: Send TWO separate command streams to each data plane worker (one for ingress, one for egress) instead of one shared stream.

**Rationale**: Ingress and egress need independent command delivery to avoid races when reading from a shared FD.

```rust
// In spawn_data_plane_worker(), after creating socketpair:

// Create two command streams (one for ingress, one for egress)
let (ingress_cmd_supervisor, ingress_cmd_worker) = UnixStream::pair()?;
let (egress_cmd_supervisor, egress_cmd_worker) = UnixStream::pair()?;

// Pass worker-side FDs via SCM_RIGHTS (instead of single command_fd)
send_fd(&worker_sock, request_fd_worker.as_raw_fd())?;
send_fd(&worker_sock, ingress_cmd_worker.as_raw_fd())?;
send_fd(&worker_sock, egress_cmd_worker.as_raw_fd())?;

// Store supervisor-side FDs in Worker struct
worker.ingress_cmd_stream = Arc::new(tokio::sync::Mutex::new(ingress_cmd_supervisor));
worker.egress_cmd_stream = Arc::new(tokio::sync::Mutex::new(egress_cmd_supervisor));

// When broadcasting commands, write to BOTH streams
async fn broadcast_command(&self, cmd: &RelayCommand) -> Result<()> {
    for worker in &self.workers {
        let bytes = serialize_length_delimited(cmd)?;
        worker.ingress_cmd_stream.lock().await.write_all(&bytes).await?;
        worker.egress_cmd_stream.lock().await.write_all(&bytes).await?;
    }
    Ok(())
}
```

**Lines changed**: ~50-80 lines

---

### 1.2 Worker Side: Remove Tokio Runtime

**File**: `src/worker/mod.rs`

**Changes**:

1. **Delete** the `tokio::spawn` bridge task (lines 423-498)
2. **Delete** mpsc channels (lines 393-407)
3. **Delete** command eventfds (lines 390-392, 400-402)
4. **Receive THREE FDs** from supervisor instead of two

```rust
pub fn run_data_plane<T: WorkerLifecycle>(  // NOTE: No longer async!
    config: DataPlaneConfig,
    lifecycle: T,
) -> Result<()> {
    // ... (privilege drop, logging setup - unchanged)

    // Convert FD 3 to async UnixStream only for FD receiving
    let supervisor_sock = unsafe {
        let std_sock = std::os::unix::net::UnixStream::from_raw_fd(3);
        std_sock.set_nonblocking(true)?;
        tokio::net::UnixStream::from_std(std_sock)?
    };

    // Receive THREE FDs from supervisor
    let _request_fd = recv_fd(&supervisor_sock).await?;
    let ingress_cmd_fd = recv_fd(&supervisor_sock).await?;  // NEW
    let egress_cmd_fd = recv_fd(&supervisor_sock).await?;   // NEW

    // Convert to OwnedFd for passing to sync threads
    let ingress_cmd_fd = unsafe { OwnedFd::from_raw_fd(ingress_cmd_fd) };
    let egress_cmd_fd = unsafe { OwnedFd::from_raw_fd(egress_cmd_fd) };

    // NO MORE MPSC, NO MORE EVENTFDS, NO MORE TOKIO TASK!

    // Call run_data_plane_task directly (synchronous)
    lifecycle.run_data_plane_task(
        config,
        ingress_cmd_fd,
        egress_cmd_fd,
        logger,
    )
}
```

**Update WorkerLifecycle trait**:

```rust
trait WorkerLifecycle {
    fn run_data_plane_task(
        &self,
        config: DataPlaneConfig,
        ingress_cmd_fd: OwnedFd,   // Changed from IngressChannelSet
        egress_cmd_fd: OwnedFd,    // Changed from EgressChannelSet
        logger: Logger,
    ) -> Result<()>;
}
```

**Lines deleted**: ~150 (bridge task + channel setup)
**Lines changed**: ~20 (trait + function signatures)

---

### 1.3 Worker Side: Update run_data_plane_task

**File**: `src/worker/data_plane_integrated.rs`

```rust
pub fn run_data_plane(
    config: DataPlaneConfig,
    ingress_cmd_fd: OwnedFd,   // NEW: direct FD
    egress_cmd_fd: OwnedFd,    // NEW: direct FD
    logger: Logger,
) -> Result<()> {
    let buffer_pool = Arc::new(BufferPool::new(/* ... */));
    let egress_queue = Arc::new(SegQueue::new());

    // Create eventfd for egress wakeup (data path - keep this)
    let egress_wakeup_eventfd = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK)?;
    let egress_wakeup_fd = egress_wakeup_eventfd.as_raw_fd();

    let egress_channel = EgressQueueWithWakeup::new(
        egress_queue.clone(),
        egress_wakeup_fd,
    );

    let ingress_loop = IngressLoop::new(
        config.clone(),
        buffer_pool.clone(),
        egress_channel,
        ingress_cmd_fd,  // NEW: pass FD directly
        logger.clone(),
    )?;

    let egress_loop = EgressLoop::new(
        EgressConfig::default(),
        buffer_pool.clone(),
        egress_wakeup_eventfd,
        egress_cmd_fd,   // NEW: pass FD directly
        logger.clone(),
    )?;

    // Spawn threads (unchanged)
    let ingress_handle = std::thread::spawn(move || {
        ingress_loop.run()
    });

    let egress_handle = std::thread::spawn(move || {
        egress_loop.run(&egress_queue)
    });

    ingress_handle.join().unwrap()?;
    egress_handle.join().unwrap()?;

    Ok(())
}
```

**Lines changed**: ~10

---

### 1.4 Ingress Loop: Add Command Stream Reading

**File**: `src/worker/ingress.rs`

**Add new struct for command parsing** (or place in separate file like `src/worker/command_reader.rs`):

```rust
/// Helper for parsing length-delimited JSON commands from a stream
struct CommandReader {
    buffer: Vec<u8>,
    pending_frame_len: Option<usize>,
}

impl CommandReader {
    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
            pending_frame_len: None,
        }
    }

    /// Process newly read bytes and return any complete commands
    fn process_bytes(&mut self, new_bytes: &[u8]) -> Result<Vec<RelayCommand>> {
        self.buffer.extend_from_slice(new_bytes);
        let mut commands = Vec::new();

        loop {
            // Parse frame length (4 bytes, big-endian)
            if self.pending_frame_len.is_none() {
                if self.buffer.len() < 4 {
                    break; // Need more data
                }
                let len_bytes: [u8; 4] = self.buffer[0..4].try_into()?;
                let frame_len = u32::from_be_bytes(len_bytes) as usize;
                self.pending_frame_len = Some(frame_len);
            }

            // Parse frame data
            if let Some(frame_len) = self.pending_frame_len {
                if self.buffer.len() >= 4 + frame_len {
                    // Full frame available
                    let frame = &self.buffer[4..4 + frame_len];
                    let cmd: RelayCommand = serde_json::from_slice(frame)?;
                    commands.push(cmd);

                    // Remove frame from buffer
                    self.buffer.drain(0..4 + frame_len);
                    self.pending_frame_len = None;
                } else {
                    break; // Need more data
                }
            }
        }

        Ok(commands)
    }
}
```

**Update IngressLoop struct**:

```rust
pub struct IngressLoop<B, E: EgressChannel> {
    // ... existing fields ...

    // REMOVE these:
    // command_rx: mpsc::Receiver<RelayCommand>,
    // command_event_fd: EventFd,

    // ADD these:
    cmd_stream_fd: OwnedFd,
    cmd_reader: CommandReader,
    cmd_buffer: Vec<u8>,  // Buffer for io_uring reads

    // ... rest unchanged ...
}
```

**Update constructor**:

```rust
impl IngressLoop<Arc<BufferPool>, EgressQueueWithWakeup> {
    pub fn new(
        config: DataPlaneConfig,
        buffer_pool: Arc<BufferPool>,
        egress_channel: EgressQueueWithWakeup,
        cmd_stream_fd: OwnedFd,  // NEW: replaces command_rx + event_fd
        logger: Logger,
    ) -> Result<Self> {
        let ring = IoUring::new(config.queue_depth)?;

        // ... existing socket setup ...

        Ok(Self {
            ring,
            socket_fd,
            buffer_pool,
            egress_channel,
            cmd_stream_fd,
            cmd_reader: CommandReader::new(),
            cmd_buffer: vec![0u8; 4096],
            logger,
            rule: None,
            shutdown_requested: false,
            // ... other fields ...
        })
    }
}
```

**Submit command read in run() method**:

```rust
const COMMAND_USER_DATA: u64 = 0;
const PACKET_RECV_BASE: u64 = 1;

pub fn run(&mut self) -> Result<()> {
    self.logger.info(Facility::Ingress, "Waiting for initial configuration...");

    // CRITICAL: Block on first command to avoid startup deadlock
    // Submit command read and wait for it
    self.submit_command_read()?;
    self.ring.submit_and_wait(1)?;

    // Process first command (AddRule)
    loop {
        let cq = self.ring.completion();
        for cqe in cq {
            if cqe.user_data() == COMMAND_USER_DATA {
                let bytes_read = cqe.result();
                if bytes_read > 0 {
                    let commands = self.cmd_reader.process_bytes(
                        &self.cmd_buffer[..bytes_read as usize]
                    )?;

                    for cmd in commands {
                        self.handle_command(cmd)?;
                    }

                    // Re-submit for next command
                    self.submit_command_read()?;
                }
                break;
            }
        }

        // If we have a rule, we're initialized
        if self.rule.is_some() {
            break;
        }

        self.ring.submit_and_wait(1)?;
    }

    self.logger.info(Facility::Ingress, "Initial configuration complete, entering main loop");

    // Submit initial packet receives
    for i in 0..self.config.batch_size {
        self.submit_recv(PACKET_RECV_BASE + i as u64)?;
    }

    // Main loop
    loop {
        self.ring.submit_and_wait(1)?;
        self.process_cqe_batch()?;

        if self.shutdown_requested {
            break;
        }
    }

    Ok(())
}

fn submit_command_read(&mut self) -> Result<()> {
    let read_op = opcode::Read::new(
        types::Fd(self.cmd_stream_fd.as_raw_fd()),
        self.cmd_buffer.as_mut_ptr(),
        self.cmd_buffer.len(),
    )
    .build()
    .user_data(COMMAND_USER_DATA);

    unsafe {
        self.ring.submission().push(&read_op)?;
    }
    Ok(())
}
```

**Handle command completions in process_cqe_batch()**:

```rust
fn process_cqe_batch(&mut self) -> Result<()> {
    let cq = self.ring.completion();

    for cqe in cq {
        let user_data = cqe.user_data();
        let result = cqe.result();

        match user_data {
            COMMAND_USER_DATA => {
                if result > 0 {
                    // Parse commands from buffer
                    let commands = self.cmd_reader.process_bytes(
                        &self.cmd_buffer[..result as usize]
                    )?;

                    for cmd in commands {
                        self.handle_command(cmd)?;
                    }

                    // Re-submit read for next command
                    self.submit_command_read()?;
                } else if result == 0 {
                    // Stream closed - supervisor disconnected
                    self.logger.info(Facility::Ingress, "Command stream closed");
                    self.shutdown_requested = true;
                } else {
                    // Error
                    self.logger.error(
                        Facility::Ingress,
                        &format!("Command read error: {}", std::io::Error::from_raw_os_error(-result))
                    );
                }
            }

            user_data if user_data >= PACKET_RECV_BASE => {
                // ... existing packet handling ...
                if result > 0 {
                    self.handle_packet_recv(result as usize)?;
                    // Re-submit recv
                    self.submit_recv(user_data)?;
                } else {
                    // Error handling
                }
            }

            _ => {
                self.logger.error(
                    Facility::Ingress,
                    &format!("Unknown user_data: {}", user_data)
                );
            }
        }
    }

    Ok(())
}

fn handle_command(&mut self, cmd: RelayCommand) -> Result<()> {
    match cmd {
        RelayCommand::AddRule(rule) => {
            self.logger.info(Facility::Ingress, &format!("Adding rule: {:?}", rule));
            self.rule = Some(rule);
        }
        RelayCommand::Shutdown => {
            self.logger.info(Facility::Ingress, "Shutdown requested");
            self.shutdown_requested = true;
        }
        _ => {
            self.logger.debug(Facility::Ingress, &format!("Ignoring command: {:?}", cmd));
        }
    }
    Ok(())
}
```

**Lines added**: ~120 (CommandReader struct + integration)
**Lines deleted**: ~30 (mpsc/eventfd handling)
**Net change**: +90 lines

---

### 1.5 Egress Loop: Mirror Ingress Changes

**File**: `src/worker/egress.rs`

Apply the same pattern as ingress:
- Add CommandReader (or import from shared module if extracted)
- Replace mpsc + eventfd fields with cmd_stream_fd, cmd_reader, cmd_buffer
- Update constructor signature
- Submit command read to io_uring in run()
- Handle COMMAND_USER_DATA completions in process_cqe_batch()
- Keep SHUTDOWN_USER_DATA handling (for the data path eventfd)

```rust
// Update struct
pub struct EgressLoop<T, B> {
    // ... existing fields ...

    // REMOVE:
    // command_rx: mpsc::Receiver<RelayCommand>,
    // (shutdown_event_fd stays - that's for data path wakeup)

    // ADD:
    cmd_stream_fd: OwnedFd,
    cmd_reader: CommandReader,
    cmd_buffer: Vec<u8>,
}

// Update constructor
impl EgressLoop<EgressWorkItem, Arc<BufferPool>> {
    pub fn new(
        config: EgressConfig,
        buffer_pool: Arc<BufferPool>,
        shutdown_event_fd: EventFd,  // Keep this - for data path
        cmd_stream_fd: OwnedFd,       // NEW
        logger: Logger,
    ) -> Result<Self> {
        // ... existing setup ...

        Ok(Self {
            // ... existing fields ...
            cmd_stream_fd,
            cmd_reader: CommandReader::new(),
            cmd_buffer: vec![0u8; 4096],
        })
    }
}

// Update run() method
const COMMAND_USER_DATA: u64 = 1;  // Different from SHUTDOWN_USER_DATA
const SHUTDOWN_USER_DATA: u64 = u64::MAX;

pub fn run(&mut self, packet_rx: &SegQueue<EgressWorkItem>) -> Result<()> {
    // Submit persistent reads on both FDs
    self.submit_shutdown_read()?;
    self.submit_command_read()?;
    self.ring.submit()?;

    loop {
        // Single blocking point
        self.ring.submit_and_wait(1)?;

        // Process completions
        self.process_cqe_batch()?;

        // ... existing shutdown check and packet processing ...
    }
}

fn submit_command_read(&mut self) -> Result<()> {
    let read_op = opcode::Read::new(
        types::Fd(self.cmd_stream_fd.as_raw_fd()),
        self.cmd_buffer.as_mut_ptr(),
        self.cmd_buffer.len(),
    )
    .build()
    .user_data(COMMAND_USER_DATA);

    unsafe {
        self.ring.submission().push(&read_op)?;
    }
    Ok(())
}

// In process_cqe_batch(), add handling for COMMAND_USER_DATA
// Similar to ingress implementation
```

**Lines changed**: ~90 (similar to ingress)

---

### 1.6 Main Entry Point: Remove Tokio Runtime

**File**: `src/main.rs`

**Change**:

```rust
// BEFORE (lines 119-128):
// D1, D7: The worker process uses a `tokio-uring` runtime
// to drive the high-performance data plane.
tokio_uring::start(async {
    if let Err(e) = worker::run_data_plane(config, worker::DefaultWorkerLifecycle).await {
        eprintln!("Data Plane worker process failed: {}", e);
        std::process::exit(1);
    }
});

// AFTER:
// Note: Worker still needs tokio briefly to receive FDs via async UnixStream,
// but we'll use a minimal runtime just for that
use tokio::runtime::Runtime;

let rt = Runtime::new()?;
if let Err(e) = rt.block_on(async {
    worker::run_data_plane(config, worker::DefaultWorkerLifecycle).await
}) {
    eprintln!("Data Plane worker process failed: {}", e);
    std::process::exit(1);
}

// Or even simpler - keep tokio_uring::start() but run_data_plane becomes sync internally
tokio_uring::start(async {
    if let Err(e) = worker::run_data_plane(config, worker::DefaultWorkerLifecycle).await {
        eprintln!("Data Plane worker process failed: {}", e);
        std::process::exit(1);
    }
});

// run_data_plane is still async ONLY for the FD receiving part,
// then calls synchronous run_data_plane_task
```

**Lines changed**: ~5 (minimal - may not need changes if we keep the async wrapper for FD receiving)

---

### Phase 1 Completion Checklist

- [ ] Supervisor sends two command streams per worker
- [ ] Supervisor broadcasts commands to both streams
- [ ] Worker receives three FDs (request, ingress_cmd, egress_cmd)
- [ ] Worker deletes tokio bridge task
- [ ] Worker deletes mpsc channels and command eventfds
- [ ] Ingress adds CommandReader and io_uring command handling
- [ ] Egress adds CommandReader and io_uring command handling
- [ ] Tests updated for new signatures
- [ ] Integration tests pass
- [ ] No startup deadlocks observed
- [ ] Shutdown works cleanly

---

## Phase 2: Replace Shared Memory Logging

**Goal**: Delete ~1,700 lines of custom shared memory ring buffer code and replace with pipe-based JSON logging

**Impact**:
- ✅ Eliminates 3 bug classes (collisions, cleanup failures, race conditions)
- ✅ Massive simplification (-1,581 lines net)
- ⚠️ Minor performance cost (10x slower per log, but negligible since logging is infrequent)

**Code Changes**:
- Lines deleted: ~1,741
- Lines added: ~160
- Net change: -1,581 lines

### 2.1 Supervisor Side: Create Pipes for Logging

**File**: `src/supervisor.rs`

**Add to spawn_data_plane_worker()**:

```rust
use nix::unistd::pipe;

fn spawn_data_plane_worker(&mut self, core_id: u32) -> Result<()> {
    // DELETE: SharedMemoryLogManager creation (no longer needed)

    // CREATE: Pipe for logging BEFORE spawning
    let (log_read_fd, log_write_fd) = pipe()?;

    // ... existing socketpair creation ...

    let mut cmd = Command::new(current_exe()?);
    cmd.args(/* ... existing args, remove supervisor_pid since no shm ... */);

    // Redirect stderr to pipe write-end
    unsafe {
        cmd.pre_exec(move || {
            // Close read end in child (not needed)
            nix::unistd::close(log_read_fd).ok();

            // Redirect stderr (FD 2) to pipe write end
            nix::unistd::dup2(log_write_fd, 2)?;

            // Close original write end (now duplicated to FD 2)
            nix::unistd::close(log_write_fd)?;

            Ok(())
        });
    }

    let child = cmd.spawn()?;

    // Close write end in parent (child has it via FD 2)
    nix::unistd::close(log_write_fd)?;

    // Store read end for consuming logs
    let worker = Worker {
        pid: child.id(),
        log_pipe_fd: Some(log_read_fd),
        // ... other fields ...
    };

    self.workers.insert(child.id(), worker);

    // Spawn async task to consume this worker's logs
    self.spawn_log_consumer(child.id(), log_read_fd)?;

    Ok(())
}
```

**Lines added**: ~30
**Lines deleted**: ~20 (SharedMemoryLogManager setup)

---

### 2.2 Supervisor Side: Consume Logs Asynchronously

**File**: `src/supervisor.rs`

**Add log consumer method**:

```rust
use tokio::io::{AsyncBufReadExt, BufReader};
use std::os::unix::io::{AsRawFd, FromRawFd};

fn spawn_log_consumer(&self, worker_pid: u32, log_fd: RawFd) -> Result<()> {
    // Convert to tokio async file
    let std_file = unsafe { std::fs::File::from_raw_fd(log_fd) };
    let tokio_file = tokio::fs::File::from_std(std_file);
    let mut reader = BufReader::new(tokio_file).lines();

    tokio::spawn(async move {
        while let Ok(Some(line)) = reader.next_line().await {
            Self::handle_worker_log(worker_pid, &line);
        }
        eprintln!("[Supervisor] Worker {} log stream closed", worker_pid);
    });

    Ok(())
}

fn handle_worker_log(worker_pid: u32, line: &str) {
    // Try to parse as JSON log entry
    if let Ok(entry) = serde_json::from_str::<JsonLogEntry>(line) {
        // Pretty print structured log
        eprintln!(
            "[Worker {}] [{}] [{}] {}",
            worker_pid,
            entry.timestamp,
            entry.level,
            entry.message
        );

        // Optionally log key-value pairs
        if !entry.fields.is_empty() {
            eprintln!("  Fields: {:?}", entry.fields);
        }
    } else {
        // Non-JSON line (e.g., panic message, raw eprintln!)
        eprintln!("[Worker {}] {}", worker_pid, line);
    }
}

#[derive(serde::Deserialize)]
struct JsonLogEntry {
    timestamp: String,
    level: String,
    #[serde(default)]
    target: String,
    message: String,
    #[serde(default)]
    fields: std::collections::HashMap<String, serde_json::Value>,
}
```

**Lines added**: ~50

---

### 2.3 Worker Side: Use Standard JSON Logging

**File**: `src/worker/mod.rs`

**Replace DataPlaneLogging with tracing**:

```rust
// DELETE THIS (lines ~311-360):
// eprintln!("[DataPlane] About to attach to shared memory logging...");
// let core_id = config.core_id.ok_or_else(...)?;
// let logging = DataPlaneLogging::attach(config.supervisor_pid, core_id as u8)?;
// let logger = logging.logger(Facility::DataPlane).ok_or_else(...)?;

// REPLACE WITH THIS:
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

// Configure JSON logging to stderr (which is redirected to pipe)
tracing_subscriber::registry()
    .with(
        fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .with_target(false)
            .with_current_span(false)
            .with_span_list(false)
    )
    .init();

eprintln!("[DataPlane] JSON logging initialized");

// Create logger adapter that wraps tracing
let logger = Logger::from_tracing();

logger.info(
    Facility::DataPlane,
    &format!("Data plane worker started on core {:?}", config.core_id),
);
```

**Update Logger to wrap tracing** (in `src/logging/logger.rs`):

```rust
use tracing;

impl Logger {
    /// Create logger that outputs to tracing (which outputs JSON to stderr)
    pub fn from_tracing() -> Self {
        Self {
            // No ring buffer needed
            backend: LogBackend::Tracing,
        }
    }

    pub fn info(&self, facility: Facility, message: &str) {
        tracing::info!(
            facility = ?facility,
            message = message
        );
    }

    pub fn debug(&self, facility: Facility, message: &str) {
        tracing::debug!(
            facility = ?facility,
            message = message
        );
    }

    pub fn error(&self, facility: Facility, message: &str) {
        tracing::error!(
            facility = ?facility,
            message = message
        );
    }

    pub fn critical(&self, facility: Facility, message: &str) {
        tracing::error!(  // No "critical" in tracing, use error
            severity = "CRITICAL",
            facility = ?facility,
            message = message
        );
    }

    pub fn trace(&self, facility: Facility, message: &str) {
        tracing::trace!(
            facility = ?facility,
            message = message
        );
    }
}

enum LogBackend {
    Tracing,
    // Old: RingBuffer(Arc<dyn RingBuffer>), etc.
}
```

**Lines changed**: ~50 (replace DataPlaneLogging with tracing setup)
**Lines added**: ~40 (Logger::from_tracing implementation)

---

### 2.4 Delete Obsolete Code

**Files to DELETE entirely**:

```bash
git rm src/logging/ringbuffer.rs      # 873 lines
git rm src/logging/integration.rs     # 368 lines
```

**Files to heavily refactor**:

**File**: `src/logging/consumer.rs`

Delete:
- `SharedBlockingConsumer` (~150 lines)
- All shared memory related code

Keep (if still used by supervisor/control plane):
- `AsyncConsumer` (for supervisor's own MPSC logging if applicable)
- `StdoutSink`, `StderrSink`

**File**: `src/logging/logger.rs`

Delete:
- `RingBuffer` trait implementations (~50 lines)
- `from_spsc()`, `from_mpsc()`, `from_shared()` constructors (~60 lines)
- Ring buffer related fields and logic (~100 lines)

Keep:
- `Logger` struct (now wraps tracing)
- Public API methods (info, debug, error, etc.) - but reimplement to call tracing
- `Facility` and `Severity` enums (still useful for structured logging)

**File**: `src/logging/mod.rs`

Update exports:
```rust
// DELETE:
// pub use integration::{DataPlaneLogging, SupervisorLogging, ControlPlaneLogging, SharedMemoryLogManager};
// pub use ringbuffer::{SPSCRingBuffer, MPSCRingBuffer, SharedSPSCRingBuffer};

// KEEP/UPDATE:
pub use logger::{Logger, Facility, Severity};
pub use entry::LogEntry;  // May still be useful for JSON deserialization
```

**Total lines deleted**: ~1,741 lines

---

### 2.5 Update Dependencies

**File**: `Cargo.toml`

**Add**:
```toml
[dependencies]
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
```

**Consider removing** (if no longer used):
```toml
# May no longer need these if only used for shared memory:
# shared_memory = "..."  (already removed based on git history)
```

---

### Phase 2 Completion Checklist

- [ ] Supervisor creates pipes for each worker
- [ ] Supervisor redirects worker stderr to pipe
- [ ] Supervisor spawns log consumer tasks
- [ ] Supervisor parses JSON logs from pipes
- [ ] Worker uses tracing with JSON formatter
- [ ] Worker Logger wraps tracing
- [ ] All worker log calls output to stderr (JSON)
- [ ] Deleted src/logging/ringbuffer.rs
- [ ] Deleted src/logging/integration.rs
- [ ] Refactored src/logging/consumer.rs (removed shared memory code)
- [ ] Refactored src/logging/logger.rs (simplified)
- [ ] Added tracing dependencies to Cargo.toml
- [ ] Integration tests pass
- [ ] Logs appear correctly in supervisor output
- [ ] No shared memory files left in /dev/shm after shutdown

---

## Phase 3: Optimize Data Path Performance

**Goal**: Eliminate 95%+ of eventfd writes on ingress→egress path using conditional signaling

**Impact**:
- ✅ **2-5% CPU saved** at high packet rates
- ✅ Reduces eventfd syscalls from 100,000/sec to 3,000-20,000/sec
- ✅ Simple implementation (one atomic flag)

**Code Changes**:
- Lines added: ~20
- No lines deleted

### 3.1 Add Sleeping Flag

**File**: `src/worker/data_plane_integrated.rs`

```rust
use std::sync::atomic::{AtomicBool, Ordering};

pub fn run_data_plane(
    config: DataPlaneConfig,
    ingress_cmd_fd: OwnedFd,
    egress_cmd_fd: OwnedFd,
    logger: Logger,
) -> Result<()> {
    // ... existing buffer pool, queue setup ...

    // NEW: Shared flag for conditional signaling
    let egress_sleeping = Arc::new(AtomicBool::new(false));

    // Create egress wakeup eventfd (still needed, but used less frequently)
    let egress_wakeup_eventfd = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK)?;
    let egress_wakeup_fd = egress_wakeup_eventfd.as_raw_fd();

    let egress_channel = EgressQueueWithWakeup::new(
        egress_queue.clone(),
        egress_wakeup_fd,
        egress_sleeping.clone(),  // NEW: pass flag to ingress
    );

    let ingress_loop = IngressLoop::new(
        config.clone(),
        buffer_pool.clone(),
        egress_channel,
        ingress_cmd_fd,
        logger.clone(),
    )?;

    let egress_loop = EgressLoop::new(
        EgressConfig::default(),
        buffer_pool.clone(),
        egress_wakeup_eventfd,
        egress_cmd_fd,
        egress_sleeping.clone(),  // NEW: pass flag to egress
        logger.clone(),
    )?;

    // ... spawn threads (unchanged) ...
}
```

**Lines changed**: ~5

---

### 3.2 Update EgressQueueWithWakeup

**File**: `src/worker/ingress.rs`

```rust
use std::sync::atomic::{AtomicBool, Ordering};

pub struct EgressQueueWithWakeup {
    queue: Arc<SegQueue<EgressWorkItem>>,
    wakeup_fd: i32,
    egress_sleeping: Arc<AtomicBool>,  // NEW
}

impl EgressQueueWithWakeup {
    pub fn new(
        queue: Arc<SegQueue<EgressWorkItem>>,
        wakeup_fd: i32,
        egress_sleeping: Arc<AtomicBool>,  // NEW
    ) -> Self {
        Self {
            queue,
            wakeup_fd,
            egress_sleeping,
        }
    }
}

impl EgressChannel for EgressQueueWithWakeup {
    type Item = EgressWorkItem;

    fn send(&self, item: Self::Item) -> Result<(), ()> {
        // Always enqueue the item
        self.queue.push(item);

        // OPTIMIZATION: Only signal if egress is sleeping
        // This reduces syscalls from 100k/sec to ~3-20k/sec at high throughput
        if self.egress_sleeping.load(Ordering::Acquire) {
            // Signal egress thread to wake up - CRITICAL: must be robust
            let value: u64 = 1;
            loop {
                let ret = unsafe {
                    libc::write(
                        self.wakeup_fd,
                        &value as *const u64 as *const libc::c_void,
                        8,
                    )
                };
                if ret == 8 {
                    break; // Success
                }
                if ret < 0 {
                    let errno = std::io::Error::last_os_error();
                    if errno.raw_os_error() == Some(libc::EAGAIN)
                        || errno.raw_os_error() == Some(libc::EWOULDBLOCK)
                    {
                        // Buffer is full, spin briefly and retry
                        std::hint::spin_loop();
                        continue;
                    }
                    // A real error occurred - this is extremely rare but fatal
                    return Err(());
                }
            }
        }
        // else: egress is awake and will drain queue before sleeping

        Ok(())
    }
}
```

**Lines changed**: ~10 (add field, add conditional check)

---

### 3.3 Update Egress Loop

**File**: `src/worker/egress.rs`

```rust
use std::sync::atomic::{AtomicBool, Ordering};

pub struct EgressLoop<T, B> {
    // ... existing fields ...
    sleeping_flag: Arc<AtomicBool>,  // NEW
}

impl EgressLoop<EgressWorkItem, Arc<BufferPool>> {
    pub fn new(
        config: EgressConfig,
        buffer_pool: Arc<BufferPool>,
        shutdown_event_fd: EventFd,
        cmd_stream_fd: OwnedFd,
        sleeping_flag: Arc<AtomicBool>,  // NEW
        logger: Logger,
    ) -> Result<Self> {
        // ... existing setup ...

        Ok(Self {
            // ... existing fields ...
            sleeping_flag,
        })
    }

    pub fn run(&mut self, packet_rx: &SegQueue<EgressWorkItem>) -> Result<()> {
        // Submit initial reads
        self.submit_shutdown_read()?;
        self.submit_command_read()?;
        self.ring.submit()?;

        loop {
            // Mark as sleeping BEFORE blocking
            // Race window: ingress might enqueue here and see sleeping=true,
            // which is CORRECT - it will signal and we'll wake immediately
            self.sleeping_flag.store(true, Ordering::Release);

            // Single blocking point
            self.ring.submit_and_wait(1)?;

            // Mark as awake IMMEDIATELY after waking
            // Any packets enqueued from this point will be caught by drain loop below
            self.sleeping_flag.store(false, Ordering::Release);

            // Process completions (commands, shutdown, send completions)
            self.process_cqe_batch()?;

            // Check shutdown
            if self.shutdown_requested() {
                // Drain remaining packets
                while let Some(packet) = packet_rx.pop() {
                    self.add_destination(&packet.interface_name, packet.dest_addr)?;
                    self.queue_packet(packet);
                }
                if !self.is_queue_empty() {
                    self.send_batch()?;
                }
                break;
            }

            // Drain packet queue
            // This catches packets that arrived while we were awake OR after we set sleeping=false
            while let Some(packet) = packet_rx.pop() {
                self.add_destination(&packet.interface_name, packet.dest_addr)?;
                self.queue_packet(packet);
            }

            // Send if we have packets
            if !self.is_queue_empty() {
                self.send_batch()?;
            }
        }

        self.print_final_stats();
        Ok(())
    }
}
```

**Lines changed**: ~5 (add field, two atomic stores)

---

### 3.4 Race Condition Analysis (For Documentation)

**Document why this is safe**:

```text
Scenario 1: Ingress enqueues while egress is awake
- Egress: sleeping = false
- Ingress: push(item), check sleeping == false, SKIP eventfd write ✅
- Egress: Will drain queue in while loop before sleeping again ✅
- Result: No packet loss, one syscall saved ✅

Scenario 2: Ingress enqueues while egress is sleeping
- Egress: sleeping = true, blocked in submit_and_wait()
- Ingress: push(item), check sleeping == true, WRITE eventfd ✅
- Egress: Wakes up, processes packet ✅
- Result: Packet delivered correctly ✅

Scenario 3: Race during sleep transition
- Egress: sleeping.store(true) [line above submit_and_wait]
- Ingress: push(item), check sleeping == true, WRITE eventfd ✅
- Egress: submit_and_wait() will wake immediately (eventfd is readable) ✅
- Result: Extra wakeup, but no packet loss ✅

Scenario 4: Race during wake transition
- Egress: Wakes from submit_and_wait(), hasn't cleared flag yet
- Ingress: push(item), check sleeping == true, WRITE eventfd (unnecessary) ⚠️
- Egress: sleeping.store(false), drains queue
- Result: Extra eventfd write, but no correctness issue ✅

Conclusion: All races are benign. Worst case is extra syscall (same as current).
Best case (common case at high throughput) is 95%+ syscall reduction.
```

---

### Phase 3 Completion Checklist

- [ ] Created `Arc<AtomicBool>` sleeping flag in data_plane_integrated.rs
- [ ] Passed flag to both EgressQueueWithWakeup and EgressLoop
- [ ] Updated EgressQueueWithWakeup::send() to check flag before writing eventfd
- [ ] Updated EgressLoop::run() to set flag before/after blocking
- [ ] Verified race conditions are benign (see analysis above)
- [ ] Performance testing shows syscall reduction
- [ ] Integration tests still pass
- [ ] No packet loss observed under load

---

## Testing Strategy

### Unit Tests

**Phase 1**:
- [ ] Test CommandReader parses single frame correctly
- [ ] Test CommandReader handles partial frames (multiple reads)
- [ ] Test CommandReader handles multiple frames in one read
- [ ] Mock tests for IngressLoop command handling
- [ ] Mock tests for EgressLoop command handling

**Phase 2**:
- [ ] Test JSON log entry serialization/deserialization
- [ ] Test supervisor log parsing handles malformed JSON gracefully
- [ ] Test Logger::from_tracing() methods produce correct JSON

**Phase 3**:
- [ ] Test sleeping flag reduces syscalls (can mock with counter)
- [ ] Test race conditions don't cause packet loss (stress test)

---

### Integration Tests

**All Phases**:
- [ ] `baseline_50k.sh` - Basic forwarding test (should pass unchanged)
- [ ] Startup/shutdown cycles (test for deadlocks)
- [ ] Multiple workers on different cores
- [ ] Worker crash recovery (supervisor respawns)
- [ ] High throughput test (100k+ pps) to verify performance

**Phase 2 specific**:
- [ ] Verify logs appear in supervisor output
- [ ] Verify no /dev/shm files left after shutdown
- [ ] Test worker crash leaves no orphaned resources

**Phase 3 specific**:
- [ ] Benchmark eventfd syscall count before/after (using strace or BPF)
- [ ] Verify packet forwarding accuracy at high load

---

### Performance Benchmarks

**Metrics to measure**:
1. **Throughput**: packets/sec at saturation
2. **CPU usage**: % per core at various loads
3. **Latency**: packet forwarding latency (p50, p99)
4. **Syscall count**: eventfd writes per second (Phase 3)

**Expected results**:
- Phase 1: Negligible performance change (command path is rare)
- Phase 2: <1% CPU increase for logging overhead (acceptable)
- Phase 3: 2-5% CPU reduction at high load, 95%+ fewer eventfd syscalls

---

## Rollback Plan

If issues arise during implementation:

**Phase 1**:
- Can be rolled back independently (revert commits)
- Main risk: CommandReader buffer handling bugs
- Mitigation: Extensive unit tests for framing logic

**Phase 2**:
- Can be rolled back independently
- Main risk: Loss of structured logging metadata
- Mitigation: JSON format preserves all metadata

**Phase 3**:
- Lowest risk, easiest to rollback (just remove flag and conditional)
- Can be disabled with a feature flag if needed

**All phases are independent and can be rolled back without affecting others.**

---

## Implementation Timeline

**Estimated effort**:
- Phase 1: 2-3 days (most complex, touches many files)
- Phase 2: 1-2 days (mostly deletion, simple additions)
- Phase 3: 0.5-1 day (simple addition)

**Total**: 4-6 days for complete refactoring

**Recommended approach**:
- Implement all three phases in sequence
- Create one PR per phase for easier review
- Or combine Phases 1+3 (both touch data path) and do Phase 2 separately

---

## Success Criteria

This refactoring is successful if:

1. ✅ All integration tests pass
2. ✅ No performance regression (preferably small improvement)
3. ✅ Code is simpler (measured by LoC reduction and cyclomatic complexity)
4. ✅ No new bugs introduced (soak test for 24+ hours)
5. ✅ Startup deadlock and shutdown hang bugs eliminated (structural fix)
6. ✅ Shared memory bugs eliminated (code deleted)
7. ✅ Eventfd syscall overhead reduced by >90% (Phase 3)

---

## Notes and Considerations

### Why This Order?

The phases are designed to be independent, but this order is recommended:

1. **Phase 2 first** (if doing sequentially): Highest value (most code deleted), lowest risk
2. **Phase 1 next**: Addresses architectural complexity, enables removing tokio
3. **Phase 3 last**: Optional performance polish

### Alternative: Combined Implementation

Phases 1 and 3 both touch the data path and can be combined:
- Update data_plane_integrated.rs once with both command FDs and sleeping flag
- Update ingress.rs once with both CommandReader and conditional signaling
- Update egress.rs once with both CommandReader and sleeping flag

This avoids touching the same files twice.

### Known Trade-offs

**Phase 2 (Logging)**:
- 10x slower per log entry (2μs vs 200ns)
- At 1000 logs/sec: 2ms CPU time = 0.2% overhead
- Acceptable because production logging is infrequent (Info level and above)

**Phase 3 (Performance)**:
- Adds atomic load per packet (~5ns overhead)
- Saves 200-500ns syscall in 95%+ of cases
- Net win: ~200-500ns saved per packet at high throughput

### Future Optimizations

After this refactoring, consider:
1. AF_PACKET socket FD passing from supervisor (enables full privilege drop)
2. io_uring msg_ring for ingress→egress (requires kernel 5.18+)
3. eBPF-based packet filtering (offload rule matching to kernel)

---

## Appendix: File Modification Summary

| File | Phase 1 | Phase 2 | Phase 3 | Net LoC Δ |
|------|---------|---------|---------|-----------|
| `src/supervisor.rs` | +80 | +80 | 0 | +160 |
| `src/worker/mod.rs` | -150, +20 | -50, +40 | 0 | -140 |
| `src/worker/data_plane_integrated.rs` | +10 | 0 | +5 | +15 |
| `src/worker/ingress.rs` | +90 | 0 | +10 | +100 |
| `src/worker/egress.rs` | +90 | 0 | +5 | +95 |
| `src/main.rs` | -3 | 0 | 0 | -3 |
| `src/logging/logger.rs` | 0 | -200, +40 | 0 | -160 |
| `src/logging/ringbuffer.rs` | 0 | -873 | 0 | -873 |
| `src/logging/integration.rs` | 0 | -368 | 0 | -368 |
| `src/logging/consumer.rs` | 0 | -300 | 0 | -300 |
| `Cargo.toml` | 0 | +5 | 0 | +5 |
| **TOTAL** | **+30** | **-1,581** | **+20** | **-1,531** |

---

## Status Tracking

**Current Status**: ✅ Planning Complete

**Phase 1**: ⏸️ Not Started
**Phase 2**: ⏸️ Not Started
**Phase 3**: ⏸️ Not Started

**Blockers**: None

**Next Steps**:
1. Review this plan for completeness
2. Choose implementation order (sequential vs. combined)
3. Create feature branch
4. Begin Phase 1 implementation (or Phase 2 if doing sequential)

---

*Document version: 1.0*
*Last updated: 2025-11-14*
