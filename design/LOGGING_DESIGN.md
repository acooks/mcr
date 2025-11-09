# Multicast Relay Logging System Design

## Implementation Status

**Phase 1: COMPLETE** ✅ (commits d72eb93, 99423bd)
- Lock-free SPSC and MPSC ring buffers
- LogEntry (256 bytes, cache-line optimized)
- Severity levels (RFC 5424) and Facilities
- Comprehensive test suite (35 tests)

**Phase 2: COMPLETE** ✅ (commit 99423bd)
- Logger API with severity helpers
- LogRegistry for managing per-facility ring buffers
- Logging macros (`log_info!`, `log_error!`, `log_kv!`, etc.)
- Consumer tasks (AsyncConsumer, BlockingConsumer)
- Pluggable output sinks (stdout, stderr, custom)

**Phase 3: COMPLETE** ✅ (commits 2833697, eb97bce, f05a370)
- Supervisor integrated with structured logging (15+ log sites)
- RuleDispatcher using logging for warnings
- Workers migrated from old `log` crate to eprintln!
- All 89 tests passing with new logging system

**Phase 4: PENDING** ⏳
- Additional output sinks (file, syslog)
- Runtime log level filtering
- Metrics extraction

## Quick Start Example

```rust
use multicast_relay::logging::*;

// 1. Create a logging registry (in supervisor/worker startup)
let registry = LogRegistry::new_mpsc();  // For async/multi-threaded
// or: LogRegistry::new_spsc(core_id)   // For data plane workers

// 2. Get a logger for a facility
let logger = registry.get_logger(Facility::Supervisor).unwrap();

// 3. Start consumer task to output logs
tokio::spawn(async move {
    AsyncConsumer::stdout(/* ringbuffers */).run().await;
});

// 4. Log messages
log_info!(logger, Facility::Supervisor, "Worker started");
log_error!(logger, Facility::Ingress, "Failed to parse packet");

// 5. Structured logging
log_kv!(logger, Severity::Info, Facility::Ingress, "Packet received",
    "src" => "10.0.0.1", "port" => "5000");
```

See `examples/logging_demo.rs` for a complete working example.

## Overview

This document defines a high-performance, ring-buffer based logging system for the Multicast Relay (MCR) project, inspired by syslog facilities/severity and FRR's per-thread buffering approach.

## Design Goals

1. **Bounded Memory**: Fixed-size ring buffers prevent unbounded memory growth
2. **High Performance**: Lock-free per-thread/per-core buffers for data plane workers
3. **Zero Allocation**: Pre-allocated buffers in hot paths (data plane)
4. **Structured Logging**: Support key-value pairs for machine-readable logs
5. **Flexible Output**: Console, file, syslog, metrics extraction
6. **Runtime Control**: Dynamic log level filtering per facility
7. **Low Latency**: Critical for io_uring data plane operations

## Severity Levels

Based on RFC 5424 syslog standard (0-7, lower is more severe):

```rust
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Emergency = 0,  // System unusable (supervisor crash, data plane fatal)
    Alert     = 1,  // Immediate action required (capability loss, socket failure)
    Critical  = 2,  // Critical conditions (worker restart, buffer exhaustion)
    Error     = 3,  // Error conditions (packet drop, rule dispatch failure)
    Warning   = 4,  // Warning conditions (high latency, approaching limits)
    Notice    = 5,  // Significant normal condition (worker startup, rule added)
    Info      = 6,  // Informational (packet forwarded, stats update)
    Debug     = 7,  // Debug-level messages (verbose packet traces)
}
```

### Severity Guidelines

| Severity | Use Case | Examples |
|----------|----------|----------|
| Emergency | Process cannot continue | Supervisor panic, all workers dead |
| Alert | Requires immediate admin action | Lost CAP_NET_RAW, AF_PACKET socket failure |
| Critical | Component degraded/restarting | Worker crash, control plane reconnect |
| Error | Operation failed | Packet parsing error, failed rule dispatch |
| Warning | Potential problem | Buffer pool 90% full, worker backoff |
| Notice | Normal significant event | Worker started, interface configured |
| Info | Routine information | Rule added, stats snapshot |
| Debug | Detailed diagnostic | Packet hexdump, io_uring CQE details |

## Facilities

Facilities identify the component generating the log message. Unlike syslog's generic facilities, MCR uses domain-specific facilities:

```rust
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Facility {
    // === Supervisor (runs in tokio async context) ===
    Supervisor    = 0,   // Supervisor core logic, worker lifecycle
    RuleDispatch  = 1,   // Rule distribution to workers
    ControlSocket = 2,   // Unix domain socket control interface

    // === Control Plane Worker (tokio async) ===
    ControlPlane  = 3,   // Control plane request/response handling

    // === Data Plane Worker (io_uring/blocking) ===
    DataPlane     = 4,   // Data plane coordinator/integration
    Ingress       = 5,   // AF_PACKET receive, packet parsing
    Egress        = 6,   // UDP transmit via io_uring
    BufferPool    = 7,   // Buffer allocation/deallocation
    PacketParser  = 8,   // Packet header parsing

    // === Cross-cutting Concerns ===
    Stats         = 9,   // Metrics and monitoring
    Security      = 10,  // Capabilities, privilege drop, FD passing
    Network       = 11,  // Socket operations, interface queries

    // === Testing and Utilities ===
    Test          = 12,  // Test harness and fixtures
    Unknown       = 255, // Fallback for uncategorized messages
}
```

### Facility Characteristics

| Facility | Threading Model | Volume | Buffering Strategy |
|----------|----------------|--------|-------------------|
| Supervisor | Tokio async | Low | Shared buffer with mutex |
| RuleDispatch | Tokio async | Low-Medium | Shared buffer |
| ControlPlane | Tokio async | Low-Medium | Per-worker buffer |
| DataPlane | Dedicated thread | Medium | Per-core ring buffer |
| Ingress | io_uring (blocking) | **Very High** | Per-core ring buffer (lock-free) |
| Egress | io_uring (blocking) | High | Per-core ring buffer (lock-free) |
| BufferPool | Shared (mutex) | Medium | Shared buffer |
| PacketParser | Called from Ingress | **Very High** | Same as Ingress |
| Stats | Tokio async | Low | Shared buffer |
| Security | Various | Low | Shared buffer |

## Ring Buffer Architecture

### Buffer Design

Each facility has its own ring buffer (or per-core ring buffer for data plane):

```rust
// Lock-free SPSC ring buffer (single producer, single consumer)
pub struct SPSCRingBuffer {
    entries: Box<[UnsafeCell<LogEntry>]>,
    capacity: usize,           // Power of 2 for efficient modulo
    write_seq: AtomicU64,      // Monotonic sequence number
    read_seq: AtomicU64,       // Reader position
    overruns: AtomicU64,       // Count of lost messages
    core_id: u8,               // CPU core ID
}

// Lock-free MPSC ring buffer (multiple producers, single consumer)
pub struct MPSCRingBuffer {
    entries: Box<[UnsafeCell<LogEntry>]>,
    capacity: usize,
    write_seq: AtomicU64,      // CAS for multiple writers
    read_seq: AtomicU64,
    overruns: AtomicU64,
    cas_failures: AtomicU64,   // Contention metric
}

// Log entry: 256 bytes, cache-line optimized (4×64 bytes)
#[repr(C, align(64))]
pub struct LogEntry {
    // Cache Line 0 (64 bytes): HOTTEST - accessed on every read/write
    state: AtomicU8,           // EMPTY/WRITING/READY state machine
    severity: Severity,
    facility: Facility,
    message_len: u8,
    kv_count: u8,
    core_id: u8,
    _pad1: [u8; 2],

    timestamp_ns: u64,         // Monotonic nanoseconds
    sequence: u64,             // Global sequence number
    process_id: u32,
    thread_id: u32,            // Truncated from full thread ID

    message_start: [u8; 32],   // First 32 bytes of message

    // Cache Lines 1-2 (128 bytes): HOT - message continuation
    message_cont: [u8; 128],   // Total message: 160 bytes

    // Cache Line 3 (64 bytes): WARM - structured logging
    kvs: [KeyValue; 2],        // 2 key-value pairs
}

// KeyValue: 32 bytes (fits exactly 2 per cache line)
#[repr(C)]
pub struct KeyValue {
    key_len: u8,
    value_len: u8,
    _pad: [u8; 2],
    key: [u8; 8],              // Short keys: "worker", "core", "port"
    value: [u8; 20],           // Values: "eth0", "10.0.0.1", "5555"
}
```

**Cache Line Optimization:** The 256-byte structure is designed for optimal cache performance:
- **Line 0** contains all fields accessed during write/read operations
- **Lines 1-2** contain the bulk of the message data
- **Line 3** contains structured logging data (accessed less frequently)
- Zero padding waste

### Buffer Sizing

Optimized for small systems (1-2 CPUs) with 256-byte entries:

| Facility | Buffer Size | Memory per Buffer | Rationale |
|----------|-------------|-------------------|-----------|
| Ingress (per-core) | 16,384 entries | 4 MB | Highest frequency facility |
| Egress (per-core) | 4,096 entries | 1 MB | High frequency transmit |
| PacketParser (per-core) | 4,096 entries | 1 MB | Called from ingress path |
| DataPlane | 2,048 entries | 512 KB | Coordinator messages |
| Supervisor | 1,024 entries | 256 KB | Low-frequency control |
| ControlPlane | 1,024 entries | 256 KB | Low-frequency async |
| Other facilities | 512 entries | 128 KB | Default for utilities |

**Memory Footprint Examples:**
- **2-core system**: ~12.5 MB total
  - Ingress: 2 × 4 MB = 8 MB
  - Egress: 2 × 1 MB = 2 MB
  - Other: ~2.5 MB
- **1-core system**: ~6.5 MB total
- **4-core system**: ~25 MB total

### Lock-Free Single-Producer Single-Consumer (SPSC)

For data plane workers (io_uring threads):
- **Single Writer**: Each io_uring thread writes only to its own per-core buffer
- **Single Reader**: Background consumer thread reads from all buffers
- **Atomic Operations**: `write_pos` and `read_pos` use `Ordering::Relaxed` for writer, `Ordering::Acquire`/`Release` for coordination
- **Overflow Handling**: On full buffer, increment `overruns` counter, drop message (preserve latency)

### Multi-Producer Single-Consumer (MPSC)

For supervisor and async workers:
- **Multiple Writers**: Tokio tasks may log concurrently
- **Atomic CAS**: Use `compare_and_swap` on `write_pos`
- **Fallback**: On contention, can fall back to immediate console output

## API Design

### Macro-Based Interface (Implemented)

```rust
// Severity-specific macros
log_info!(logger, Facility::Supervisor, "Starting workers");
log_error!(logger, Facility::Ingress, "Failed to parse packet");
log_debug!(logger, Facility::PacketParser, "Packet details");
log_warning!(logger, Facility::BufferPool, "Pool near capacity");

// Structured logging with key-value pairs (max 2 pairs)
log_kv!(
    logger,
    Severity::Info,
    Facility::Ingress,
    "Packet received",
    "src" => "10.0.0.1",
    "port" => "5000"
);
```

### Programmatic Interface (Implemented)

```rust
// Logger: lightweight handle for writing logs
pub struct Logger {
    ringbuffer: Arc<dyn RingBuffer>,  // SPSC or MPSC
}

impl Logger {
    // Severity helpers
    pub fn info(&self, facility: Facility, message: &str);
    pub fn error(&self, facility: Facility, message: &str);
    pub fn debug(&self, facility: Facility, message: &str);
    // ... all 8 severity levels

    // Generic methods
    pub fn log(&self, severity: Severity, facility: Facility, message: &str);
    pub fn log_kv(&self, severity: Severity, facility: Facility,
                  message: &str, kvs: &[(&str, &str)]);
}

// LogRegistry: creates and manages ring buffers per facility
pub struct LogRegistry {
    loggers: HashMap<Facility, Logger>,
}

impl LogRegistry {
    // For supervisor/control plane (async, multiple writers)
    pub fn new_mpsc() -> Self;

    // For data plane workers (single thread, single writer)
    pub fn new_spsc(core_id: u8) -> Self;

    pub fn get_logger(&self, facility: Facility) -> Option<Logger>;
}
```

### Consumer Interface (Implemented)

```rust
// Output sink trait
pub trait LogSink: Send {
    fn write_entry(&mut self, entry: &LogEntry);
    fn flush(&mut self);
}

// Async consumer for tokio
pub struct AsyncConsumer {
    ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>,
    sink: Box<dyn LogSink>,
    running: Arc<AtomicBool>,
}

impl AsyncConsumer {
    pub fn stdout(ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>) -> Self;
    pub fn stderr(ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>) -> Self;
    pub async fn run(self);  // Runs until stopped
}

// Blocking consumer for threads
pub struct BlockingConsumer {
    ringbuffers: Vec<(Facility, Arc<SPSCRingBuffer>)>,
    sink: Box<dyn LogSink>,
    running: Arc<AtomicBool>,
}

impl BlockingConsumer {
    pub fn stdout(ringbuffers: Vec<(Facility, Arc<SPSCRingBuffer>)>) -> Self;
    pub fn run(self);  // Blocks until stopped
}

// Built-in consumers
pub struct StdoutConsumer { /* formats and prints to stdout */ }
pub struct SyslogConsumer { /* sends to syslog daemon */ }
pub struct FileConsumer { /* writes to rotating log files */ }
pub struct MetricsConsumer { /* extracts error counts for Prometheus */ }
```

## Performance Optimizations

### 1. Compile-Time Filtering

```rust
// In Cargo.toml
[features]
log-level-info = []    # Compile out Debug logs
log-level-notice = []  # Compile out Info and Debug
log-level-error = []   # Only Error and above

// In code
#[cfg(any(debug_assertions, not(feature = "log-level-info")))]
macro_rules! log_debug { ... }
```

### 2. Zero-Allocation Fast Path

```rust
// Pre-allocated thread-local scratch buffer
thread_local! {
    static LOG_SCRATCH: RefCell<String> = RefCell::new(String::with_capacity(256));
}

// Format into scratch buffer, then copy to ring buffer
```

### 3. Async Batch Flush

```rust
// Background consumer reads in batches
pub struct ConsumerTask {
    interval: Duration,  // e.g., 100ms
    batch_size: usize,   // e.g., 1000 entries
}

impl ConsumerTask {
    async fn run(&mut self) {
        loop {
            tokio::time::sleep(self.interval).await;
            for buffer in &self.buffers {
                self.consume_batch(buffer, self.batch_size);
            }
        }
    }
}
```

### 4. Critical Message Bypass

For Emergency/Alert messages, bypass ring buffer and write directly to stderr:

```rust
if severity <= Severity::Alert {
    // Immediately flush to stderr
    eprintln!("[{}] [{}] {}", facility, severity, message);
}
// Also write to ring buffer for archival
```

## Runtime Configuration

### CLI Flags

```bash
multicast_relay \
  --log-level=info \                          # Global minimum level
  --log-facility-level="Ingress=debug" \      # Per-facility override
  --log-output=stdout \                       # Output destination
  --log-buffer-size=65536 \                   # Override buffer size
  --log-format=json                           # json|text|syslog
```

### Environment Variables

```bash
MCR_LOG_LEVEL=debug
MCR_LOG_INGRESS=trace      # Even more verbose than debug
MCR_LOG_FORMAT=json
MCR_LOG_FILE=/var/log/mcr/relay.log
```

### Dynamic Runtime Control via Control Socket

```bash
# Query current log levels
mcr-control log status

# Change log level for facility
mcr-control log set Ingress debug
mcr-control log set Supervisor info

# Dump ring buffer to file
mcr-control log dump /tmp/mcr-debug.log

# Reset overrun counters
mcr-control log reset-stats
```

## Output Format Examples

### Text Format (Human-Readable)

```
2025-11-09T13:45:23.123456789Z [Supervisor] INFO [pid:1234 tid:5678] Starting 4 workers
2025-11-09T13:45:23.145678901Z [DataPlane] NOTICE [pid:1235 tid:5679 core:0] Worker started worker_id=dp-0 interface=eth0
2025-11-09T13:45:24.234567890Z [Ingress] ERROR [pid:1235 tid:5679 core:0] Failed to parse packet src_ip=192.168.1.1 error="invalid checksum"
```

### JSON Format (Machine-Readable)

```json
{
  "timestamp": "2025-11-09T13:45:23.123456789Z",
  "timestamp_ns": 1731163523123456789,
  "facility": "Supervisor",
  "severity": "INFO",
  "severity_code": 6,
  "process_id": 1234,
  "thread_id": 5678,
  "core_id": null,
  "message": "Starting 4 workers",
  "kvs": {}
}
```

### Syslog Format (RFC 5424)

```
<14>1 2025-11-09T13:45:23.123456Z hostname mcr 1234 Supervisor - Starting 4 workers
<13>1 2025-11-09T13:45:24.234567Z hostname mcr 1235 Ingress - Failed to parse packet [src_ip="192.168.1.1" error="invalid checksum"]
```

## Migration Strategy

### Phase 1: Core Infrastructure ✅ COMPLETE
1. ✅ Implement `SPSCRingBuffer`, `MPSCRingBuffer` (lock-free, cache-optimized)
2. ✅ Implement `LogEntry` (256 bytes, 4 cache lines)
3. ✅ Implement `Severity` (RFC 5424) and `Facility` (MCR-specific)
4. ✅ Comprehensive test suite (35 tests, all passing)

### Phase 2: Logger and Consumer ✅ COMPLETE
1. ✅ Implement `Logger` with severity helper methods
2. ✅ Implement `LogRegistry` (per-facility ring buffers)
3. ✅ Implement logging macros: `log_info!`, `log_error!`, `log_kv!`, etc.
4. ✅ Implement `AsyncConsumer` and `BlockingConsumer`
5. ✅ Implement output sinks (stdout, stderr, custom)

### Phase 3: Integration ⏳ PENDING
1. Create supervisor `LogRegistry` with MPSC buffers
2. Start `AsyncConsumer` task in supervisor
3. Replace `println!`/`eprintln!` in supervisor with logging macros
4. Create worker `LogRegistry` with SPSC buffers (data plane) or MPSC (control plane)
5. Start consumer tasks in workers
6. Replace existing logging calls in workers
7. Add feature flags for compile-time control (`--features logging`)

### Phase 4: Advanced Features ⏳ PENDING
1. Implement `FileConsumer` with rotation support
2. Implement `SyslogConsumer` (local/remote)
3. Add runtime log level filtering via control socket
4. Add `MetricsConsumer` for extracting counters from log stream
5. Add sampling for high-frequency events (`log_sampled!` macro)

## Testing Strategy

1. **Unit Tests**: Ring buffer wrap-around, overflow handling, atomic operations
2. **Concurrency Tests**: Multi-threaded logging stress test
3. **Performance Tests**: Benchmark logging overhead (latency, throughput)
4. **Integration Tests**: Verify log output in E2E tests
5. **Chaos Tests**: Random log floods, verify no crashes/memory leaks

## Performance Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Logging latency (data plane) | < 100ns | Minimal impact on packet processing |
| Logging latency (control plane) | < 1µs | Acceptable for async operations |
| Memory overhead | < 100 MB | Bounded ring buffers |
| Log throughput | > 1M msgs/sec | High-frequency ingress events |
| Overrun rate | < 0.01% | Rarely drop messages |

## Open Questions

1. **Timestamp Source**: `CLOCK_MONOTONIC` vs `CLOCK_REALTIME`?
   - **Recommendation**: Use `CLOCK_MONOTONIC` (no NTP jumps) and provide converter for display

2. **Cross-Process Correlation**: How to correlate logs from supervisor + N workers?
   - **Recommendation**: Include process ID, worker ID, and monotonic boot timestamp

3. **Log Rotation**: Who handles log file rotation?
   - **Recommendation**: External tool (`logrotate`) or built-in rotation by file size/time

4. **Syslog Integration**: Send to local syslog daemon or remote syslog server?
   - **Recommendation**: Support both via configuration

5. **Trace-Level Logging**: Do we need severity level 8 (more verbose than Debug)?
   - **Recommendation**: Start with 0-7, add later if needed

6. **Sampling**: For extremely high-frequency events (e.g., every packet), sample logs?
   - **Recommendation**: Add `log_sampled!` macro with 1/N sampling ratio

## Related Work

- **slog-rs**: Structured logging for Rust (inspiration for KV pairs)
- **tracing**: Async-aware structured logging (complex for io_uring)
- **log**: De-facto standard Rust logging facade (too generic)
- **FRR zlog**: Per-thread buffers with batching (inspiration for ring buffers)
- **systemd journal**: Structured logging with indexing (too heavy)

## References

- RFC 5424: The Syslog Protocol
- RFC 3164: BSD Syslog Protocol (obsolete)
- FRR Logging Documentation: https://docs.frrouting.org/projects/dev-guide/en/latest/logging.html
- Linux `io_uring` performance considerations
- Rust `std::sync::atomic` documentation
