# Multicast Relay Logging System Design

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
pub struct RingBuffer {
    entries: Box<[LogEntry]>,  // Fixed-size array
    capacity: usize,           // Power of 2 for efficient modulo
    write_pos: AtomicUsize,    // Writer position (monotonic)
    read_pos: AtomicUsize,     // Reader position (monotonic)
    overruns: AtomicU64,       // Count of lost messages
}

pub struct LogEntry {
    timestamp: u64,            // Monotonic nanoseconds since boot
    severity: Severity,
    facility: Facility,
    core_id: u8,               // CPU core (0-255), 255 = unknown
    process_id: u32,           // Worker process ID
    thread_id: u64,            // Thread ID for correlation
    message: [u8; 256],        // Fixed-size message buffer
    message_len: u16,          // Actual message length
    kvs: [KeyValue; 8],        // Up to 8 key-value pairs
    kv_count: u8,              // Number of key-value pairs
}

pub struct KeyValue {
    key: [u8; 32],
    key_len: u8,
    value: [u8; 96],
    value_len: u8,
}
```

### Buffer Sizing

Different facilities have different log volumes:

| Facility | Buffer Size | Rationale |
|----------|-------------|-----------|
| Ingress/Egress (per-core) | 65,536 entries | ~17 MB/core, handles burst traffic |
| DataPlane | 8,192 entries | ~2 MB, coordinator messages |
| Supervisor/ControlPlane | 4,096 entries | ~1 MB, low-frequency |
| Other facilities | 2,048 entries | ~512 KB default |

**Total Memory Budget**: ~50-100 MB for 4-core system

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

### Macro-Based Interface (Zero-Cost Abstractions)

```rust
// Basic logging (format string + args)
log_info!(Facility::Supervisor, "Starting {} workers", num_workers);
log_error!(Facility::Ingress, "Failed to parse packet: {}", err);

// Structured logging with key-value pairs
log_notice!(Facility::DataPlane, "Worker started";
    "worker_id" => worker_id,
    "core" => core_id,
    "interface" => interface_name
);

// Conditional compilation for debug logs
#[cfg(debug_assertions)]
log_debug!(Facility::PacketParser, "Parsed header: {:?}", header);

// High-frequency data plane logging with rate limiting
log_rate_limited!(Facility::Ingress, Severity::Info, Duration::from_secs(1),
    "Packets processed: {}", count);
```

### Programmatic Interface

```rust
pub struct Logger {
    facility: Facility,
    min_severity: AtomicU8,  // Runtime filtering
    buffer: Arc<RingBuffer>,
}

impl Logger {
    pub fn log(&self, severity: Severity, msg: &str);
    pub fn log_kv(&self, severity: Severity, msg: &str, kvs: &[(&str, &dyn Display)]);
    pub fn set_min_severity(&self, severity: Severity);
}

// Global registry
pub struct LogRegistry {
    buffers: HashMap<(Facility, Option<u8>), Arc<RingBuffer>>, // (facility, core_id)
    consumers: Vec<Box<dyn LogConsumer>>,
}
```

### Consumer Interface

```rust
pub trait LogConsumer: Send {
    fn consume(&mut self, entry: &LogEntry) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
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

### Phase 1: Core Infrastructure
1. Implement `RingBuffer`, `LogEntry`, `Severity`, `Facility`
2. Implement basic macros: `log_info!`, `log_error!`, etc.
3. Implement `StdoutConsumer`
4. Add global `LogRegistry`

### Phase 2: Integration
1. Replace `println!` in supervisor with `log_info!`
2. Replace `eprintln!` errors with `log_error!`
3. Keep existing output format for compatibility

### Phase 3: Data Plane Optimization
1. Add per-core ring buffers for Ingress/Egress
2. Implement lock-free SPSC for io_uring threads
3. Add rate limiting for high-frequency messages

### Phase 4: Advanced Features
1. Add structured logging with key-value pairs
2. Implement `SyslogConsumer`, `FileConsumer`
3. Add runtime log level control via control socket
4. Add metrics extraction via `MetricsConsumer`

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
