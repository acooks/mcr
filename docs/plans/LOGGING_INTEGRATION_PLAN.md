# Logging System Integration Plan

**Created:** 2025-11-11
**Status:** 📋 PLANNED
**Priority:** 🔴 HIGH

---

## Problem Statement

Data plane workers currently use `println!` for stats and debug output instead of the proper logging system. This violates the design which specifies:

1. **Facility-based logging** - Different components use different facilities (`Facility::Ingress`, `Facility::Egress`, `Facility::Stats`)
2. **Severity-based filtering** - Runtime control of log levels per facility
3. **Periodic stats reporting** - Workers report stats automatically (not queried by supervisor)
4. **Zero-allocation hot path** - Logging must not cause allocations in packet processing loops

---

## Current State

### Files Using println!

1. **src/worker/ingress.rs**
   - Line 166: `[Ingress] Adding rule` (Facility::Ingress, Severity::Notice)
   - Line 187: `[Ingress] Removing rule` (Facility::Ingress, Severity::Notice)
   - Line 305: `[STATS:Ingress]` **periodic stats** (Facility::Stats, Severity::Info)
   - Line 371: `[Ingress] Parse failed` (Facility::Ingress, Severity::Debug)
   - Lines 524-570: Socket setup messages (Facility::Ingress, Severity::Info)

2. **src/worker/data_plane_integrated.rs**
   - Line 226: `[DataPlane] Ingress channel closed` (Facility::DataPlane, Severity::Info)
   - Line 241: `[STATS:Egress]` **periodic stats** (Facility::Stats, Severity::Info)

3. **src/worker/egress.rs**
   - Various debug prints (Facility::Egress, Severity::Debug)

### Existing Logging Infrastructure

**Available:**
- ✅ `Logger` struct with facility/severity filtering
- ✅ `MPSCRingBuffer` for lock-free log collection
- ✅ `log_info!`, `log_debug!`, `log_warning!`, etc. macros
- ✅ `Facility::Stats`, `Facility::Ingress`, `Facility::Egress` defined
- ✅ `Severity` levels (Emergency → Debug)

**Example from `examples/logging_demo.rs`:**
```rust
let ingress_ringbuffer = Arc::new(MPSCRingBuffer::new(Facility::Ingress.buffer_size()));
let ingress_logger = Logger::from_mpsc(
    ingress_ringbuffer.clone(),
    global_min_level.clone(),
    facility_min_levels.clone(),
);

log_info!(ingress_logger, Facility::Ingress, "Packet received");
```

**Missing:**
- ❌ Logger instances not plumbed through to data plane workers
- ❌ Data plane worker main loop doesn't create/pass loggers
- ❌ No integration between supervisor and worker loggers

---

## Design Constraints

### 1. Zero-Allocation Hot Path

**Constraint:** Packet processing loops must not allocate memory.

**Implication:**
- Logger uses pre-allocated ring buffers
- `MPSCRingBuffer` is lock-free SPSC (single producer, single consumer)
- Stats logging (every 1 second) is acceptable for allocation
- Per-packet debug logging must be zero-alloc or disabled by default

### 2. Thread Safety

**Constraint:** Data plane workers run in separate threads (not tokio tasks).

**Implication:**
- Each worker needs its own logger instance (or shared Arc<Logger>)
- Ring buffers are thread-safe (MPSC pattern)
- Supervisor must collect from multiple ring buffers

### 3. Supervisor-Worker Architecture

**Constraint:** Supervisor spawns workers as child processes, communicates via Unix sockets.

**Current approach:**
- Control plane worker: async (tokio)
- Data plane workers: blocking threads with io_uring

**Implication:**
- Can't share memory between supervisor and workers
- Must use IPC for log shipping (or workers write to stdout/file)

---

## Proposed Architecture

### Option A: Workers Write to Stdout (Simplest)

**Approach:**
- Data plane workers create their own Logger instances
- Logger writes to stdout (captured by supervisor via pipe)
- Supervisor parses and routes to appropriate ring buffers

**Pros:**
- Simple - no new IPC mechanism
- Supervisor already captures stdout
- Workers remain stateless

**Cons:**
- Parsing overhead
- Less structured than binary format
- Hard to distinguish log lines from other output

### Option B: Dedicated Log Socket (Proper IPC)

**Approach:**
- Supervisor creates Unix socket for log shipping
- Each worker connects and sends structured log messages
- Supervisor receives and distributes to ring buffers

**Pros:**
- Structured binary format (serde)
- Clear separation of concerns
- Supports filtering before transmission

**Cons:**
- Additional IPC overhead
- More complex than Option A
- Another socket to manage

### Option C: Hybrid - Stdout for Workers, Proper Logger for Supervisor

**Approach:**
- **Workers:** Use `log_info!` macros that write to stdout (no ring buffer)
- **Supervisor:** Use full Logger with ring buffers
- Test scripts capture stdout and parse `[STATS:...]` format

**Pros:**
- Workers remain simple
- Supervisor gets proper structured logging
- No new IPC mechanism
- Matches current println! behavior

**Cons:**
- Two logging implementations to maintain
- Stats format must be parseable (but already is)

---

## Recommended Approach: **Option C (Hybrid)**

### Rationale

1. **Minimize changes** - Workers keep simple stdout logging
2. **Preserve test output** - Test scripts already grep for `[STATS:...]`
3. **No IPC overhead** - Workers don't need to connect to log socket
4. **Supervisor gets structure** - Control plane benefits from ring buffers
5. **Future-proof** - Can migrate to Option B later if needed

### Implementation Plan

#### Phase 1: Create Worker Logger Facade

**File:** `src/worker/logger.rs` (new)

```rust
/// Simple logger for data plane workers that writes to stdout
pub struct WorkerLogger {
    worker_id: String,
}

impl WorkerLogger {
    pub fn new(worker_id: String) -> Self {
        Self { worker_id }
    }

    pub fn stats(&self, facility: Facility, message: &str) {
        println!("[STATS:{}] {}", facility.as_str(), message);
    }

    pub fn info(&self, facility: Facility, message: &str) {
        println!("[{}] {}", facility.as_str(), message);
    }

    pub fn debug(&self, facility: Facility, message: &str) {
        // Only log debug if explicitly enabled
        if std::env::var("MCR_DEBUG").is_ok() {
            println!("[DEBUG:{}] {}", facility.as_str(), message);
        }
    }

    pub fn error(&self, facility: Facility, message: &str) {
        eprintln!("[ERROR:{}] {}", facility.as_str(), message);
    }
}
```

**Usage:**
```rust
let logger = WorkerLogger::new("worker-0".to_string());
logger.stats(Facility::Ingress, &format!("recv={} matched={}", recv, matched));
logger.info(Facility::Ingress, &format!("Adding rule: {:?}", key));
logger.debug(Facility::Ingress, "Parse failed: invalid protocol");
```

#### Phase 2: Replace println! in Workers

**src/worker/ingress.rs:**
```rust
// Add logger field to IngressLoop
pub struct IngressLoop {
    // ... existing fields ...
    logger: WorkerLogger,
}

// Update add_rule()
pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
    let key = (rule.input_group, rule.input_port);
    self.logger.info(Facility::Ingress, &format!("Adding rule: {:?}", key));
    // ...
}

// Update periodic stats
self.logger.stats(
    Facility::Ingress,
    &format!(
        "recv={} matched={} parse_err={} no_match={} buf_exhaust={} ({:.0} pps)",
        self.stats.packets_received,
        self.stats.packets_matched,
        self.stats.parse_errors,
        self.stats.no_rule_match,
        self.stats.buffer_exhaustion,
        pps
    )
);
```

**src/worker/data_plane_integrated.rs:**
```rust
logger.stats(
    Facility::Egress,
    &format!(
        "sent={} submitted={} errors={} bytes={} ({:.0} pps)",
        stats.packets_sent,
        stats.packets_submitted,
        stats.send_errors,
        stats.bytes_sent,
        pps
    )
);
```

#### Phase 3: Plumb Logger Through

**src/worker/data_plane_integrated.rs:**
```rust
pub fn run_data_plane(
    config: DataPlaneConfig,
    command_rx: mpsc::Receiver<RelayCommand>,
    event_fd: nix::sys::eventfd::EventFd,
) -> Result<()> {
    let logger = WorkerLogger::new(format!("dp-worker-{}", config.core_id.unwrap_or(0)));

    // Pass logger to ingress
    let mut ingress = IngressLoop::new(
        ingress_config,
        buffer_pool.clone(),
        logger.clone(), // Add this
    )?;

    // Egress doesn't need separate logger - logs from main thread
    // ...
}
```

#### Phase 4: Update Tests

**No changes needed** - Test scripts already grep for `[STATS:Ingress]` and `[STATS:Egress]`

---

## Implementation Tasks

### Step 1: Create WorkerLogger ✅ Ready

- [ ] Create `src/worker/logger.rs`
- [ ] Implement `WorkerLogger` struct with `stats()`, `info()`, `debug()`, `error()` methods
- [ ] Add to `src/worker/mod.rs`
- [ ] Write unit tests

**Estimated time:** 1 hour

### Step 2: Update IngressLoop ✅ Ready

- [ ] Add `logger: WorkerLogger` field to `IngressLoop`
- [ ] Replace `println!` with `logger.info()` / `logger.debug()` / `logger.stats()`
- [ ] Update `add_rule()` and `remove_rule()`
- [ ] Update periodic stats reporting
- [ ] Update socket setup functions

**Estimated time:** 1 hour

### Step 3: Update Egress & DataPlane ✅ Ready

- [ ] Add logger to `run_data_plane()` function
- [ ] Replace `println!` in `data_plane_integrated.rs`
- [ ] Pass logger to egress stats reporting

**Estimated time:** 30 minutes

### Step 4: Testing ✅ Ready

- [ ] Run library tests (`cargo test --lib`)
- [ ] Run veth pipeline test
- [ ] Verify output format unchanged
- [ ] Verify debug logging can be enabled via `MCR_DEBUG=1`

**Estimated time:** 30 minutes

### Step 5: Documentation ✅ Ready

- [ ] Update ARCHITECTURE.md with logging design
- [ ] Document WorkerLogger API
- [ ] Add to LOGGING_DESIGN.md

**Estimated time:** 30 minutes

---

## Total Estimated Time: 3.5 hours

---

## Future Enhancements (Post-Implementation)

### 1. Structured Stats Format

**Current:** String formatting
```rust
logger.stats(Facility::Ingress, &format!("recv={} matched={}", recv, matched));
```

**Future:** Structured key-value pairs
```rust
logger.stats_kv(Facility::Ingress, &[
    ("recv", recv),
    ("matched", matched),
    ("parse_err", parse_err),
]);
```

### 2. Binary Log Shipping (Option B)

**If needed:** Implement dedicated log socket with serde serialization for structured log shipping to supervisor.

### 3. Runtime Log Level Control

**Current:** Global `MCR_DEBUG` environment variable

**Future:** Per-facility log levels via control socket:
```bash
control_client --socket-path /tmp/mcr.sock set-log-level --facility Ingress --level Debug
```

---

## Success Criteria

Phase is complete when:

1. ✅ No `println!` in ingress/egress/data_plane_integrated.rs (except error paths)
2. ✅ All logging uses `WorkerLogger` facade
3. ✅ Test output format unchanged (still grep for `[STATS:...]`)
4. ✅ Debug logging can be enabled via environment variable
5. ✅ Library tests pass (122 tests)
6. ✅ Veth pipeline test produces same output format
7. ✅ Documentation updated

---

## Risks & Mitigations

### Risk: Performance regression from string formatting

**Likelihood:** Low
**Impact:** Low

**Mitigation:**
- Stats logging only happens every 1 second (not per-packet)
- String formatting is negligible compared to packet processing
- Can profile if concerned

### Risk: Breaking test scripts

**Likelihood:** Low (if we keep format)
**Impact:** Medium

**Mitigation:**
- Keep exact same output format: `[STATS:Ingress] ...`
- Test scripts already updated to use this format
- Run integration tests before merging

### Risk: Logger plumbing complexity

**Likelihood:** Low
**Impact:** Low

**Mitigation:**
- Simple facade pattern (no ring buffers in workers)
- Just wraps println! initially
- Can enhance later without breaking API

---

## Appendix: Logging Format Examples

### Stats (Periodic, every 1 second)
```
[STATS:Ingress] recv=6129022 matched=3881980 parse_err=1 no_match=21 buf_exhaust=2247020 (490000 pps)
[STATS:Egress] sent=4176384 submitted=4176384 errors=0 bytes=5846937600 (307000 pps)
```

### Info (One-time events)
```
[Ingress] Adding rule: (239.1.1.1, 5001)
[Ingress] Removing rule: abc-123-def
[Ingress] Setting up AF_PACKET socket for interface veth0p
[Ingress] Interface index for veth0p: 50
```

### Debug (Verbose, disabled by default)
```
[DEBUG:Ingress] Parse failed: Invalid IP protocol: expected 17 (UDP), got 2
```

### Error (Exceptional conditions)
```
[ERROR:Ingress] FATAL: Failed to create AF_PACKET socket: Permission denied
[ERROR:Ingress] This likely means CAP_NET_RAW capability is missing
```

---

## Conclusion

This plan provides a pragmatic path to integrate the logging system with minimal changes and no performance impact. The WorkerLogger facade keeps workers simple while preserving the output format expected by test scripts. Future enhancements can add structured logging and IPC-based log shipping if needed.

**Recommendation:** Proceed with Option C (Hybrid approach) as outlined above.
