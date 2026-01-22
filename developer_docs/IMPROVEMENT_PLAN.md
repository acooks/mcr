# Project Improvement Plan

Last updated: January 2026

## Priority Legend

- **CRITICAL** - Security, correctness, or major undocumented features
- **HIGH** - Significant impact on maintainability or user experience
- **MEDIUM** - Quality improvements, technical debt
- **LOW** - Nice-to-have, future enhancements

---

## Recently Completed

### ✅ PIM-SM and IGMP Protocol Support (January 2026)

Implemented multicast routing protocol support:

- **IGMPv2 Querier:** Querier election, group membership tracking, RFC 2236 timers
- **PIM-SM:** Neighbor discovery, DR election, (*,G) and (S,G) state machines
- **Multicast RIB:** Unified abstraction merging static rules with protocol-learned routes
- **Per-interface Rule Filtering:** Rules synced to workers based on their interface
- **CLI Commands:** `mcrctl pim neighbors`, `mcrctl igmp groups`, `mcrctl mroute`

**Implementation:** `src/protocols/`, `src/mroute.rs`, protocol integration in `src/supervisor.rs`

---

## CRITICAL: Architectural Defects

### Dynamic Log Levels do not propagate to Workers

**Issue:** The `mcrctl log-level set` command updates the Supervisor's log level configuration, but this state is **not** propagated to the Data Plane workers. Workers run as separate processes with their own isolated `Logger` instances initialized with default levels (Info).

**Impact:** Users cannot debug data plane issues (e.g., packet parsing errors) by raising the log level at runtime.

**Implementation Plan:**

1. Update IPC Protocol (`src/lib.rs`):
   - Add a new variant to `RelayCommand` enum:

     ```rust
     SetLogLevel {
         facility: logging::Facility,
         level: logging::Severity,
     }
     ```

2. Update Supervisor (`src/supervisor.rs`):
   - In `handle_set_facility_log_level` and `handle_set_global_log_level`, iterate over all active worker channels.
   - Serialize and send the new `RelayCommand::SetLogLevel` to each worker.

3. Update Worker Loop (`src/worker/unified_loop.rs`):
   - In `handle_command_completion`, add a match arm for `RelayCommand::SetLogLevel`.
   - Implement logic to update the worker's local `Logger` instance:

     ```rust
     // In UnifiedDataPlane struct
     fn set_log_level(&mut self, facility: Facility, level: Severity) {
         self.logger.set_facility_level(facility, level);
     }
     ```

---

## HIGH: Code Simplification & Performance

### Delete Massive Logging Dead Code

**Analysis:** ~80% of the `src/logging/` module consists of complex, lock-free shared memory ring buffers (`SPSCRingBuffer`, `MPSCRingBuffer`, `SharedSPSCRingBuffer`) that are **never used in production**.

**Implementation Plan:**

1. **Delete Files:**
   - `src/logging/ringbuffer.rs`
   - `src/logging/consumer.rs`

2. **Clean up `src/logging/mod.rs`:**
   - Remove `pub mod ringbuffer;` and `pub mod consumer;`.
   - Remove re-exports of `SPSCRingBuffer`, `MPSCRingBuffer`, etc.

3. **Update `src/logging/logger.rs`:**
   - Remove `RingBuffer` trait implementations for the deleted types.
   - Remove `from_spsc`, `from_mpsc`, `from_shared` constructors.
   - Keep `Logger`, `LogRegistry` (simplified), and `StderrJsonLogger`.

4. **Fix Tests:**
   - Remove tests that rely on the deleted ring buffers.
   - Ensure `examples/logging_demo.rs` is updated or deleted.

### Implement Async io_uring Logging

**Issue:** The current `StderrJsonLogger` uses `eprintln!`, which locks stderr and performs blocking I/O syscalls in the hot data path.

**Implementation Plan:**

1. **New `IoUringLogger` Backend:**
   - Create a new struct `IoUringLogger` implementing `RingBuffer`.
   - It holds an `Arc<crossbeam_queue::SegQueue<String>>`.
   - Its `write()` method formats the `LogEntry` to JSON and pushes the String to the queue.

2. **Update `UnifiedDataPlane`:**
   - Add `log_queue: Arc<SegQueue<String>>` to the struct.
   - Add `in_flight_logs: HashMap<u64, ManagedBuffer>` to track submitted writes.
   - Define `LOG_BASE` / `LOG_MAX` user_data range.

3. **Modify Event Loop (`unified_loop.rs`):**
   - Add `submit_log_writes()` method:
     - Drain the `log_queue`.
     - For each log, acquire a `Small` (2KB) buffer from `BufferPool`.
     - Copy string bytes into buffer.
     - Submit `opcode::Write` targeting FD 2 (stderr).
     - Use `IOSQE_IO_LINK` if ordering is critical (optional).
   - Update `process_completions`:
     - Handle `LOG_BASE..LOG_MAX` completions.
     - Drop the `ManagedBuffer` to return it to the pool.

4. **Worker Initialization (`mod.rs`):**
   - Initialize `log_queue`.
   - Create `Logger` with `IoUringLogger(log_queue)`.
   - Pass `log_queue` (consumer side) to `UnifiedDataPlane`.

---

## Documentation & API Parity

### HIGH: Undocumented Features

**Implementation Plan:**

1. **Update `user_docs/REFERENCE.md`:**
   - **Config Load:** Add documentation for `mcrctl config load <file> --replace`.
   - **Facilities:** Add a table listing all 12 logging facilities.
   - **Pinning:** Add a formal definition of the `pinning` JSON object.

### HIGH: User Experience & Troubleshooting

**Implementation Plan:**

1. **Create `user_docs/TROUBLESHOOTING.md`:**
   - **Permission Denied:** Explain `CAP_NET_RAW` and `setcap`.
   - **Buffer Exhaustion:** Explain `buf_exhaust` counter.
   - **Performance:** Explain `MCR_SOCKET_SNDBUF`.

2. **Update `user_docs/GUIDE.md`:**
   - Add "Known Limitations" section regarding CLI rule names.

---

## Code Improvements (General)

### HIGH Priority

#### Network State Reconciliation

- **Goal:** Detect when interfaces go down or change IP.
- **Plan:** Use `rtnetlink` crate in supervisor to monitor network events.

#### Automated Drift Recovery (Phase 2)

- **Goal:** Supervisor automatically fixes worker state.
- **Plan:** Workers report ruleset hash; Supervisor reconciles.

### MEDIUM Priority

#### Dynamic Worker Idle Cleanup

- **Goal:** Save resources.
- **Plan:** Shut down workers with 0 rules after idle timeout.

#### Buffer Size for Jumbo Frames

- **Goal:** Support 9k packets.
- **Plan:** Add Jumbo slab to `BufferPool` and use in `UnifiedDataPlane`.

### LOW Priority

#### On-Demand Packet Tracing

- **Plan:** Add `TraceRule` command to log sampled packets.

---

## Roadmap

**Phase 1 (Immediate - Maintenance):**

1. **Simplify Logging:** Delete unused ring buffers.
2. **Fix Dynamic Log Levels:** Implement IPC command.
3. **Documentation Parity:** Update Reference and create Troubleshooting guide.

**Phase 2 (Performance & Stability):**

1. **Async Logging:** Implement io_uring log writer.
2. **Network Reconciliation:** Handle interface flaps.

**Phase 3 (Features):**

1. Drift Recovery.
2. Packet Tracing.
