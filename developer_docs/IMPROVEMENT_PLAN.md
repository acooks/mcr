# Project Improvement Plan

Last updated: January 2026

## Priority Legend

- **CRITICAL** - Security, correctness, or major undocumented features
- **HIGH** - Significant impact on maintainability or user experience
- **MEDIUM** - Quality improvements, technical debt
- **LOW** - Nice-to-have, future enhancements

---

## Recently Completed

### ✅ Logging Subsystem Cleanup (January 2026)

Removed ~600 lines of dead code and fixed critical log level propagation bug:

- **Dead Code Removal:** Deleted unused `SPSCRingBuffer`, `SharedSPSCRingBuffer`, `BlockingConsumer`, and `SharedBlockingConsumer` types
- **Log Level Propagation:** Added `RelayCommand::SetLogLevel` to propagate log level changes from supervisor to workers
- **Logger API:** Added `set_global_level()`, `set_facility_level()`, and `clear_facility_level()` methods to `Logger`
- **Documentation:** Updated REFERENCE.md with logging facilities table

**Implementation:** `src/logging/`, `src/lib.rs`, `src/supervisor.rs`, `src/worker/unified_loop.rs`

### ✅ PIM-SM and IGMP Protocol Support (January 2026)

Implemented multicast routing protocol support:

- **IGMPv2 Querier:** Querier election, group membership tracking, RFC 2236 timers
- **PIM-SM:** Neighbor discovery, DR election, (*,G) and (S,G) state machines
- **Multicast RIB:** Unified abstraction merging static rules with protocol-learned routes
- **Per-interface Rule Filtering:** Rules synced to workers based on their interface
- **CLI Commands:** `mcrctl pim neighbors`, `mcrctl igmp groups`, `mcrctl mroute`

**Implementation:** `src/protocols/`, `src/mroute.rs`, protocol integration in `src/supervisor.rs`

---

## HIGH: Code Simplification & Performance

### Implement Async io_uring Logging (Deferred)

**Status:** Deferred - not needed for current use cases.

**Rationale:** The worker's hot packet processing path does NOT log. Logging is strategically excluded from performance-critical code. The current `StderrJsonLogger` using `eprintln!()` is acceptable because it's only called during command processing and error handling, not during normal packet forwarding.

**Original Issue:** The current `StderrJsonLogger` uses `eprintln!`, which locks stderr and performs blocking I/O syscalls in the hot data path.

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
   - ~~**Facilities:** Add a table listing all 12 logging facilities.~~ ✅ Done (January 2026)
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
