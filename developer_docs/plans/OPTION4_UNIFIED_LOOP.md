# Option 4: Single-Threaded Unified io_uring Architecture

**Date:** 2025-11-17
**Status:** INTEGRATED AND ACTIVE - Testing in progress
**Priority:** HIGH
**Related:** EGRESS_EVENT_DRIVEN_FIX.md (Option 2 - failed), EGRESS_REGRESSION_ANALYSIS_2025-11-16.md

---

## Executive Summary

Option 4 eliminates the cross-thread communication bottleneck by merging ingress and egress into a single-threaded event loop with one unified io_uring instance. This addresses the fundamental architectural concern: **"Why have a slow SegQueue between two fast io_uring queues?"**

---

## Problem Analysis

### Current Two-Thread Architecture Issues

```text
Ingress Thread          SegQueue/mpsc          Egress Thread
io_uring (RX) --------> [bottleneck] --------> io_uring (TX)
   Fast                    Slow?                   Fast
```

**Bottlenecks identified:**
1. **Cross-thread queue** - SegQueue or mpsc::channel between threads
2. **Eventfd overhead** - Cross-thread wakeup mechanism
3. **Context switches** - CPU switching between threads
4. **Cache coherency** - Data bouncing between CPU caches
5. **Buffer pool synchronization** - Arc<Mutex<>> or Arc<SegQueue<>>

### Why Option 2 (Event-Driven Egress) Failed

Option 2 attempted to make egress event-driven via io_uring PollAdd on eventfd, but created a **chicken-and-egg deadlock**:

1. Egress blocks in `submit_and_wait()` waiting for eventfd
2. Ingress can't send (buffer pool exhausted)
3. Buffers stuck in egress's `in_flight` map (not being processed)
4. Eventfd never fires (no packets from ingress)
5. → **Complete deadlock at startup**

Result: 99.8% buffer exhaustion, egress froze with zero stats output.

---

## Option 4: Unified Single-Threaded Architecture

### Design

```text
Single Thread, One io_uring Instance
┌─────────────────────────────────────────────────┐
│  io_uring Submission Queue (SQ):                │
│    - RecvMsg ops (AF_PACKET)                    │
│    - Send ops (UDP/INET)                        │
│    - Command stream Read ops                    │
│                                                  │
│  io_uring Completion Queue (CQ):                │
│    - Packet received (user_data: RECV_BASE)     │
│    - Packet sent (user_data: SEND_BASE)         │
│    - Command received (user_data: COMMAND)      │
│    - Shutdown signal (user_data: SHUTDOWN)      │
└─────────────────────────────────────────────────┘
                    ↓
              Event Loop:
    1. Process available completions
    2. Submit new operations
    3. Wait for next event if idle
```

### Event Loop Logic

```rust
loop {
    // 1. Check shutdown
    if shutdown_requested { drain_and_exit(); }

    // 2. Process all available completions (non-blocking)
    for completion in ring.completion() {
        match completion.user_data() {
            RECV_BASE..=RECV_MAX => {
                // Packet received
                parse_packet();
                lookup_rule();
                if matched { queue_send(); }
                resubmit_recv();
            }
            SEND_BASE..=SEND_MAX => {
                // Packet sent
                // Buffer automatically freed by Drop
            }
            COMMAND_USER_DATA => {
                // Command received
                process_command();
                resubmit_command_read();
            }
            SHUTDOWN_USER_DATA => {
                shutdown_requested = true;
            }
        }
    }

    // 3. Submit batched sends
    if !send_queue.is_empty() {
        submit_send_batch();
    }

    // 4. If idle, wait for next event
    if ring.completion().is_empty() && send_queue.is_empty() {
        ring.submit_and_wait(1);
    }
}
```

---

## Benefits

### Performance

1. **No cross-thread queue** - SegQueue/mpsc eliminated entirely
2. **No eventfd overhead** - No cross-thread signaling needed
3. **No context switches** - Everything in one thread
4. **Better cache locality** - All data stays in same CPU cache
5. **Simpler buffer pool** - No Arc<> needed (single owner)

### Architectural

1. **Natural batching** - Receive N packets, process N, send N
2. **Immediate feedback** - Send completions free buffers in same loop
3. **Unified event stream** - All events flow through one queue
4. **Simpler reasoning** - No concurrency to reason about

### Implementation

1. **Less code** - No thread spawning, channel setup, wakeup strategies
2. **Easier debugging** - Single call stack, no cross-thread issues
3. **Fewer dependencies** - No crossbeam_queue needed

---

## Implementation Status

### Completed ✅

- `src/worker/unified_loop.rs` created (600+ lines)
- Core data structures defined
- io_uring setup for AF_PACKET and UDP
- Event loop skeleton implemented
- Command stream handling
- Buffer pool integration
- User data ranges for different operation types
- **Packet parsing fully integrated** (2025-11-17 Phase 1)
  - Added `parse_packet` import from `packet_parser` module
  - Implemented `ForwardingTarget` struct for packet metadata
  - Implemented `process_received_packet()` with full parsing logic
  - Parses Ethernet → IPv4 → UDP headers
  - Looks up rules by (multicast_group, port) key
  - Copies payload from receive buffer to send buffer
  - Added `packets_filtered` stat for non-UDP packets
- **Data plane integration completed** (2025-11-17 Phase 2)
  - Created `run_unified_data_plane()` in `data_plane_integrated.rs`
  - Wired up buffer pool configuration from environment variables
  - Integrated with supervisor FD passing (ingress_cmd_stream_fd)
  - Made unified loop the DEFAULT via `mod.rs` import switch
  - Legacy two-thread model commented out but available
- **Compiles cleanly with no warnings!**
- **Submission queue overflow FIX** (2025-11-17 Phase 3)
  - Added capacity checks in `submit_recv_buffers()` and `submit_send_batch()`
  - Limit submissions to available queue space: `to_submit = buffers.len().min(sq_available)`
  - Verified: Workers run for 10+ minutes without "submission queue is full" crash
  - File: `src/worker/unified_loop.rs:507-554`
- **Buffer pool exhaustion FIX** (2025-11-17 Phase 3)
  - Reduced `num_recv_buffers` from 64 to 32 (line 95)
  - With 20 workers: 640 buffers vs 1,700 total pool size
  - Verified: No "Buffer pool exhausted" errors at startup
- **Basic startup verification PASSED** ✅
  - Unified loop starts successfully
  - No buffer pool errors
  - No submission queue errors
  - Event loop running

### Pending ⏳

1. **Functional Testing** (NEXT)
   - Verify packet forwarding actually works
   - Test with actual multicast traffic
   - Verify rules can be added/removed
2. **Performance Testing** (CRITICAL)
   - Integration test with traffic generator
   - Performance comparison vs PHASE4 baseline (307k pps target)
   - Compare vs current two-thread model (~97k pps egress)

---

## Code Structure

```text
src/worker/unified_loop.rs
├── UnifiedDataPlane struct
│   ├── ring: IoUring (single instance!)
│   ├── recv_socket: Socket (AF_PACKET)
│   ├── egress_sockets: HashMap (per-destination UDP sockets)
│   ├── rules: HashMap (forwarding rules)
│   ├── buffer_pool: Arc<BufferPool>
│   ├── send_queue: Vec<SendWorkItem>
│   └── in_flight tracking
│
├── new() - Setup
│   ├── Create AF_PACKET socket
│   ├── Bind to interface
│   ├── Create io_uring instance
│   └── Pre-post recv buffers
│
├── run() - Main event loop
│   ├── Check shutdown
│   ├── Process completions
│   ├── Submit sends
│   └── Wait if idle
│
├── handle_recv_completion()
│   ├── Parse packet
│   ├── Lookup rule
│   ├── Queue send if matched
│   └── Resubmit recv
│
├── handle_send_completion()
│   └── Buffer freed automatically
│
└── submit_send_batch()
    └── Batch submit UDP sends
```

---

## User Data Strategy

To distinguish different operation types in the completion queue:

```rust
const SHUTDOWN_USER_DATA: u64 = u64::MAX;
const COMMAND_USER_DATA: u64 = u64::MAX - 1;
const RECV_BASE: u64 = 0;
const RECV_MAX: u64 = 1_000_000;
const SEND_BASE: u64 = 1_000_001;
const SEND_MAX: u64 = 2_000_000;
```

Allows 1M concurrent receives and 1M concurrent sends.

---

## Next Steps

### Phase 1: Packet Parsing Integration (Priority: HIGH)

**Task:** Integrate packet parsing from `ingress.rs`

**Files to modify:**
- `src/worker/unified_loop.rs::process_received_packet()`

**Integration points:**

```rust
fn process_received_packet(&mut self, packet_data: &[u8]) -> Result<Option<SendWorkItem>> {
    // 1. Parse Ethernet header (14 bytes)
    // 2. Parse IP header (20+ bytes)
    // 3. Parse UDP header (8 bytes)
    // 4. Extract multicast group and port
    // 5. Lookup in self.rules HashMap
    // 6. If matched, create SendWorkItem

    // Can reuse code from ingress.rs parse_and_forward()
}
```

**Estimated effort:** 2-3 hours

### Phase 2: Wire Up in Data Plane (Priority: HIGH)

**Task:** Replace two-thread model with unified loop

**Files to modify:**
- `src/worker/data_plane_integrated.rs` or create new variant

**Changes:**

```rust
pub fn run_unified_data_plane(
    config: DataPlaneConfig,
    logger: Logger,
    cmd_stream_fd: OwnedFd,
) -> Result<()> {
    let buffer_pool = BufferPool::new(
        config.buffer_pool_small,
        config.buffer_pool_standard,
        config.buffer_pool_jumbo,
    );

    let mut unified = UnifiedDataPlane::new(
        &interface_name,
        UnifiedConfig::default(),
        buffer_pool,
        cmd_stream_fd,
        logger,
    )?;

    unified.run()
}
```

**Estimated effort:** 1-2 hours

### Phase 3: Performance Testing (Priority: CRITICAL)

**Task:** Compare against PHASE4 baseline

**Test:** Run `tests/data_plane_pipeline_veth.sh`

**Success criteria:**
- Ingress ≥ 690k pps (current baseline)
- Egress ≥ 307k pps (PHASE4 target)
- Buffer exhaustion < 40%

**Estimated effort:** 1 hour

---

## Risk Assessment

### Low Risk ✅

- **Compiles successfully** - No type errors, clean architecture
- **Proven pattern** - Single-threaded event loops are well-understood
- **Incremental** - Can implement alongside existing code
- **Reversible** - Easy to switch back if performance disappoints

### Questions ❓

1. **Single-threaded scalability** - Does one thread saturate at high packet rates?
   - **Mitigation:** Can scale horizontally with multiple workers per interface

2. **io_uring queue depth** - Can one ring handle both RX and TX at high rates?
   - **Mitigation:** Configurable queue depth, can tune if needed

3. **AF_PACKET + UDP in same ring** - Any kernel-level conflicts?
   - **Mitigation:** These are fundamentally different operations, should be fine

---

## References

- **Inspiration:** Your insight about SegQueue bottleneck
- **Option 2 failure:** EGRESS_EVENT_DRIVEN_FIX.md
- **PHASE4 baseline:** commit 2d5e8ef (307k pps egress)
- **Current baseline:** ~689k pps ingress, ~97k pps egress

---

## Decision Log

**2025-11-17:** Option 4 skeleton implemented
- Recognized Option 2's fundamental deadlock issue
- User questioned cross-thread queue necessity
- Designed unified single-threaded architecture
- Implemented and successfully compiled skeleton
- Next: packet parsing integration
