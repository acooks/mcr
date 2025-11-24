# Option 4: Unified Single-Threaded Loop - Implementation Summary

**Date:** 2025-11-17
**Session Duration:** ~3 hours
**Status:** Phase 3 Complete - Ready for Functional Testing

---

## Executive Summary

Successfully implemented and debugged the unified single-threaded data plane loop (Option 4), which eliminates cross-thread communication by handling both ingress (packet receive) and egress (packet send) in a single thread with one io_uring instance. Fixed two critical bugs (submission queue overflow and buffer pool exhaustion) that were preventing startup and causing crashes.

**Key Achievement:** The unified loop now starts successfully and runs stably without crashes, ready for functional and performance testing.

---

## Implementation Phases Completed

### Phase 1: Packet Parsing Integration ✅

**Objective:** Integrate packet parsing logic from the existing ingress module

**Work Done:**

- Added `parse_packet` import from `packet_parser` module
- Created `ForwardingTarget` struct for clean separation of concerns:

  ```rust
  struct ForwardingTarget {
      payload_offset: usize,
      payload_len: usize,
      dest_addr: SocketAddr,
      interface_name: String,
  }
  ```

- Implemented `process_received_packet()` method:
  - Parses Ethernet → IPv4 → UDP headers
  - Looks up forwarding rules by (multicast_group, port) key
  - Returns forwarding metadata without touching buffers
- Updated `handle_recv_completion()` to:
  - Call packet parser
  - Allocate send buffer only if rule matches
  - Copy payload from receive buffer to send buffer
- Added `packets_filtered` stat for non-UDP packets (ARP, IPv6, TCP, etc.)

**File:** `/home/acooks/mcr/src/worker/unified_loop.rs`

---

### Phase 2: Data Plane Integration ✅

**Objective:** Wire the unified loop into the supervisor/worker architecture

**Work Done:**

**A. Created `run_unified_data_plane()` function**

- Location: `/home/acooks/mcr/src/worker/data_plane_integrated.rs:176-238`
- Extracts command stream FD from ingress channels
- Reads buffer pool configuration from environment variables:
  - `MCR_BUFFER_POOL_SMALL` (default: 1000)
  - `MCR_BUFFER_POOL_STANDARD` (default: 500)
  - `MCR_BUFFER_POOL_JUMBO` (default: 200)
- Creates `BufferPool` instance
- Initializes `UnifiedDataPlane` with supervisor-provided FD
- Calls `unified.run()` to start event loop

#### B. Made unified loop the DEFAULT

- File: `/home/acooks/mcr/src/worker/mod.rs`
- Changed import to use `run_unified_data_plane`:

  ```rust
  // Option 4: Unified single-threaded loop (default)
  use data_plane_integrated::run_unified_data_plane as data_plane_task;

  // Option 3: Two-thread model (legacy)
  // use data_plane_integrated::run_data_plane as data_plane_task;
  ```

- Legacy two-thread model remains available (commented out)
- Easy to switch back if needed

**Verification:**

- Compiles cleanly with no warnings
- Supervisor spawns workers using unified loop

---

### Phase 3: Critical Bug Fixes ✅

#### Bug 1: Submission Queue Overflow (CRITICAL)

**Symptoms:**

```text
[Worker 1741402] Data Plane worker process failed: submission queue is full
```

- Workers crashed after ~5 minutes of operation
- Supervisor continuously restarted failed workers
- Completely prevented sustained operation

**Root Cause:**
The unified loop was submitting io_uring operations without checking if there was available space in the submission queue. When the queue filled up, the next `push()` call would fail with "queue full" error.

**Analysis:**

```rust
// BEFORE (buggy code):
for _ in 0..num_recv_buffers {
    let recv_op = opcode::RecvMsg::new(...);
    self.ring.submission().push(&recv_op)?;  // ❌ Can overflow!
}
```

Under high load:

1. Event loop processes completions slowly
2. More receives/sends submitted than completions processed
3. Submission queue fills to capacity (default: 128)
4. Next `push()` call fails with ENOSPC
5. Worker crashes

**Fix Applied:**
Added capacity checks before submitting operations:

```rust
// File: src/worker/unified_loop.rs

fn submit_recv_buffers(&mut self) -> Result<()> {
    // ... allocate buffers ...
    
    // Check available space in submission queue
    let sq = self.ring.submission();
    let sq_available = sq.capacity() - sq.len();
    drop(sq); // Release borrow before loop
    
    // Only submit as many as we have space for
    let to_submit = self.recv_buffers.len().min(sq_available);
    
    for _ in 0..to_submit {
        // ... create and push operation ...
    }
    Ok(())
}

fn submit_send_batch(&mut self) -> Result<()> {
    // Check available space in submission queue
    let sq = self.ring.submission();
    let sq_available = sq.capacity() - sq.len();
    drop(sq); // Release borrow before loop
    
    // Limit batch size to available space
    let batch_size = self.send_queue.len()
        .min(self.config.send_batch_size)
        .min(sq_available);  // ✅ Never overflow!
    
    for _ in 0..batch_size {
        // ... create and push operation ...
    }
    Ok(())
}
```

**Verification:**

- Test: `cargo test --release test_add_and_remove_rule_e2e`
- Result: Workers ran for 10+ minutes without crashes
- Previous behavior: Crashed at ~5 minutes
- ✅ Bug FIXED

**Files Modified:**

- `/home/acooks/mcr/src/worker/unified_loop.rs:499-542` (`submit_recv_buffers`)
- `/home/acooks/mcr/src/worker/unified_loop.rs:545-599` (`submit_send_batch`)

---

#### Bug 2: Buffer Pool Exhaustion at Startup

**Symptoms:**

```text
[Worker 1745431] Data Plane worker process failed: Buffer pool exhausted during recv buffer setup
```

- Workers failed to initialize
- Crashed immediately at startup
- Prevented unified loop from ever running

**Root Cause:**
Configuration mismatch between per-worker buffer allocation and total pool size:

```text
Default Configuration (BEFORE):
- num_recv_buffers per worker: 64
- Number of workers: 20 (on 20-core system)
- Total recv buffers needed: 64 × 20 = 1,280

Buffer Pool Totals:
- Small: 1,000
- Standard: 500
- Jumbo: 200
- TOTAL: 1,700

Problem: 1,280 recv buffers consumed at startup, leaving only 420 for:
- Send buffers (needed for every forwarded packet)
- Temporary allocations
- Operating margin
```

Result: Immediate exhaustion under any load.

**Fix Applied:**
Reduced `num_recv_buffers` to more reasonable value:

```rust
// File: src/worker/unified_loop.rs:91-100

impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            queue_depth: 128,
            num_recv_buffers: 32,  // CHANGED from 64
            send_batch_size: 32,
            track_stats: true,
        }
    }
}
```

**New Calculation:**

```text
After Fix:
- num_recv_buffers per worker: 32
- Number of workers: 20
- Total recv buffers needed: 32 × 20 = 640

Remaining for sends/operations: 1,700 - 640 = 1,060 buffers
Operating margin: 62% of total pool available
```

**Verification:**

- Test: Manual startup with 1 worker and 20 workers
- Result: No buffer pool exhaustion errors
- Workers initialize successfully
- ✅ Bug FIXED

**File Modified:**

- `/home/acooks/mcr/src/worker/unified_loop.rs:95`

---

## Architecture Overview

### Single-Threaded Unified Event Loop

```text
┌───────────────────────────────────────────────────────────┐
│                    Single Thread                          │
│                                                            │
│  ┌──────────────────────────────────────────────────┐    │
│  │            io_uring Instance (unified)           │    │
│  │                                                   │    │
│  │  Submission Queue (SQ):                          │    │
│  │    - RecvMsg ops (AF_PACKET socket)             │    │
│  │    - Send ops (UDP/INET sockets)                │    │
│  │    - Command stream Read ops                    │    │
│  │    - Capacity: 128 operations                   │    │
│  │                                                   │    │
│  │  Completion Queue (CQ):                          │    │
│  │    - Packet received (user_data: RECV_BASE)     │    │
│  │    - Packet sent (user_data: SEND_BASE)         │    │
│  │    - Command received (user_data: COMMAND)      │    │
│  │    - Shutdown signal (user_data: SHUTDOWN)      │    │
│  └──────────────────────────────────────────────────┘    │
│                          ↓                                 │
│                   Event Loop:                              │
│   1. Check shutdown flag                                  │
│   2. Process available completions (non-blocking)         │
│   3. Submit new receive operations (with capacity check)  │
│   4. Submit batched sends (with capacity check)           │
│   5. Wait for next event if idle                          │
└───────────────────────────────────────────────────────────┘
```

### Benefits Over Two-Thread Model

**Eliminated:**

- ❌ Cross-thread queue (SegQueue/mpsc)
- ❌ Eventfd wakeup mechanism
- ❌ Context switches between threads
- ❌ Cache coherency overhead
- ❌ Arc<Mutex<>> for buffer pool synchronization

**Gained:**

- ✅ Single-threaded simplicity
- ✅ Better cache locality
- ✅ Natural batching (receive N, process N, send N)
- ✅ Immediate feedback (send completions free buffers in same loop)
- ✅ Unified event stream (all events through one queue)

---

## Verification Results

### Startup Tests ✅

#### Test 1: Single Worker Startup

```bash
sudo multicast_relay supervisor \
    --control-socket-path /tmp/test.sock \
    --interface lo \
    --num-workers 1
```

**Result:**

```text
[Worker 1747319] [run_unified_data_plane] Entry point reached
[Worker 1747319] {"facility":"DataPlane","level":"Info","message":"Unified data plane starting",...}
[Worker 1747319] [run_unified_data_plane] Creating UnifiedDataPlane
[Worker 1747319] {"facility":"DataPlane","level":"Info","message":"Creating unified data plane loop",...}
[Worker 1747319] [run_unified_data_plane] Starting event loop
[Worker 1747319] {"facility":"DataPlane","level":"Info","message":"Unified event loop starting",...}
[Worker 1747319] {"facility":"DataPlane","level":"Info","message":"Starting unified event loop",...}
```

✅ **PASS:** Worker started successfully, event loop running

#### Test 2: Multi-Worker Startup (20 workers)

```bash
cargo test --release test_add_and_remove_rule_e2e
```

**Result:**

- All 20 workers started successfully
- No buffer pool exhaustion errors
- No submission queue overflow errors
- Workers ran for 10+ minutes without crashes

✅ **PASS:** Stable multi-worker operation

### Stability Tests ✅

#### Test: Extended Run

- Duration: 10+ minutes
- Workers: 20 (default for 20-core system)
- Load: Rule add/remove operations

**Previous Behavior (before fixes):**

- Crashed at ~5 minutes with "submission queue is full"
- OR crashed immediately with "Buffer pool exhausted"

**Current Behavior:**

- ✅ No crashes
- ✅ No submission queue errors
- ✅ No buffer pool errors
- ✅ Workers remain healthy

---

## Code Quality

### Compilation

```bash
$ cargo build --release
   Compiling multicast_relay v0.1.0 (/home/acooks/mcr)
    Finished `release` profile [optimized] target(s) in 2.95s
```

✅ **Clean build with ZERO warnings**

### Binary Info

```text
File: /home/acooks/mcr/target/release/multicast_relay
Built: 2025-11-17 20:13
Size: 3,364,664 bytes
MD5: 48b1fcf85d86ab452099e71f0d862621
```

---

## Files Modified

### Core Implementation

1. **`src/worker/unified_loop.rs`** (600+ lines)
   - Packet parsing integration (Phase 1)
   - Submission queue overflow fix (Phase 3)
   - Buffer pool exhaustion fix (Phase 3)

### Integration

1. **`src/worker/data_plane_integrated.rs`**
   - Added `run_unified_data_plane()` function (Phase 2)

2. **`src/worker/mod.rs`**
   - Made unified loop the default (Phase 2)

### Documentation

1. **`developer_docs/plans/OPTION4_UNIFIED_LOOP.md`**
   - Updated status to reflect Phase 3 completion

---

## Next Steps

### 1. Functional Testing (HIGH PRIORITY)

**Objective:** Verify packet forwarding actually works

**Test Plan:**

- Start supervisor with unified loop
- Add forwarding rule via control_client
- Send multicast traffic
- Verify packets forwarded correctly
- Check stats for correct counts

**Expected:** Packets received → rules matched → packets sent

### 2. Performance Testing (CRITICAL)

**Objective:** Compare against baselines

**Baselines:**

- PHASE4 (historical best): 307k pps egress
- Current two-thread model: ~97k pps egress (regressed)

**Test:**

```bash
sudo tests/data_plane_pipeline_veth.sh
```

**Success Criteria:**

- Ingress ≥ 690k pps (current baseline)
- Egress ≥ 307k pps (PHASE4 target)
- Buffer exhaustion < 40%

**Key Question:** Does unified loop recover the lost egress performance?

### 3. Optimization (if needed)

Potential areas:

- io_uring queue depth tuning
- Batch size optimization
- Buffer pool sizing
- Multiple workers per interface (horizontal scaling)

---

## Risk Assessment

### Low Risk ✅

- Clean compilation
- Stable startup
- No crashes in extended testing
- Well-understood single-threaded event loop pattern
- Easy to revert (legacy two-thread model still available)

### Questions to Answer

1. **Does it forward packets correctly?**
   - Status: Not yet tested with actual traffic
   - Next: Functional testing

2. **Does it perform better than two-thread model?**
   - Status: Not yet tested
   - Next: Performance benchmarking

3. **Can it saturate 1 Gbps?**
   - Status: Unknown
   - Mitigation: Can scale horizontally with multiple workers

---

## Conclusion

The unified single-threaded loop (Option 4) is now in a stable, testable state:

✅ **Implementation Complete**

- Packet parsing integrated
- Data plane wired up
- Default in supervisor

✅ **Critical Bugs Fixed**

- Submission queue overflow resolved
- Buffer pool exhaustion resolved

✅ **Stable Operation**

- Workers start successfully
- Run for 10+ minutes without crashes
- No resource errors

🔄 **Ready for Testing**

- Functional testing: Verify packet forwarding
- Performance testing: Compare vs baselines

The architecture eliminates the cross-thread communication bottleneck that was hypothesized to cause the egress performance regression. Now we need to validate that it actually forwards packets and measure whether it delivers the expected performance improvement.

---

## End of Session Summary
