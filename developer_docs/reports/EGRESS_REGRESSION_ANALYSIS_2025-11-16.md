# Egress Performance Regression - Root Cause Analysis

**Date:** 2025-11-16
**Status:** **CRITICAL REGRESSION IDENTIFIED**
**Related:** PERFORMANCE_REGRESSION_2025-11-16.md, PERFORMANCE_FIX_2025-11-16.md

---

## Executive Summary

Identified **critical architectural regression** in egress path that explains the 68% performance drop (307k pps → 97k pps) compared to PHASE4.

**Root Cause:** The `send_batch()` function was refactored to **remove synchronous io_uring submission and completion reaping**, breaking the tight coupling between packet submission and kernel processing.

---

## Code Comparison

### PHASE4 (Commit 2d5e8ef) - HIGH PERFORMANCE ✅

```rust
pub fn send_batch(&mut self) -> Result<usize> {
    if self.egress_queue.is_empty() {
        return Ok(0);
    }

    let batch_size = self.egress_queue.len().min(self.config.batch_size);

    // Submit send operations for each packet in the batch
    for _ in 0..batch_size {
        let packet = self.egress_queue.remove(0);
        self.submit_send(packet)?;
    }

    // Submit all operations to io_uring
    self.ring
        .submit()
        .context("Failed to submit send operations")?;

    // Reap completions
    let sent_count = self.reap_completions(batch_size)?;

    Ok(sent_count)
}
```

**Key behaviors:**
1. **Immediate submission** after preparing batch
2. **Synchronous completion reaping** - waits for sends to complete
3. **Buffer deallocation** happens immediately after completion
4. **Tight feedback loop** - buffers return to pool quickly

---

### CURRENT (HEAD) - LOW PERFORMANCE ❌

```rust
pub fn send_batch(&mut self) -> Result<usize> {
    if self.egress_queue.is_empty() {
        return Ok(0);
    }
    let batch_size = self.egress_queue.len().min(self.config.batch_size);
    for _ in 0..batch_size {
        let packet = self.egress_queue.remove(0);
        self.submit_send(packet)?;
    }
    // NOTE: We do NOT call ring.submit() or reap_completions() here.
    // The main event loop is the ONLY place that calls submit_and_wait().
    // This keeps the event loop non-blocking and ensures we continuously drain packet_rx.
    Ok(batch_size)
}
```

**Changed behaviors:**
1. **No submission** in send_batch() - operations stay in submission queue
2. **No completion reaping** - buffers stay allocated
3. **Deferred submission** - happens later in event loop
4. **Broken feedback loop** - buffers accumulate in "in_flight" state

---

## Event Loop Analysis

### Current Event Loop (egress.rs:430-496)

```rust
pub fn run(&mut self, packet_rx: &crossbeam_queue::SegQueue<EgressWorkItem>) -> Result<()> {
    loop {
        // 1. Non-blockingly drain the packet queue and submit sends
        while let Some(packet) = packet_rx.pop() {
            self.add_destination(&packet.interface_name, packet.dest_addr)?;
            self.queue_packet(packet);
        }
        if !self.is_queue_empty() {
            self.send_batch()?;  // <- Does NOT submit or reap!
        }

        // 2. Check for completions (non-blocking)
        self.process_cqe_batch()?;

        // 3. Check shutdown
        if self.shutdown_requested() {
            // ... drain logic
        }

        // 4. Always submit pending I/O operations (non-blocking)
        self.ring.submit()?;  // <- Submission happens HERE

        // 5. Idle handling based on wakeup strategy
        if !self.in_flight.is_empty() || !packet_rx.is_empty() {
            std::hint::spin_loop();
        } else {
            self.wakeup_strategy.wait();
        }
    }
}
```

**The Problem:**
1. Packets are prepared in `send_batch()` but NOT submitted
2. Submission happens once per loop iteration at line 485
3. Completion reaping happens once per loop iteration at line 445
4. **This creates a 1-iteration delay between submission and completion reaping**

---

## Performance Impact Analysis

### Buffer Pool Exhaustion Mechanism

**PHASE4 behavior (synchronous):**
```
Iteration N:
  1. Ingress allocates 32 buffers from pool
  2. Sends to egress channel
  3. Egress calls send_batch()
  4. send_batch() submits to io_uring
  5. send_batch() reaps completions
  6. Buffers deallocated, returned to pool
  7. Pool has 32 buffers available for iteration N+1
```

**Current behavior (asynchronous):**
```
Iteration N:
  1. Ingress allocates 32 buffers from pool
  2. Sends to egress channel
  3. Egress calls send_batch() - buffers stay in in_flight
  4. Event loop continues (no submission yet)
  5. process_cqe_batch() - may reap some old completions
  6. ring.submit() - submits batch from step 3
  7. Buffers STILL in in_flight, NOT returned to pool

Iteration N+1:
  1. Ingress tries to allocate buffers - pool DEPLETED
  2. Buffer exhaustion → packet drop
  3. Eventually completions from iteration N are reaped
  4. Buffers return to pool, but TOO LATE
```

**Result:** Ingress allocates faster than egress deallocates → 86% buffer exhaustion

---

## Why This Happens

### Queue Depth Limits

- **io_uring queue depth:** 64 (from config)
- **Batch size:** 32 (from config)
- **In-flight capacity:** ~64 packets maximum

**Saturation calculation:**
- Ingress can queue packets at ~689k pps
- Egress can only have 64 in-flight at once
- At 97k pps completion rate: 64 buffers / 97k pps = **0.66ms buffer lifetime**
- But ingress needs buffers every: 64 buffers / 689k pps = **0.09ms**

**The math doesn't work!** Ingress needs buffers 7x faster than egress can return them.

---

## Why PHASE4 Worked

With synchronous `send_batch()`:
- Each batch completes BEFORE next batch starts
- Buffer lifetime = batch processing time (~34.6µs for 64 packets from Exp #5)
- Buffers return to pool before ingress needs them again
- **No buffer exhaustion** (or only 37% in worst case)

---

## Performance Comparison

| Metric | PHASE4 (Sync) | Current (Async) | Impact |
|--------|---------------|-----------------|--------|
| Egress Rate | 307k pps | 97k pps | **-68%** |
| Buffer Exhaustion | 37% | 86% | +132% |
| In-flight Buffers | ~32 (one batch) | ~64 (saturated) | +100% |
| Buffer Lifetime | ~35µs | ~660µs | +1786% |

---

## Root Cause Timeline

### When Did This Break?

Looking at the diff, the refactor happened between PHASE4 (2d5e8ef, 2025-11-10) and now. The comment in the code gives us a clue:

```rust
// NOTE: We do NOT call ring.submit() or reap_completions() here.
// The main event loop is the ONLY place that calls submit_and_wait().
// This keeps the event loop non-blocking and ensures we continuously drain packet_rx.
```

**Intent:** Make event loop non-blocking for better responsiveness

**Reality:** Broke buffer pool feedback loop, causing catastrophic performance regression

---

## Why It Wasn't Caught

1. **No performance regression tests** in CI
2. **Different test scenarios** - PHASE4 tested 3-hop pipeline, later tests may have been simpler
3. **Gradual degradation** - async refactor seemed like an improvement for responsiveness
4. **Focus on ingress** - egress bottleneck masked by logging overhead until now

---

## Fix Strategy

### Option 1: Revert to Synchronous send_batch() ✅ RECOMMENDED

**Change:**
```rust
pub fn send_batch(&mut self) -> Result<usize> {
    if self.egress_queue.is_empty() {
        return Ok(0);
    }
    let batch_size = self.egress_queue.len().min(self.config.batch_size);

    for _ in 0..batch_size {
        let packet = self.egress_queue.remove(0);
        self.submit_send(packet)?;
    }

    // RESTORE: Submit and reap immediately
    self.ring.submit().context("Failed to submit send operations")?;
    let sent_count = self.reap_completions(batch_size)?;

    Ok(sent_count)
}
```

**Pros:**
- Proven to work (PHASE4 results)
- Simple revert
- Restores buffer pool feedback loop

**Cons:**
- May block event loop during completion waiting
- Could affect responsiveness to shutdown signals

---

### Option 2: Increase Buffer Pool Size ❌ NOT RECOMMENDED

**Change:** Increase buffer pool from current size to accommodate in-flight delay

**Why not:**
- Doesn't fix root cause
- Wastes memory
- Still limits maximum throughput
- Band-aid solution

---

### Option 3: Aggressive Completion Reaping ⚠️ COMPLEX

**Change:** Reap completions immediately after every submit

```rust
// 4. Always submit pending I/O operations (non-blocking)
self.ring.submit()?;
// IMMEDIATELY reap to return buffers to pool
self.process_cqe_batch()?;
```

**Pros:**
- Keeps async event loop
- Reduces buffer lifetime

**Cons:**
- Still has 1-iteration delay
- More complex
- Unproven

---

## Recommended Fix

**Revert send_batch() to synchronous submission + completion reaping**

This is the simplest fix that restores PHASE4 performance levels. The async refactor was well-intentioned but broke a critical performance assumption.

---

## Validation Plan

1. Apply fix to send_batch()
2. Run `tests/data_plane_pipeline_veth.sh`
3. Verify:
   - Egress rate ≥ 300k pps (PHASE4 level)
   - Buffer exhaustion < 40%
   - Ingress rate maintained at ~690k pps
4. Compare with PHASE4 baseline

---

## Lessons Learned

1. **Performance-critical code needs benchmarks** - The async refactor would have been caught by regression tests
2. **Tight coupling can be intentional** - The sync submission/reaping was not a bug, it was a design choice
3. **Comments matter** - The "NOTE" comment explained the intent but not the cost
4. **Buffer pool feedback loops are fragile** - Breaking the tight loop caused cascade failure

---

## Files Affected

- `src/worker/egress.rs` - send_batch() method (lines 122-135 in current version)

## Related Commits

- `2d5e8ef` (2025-11-10) - Last known good performance
- Unknown commit between 2d5e8ef and current - introduced async refactor

## Priority

**CRITICAL** - 68% performance regression, blocks achieving PHASE4 performance goals
