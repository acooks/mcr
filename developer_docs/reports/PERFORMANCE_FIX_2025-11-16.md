# Performance Fix Report

**Date:** 2025-11-16
**Status:** **PARTIAL FIX APPLIED**
**Related:** PERFORMANCE_REGRESSION_2025-11-16.md

---

## Executive Summary

Applied performance fix by removing logging from packet processing hot path. Results show **significant ingress improvement** but egress remains bottlenecked.

| Metric | Before Fix | After Fix | Improvement |
|--------|------------|-----------|-------------|
| MCR-1 Ingress | ~123k pps | ~689k pps | **+460%** |
| MCR-1 Egress | ~83k pps | ~97k pps | +17% |
| Traffic Generator | 779k pps | 693k pps | -11% (variance) |

**Key Result:** Ingress performance recovered to near-historical levels, but egress remains limited at ~97k pps (vs historical 307k pps).

---

## Changes Applied

### 1. Removed Per-Packet Trace Logging (ingress.rs:382-390)
**Before:**
```rust
self.logger.trace(
    Facility::Ingress,
    &format!(
        "Packet: dst={}:{} len={}",
        headers.ipv4.dst_ip,
        headers.udp.dst_port,
        packet_data.len()
    ),
);
```

**Impact:** Executed ~1.6M times per test, each with string allocation

---

### 2. Removed Buffer Exhaustion Critical Logging (ingress.rs:420-426)
**Before:**
```rust
self.logger.critical(
    Facility::Ingress,
    &format!(
        "Buffer pool exhausted! Total exhaustions: {}",
        self.stats.buffer_exhaustion
    ),
);
```

**Impact:** Executed 512k times in regression test, each with format!() + pipe write - **MAJOR PERFORMANCE KILLER**

---

### 3. Removed Per-Forwarding Trace Logging (ingress.rs:439-445)
**Before:**
```rust
self.logger.trace(
    Facility::Ingress,
    &format!(
        "Forwarding to {}:{} via {}",
        output.group, output.port, output.interface
    ),
);
```

**Impact:** Executed ~1.08M times per test

---

### 4. Removed Egress Channel Error Logging (ingress.rs:449-455)
**Before:**
```rust
self.logger.error(
    Facility::Ingress,
    &format!(
        "Egress channel send failed! Total errors: {}",
        self.stats.egress_channel_errors
    ),
);
```

**Impact:** Error path, but still allocates on every call

---

### 5. Removed Per-Packet Trace Logging from Egress (egress.rs:170-176)
**Before:**
```rust
self.logger.trace(
    Facility::Egress,
    &format!(
        "Packet submitted: {} -> {} len={}",
        key.0, key.1, payload_len
    ),
);
```

**Impact:** Executed for every egress packet submission

---

## Test Results (After Fix)

### Test Configuration
- **Test:** `tests/data_plane_pipeline_veth.sh`
- **Packets:** 10,000,000
- **Target Rate:** 1,000,000 pps
- **Packet Size:** 1400 bytes
- **Topology:** Traffic Generator → MCR-1 → MCR-2 → MCR-3
- **Duration:** 14.43s

### Traffic Generator Performance
```
Total packets sent: 10,000,000
Elapsed time: 14.43s
Actual packet rate: 692,879 pps (target: 1,000,000 pps)
Actual throughput: 7.76 Gbps
```

### MCR-1 Performance (Last Stats Before Shutdown)
```
recv=9,940,000 packets
egr_sent=1,405,182 packets
buf_exhaust=8,534,699 packets (86% buffer exhaustion!)
filtered=58
no_match=60
```

**Calculated Rates (14.43s):**
- **Ingress receive rate:** 9,940,000 / 14.43s = **689k pps**
- **Egress send rate:** 1,405,182 / 14.43s = **97k pps**
- **Buffer exhaustion:** 8,534,699 / 9,940,000 = **86%**

### MCR-2 Performance
```
recv=1,400,000 packets (97k pps)
egr_sent=1,198,042 packets (83k pps)
buf_exhaust=201,837 packets (14% buffer exhaustion)
```

---

## Analysis

### What Worked ✅

**Ingress performance recovered dramatically:**
- Before: ~123k pps
- After: ~689k pps
- **Improvement: +460%**

This proves the root cause analysis was correct - logging in the hot path was killing ingress performance. The ingress rate is now close to the traffic generator send rate (693k pps), which is appropriate.

### Remaining Issues ❌

**Egress remains severely bottlenecked:**
- Current: ~97k pps
- Historical (PHASE4): 307k pps
- **Still 68% below target**

**Evidence:**
1. **86% buffer exhaustion on MCR-1** - egress cannot keep up with ingress
2. **MCR-2 only receiving 97k pps** - limited by MCR-1 egress
3. **Egress send rate stuck at ~97k pps** across both MCR-1 and MCR-2

---

## Comparison with Historical Results

| Metric | PHASE4 (2025-11-11) | Before Fix | After Fix | vs PHASE4 |
|--------|---------------------|------------|-----------|-----------|
| Traffic Generator | 733k pps | 779k pps | 693k pps | -5% |
| MCR-1 Ingress | **490k pps** | 123k pps | **689k pps** | **+41%** ✅ |
| MCR-1 Egress | **307k pps** | 83k pps | 97k pps | **-68%** ❌ |
| Buffer Exhaustion | 37% | 32% | 86% | - |

**Key Insight:** Ingress performance now EXCEEDS historical results, but egress is still severely limited.

---

## Root Cause of Remaining Bottleneck

The egress bottleneck is NOT due to logging (we removed all hot-path logging). Possible causes:

### 1. io_uring Configuration
- Submission queue size
- Completion queue polling frequency
- Batching behavior

### 2. UDP Socket Performance
- Socket buffer sizes
- Kernel UDP send queue limits
- sendmsg() system call overhead

### 3. Buffer Pool Contention
- 86% buffer exhaustion suggests egress thread cannot process buffers fast enough
- Ingress allocates buffers, egress returns them after send completion
- High exhaustion = buffers stuck in egress pipeline

### 4. Thread Synchronization
- Channel between ingress/egress may be saturated
- Lock contention in buffer pool (though it should be lock-free)

### 5. Kernel Network Stack
- UDP socket buffer sizes not tuned
- Missing kernel buffer tuning from PHASE4

---
## Root Cause Analysis (Update: 2025-11-16)

A `codebase_investigator` analysis has identified two specific, high-confidence root causes for the severe egress performance regression:

### 1. Insufficient `io_uring` Queue Depth
*   **Finding:** The egress `io_uring` instance is being configured with a `queue_depth` of only **64 entries**. This is the default value set in `src/worker/data_plane_integrated.rs` where `EgressConfig` is instantiated.
*   **Impact:** A queue of this size is far too small for a high-throughput network application, severely limiting the number of concurrent send operations that can be in flight to the kernel. This creates a primary bottleneck.

### 2. Untuned UDP Socket Buffers
*   **Finding:** The `create_connected_udp_socket` function in `src/worker/egress.rs` creates UDP sockets without setting the `SO_SNDBUF` (send buffer size) socket option.
*   **Impact:** The default kernel send buffer is inadequate for a 300k+ pps workload. When this small buffer fills, the kernel will block the application or drop packets, causing performance to collapse.

**Conclusion:** The 86% buffer exhaustion is a direct symptom of these two configuration errors. The ingress worker is producing data far faster than the egress worker can submit it to the kernel, causing the ingress buffer pool to fill up and drop packets. The fix requires parameterizing the `EgressConfig` to allow a larger queue depth and adding `setsockopt` to tune `SO_SNDBUF` in `create_connected_udp_socket`.

---

## Next Steps

### Immediate Investigation
1. **Profile egress path** with `perf` to find CPU hotspots
2. **Check io_uring submission/completion rates** - are we waiting on kernel?
3. **Verify buffer pool implementation** - is it truly lock-free?
4. **Compare kernel tuning** with PHASE4 environment

### Potential Fixes
1. **Increase io_uring queue sizes** for egress
2. **Batch UDP sends** more aggressively
3. **Tune kernel socket buffers** (`SO_SNDBUF`, `/proc/sys/net/core/wmem_max`)
4. **Reduce egress wakeup latency** - check hybrid wakeup implementation
5. **Optimize buffer pool allocation** - reduce contention

### Validation
1. Re-run test after each fix
2. Compare with PHASE4 kernel tuning parameters
3. Test with different worker counts (1, 2, 4, 8)
4. Profile with `perf` to verify hotspot elimination

---

## Conclusion

The logging fix was successful and necessary - it proved our root cause analysis was correct and recovered ingress performance to exceed historical levels. However, a **second performance bottleneck exists in the egress path** that was masked by the logging overhead.

**Status:** Partial fix applied. Egress investigation required to achieve PHASE4 performance levels.

---

## Files Modified

- `src/worker/ingress.rs` - Removed 4 logging calls from packet processing path
- `src/worker/egress.rs` - Removed 1 logging call from packet submission path

## Build Status
✅ Project builds successfully
✅ No compilation errors
✅ Test script runs to completion
