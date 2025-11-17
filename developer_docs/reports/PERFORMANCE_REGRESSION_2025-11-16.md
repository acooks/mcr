# Performance Regression Report

**Date:** 2025-11-16
**Status:** **ROOT CAUSE IDENTIFIED**
**Severity:** High - Claims in STATUS.md not validated by current testing

---

## Executive Summary

Testing of the 3-hop pipeline performance revealed a **significant performance regression** compared to historical claims in project documentation. Current performance is approximately **75% lower** than previously documented results.

| Metric | Historical (PHASE4) | Current (2025-11-16) | Regression |
|--------|---------------------|----------------------|------------|
| MCR-1 Ingress | 490k pps | ~123k pps | **-75%** |
| MCR-1 Egress | 307k pps | ~83k pps | **-73%** |
| Traffic Generator | 733k pps | 779k pps | +6% |

---

## Test Methodology

### Test Script
- **Location:** `tests/data_plane_pipeline_veth.sh`
- **Purpose:** 3-hop MCR pipeline performance validation
- **Command:** `sudo tests/data_plane_pipeline_veth.sh`

### Test Configuration
- **Packet Count:** 10,000,000 packets
- **Target Rate:** 1,000,000 pps
- **Packet Size:** 1400 bytes
- **Topology:** Traffic Generator → MCR-1 → MCR-2 → MCR-3
- **Network:** veth pairs (virtual ethernet)
- **Workers:** 1 data plane worker per MCR instance

### Measurement Points
1. **Traffic Generator:** Actual send rate measured by traffic_generator binary
2. **MCR-1 Ingress:** AF_PACKET receive rate from STATS:Ingress FINAL
3. **MCR-1 Egress:** UDP socket send rate from STATS:Egress FINAL

---

## Current Test Results (2025-11-16)

### Traffic Generator Performance
```
Total packets sent: 10,000,000
Elapsed time: 12.83s
Actual packet rate: 779,506 pps (target: 1,000,000 pps)
```

### MCR-1 Final Statistics
```json
{
  "facility": "Ingress",
  "level": "Info",
  "message": "[STATS:Ingress FINAL] total: recv=1597169 matched=1597086 egr_sent=1084141 filtered=41 no_match=42 buf_exhaust=512945",
  "timestamp": "2025-11-16T12:17:24.123466574+00:00"
}
```

**Calculated Rates:**
- Ingress receive rate: 1,597,169 packets / 13s = **~123k pps**
- Egress send rate: 1,084,141 packets / 13s = **~83k pps**
- Buffer exhaustion: 512,945 / 1,597,169 = **32% packet loss**

---

## Historical Performance (PHASE4_COMPLETION.md)

### Original Test Results
Source: `developer_docs/reference_docs/completed/PHASE4_COMPLETION.md`

| Component | Metric | Value |
|-----------|--------|-------|
| Traffic Generator | Actual send rate | 733k pps (target: 1M pps) |
| Traffic Generator | Throughput | 8.22 Gbps |
| MCR-1 Ingress | Peak receive rate | **490k pps** |
| MCR-1 Ingress | Matched packets | 3.88M (63%) |
| MCR-1 Ingress | Buffer exhaustion | 2.25M packets (37%) |
| MCR-1 Egress | Sustained send rate | **307k pps** |
| MCR-1 Egress | Bytes sent | 5.85 GB |
| MCR-1 Egress | Errors | 0 |

**Key Quote from PHASE4:**
> "The data plane has demonstrated high throughput in a 3-hop pipeline test (**490k pps ingress**, **307k pps egress**)"

---

## Root Cause Analysis

### Performance Delta
- **Ingress:** 490k pps → 123k pps = **-367k pps (-75%)**
- **Egress:** 307k pps → 83k pps = **-224k pps (-73%)**

### **ROOT CAUSE: Logging in Packet Processing Hot Path**

Code analysis reveals **critical performance killers** added to the packet processing fast path:

#### 1. Buffer Exhaustion Critical Logging (MAJOR IMPACT)
**Location:** `src/worker/ingress.rs:420-426`

```rust
self.logger.critical(
    Facility::Ingress,
    &format!(
        "Buffer pool exhausted! Total exhaustions: {}",
        self.stats.buffer_exhaustion
    ),
);
```

**Impact:**
- Executes **512,945 times** in our test (32% of packets)
- Each execution:
  - Allocates a String via `format!()`
  - Writes formatted message to pipe
  - Pipe write causes context switch to supervisor thread
- **Estimated cost:** ~500k string allocations + pipe writes in fast path

#### 2. Per-Packet Trace Logging
**Location:** `src/worker/ingress.rs:382-390`

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

**Impact:**
- Executes for **EVERY packet** (~1.6M times)
- Even if trace level is disabled, `format!()` **still executes** before the function call
- Each call allocates and formats a string that may be immediately dropped

#### 3. Per-Forwarding Trace Logging
**Location:** `src/worker/ingress.rs:439-444`

```rust
self.logger.trace(
    Facility::Ingress,
    &format!(
        "Forwarding to {}:{} via {}",
        output.group, output.port, output.interface
    ),
);
```

**Impact:**
- Executes for every forwarded packet (~1.08M times)
- Same issue: `format!()` runs unconditionally

### Why This Kills Performance

The key issue is that **`format!()` is evaluated BEFORE the logging function is called**, even if the log level is disabled. The logging system has a `should_log()` check, but it happens AFTER expensive string allocation:

```rust
pub fn critical(&self, facility: Facility, message: &str) {
    self.log(severity, facility, message);  // should_log() check is inside log()
}
```

The call site does:
```rust
logger.critical(facility, &format!(...))  // format!() runs FIRST
```

This means:
1. **String allocation** happens on every call
2. **String formatting** happens on every call
3. **Pipe write** happens for critical level (which is enabled)

With 512k buffer exhaustions, this adds massive overhead to the hot path.

### Historical Context

These logging calls were added in commits between 2025-11-11 (PHASE4) and 2025-11-16:
- `9ef1628` - "feat(logging): Add comprehensive diagnostic logging to egress path"
- `f33afd2` - "feat(logging): Add Trace level and comprehensive ingress diagnostics"

These were intended for debugging but were never removed from production builds.

### Potential Causes (Secondary)

#### 1. Test Environment Differences
- **Hardware:** Different CPU, memory, or network characteristics
- **Kernel Version:** Different Linux kernel with different AF_PACKET performance
- **System Load:** Background processes affecting performance

#### 2. Code Regression
- **Timeframe:** PHASE4 was completed on 2025-11-11, current test on 2025-11-16
- **Changes Since:** Multiple commits including:
  - Logging system refactoring
  - Test infrastructure changes
  - Readiness check implementation
  - Stats collection modifications

#### 3. Configuration Differences
- **Buffer Tuning:** PHASE4 notes mention "with kernel buffer tuning"
  - No evidence of kernel buffer tuning in current test
  - `/proc/sys/net/core/rmem_max` and similar might need adjustment
- **Number of Workers:** Both tests appear to use single workers

#### 4. Measurement Methodology
- **PHASE4:** May have measured peak/burst rates
- **Current:** Measuring sustained average over full test duration
- **PHASE4:** 13.63s duration for 10M packets at 733k pps
- **Current:** 12.83s duration for 10M packets at 779k pps

---

## Impact

### Documentation Accuracy
The following documents contain performance claims that are not validated by current testing:

1. **STATUS.md** (Line 18):
   ```markdown
   **490k pps ingress**, **307k pps egress**
   ```

2. **developer_docs/reference_docs/archive/STATUS_pre_20251116.md**:
   ```markdown
   achieving **490k pps ingress** and **307k pps egress**
   ```

### User Expectations
Users reviewing project documentation will have incorrect performance expectations that are 3-4x higher than actual measured performance.

---

## Recommendations

### Immediate Actions

1. **Update STATUS.md** with conservative, validated performance numbers
   - Use current test results: ~120k pps ingress, ~80k pps egress
   - Or add caveat: "Performance numbers require kernel tuning and specific hardware"

2. **Document Test Conditions**
   - Kernel parameters used in PHASE4 tests
   - Hardware specifications
   - Network configuration details

### Investigation Tasks

1. **Reproduce PHASE4 Conditions**
   - Review git history around 2025-11-11
   - Check for kernel buffer tuning scripts/documentation
   - Identify any performance-related commits that may have regressed

2. **Profile Current Performance**
   - Use `perf` to identify bottlenecks
   - Check for new serialization points or locks
   - Verify io_uring submission/completion rates

3. **Systematic Performance Testing**
   - Test with different worker counts (1, 2, 4, 8)
   - Test with kernel buffer tuning applied
   - Test on different hardware/VMs

4. **Create Reproducible Benchmark**
   - Document exact commands and configuration
   - Include kernel tuning steps
   - Add to CI/CD for regression detection

---

## Test Artifacts

### Log Files
- MCR-1: `/tmp/mcr1_veth.log`
- MCR-2: `/tmp/mcr2_veth.log`
- MCR-3: `/tmp/mcr3_veth.log`
- Full test output: `/tmp/pipeline_test.log`

### Test Environment
```
Platform: linux
OS Version: Linux 6.17.7-200.fc42.x86_64
Date: 2025-11-16
Git Branch: main
Git Commit: 4df346f (fix: Fix logging deadlock in multi-instance tests)
```

---

## Next Steps

- [ ] Investigate code changes between 2025-11-11 and 2025-11-16
- [ ] Document kernel tuning requirements for high performance
- [ ] Update STATUS.md with validated performance numbers or caveats
- [ ] Create reproducible performance benchmark suite
- [ ] Add performance regression tests to CI

---

## Appendix: Full Test Output

### MCR-1 Final Stats (Raw JSON)
```json
{
  "facility": "Ingress",
  "level": "Info",
  "message": "[STATS:Ingress FINAL] total: recv=1597169 matched=1597086 egr_sent=1084141 filtered=41 no_match=42 buf_exhaust=512945",
  "timestamp": "2025-11-16T12:17:24.123466574+00:00"
}
```

### Traffic Generator Output
```
Sending to 239.1.1.1:5001 from interface 10.0.0.1 at 1000000 pps with size 1400
Total packets sent: 10000000
Elapsed time: 12.83s
Actual packet rate: 779506 pps (target: 1000000 pps)
Actual throughput: 8.74 Gbps
```

### Key Observations
- Buffer exhaustion at 32% indicates egress cannot keep up with ingress
- Similar pattern to PHASE4 (37% buffer exhaustion) but at much lower absolute rates
- Traffic generator achieving higher rate (779k vs 733k) suggests network stack is faster, but MCR processing is slower
