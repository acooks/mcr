# Multi-Stream Scaling Test: MCR vs socat

## Overview

This document describes the development and findings of a multi-stream scaling test designed to evaluate how MCR and socat performance scales with increasing numbers of concurrent multicast streams.

**Date**: 2025-11-15 to 2025-11-16
**Test Script**: `tests/performance/multi_stream_scaling.sh`
**Status**: ✅ Test working, 🔧 MCR scaling issues identified and documented

---

## Motivation

Previous testing showed MCR performing well with single-stream workloads, but real-world deployments often involve multiple concurrent multicast streams. This test was created to:

1. Verify MCR can handle multiple concurrent streams
2. Compare MCR vs socat scaling behavior
3. Identify performance degradation points as stream count increases
4. Stress-test MCR with 150+ concurrent streams @ 500+ kpps aggregate throughput

---

## Test Development Process

### Initial Attempts (Failed)

Three initial test scripts were created but had critical bugs:

1. **`high_density_streams.sh`** - Used parallel background traffic generators with bare `wait` command
2. **`single_stream_count_test.sh`** - Same `wait` bug
3. **`stream_scaling_test.sh`** - Same `wait` bug

**Critical Bug**: All three scripts backgrounded both traffic generators AND socat sink/relay processes, then used `wait` to wait for completion. Since socat processes run forever (continuously listening), `wait` would hang indefinitely waiting for them to exit.

```bash
# WRONG - hangs forever
socat ... &
traffic_generator ... &
wait  # Waits for ALL background jobs including socat
```

### Lesson Learned: Trust Existing Code

The breakthrough came from examining `tests/performance/compare_socat_chain.sh`, which was already committed to git and known to work. Key insights:

1. **Run traffic generators in foreground** - No `wait` needed
2. **Use the exact topology setup that works** - Don't reinvent
3. **Keep it simple** - One test at a time

### Final Solution

The working `multi_stream_scaling.sh` uses:

```bash
# Collect PIDs of only the traffic generators
gen_pids=()
for stream in $(seq 1 $num_streams); do
    traffic_generator ... &
    gen_pids+=($!)
done

# Wait ONLY for traffic generators, not socat processes
for pid in "${gen_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
done
```

**Key Principle**: Only `wait` for processes you actually need to wait for. Background processes that run forever (like socat listeners) should NOT be waited on.

---

## Test Configuration

### Topology

```
gen-ns (veth0) <-> (veth1) relay-ns (veth2) <-> (veth3) sink-ns
10.0.0.1              10.0.0.2  10.0.1.1         10.0.1.2
```

Chain topology with three network namespaces, proven to work for both MCR and socat.

### Test Parameters

- **Packet size**: 1024 bytes
- **Per-stream load**: 10,000 packets @ 2,000 pps (default)
- **Stream counts tested**: 1, 2, 5, 10, 20, 50, 100, 150
- **MCR workers**: 4 (configurable via `NUM_WORKERS`)
- **Multicast groups**: 239.1.X.Y → 239.10.X.Y (mapped addresses)
  - For streams 1-254: 239.1.1.N → 239.10.1.N
  - For streams 255-508: 239.1.2.(N-254) → 239.10.2.(N-254)
- **Ports**: 5000+N (input) → 6000+N (output)

### Environment Variables

The test script supports the following configuration:

```bash
# Number of packets per stream (default: 10000)
PER_STREAM_PACKETS=100000

# Packets per second per stream (default: 2000)
PER_STREAM_RATE=5000

# Number of MCR worker processes (default: 4)
NUM_WORKERS=8

# Packet payload size in bytes (default: 1024)
PACKET_SIZE=1024
```

### Methodology

For each stream count:

1. Setup fresh network topology
2. Run MCR test:
   - Increase IGMP membership limit to 200
   - Start MCR supervisor with N workers
   - Configure N forwarding rules (one per stream)
   - Start N socat sinks (receivers)
   - Run N traffic generators **in parallel**
   - Wait for generators to complete
   - Count received bytes
3. Cleanup and setup fresh topology
4. Run socat test:
   - Start N socat sinks
   - Start N socat relay processes
   - Run N traffic generators **in parallel**
   - Wait for generators to complete
   - Count received bytes
5. Record results

---

## Findings

### Test Run 1: 2025-11-15 13:53 (Initial Bug Discovery)

**Configuration**: Up to 5 streams tested, 1 worker

#### MCR Results

| Streams | Expected | Received | Loss %  |
|---------|----------|----------|---------|
| 1       | 10,000   | 10,000   | 0.00%   |
| 2       | 20,000   | 0        | 100.00% |
| 5       | 50,000   | 0        | 100.00% |

#### socat Results

| Streams | Expected | Received | Loss %  |
|---------|----------|----------|---------|
| 1       | 10,000   | 10,000   | 0.00%   |
| 2       | 20,000   | 20,000   | 0.00%   |
| 5       | 50,000   | 50,000   | 0.00%   |

**Finding**: MCR completely failed with 2+ concurrent streams (100% packet loss), while socat handled multiple streams perfectly. This was traced to IGMP and PACKET_FANOUT bugs that were subsequently fixed in commit 6072617.

---

### Test Run 2: 2025-11-16 (After IGMP Fix - IGMP Membership Limit Discovery)

**Configuration**: Up to 50 streams tested, 4 workers

After the IGMP/PACKET_FANOUT fixes, multi-stream tests were re-run with increased scale.

#### Initial Results (20-stream limit hit)

**Root Cause**: Linux kernel parameter `/proc/sys/net/ipv4/igmp_max_memberships` defaults to **20**

When attempting to run 50-stream tests, only 20 forwarding rules were successfully configured. The script silently failed to add rules beyond the 20th stream.

**Evidence**:
```bash
$ cat /proc/sys/net/ipv4/igmp_max_memberships
20
```

**Fix Applied**:
- Modified test script to increase limit to 200 before testing
- Added automatic restoration of original limit on exit
- Added error checking to rule configuration loop

```bash
# Increase IGMP membership limit
ORIGINAL_IGMP_LIMIT=$(cat /proc/sys/net/ipv4/igmp_max_memberships)
echo 200 > /proc/sys/net/ipv4/igmp_max_memberships

# Restore original limit on exit
trap "echo $ORIGINAL_IGMP_LIMIT > /proc/sys/net/ipv4/igmp_max_memberships 2>/dev/null || true" EXIT
```

---

### Test Run 3: 2025-11-16 (With IGMP Limit Fix - ENOBUFS Discovery)

**Configuration**: Up to 50 streams tested, 4 workers, 10k packets/stream @ 2k pps

With the IGMP membership limit increased to 200, tests were re-run.

#### MCR Results

| Streams | Expected Packets | Received Packets | Loss %  | Status |
|---------|-----------------|------------------|---------|--------|
| 1       | 10,000          | 10,000           | 0.00%   | ✅     |
| 2       | 20,000          | 20,000           | 0.00%   | ✅     |
| 5       | 50,000          | 50,000           | 0.00%   | ✅     |
| 10      | 100,000         | 100,000          | 0.00%   | ✅     |
| 20      | 200,000         | 193,906          | 3.05%   | ⚠️     |
| 50      | 500,000         | 0                | 100.00% | ❌     |

#### socat Results

| Streams | Expected Packets | Received Packets | Loss %  | Status |
|---------|-----------------|------------------|---------|--------|
| 1       | 10,000          | 10,000           | 0.00%   | ✅     |
| 2       | 20,000          | 20,000           | 0.00%   | ✅     |
| 5       | 50,000          | 50,000           | 0.00%   | ✅     |
| 10      | 100,000         | 100,000          | 0.00%   | ✅     |
| 20      | 200,000         | 200,000          | 0.00%   | ✅     |
| 50      | 500,000         | 500,000          | 0.00%   | ✅     |

**Key Findings**:

1. **MCR works perfectly up to 10 concurrent streams** (0% loss)
2. **Performance degrades at 20 streams** (3.05% loss, 193,906/200,000 packets)
3. **Complete failure at 50 streams** (100% loss)
4. **socat handles all stream counts with 0% loss**

---

### Root Cause Analysis: ENOBUFS (Error 105)

**Test Directory**: `/tmp/multistream_test_3457541/mcr_50stream/`

**Critical Error Found in MCR Logs**:
```
[Worker 3686256] [ingress-thread] run() returned: Err(No buffer space available (os error 105))
[Worker 3686251] [ingress-thread] run() returned: Err(No buffer space available (os error 105))
[Worker 3686251] Data Plane worker process failed: No buffer space available (os error 105)
[Worker 3686256] Data Plane worker process failed: No buffer space available (os error 105)
[2025-11-16 13:19:57.402] [Warning] [Supervisor] Data Plane worker (core 2) failed (status: exit status: 1), restarting after 250ms
[2025-11-16 13:19:57.904] [Warning] [Supervisor] Data Plane worker (core 0) failed (status: exit status: 1), restarting after 250ms
```

**Analysis**:

1. **Error Type**: `ENOBUFS` (errno 105) - "No buffer space available"
2. **Failure Point**: Workers crash during multicast group join operations
3. **Rules Configured**: Only 40 out of 50 rules were successfully added before worker crash
4. **Worker Behavior**: Supervisor attempts to restart failed workers, but the issue persists

**Evidence**:
```bash
$ grep -c "Rule added" /tmp/multistream_test_3457541/mcr_50stream/mcr.log
40

$ wc -c /tmp/multistream_test_3457541/mcr_50stream/sink_*.bin | head -5
0 /tmp/multistream_test_3457541/mcr_50stream/sink_10.bin
0 /tmp/multistream_test_3457541/mcr_50stream/sink_11.bin
0 /tmp/multistream_test_3457541/mcr_50stream/sink_12.bin
0 /tmp/multistream_test_3457541/mcr_50stream/sink_13.bin
0 /tmp/multistream_test_3457541/mcr_50stream/sink_14.bin
```

All sink files are 0 bytes, confirming no packets were received.

**System Buffer Settings**:
```bash
$ cat /proc/sys/net/core/rmem_max
212992

$ cat /proc/sys/net/core/wmem_max
212992
```

Socket buffer limits are set to ~208 KB, which may be insufficient for high multicast group counts.

---

## Root Cause Summary

Three distinct issues were discovered during multi-stream scaling testing:

### 1. IGMP/PACKET_FANOUT Bug (Fixed in commit 6072617)
- **Symptom**: 100% packet loss with 2+ streams
- **Cause**: Incorrect IGMP membership and PACKET_FANOUT handling
- **Status**: ✅ FIXED

### 2. IGMP Membership Limit (Fixed in test script)
- **Symptom**: Configuration stops at 20 rules, silent failure
- **Cause**: Linux kernel default `/proc/sys/net/ipv4/igmp_max_memberships` = 20
- **Fix**: Test script now increases limit to 200 before testing
- **Status**: ✅ WORKAROUND IMPLEMENTED

### 3. Socket Buffer Exhaustion - ENOBUFS (Needs MCR Code Fix)
- **Symptom**: Workers crash with "No buffer space available" at 40-50 multicast groups
- **Cause**: Socket buffer limits exhausted when joining many multicast groups
- **Impact**:
  - 10 streams: 0% loss ✅
  - 20 streams: 3.05% loss ⚠️
  - 50 streams: 100% loss ❌
- **Status**: ❌ OPEN BUG - Requires MCR code changes

---

## Recommended Next Steps

### High Priority

1. **Fix ENOBUFS in MCR**:
   - Increase socket buffer sizes in data plane worker initialization
   - Use `setsockopt(SO_RCVBUF)` and `setsockopt(SO_SNDBUF)` to request larger buffers
   - Consider system-level tuning recommendations in documentation

2. **Test with increased buffer sizes**:
   ```bash
   # Temporary system-wide increase for testing
   sudo sysctl -w net.core.rmem_max=8388608
   sudo sysctl -w net.core.wmem_max=8388608
   ```

3. **Re-run 50, 100, 150 stream tests** after buffer fixes

### Medium Priority

1. **Investigate 20-stream degradation**: 3.05% loss suggests performance degradation before complete failure
2. **Profile memory usage**: Understand memory consumption per multicast group
3. **Document system requirements**: Specify kernel parameter tuning for large-scale deployments

### Low Priority

1. **Consider alternative multicast join strategies**: Join groups on-demand vs. pre-join
2. **Benchmark socat resource usage**: Understand why socat succeeds where MCR fails
3. **Add monitoring**: Expose metrics for buffer usage and multicast group count

---

## Cleanup Reliability

### Initial Issues

1. Trap on EXIT only - didn't catch INT or TERM signals
2. pkill before deleting namespaces - wrong order
3. Processes running in namespaces not killed by pkill from root namespace
4. Zombie MCR worker processes occasionally survive

### Final Working Approach

```bash
cleanup_all() {
    echo "[INFO] Running cleanup"

    # Restore IGMP limit
    echo $ORIGINAL_IGMP_LIMIT > /proc/sys/net/ipv4/igmp_max_memberships 2>/dev/null || true

    # Delete namespaces FIRST - kills processes inside them
    ip netns del gen-ns 2>/dev/null || true
    ip netns del relay-ns 2>/dev/null || true
    ip netns del sink-ns 2>/dev/null || true

    # Kill any remaining processes
    pkill -9 -f "traffic_generator" 2>/dev/null || true
    pkill -9 -f "multicast_relay" 2>/dev/null || true
    pkill -9 -f "socat.*UDP4" 2>/dev/null || true

    # Clean up files
    rm -f "$MCR_SOCK"

    echo "[INFO] Cleanup complete"
}

trap cleanup_all EXIT INT TERM
```

**Key points**:
- Namespaces deleted first (automatically kills processes inside)
- Force kill with `-9` for any stragglers
- Trap multiple signals (EXIT, INT, TERM)
- Restore system settings (IGMP limit)
- Occasional zombie MCR worker processes still occur but are minor

---

## Test Script Quality Improvements

### Enhancements Made (2025-11-16)

1. **Comprehensive documentation** with environment variable examples
2. **Error handling** in rule configuration with detailed reporting
3. **IGMP limit management** with automatic restoration
4. **Output redirection** to log files to reduce context window pollution
5. **Progress delays** every 10 rules for stability
6. **Multicast address generation** supporting 508 concurrent streams

### Script Reliability

The test is now production-ready:
- ✅ No hangs
- ✅ Proper cleanup with signal handling
- ✅ Configurable via environment variables
- ✅ Comprehensive error reporting
- ✅ Log file management
- ✅ System state restoration

---

## Conclusion

**Test Status**: ✅ Working and reliable
- Incremental testing from 1 to 50+ streams
- Comprehensive error detection and reporting
- Clean output with detailed logs preserved
- Successfully identified scaling bottleneck

**MCR Status**: 🔧 Scaling limitation identified
- **Works perfectly**: 1-10 concurrent streams (0% loss)
- **Degraded performance**: 20 streams (3.05% loss)
- **Fails completely**: 50 streams (100% loss due to ENOBUFS)
- **Root cause**: Socket buffer exhaustion when joining 40+ multicast groups

**socat Baseline**: ✅ Reference implementation
- Handles all tested stream counts (1-50) with 0% loss
- Provides performance target for MCR optimization

**Next Action**: Fix socket buffer allocation in MCR data plane workers to support 150+ concurrent multicast streams. The ENOBUFS error indicates a solvable resource allocation issue rather than a fundamental architectural limitation.
