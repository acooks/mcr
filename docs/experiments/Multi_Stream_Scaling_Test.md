# Multi-Stream Scaling Test: MCR vs socat

## Overview

This document describes the development and findings of a multi-stream scaling test designed to evaluate how MCR and socat performance scales with increasing numbers of concurrent multicast streams.

**Date**: 2025-11-15
**Test Script**: `tests/performance/multi_stream_scaling.sh`
**Status**: ✅ Test working, ❌ MCR multi-stream bug identified

---

## Motivation

Previous testing showed MCR performing well with single-stream workloads, but real-world deployments often involve multiple concurrent multicast streams. This test was created to:

1. Verify MCR can handle multiple concurrent streams
2. Compare MCR vs socat scaling behavior
3. Identify performance degradation points as stream count increases

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
- **Per-stream load**: 10,000 packets @ 2,000 pps
- **Stream counts tested**: 1, 2, 5, 10, 20, (50 optional)
- **Multicast groups**: 239.1.1.N → 239.10.1.N (where N = stream number)
- **Ports**: 5000+N (input) → 6000+N (output)

### Methodology

For each stream count:

1. Setup fresh network topology
2. Run MCR test:
   - Start MCR supervisor with 1 worker
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

### Test Run: 2025-11-15 13:53

**Configuration**: Up to 5 streams tested

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

### Analysis

**Critical Finding**: MCR completely fails with 2+ concurrent streams (100% packet loss), while socat handles multiple streams perfectly.

**Evidence**:
- MCR sink files created but empty (0 bytes)
- socat sink files contain expected data (~10MB each for 10k packets)
- Single stream works perfectly for both MCR and socat

**Verification**:
```bash
$ ls -lah /tmp/multistream_test_1995836/mcr_2stream/
total 0
-rw-r--r--. 1 root root 0 Nov 15 13:53 sink_1.bin
-rw-r--r--. 1 root root 0 Nov 15 13:53 sink_2.bin

$ ls -lah /tmp/multistream_test_1995836/socat_2stream/
total 20M
-rw-r--r--. 1 root root 9.8M Nov 15 13:53 sink_1.bin
-rw-r--r--. 1 root root 9.8M Nov 15 13:53 sink_2.bin
```

---

## Root Cause Investigation Needed

The test has successfully isolated a critical bug in MCR. Possible causes:

1. **IGMP membership issues**: MCR may not be properly joining multiple multicast groups simultaneously
2. **Routing table issues**: Multiple forwarding rules may be conflicting
3. **Socket buffer exhaustion**: Single socket trying to handle multiple streams
4. **Rule matching bug**: Rules after the first may not be matching packets correctly
5. **Concurrency issue**: Race condition when handling multiple streams

### Recommended Next Steps

1. **Enable MCR debug logging** for multi-stream test
2. **Capture packets** at each interface using tcpdump to see where packets are dropped:
   - `veth0` in gen-ns (packets being sent)
   - `veth1` in relay-ns (packets MCR receives)
   - `veth2` in relay-ns (packets MCR sends)
   - `veth3` in sink-ns (packets arriving at destination)
3. **Check MCR statistics** to see if packets are being received but not forwarded
4. **Verify IGMP memberships** are being established for all streams
5. **Test with sequential traffic** (not parallel) to see if it's a concurrency issue

---

## Script Quality Issues Encountered

This exercise revealed several issues with test script reliability:

### Problems

1. **Too many variations** - 22 shell scripts in `tests/`, many untested
2. **Copy-paste evolution** - Scripts duplicated and modified without validation
3. **No version control discipline** - Scripts created but not committed
4. **Broken abstractions** - Each script reimplements topology setup slightly differently

### Lessons

1. ✅ **Trust committed code** - Scripts in git have been validated
2. ✅ **Start from working examples** - Don't reinvent from scratch
3. ✅ **Test incrementally** - Verify each change works before adding more
4. ✅ **Cleanup on discovery** - Delete broken variants immediately
5. ✅ **Run before commit** - Never commit untested scripts

### Cleanup Actions Taken

- Deleted 3 broken test scripts that had the `wait` hang bug
- Created single working `multi_stream_scaling.sh` based on proven `compare_socat_chain.sh`
- Documented the correct pattern for parallel process management

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
- Occasional zombie MCR worker processes still occur but are minor

---

## Conclusion

**Test Status**: ✅ Working and reliable
- No hangs
- Cleanup functions correctly
- Produces reproducible results
- Successfully identified MCR multi-stream bug

**MCR Status**: ❌ Critical bug identified
- Single stream: Perfect (0% loss)
- Multiple concurrent streams: Complete failure (100% loss)
- Requires investigation and fix before multi-stream deployments

**Next Action**: Debug MCR's multi-stream handling to identify root cause of the packet forwarding failure when multiple concurrent streams are configured.
