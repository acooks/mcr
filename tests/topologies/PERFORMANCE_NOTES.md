# Topology Test Performance Notes

## Observed Performance Characteristics

### Single-Worker Configuration (`--num-workers 1`)

**Test Setup:**
- Virtual ethernet (veth) interfaces
- Network namespace isolation
- 3-hop chain topology
- 1400-byte packets

**Results @ 500k pps target:**
```text
Traffic sent: 1,000,000 packets @ 500k pps
MCR-1 received: 301,950 packets (30%)
MCR-1 matched: 239,634 packets (24%)
Buffer exhaustion: 62,316 packets (21% of received)
```

**Bottlenecks Identified:**

1. **Kernel-Level Drops (70%)**
   - AF_PACKET socket only receives ~300k pps out of 500k sent
   - Drops occur in kernel before reaching userspace
   - Root causes:
     - veth interface queue limits (txqueuelen)
     - Kernel netdev backlog size (net.core.netdev_max_backlog)
     - Single-threaded worker cannot keep up

2. **Buffer Pool Exhaustion (21% of received)**
   - Of packets that reach AF_PACKET, 21% dropped due to buffer exhaustion
   - This is expected backpressure behavior
   - Indicates egress is slower than ingress

3. **Effective Throughput: ~240k pps**
   - Single worker with veth interfaces: ~240k-300k pps sustained
   - Well below the 490k pps achieved with real interfaces (see PHASE4_COMPLETION.md)

## Performance Comparison

| Configuration | Interfaces | Workers | Throughput | Notes |
|---------------|------------|---------|------------|-------|
| **Production** (PHASE4) | Real veth (point-to-point) | 1 | **490k pps** ingress | With kernel buffer tuning |
| **Test** (chain_3hop) | Virtual veth (in namespace) | 1 | **240k pps** effective | Untuned kernel, isolated namespace |
| **Theoretical** | Real NIC | 8 | >3M pps | Multi-core, lazy socket creation |

## Why veth Performance is Lower

### 1. **Virtual vs. Real Interfaces**
- Real veth pairs (host namespace): Near-native performance
- Virtual veth (namespace-isolated): More kernel overhead
- Namespace isolation adds context switching costs

### 2. **Kernel Buffer Limits**
In isolated namespace, default kernel parameters are conservative:
```bash
# Check current values
sysctl net.core.netdev_max_backlog    # Often 1000 (too small!)
sysctl net.core.rmem_max               # Max socket buffer
ip link show veth0 | grep qlen         # Interface queue length
```

### 3. **Single Worker Architecture**
Current test uses `--num-workers 1` due to architectural limitations:
- **Issue**: Eager AF_PACKET socket creation (see STATUS.md, D23)
- **Impact**: All workers create identical sockets, exhausting resources
- **Workaround**: Force single worker
- **Solution**: Implement lazy socket creation (HIGH PRIORITY)

## Recommendations

### Short-Term (For Tests)

**Adjust test to match actual capacity:**
```bash
PACKET_COUNT=500000   # 500k packets
SEND_RATE=250000      # 250k pps (realistic for single worker + veth)
```

**Result:** Test validates functionality without false failures due to capacity limits.

### Medium-Term (Kernel Tuning)

Add kernel tuning to test setup:
```bash
# Increase network buffers before entering namespace
sysctl -w net.core.netdev_max_backlog=5000
sysctl -w net.core.rmem_max=134217728  # 128MB

# Inside namespace, increase veth queue
ip link set veth0 txqueuelen 10000
```

**Expected improvement:** ~350-400k pps effective throughput

### Long-Term (Architecture)

**Implement Lazy Socket Creation (D23):**
- Workers create AF_PACKET sockets only when rules are added
- Enables multi-worker configuration
- Each worker handles subset of flows (consistent hashing)

**Expected improvement:** Linear scaling with CPU cores
- 1 worker: ~300k pps
- 4 workers: ~1.2M pps
- 8 workers: ~2.4M pps

**Implement Privilege Separation (D24):**
- Supervisor creates AF_PACKET sockets
- Passes FDs to unprivileged workers
- Improves security without performance impact

## CPU Isolation Findings

### Test Configuration
- Each MCR instance pinned to separate CPU core via `taskset`
- Tree fanout topology: 4 MCR instances on cores 0-3
- 500k packets @ 300k pps with 3x amplification

### Results
**Before CPU isolation (all on core 0):**
```text
MCR-1 matched: 87k (29% efficiency)
All instances competing for 1 core (8 threads total)
```

**After CPU isolation (cores 0-3):**
```text
MCR-1 matched: 85k (17% efficiency)
Each instance on dedicated core
```

### Key Finding: CPU Isolation Did NOT Improve Throughput

**Reason:** The bottlenecks are **not CPU contention**, but:

1. **Kernel packet drops (58%)** - Before AF_PACKET socket
   - 500k sent → 211k received by AF_PACKET
   - veth interface limits
   - Single AF_PACKET socket saturation

2. **Buffer pool exhaustion (60% of received)**
   - 211k received → 85k matched
   - 126k packets dropped (buffer pool full)
   - Pool sized for 1:1 forwarding (1000 buffers)
   - 3x amplification needs 3x capacity or faster egress

3. **Single-worker architecture**
   - One thread doing ingress AND egress
   - Egress can't drain fast enough (3x output rate)
   - Backpressure fills buffer pool

### Value of CPU Isolation

While it didn't improve throughput, CPU isolation still provides:
- ✅ **Stability** - No thread contention between MCR instances
- ✅ **Predictability** - Each instance has guaranteed CPU time
- ✅ **Testing** - Isolates per-instance performance issues
- ✅ **Production** - Best practice for multi-tenant scenarios

### Amplification-Specific Issues

#### CRITICAL FINDING: Buffer Pool Size is NOT the Bottleneck

Experiment tested buffer pool sizing impact on 3x amplification:
- **Before:** 1000 small buffers → 64% buffer exhaustion (126k / 206k)
- **After:** 4000 small buffers (4x capacity) → 65% buffer exhaustion (135k / 207k)
- **Result:** NO IMPROVEMENT - same exhaustion percentage!

**Conclusion:** Egress throughput is the real bottleneck, not buffer capacity.

**Root Cause Analysis:**
1. **Egress Saturation:** Must send 3x packets (to 3 outputs), ~219k pps egress vs 73k pps ingress
2. **Single Worker Limitation:** One thread alternates ingress ↔ egress, can't parallelize
3. **Buffers Fill Regardless:** Egress can't drain fast enough, any size buffer pool eventually fills
4. **Ingress Blocks:** When buffers full, ingress drops packets, limiting overall throughput

**Why Increasing Buffers Doesn't Help:**
- Larger buffers delay the problem but don't solve it
- If egress sends 200k pps but needs 300k pps, buffers will always fill
- It's like trying to fix a traffic jam by building a bigger parking lot

**The Real Fixes:**
1. **Separate Ingress/Egress Workers (D23)** - Run on different cores in parallel
2. **Batch Egress Operations** - Send multiple packets per syscall
3. **Backpressure** - Slow ingress to match egress capacity
4. **Accept Limitation** - Single worker @ 3x amplification = ~70k pps ingress capacity

## Current Test Strategy

**Goal:** Validate **functionality**, not maximum performance

**Approach:**
- Use realistic packet rates (250k pps) that work reliably
- Focus on end-to-end packet flow validation
- Accept buffer exhaustion as expected behavior
- Document performance characteristics for future optimization

**Non-Goals:**
- ❌ Stress testing at maximum capacity (different test needed)
- ❌ Multi-core performance testing (blocked by D23)
- ❌ Production-level throughput benchmarks (use real NICs)

## Future Test Ideas

### 1. **High-Performance Test** (Post-D23)
```bash
# Multi-worker, real interfaces, kernel tuning
--num-workers 8
--interface eth0  # Real NIC
Target: >2M pps sustained
```

### 2. **Stress Test**
```bash
# Deliberately overload to test backpressure
SEND_RATE=1000000  # 1M pps
Validate: No crashes, stats accurate, graceful degradation
```

### 3. **Long-Duration Test**
```bash
# Run for hours to detect memory leaks, degradation
DURATION=3600  # 1 hour
Validate: Stable throughput, no memory growth
```

## Conclusion

**Current topology tests are fit for purpose:**
- ✅ Validate end-to-end packet flow
- ✅ Detect configuration errors
- ✅ Verify stats accuracy
- ✅ Demonstrate backpressure behavior

**Known limitation:** Single-worker + veth = ~250k pps effective
**Root cause:** Architectural debt (D23, D24)
**Mitigation:** Document and set realistic expectations
**Path forward:** High-priority work items in STATUS.md
