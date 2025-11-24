# Buffer Pool Performance Model - Quick Reference

This document contains the mathematical model and key calculations for buffer pool sizing and performance analysis.

## System Parameters

```text
Target throughput:    5M packets/second (total system)
Reference config:     16 cores
Per-core rate:        312,500 packets/second
Inter-packet time:    3.2 µs
```

## Key Formulas

### 1. In-Flight Buffer Count

```text
Buffers_in_flight = Packet_rate × Buffer_lifetime

Where Buffer_lifetime = Parse + Copy + Submit + Completion + Dealloc
```

**Example calculations (312.5k pps/core):**

| Scenario    | Completion | Total Lifetime | Buffers In-Flight |
| ----------- | ---------- | -------------- | ----------------- |
| Optimistic  | 5 µs       | 7 µs           | 2.2               |
| Realistic   | 20 µs      | 22 µs          | 6.9               |
| Pessimistic | 100 µs     | 102 µs         | 31.9              |

### 2. io_uring Batch Effects

```text
Batch_window = SQ_depth / Packet_rate
Buffers_accumulated = SQ_depth
Buffers_in_completion = Completion_time × Packet_rate

Total_in_flight = Buffers_accumulated + Buffers_in_completion
```

**For SQ depth = 256, 312.5k pps/core, 20 µs completion:**

```text
Batch_window = 256 / 312,500 = 819 µs
Accumulated = 256 buffers
In_completion = 20 µs × 312,500 = 6.25 buffers
Total = 262 buffers
```

### 3. Burst Traffic Modeling

```text
Burst_packets = Burst_factor × Nominal_rate × Burst_duration

Queue_buildup = (Ingress_rate - Egress_rate) × Burst_duration
```

**Example: 3x burst for 50ms, egress handles 1.5x:**

```text
Burst_packets = 3 × 312,500 × 0.05 = 46,875 packets
Queue_buildup = (3 - 1.5) × 312,500 × 0.05 = 23,437 buffers
```

**This shows pools must be sized for bursts, not just steady-state.**

### 4. Memory Footprint

```text
Pool_memory = Σ(Buffer_count × Buffer_size) for each size class

Total_memory = Pool_memory × Core_count
```

**Proposed configuration:**

```text
Small (1500B):    1,000 × 1,500 = 1,500 KB
Standard (4096B):   500 × 4,096 = 2,000 KB
Jumbo (9000B):      200 × 9,000 = 1,800 KB
───────────────────────────────────────────
Per core:                         5,300 KB

For 16 cores:    16 × 5.3 MB = 84.8 MB
```

### 5. Performance Metrics

**Allocation Latency:**

```text
Pool_latency = Check_empty + Pop + Update_counter
             ≈ 5-10 ns (L1 cache hit)

Vec_latency = Lock + Lookup + Metadata + (Syscall if needed)
            ≈ 50-100 ns (fast path)
            ≈ 1,000-10,000 ns (slow path)

Speedup = Vec_latency / Pool_latency = 5-1000x
```

**Cache Savings:**

```text
Cold_buffer_penalty = RAM_access + TLB_miss
                    ≈ 100-150 ns

CPU_savings = Packet_rate × Cold_buffer_penalty
            = 312,500 × 100 ns
            = 31.25 ms/second
            = 3.125% CPU per core
```

### 6. Exhaustion Time

```text
Time_to_exhaustion = Pool_size / (Burst_rate - Nominal_rate)
```

**Example: 1000-buffer pool, 3x burst (937.5k pps burst vs 312.5k nominal):**

```text
Time_to_exhaustion = 1,000 / (937,500 - 312,500)
                   = 1,000 / 625,000
                   = 1.6 ms
```

**Fast exhaustion under sustained bursts - need graceful drop behavior.**

### 7. Recovery Time

After burst ends, how long to refill pool?

```text
Recovery_time = Pool_size / Deallocation_rate
```

Assuming egress completes at normal rate after burst:

```text
Recovery_time = 1,000 / 312,500 = 3.2 ms
```

**Very fast recovery - pools refill quickly once pressure drops.**

## Size Class Distribution

Typical multicast traffic distribution (assumption):

```text
Small packets (< 1500B):    60%  →  1,000 buffers
Standard packets (< 4KB):   30%  →    500 buffers
Jumbo packets (< 9KB):      10%  →    200 buffers
```

This weighting balances:

- Memory efficiency (don't over-allocate large buffers)
- Common case performance (most packets are small)
- Burst tolerance (enough headroom for temporary spikes)

## Benchmark Targets

Based on this model, experiment success criteria:

| Metric                   | Target                  | Rationale                    |
| ------------------------ | ----------------------- | ---------------------------- |
| Pool alloc latency (p99) | < 50 ns                 | 5-10x better than Vec        |
| Pool throughput          | > 5M ops/sec            | 16x headroom over 312.5k pps |
| Exhaustion behavior      | Graceful drop           | No crashes, predictable      |
| Recovery time            | < 100 ms                | Fast return to normal        |
| Metrics overhead         | < 10%                   | Acceptable for observability |
| Cache benefit            | 10-100x fewer L3 misses | Quantifiable via perf        |

## Validation Checklist

- [ ] Latency benchmark confirms pool < 50 ns (p99)
- [ ] Throughput benchmark shows > 5M ops/sec
- [ ] Exhaustion test shows graceful degradation
- [ ] Recovery test shows < 100ms return to steady state
- [ ] Metrics overhead test shows < 10% impact
- [ ] Perf analysis shows measurable cache benefits
- [ ] Memory footprint < 100 MB for 16-core system
- [ ] No panics or crashes under any test scenario

## References

- D15: Core-Local Buffer Pools
- D16: Buffer Pool Observability
- D5: Memory Copy Egress (necessitates efficient allocation)
- ARCHITECTURE.md: Performance requirements
- DEVLOG.md: Original 5M pps target, multi-core design
