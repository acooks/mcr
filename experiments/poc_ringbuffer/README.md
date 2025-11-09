# Ring Buffer Proof of Concept

This experiment implements and validates lockless ring buffers for the MCR logging system, based on analysis of Linux `printk_ringbuffer` and FreeBSD `msgbuf` designs.

## Overview

The PoC demonstrates two ring buffer implementations:
- **SPSC** (Single-Producer Single-Consumer): For data plane workers (io_uring threads)
- **MPSC** (Multiple-Producer Single-Consumer): For control plane (async Tokio tasks)

## Key Design Features

### 1. Sequence Number-Based Indexing
- Uses monotonic `u64` sequence numbers instead of wrap-around pointers
- Eliminates reader-writer cache line sharing (FreeBSD insight)
- Fast position calculation: `pos = seq & (capacity - 1)`

### 2. State Machine for Entry Validity
- States: `EMPTY → WRITING → READY → EMPTY`
- Readers can detect partial writes and wait safely
- Based on Linux printk's descriptor state machine

### 3. UnsafeCell for Interior Mutability
- Entries wrapped in `UnsafeCell<LogEntry>`
- Allows mutation through shared reference `&self`
- Safety guaranteed by state machine protocol

### 4. Memory Ordering
- `Ordering::Relaxed` for SPSC writes (no contention)
- `Ordering::AcqRel` for MPSC CAS operations
- `Ordering::Release` when marking READY (publish data)
- `Ordering::Acquire` when loading state (read data)

## Building and Running

```bash
# Build
cargo build --release

# Run demos and benchmarks
cargo run --release

# Run unit tests
cargo test

# Run criterion benchmarks (future)
cargo bench
```

## Demos

### SPSC Demo
- Single writer thread sends 10 messages
- Single reader thread consumes them
- Validates sequence numbers and message content

### MPSC Demo
- 4 writer threads (simulating cores) send 5 messages each
- Single reader thread consumes all 20 messages
- Demonstrates CAS-based coordination

## Benchmarks

### SPSC Benchmark
- 1 million write/read operations
- Measures throughput (ops/sec) and latency (ns/op)
- Target: >10M ops/sec, <100ns latency

### MPSC Benchmark
- 4 writers × 250K operations each = 1M total
- Measures CAS contention and overrun rate
- Target: >5M ops/sec aggregate

## Performance Targets (from design spec)

| Metric | SPSC Target | MPSC Target |
|--------|-------------|-------------|
| Write latency (p50) | < 100 ns | < 200 ns |
| Write latency (p99) | < 500 ns | < 2 µs |
| Throughput (single) | > 10M ops/sec | > 5M ops/sec |
| Overrun rate | < 0.01% | < 0.1% |

## Implementation Details

### LogEntry Structure
- Size: 512 bytes (cache-friendly, power-of-2)
- Fields: state, timestamp, sequence, core_id, message (256B)
- Cache-line aligned (`#[repr(align(64))]`)

### Ring Buffer Structure
```rust
pub struct SPSCRingBuffer {
    entries: Box<[UnsafeCell<LogEntry>]>,  // Heap-allocated
    capacity: usize,                       // Power of 2
    write_seq: CacheAligned<AtomicU64>,    // Separate cache line
    read_seq: CacheAligned<AtomicU64>,     // Separate cache line
    overruns: AtomicU64,                   // Statistics
    core_id: u8,                           // Which core this buffer serves
}
```

### Safety Invariants

**SPSC**:
- Only one thread writes (`write_seq`)
- Only one thread reads (`read_seq`)
- State machine prevents concurrent access to same entry

**MPSC**:
- Multiple writers use CAS to reserve slots
- Only one reader
- State machine prevents concurrent access

## Unit Tests

Tests cover:
- Basic write/read operations
- Wraparound after filling buffer
- Overrun detection and counting
- Concurrent writes (MPSC)
- Sequential consistency

## Related Documents

- `design/RINGBUFFER_IMPLEMENTATION.md` - Detailed implementation spec
- `design/KERNEL_RINGBUFFER_ANALYSIS.md` - Linux/FreeBSD analysis
- `design/LOGGING_DESIGN.md` - Overall logging system design

## Next Steps

1. ✅ Validate basic functionality (demos)
2. ✅ Measure performance (benchmarks)
3. ⏳ Compare vs design targets
4. ⏳ Run under `miri` (detect UB)
5. ⏳ Test with ThreadSanitizer (detect races)
6. ⏳ Integrate into MCR logging infrastructure
