# Ring Buffer Implementation Specification

## Overview

This document specifies the ring buffer implementation for MCR's logging system, based on analysis of Linux `printk_ringbuffer` and FreeBSD `msgbuf` designs.

## Design Decisions

### 1. Sequence Number-Based Indexing

**Decision**: Use monotonic sequence numbers (u64) instead of wrap-around pointers.

**Rationale**:

- Avoids reader-writer cache line sharing (FreeBSD msgbuf insight)
- u64 never wraps in practice (584 years at 1B ops/sec)
- Simpler than Linux's ID+wrap count approach
- Fast position calculation: `pos = seq & (capacity - 1)` (for power-of-2 capacity)

**Example**:

```text
Sequence:    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10, ...
Position:    0,   1,   2,   3,   0,   1,   2,   3,   0,   1,   2, ... (capacity=4)
```

### 2. Dual Ring Buffer Approach

**Decision**: Two ring buffer implementations for different concurrency patterns.

| Buffer Type | Use Case              | Writers         | Readers      | Synchronization            |
| ----------- | --------------------- | --------------- | ------------ | -------------------------- |
| **SPSC**    | Data plane (io_uring) | 1 per core      | 1 (consumer) | Lock-free, Relaxed atomics |
| **MPSC**    | Control plane (async) | N (tokio tasks) | 1 (consumer) | CAS-based reservation      |

### 3. Entry State Machine

**Decision**: Use 3-state atomic field per entry.

**States**:

```rust
const EMPTY: u8   = 0;  // Slot available for writing
const WRITING: u8 = 1;  // Writer is filling the entry
const READY: u8   = 2;  // Entry ready for reading
```

**State Transitions**:

```text
Writer: EMPTY → WRITING → READY
Reader: READY → EMPTY (after consuming)
```

**Rationale**: Reader can detect partial writes and skip them (Linux printk insight).

### 4. Memory Ordering

**Critical for Correctness**:

| Operation             | Ordering                           | Rationale                                          |
| --------------------- | ---------------------------------- | -------------------------------------------------- |
| Write seq increment   | `Relaxed` (SPSC) / `AcqRel` (MPSC) | SPSC has no contention, MPSC needs synchronization |
| Read seq load         | `Acquire`                          | Synchronize with writer                            |
| Entry state → WRITING | `Release`                          | Signal start of write                              |
| Entry state → READY   | `Release`                          | Ensure data visible before ready                   |
| Entry state load      | `Acquire`                          | Ensure reading latest data                         |

**Key Insight**: Paired `Release`/`Acquire` creates happens-before relationship.

```rust
// Writer
entry.data = value;                              // Regular store
entry.state.store(READY, Ordering::Release);     // Release: all prior stores visible

// Reader
if entry.state.load(Ordering::Acquire) == READY { // Acquire: see all writer's stores
    let data = entry.data;                       // Safe to read
}
```

### 5. Overflow Strategy

**Decision**: Drop oldest entries (overwrite), track overrun count.

**Rationale**:

- Preserves low latency (no blocking)
- Recent logs are more valuable than old logs
- Overrun counter signals buffer sizing issues
- Both Linux and FreeBSD use this approach

**Detection**:

```rust
if write_seq >= read_seq + capacity {
    // Overwriting unread entry
    overruns.fetch_add(1, Ordering::Relaxed);
}
```

## Data Structures

### Log Entry

```rust
#[repr(C, align(64))]  // Cache line alignment
pub struct LogEntry {
    // === Synchronization (8 bytes) ===
    state: AtomicU8,           // EMPTY, WRITING, READY
    _pad1: [u8; 7],            // Alignment padding

    // === Metadata (32 bytes) ===
    timestamp_ns: u64,         // Monotonic nanoseconds since boot
    sequence: u64,             // Global sequence number
    severity: u8,              // 0-7 (syslog levels)
    facility: u8,              // Component identifier
    core_id: u8,               // CPU core (255 = unknown)
    _pad2: u8,                 // Alignment
    process_id: u32,           // Worker PID
    thread_id: u64,            // Thread ID

    // === Message (272 bytes) ===
    message_len: u16,          // Actual message length (0-256)
    _pad3: [u8; 6],            // Alignment
    message: [u8; 256],        // Fixed-size message buffer

    // === Key-Value Pairs (192 bytes) ===
    kv_count: u8,              // Number of KV pairs (0-8)
    _pad4: [u8; 7],            // Alignment
    kvs: [KeyValue; 8],        // 8 × 24 bytes = 192 bytes
}

#[repr(C)]
pub struct KeyValue {
    key_len: u8,               // Key length (0-15)
    value_len: u8,             // Value length (0-21)
    _pad: [u8; 2],             // Alignment
    key: [u8; 16],             // Key buffer
    value: [u8; 64],           // Value buffer
}

// Total: 64 + 32 + 272 + 192 = 560 bytes (round to 512 for simplicity)
// Use 512 bytes per entry for cache-friendly size
```

**Design Choices**:

- **Cache line aligned**: Prevents false sharing between adjacent entries
- **Fixed size**: Zero-allocation, predictable memory layout
- **Power-of-2 size**: Fast modulo via bitwise AND

### SPSC Ring Buffer (Data Plane)

```rust
pub struct SPSCRingBuffer {
    // === Ring Buffer ===
    entries: Box<[LogEntry]>,   // Heap-allocated, fixed size
    capacity: usize,            // Power of 2 (e.g., 65536)

    // === Sequence Numbers (in separate cache lines) ===
    write_seq: CacheAligned<AtomicU64>,  // Writer's position
    read_seq: CacheAligned<AtomicU64>,   // Reader's position

    // === Statistics ===
    overruns: AtomicU64,        // Messages dropped due to overflow

    // === Metadata ===
    core_id: u8,                // Which CPU core this buffer serves
    facility: Facility,         // Logging facility
}

#[repr(align(64))]
struct CacheAligned<T>(T);  // Force separate cache lines
```

**Key Feature**: `write_seq` and `read_seq` in separate cache lines to prevent false sharing.

### MPSC Ring Buffer (Control Plane)

```rust
pub struct MPSCRingBuffer {
    // === Ring Buffer ===
    entries: Box<[LogEntry]>,
    capacity: usize,

    // === Sequence Numbers ===
    write_seq: CacheAligned<AtomicU64>,  // Multiple writers compete via CAS
    read_seq: CacheAligned<AtomicU64>,   // Single reader

    // === Statistics ===
    overruns: AtomicU64,
    cas_failures: AtomicU64,    // CAS contention metric
}
```

**Difference from SPSC**: Writers use `compare_exchange_weak` to reserve sequence numbers.

## Algorithms

### SPSC Write (Lock-Free, Single Producer)

```rust
impl SPSCRingBuffer {
    pub fn write(&self, mut entry: LogEntry) -> Result<(), LogEntry> {
        // 1. Reserve sequence number (no contention, use Relaxed)
        let seq = self.write_seq.fetch_add(1, Ordering::Relaxed);
        let pos = (seq as usize) & (self.capacity - 1);  // Fast modulo

        // 2. Check for overrun
        let read_seq = self.read_seq.load(Ordering::Acquire);
        if seq >= read_seq + self.capacity as u64 {
            self.overruns.fetch_add(1, Ordering::Relaxed);
            // Continue writing (overwrite old entry)
        }

        // 3. Mark entry as WRITING
        self.entries[pos].state.store(WRITING, Ordering::Release);

        // 4. Fill entry fields
        entry.sequence = seq;
        entry.state = AtomicU8::new(READY);  // Will be stored atomically below
        self.entries[pos] = entry;

        // 5. Mark entry as READY (all data visible to reader)
        self.entries[pos].state.store(READY, Ordering::Release);

        Ok(())
    }
}
```

**Complexity**: O(1), ~50-100ns expected latency

### SPSC Read (Lock-Free, Single Consumer)

```rust
impl SPSCRingBuffer {
    pub fn read(&self) -> Option<LogEntry> {
        // 1. Check if data available
        let read_seq = self.read_seq.load(Ordering::Relaxed);
        let write_seq = self.write_seq.load(Ordering::Acquire);

        if read_seq >= write_seq {
            return None;  // Buffer empty
        }

        let pos = (read_seq as usize) & (self.capacity - 1);

        // 2. Wait for entry to be READY (rare: writer might be mid-write)
        let mut spins = 0;
        loop {
            let state = self.entries[pos].state.load(Ordering::Acquire);
            if state == READY {
                break;
            }
            if spins > 1000 {
                // Writer stalled? Shouldn't happen, but don't hang forever
                return None;
            }
            spins += 1;
            std::hint::spin_loop();
        }

        // 3. Read entry (safe: state == READY guarantees complete write)
        let entry = self.entries[pos].clone();

        // 4. Mark as consumed
        self.entries[pos].state.store(EMPTY, Ordering::Release);
        self.read_seq.fetch_add(1, Ordering::Release);

        Some(entry)
    }
}
```

**Complexity**: O(1), ~50-100ns expected latency (no spin in normal case)

### MPSC Write (Lock-Free via CAS, Multiple Producers)

```rust
impl MPSCRingBuffer {
    pub fn write(&self, mut entry: LogEntry) -> Result<(), LogEntry> {
        // 1. Reserve sequence number via CAS (contention possible)
        let seq = loop {
            let current = self.write_seq.load(Ordering::Relaxed);

            match self.write_seq.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,  // Success: acquire current, release new
                Ordering::Relaxed, // Failure: retry
            ) {
                Ok(_) => break current,  // Reserved slot
                Err(_) => {
                    self.cas_failures.fetch_add(1, Ordering::Relaxed);
                    std::hint::spin_loop();  // Brief pause before retry
                }
            }
        };

        let pos = (seq as usize) & (self.capacity - 1);

        // 2-5. Same as SPSC (check overrun, write entry, mark READY)
        let read_seq = self.read_seq.load(Ordering::Acquire);
        if seq >= read_seq + self.capacity as u64 {
            self.overruns.fetch_add(1, Ordering::Relaxed);
        }

        self.entries[pos].state.store(WRITING, Ordering::Release);
        entry.sequence = seq;
        entry.state = AtomicU8::new(READY);
        self.entries[pos] = entry;
        self.entries[pos].state.store(READY, Ordering::Release);

        Ok(())
    }
}
```

**Complexity**: O(1) expected, O(N) worst case (N = number of concurrent writers)
**Expected Latency**: 100-500ns (depends on contention)

### MPSC Read (Same as SPSC)

Reader implementation identical to SPSC (single consumer in both cases).

## Buffer Sizing

### Memory Budget

| Component          | Buffer Size | Entry Size | Total Memory | Rationale                        |
| ------------------ | ----------- | ---------- | ------------ | -------------------------------- |
| Ingress (per-core) | 65,536      | 512 B      | 32 MB        | Fits in L3 cache, handles bursts |
| Egress (per-core)  | 16,384      | 512 B      | 8 MB         | Lower volume than ingress        |
| DataPlane          | 8,192       | 512 B      | 4 MB         | Coordinator, moderate volume     |
| Supervisor         | 4,096       | 512 B      | 2 MB         | Low frequency                    |
| ControlPlane       | 4,096       | 512 B      | 2 MB         | Low frequency                    |
| Other facilities   | 2,048       | 512 B      | 1 MB         | Default for misc facilities      |

**4-Core System Total**: (32 + 8) × 4 cores + 4 + 2 + 2 + 5 × 1 = **173 MB**

### Power-of-2 Requirement

All capacities must be powers of 2 for fast modulo:

```rust
pos = seq & (capacity - 1)  // Fast: single AND instruction
// vs
pos = seq % capacity        // Slow: division instruction
```

## Concurrency Guarantees

### SPSC Guarantees

1. **Single Writer**: Only one thread writes to `write_seq` (guaranteed by architecture)
2. **Single Reader**: Only one thread reads from `read_seq` (enforced by consumer task)
3. **No Data Races**: Sequence numbers + state machine prevent concurrent access to same entry
4. **Progress**: Writer never blocks (drops on overflow), reader never blocks (returns None if empty)

### MPSC Guarantees

1. **Multiple Writers**: Any number of threads can call `write()` concurrently
2. **Single Reader**: Only one consumer thread (same as SPSC)
3. **Atomicity**: CAS ensures only one writer gets each sequence number
4. **No Data Races**: Same as SPSC (state machine protects entry access)
5. **Progress**: All writers eventually succeed (lock-free, no deadlock)

### Memory Ordering Guarantees

**Happens-Before Relationships**:

```text
Writer: entry.data = X (1)
Writer: fence(Release) (2)
Writer: state.store(READY, Release) (3)

Reader: state.load(Acquire) == READY (4)
Reader: fence(Acquire) (5)
Reader: read entry.data (6)

Ordering guarantee: (1) happens-before (2) happens-before (3) happens-before (4) happens-before (5) happens-before (6)
Therefore: Writer's data store (1) happens-before Reader's data load (6) ✓
```

## Performance Targets

| Metric                     | SPSC (Data Plane) | MPSC (Control Plane) |
| -------------------------- | ----------------- | -------------------- |
| Write latency (p50)        | < 100 ns          | < 200 ns             |
| Write latency (p99)        | < 500 ns          | < 2 µs               |
| Read latency               | < 100 ns          | < 200 ns             |
| Throughput (single thread) | > 10M ops/sec     | > 5M ops/sec         |
| Throughput (4 writers)     | N/A               | > 15M ops/sec        |
| Overrun rate               | < 0.01%           | < 0.1%               |

**Baseline Comparison**:

- Linux `printk`: ~100-500 ns
- FreeBSD `msgbuf`: ~200-800 ns (spinlock overhead)
- Rust `crossbeam::queue`: ~50-150 ns (similar SPSC design)

## Testing Strategy

### Unit Tests

1. **Basic Operations**: Write, read, empty buffer, full buffer
2. **Wraparound**: Fill buffer multiple times, verify sequence numbers
3. **Overrun**: Write beyond capacity, verify overrun counter
4. **State Machine**: Verify state transitions, detect partial writes

### Concurrency Tests

1. **SPSC Stress**: Single writer, single reader, 10M operations
2. **MPSC Stress**: 4 writers, single reader, 10M operations each
3. **Race Detection**: Run under `miri` (Rust interpreter that detects UB)
4. **Thread Sanitizer**: Detect data races (if available)

### Performance Benchmarks

1. **Latency Distribution**: Measure p50, p90, p99, p999 for write/read
2. **Throughput**: Measure ops/sec for varying workloads
3. **Contention Impact**: MPSC with 1, 2, 4, 8 concurrent writers
4. **Cache Effects**: Compare performance with different buffer sizes

### Property-Based Tests

Using `proptest`:

1. **Sequential Consistency**: All reads occur in write order
2. **No Lost Messages**: Read count + overrun count = write count
3. **No Duplicates**: Every sequence number appears at most once

## Implementation Phases

### Phase 1: Core SPSC Implementation ✓ (PoC)

- [ ] `LogEntry` struct with state field
- [ ] `SPSCRingBuffer` with sequence numbers
- [ ] Basic write/read operations
- [ ] Unit tests

### Phase 2: Core MPSC Implementation ✓ (PoC)

- [ ] `MPSCRingBuffer` with CAS-based write
- [ ] Concurrent write tests
- [ ] Benchmarks vs SPSC

### Phase 3: Performance Validation

- [ ] Latency benchmarks (compare vs targets)
- [ ] Throughput benchmarks
- [ ] Memory ordering verification (miri)
- [ ] Optimize hot paths if needed

### Phase 4: Integration

- [ ] Integrate into logging infrastructure
- [ ] Add facility-specific buffers
- [ ] Consumer task implementation
- [ ] End-to-end testing

## Open Questions

1. **Clone vs. Copy for LogEntry**:
   - Clone: Flexible but potential allocation
   - Copy: Fast but requires all fields be Copy
   - **Decision**: Use Copy with fixed-size arrays (no allocation)

2. **Capacity Configuration**:
   - Fixed at compile time or runtime configurable?
   - **Decision**: Runtime configurable via constructor, but must be power-of-2

3. **Timestamp Source**:
   - `CLOCK_MONOTONIC` (no NTP jumps) or `CLOCK_REALTIME` (wall clock)?
   - **Decision**: Start with `CLOCK_MONOTONIC`, provide conversion for display

4. **Entry Reclamation**:
   - Mark EMPTY immediately or batch reclamation?
   - **Decision**: Immediate (simpler, reader controls pace)

## References

- Linux `printk_ringbuffer`: kernel/printk/printk_ringbuffer.c
- FreeBSD `msgbuf`: sys/kern/subr_msgbuf.c
- Rust Atomics and Locks (Mara Bos): <https://marabos.nl/atomics/>
- crossbeam-rs: Lock-free data structures
- Linux kernel memory barriers: Documentation/memory-barriers.txt
