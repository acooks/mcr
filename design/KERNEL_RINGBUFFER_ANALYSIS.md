# Kernel Ring Buffer Analysis: Linux vs FreeBSD

## Executive Summary

This document analyzes the ring buffer implementations used for kernel logging in Linux (`printk_ringbuffer`) and FreeBSD (`msgbuf`) to extract design patterns applicable to the MCR logging system.

**Key Takeaway**: Linux uses a complex lockless multi-ring design optimized for extreme concurrency, while FreeBSD uses a simpler spinlock-protected single buffer with sequence number-based indexing. Both avoid the reader-writer pointer sharing problem but use different techniques.

---

## Linux: `printk_ringbuffer` (kernel/printk/printk_ringbuffer.c)

### Architecture Overview

**Three Coordinated Rings**:

1. **Descriptor Ring**: Metadata (sequence number, timestamp, log level, state, pointers to text)
2. **Text Data Ring**: Actual log message content (byte array with data blocks)
3. **Info Array**: Parallel metadata array (`printk_info` structs) for quick access

**Design Philosophy**: Fully lockless for multiple readers, per-CPU synchronization for writers, works in all contexts including NMI (Non-Maskable Interrupt).

### Synchronization Mechanism

#### State Machine for Descriptors

Each descriptor has a combined **ID + State** field stored as `atomic_long`:

```c
// States (from least to most finalized):
desc_miss      = -1  // Descriptor not yet allocated
desc_reserved  = 0   // Writer has reserved, not committed
desc_committed = 1   // Data written, not yet finalized
desc_finalized = 2   // Visible to readers
desc_reusable  = 3   // Can be recycled for new records
```

**ID Field**: Tracks wrap count to prevent ABA problem (recycled descriptors get new ID).

#### Atomic Operations

**Writer Path**:

1. Reserve descriptor with `cmpxchg(desc_state, desc_reusable, desc_reserved)`
2. Write text data to data ring
3. Commit descriptor with atomic state transition to `desc_committed`
4. Finalize with atomic state transition to `desc_finalized`

**Reader Path**:

1. Read descriptor state (atomic load)
2. If state >= `desc_committed`, read descriptor metadata
3. Read state again after copying
4. If states match and ID unchanged, data is valid (no concurrent modification)

#### Memory Barriers

Critical barriers ensure ordering:

```c
// From desc_read() documentation:
"Guarantee the state is loaded before copying descriptor content.
This avoids copying obsolete descriptor content."
```

Paired barriers between writer commits and reader checks prevent stale reads.

### Logical Positions and ABA Prevention

**Logical Position**: Combines actual index with wrap count bits:

- Lower bits: Index into ring
- Upper bits: Wrap count (increments each time ring wraps)

**Why**: On 32-bit systems, prevents ABA problem where position value wraps and appears identical to old value.

**Example**:

```text
Position 0x00000005: wrap=0, index=5
Position 0x10000005: wrap=1, index=5  // Different position despite same index
```

### Per-CPU Optimizations

1. **Interrupt Disabling**: Writers disable local interrupts during reserve/commit to reduce contention
2. **Relaxed Atomics**: Uses `cmpxchg_relaxed` where explicit barriers handle ordering
3. **Data Block Wrapping**: If data doesn't fit at end of ring, wraps to beginning (minimizes copying)

### Buffer Sizing

**Default**: `CONFIG_LOG_BUF_SHIFT=17` → 128 KB buffer

- Configurable at compile time
- Larger for servers, smaller for embedded systems

---

## FreeBSD: `msgbuf` (sys/kern/subr_msgbuf.c)

### Architecture Overview

**Single Ring Buffer** with sequence number-based indexing:

- One circular byte buffer (`msg_ptr`)
- Two sequence counters: `msg_wseq` (write), `msg_rseq` (read)
- Spinlock protection: `msg_lock` (MTX_SPIN type)

**Design Philosophy**: Simpler than Linux, uses spinlocks but optimizes to avoid reader/writer pointer dependencies.

### Synchronization Mechanism

#### Spinlock Protection

```c
mtx_lock_spin(&mbp->msg_lock);
// Critical section: update msg_wseq, write data
mtx_unlock_spin(&mbp->msg_lock);
```

**Spin Lock** (not sleep lock): Short critical sections, safe in interrupt context.

#### Sequence Number Innovation

**Key Insight**: Instead of read/write pointers that must be shared, use **sequence numbers** that are independent.

```c
// Sequence numbers are modulo (buffer_size * 16):
#define MSGBUF_SEQMOD(mbp) ((mbp)->msg_size * 16)

// Convert sequence to buffer position:
#define MSGBUF_SEQ_TO_POS(mbp, seq) ((seq) % (mbp)->msg_size)

// Normalize sequence after increment:
#define MSGBUF_SEQNORM(mbp, seq) ((seq) % MSGBUF_SEQMOD(mbp))
```

**Sequence Modulus**: 16× buffer size allows sequence numbers to distinguish between multiple wraparounds without collision.

**Example** (128 KB buffer):

- Buffer size: 131,072 bytes
- Sequence modulus: 131,072 × 16 = 2,097,152
- Write at sequence 131,080 → position 8 (wrapped once)
- Write at sequence 262,152 → position 8 (wrapped twice, different sequence)

### Why Sequence Numbers Matter

**Traditional Approach** (problematic):

```c
// Writer updates write_pos
write_pos = (write_pos + 1) % buffer_size;

// Reader needs to check write_pos to know how much data is available
available = (write_pos - read_pos) % buffer_size;
```

**Problem**: Reader must access writer's pointer (cache line sharing, contention).

**FreeBSD Approach** (elegant):

```c
// Writer updates msg_wseq (independent variable)
msg_wseq = MSGBUF_SEQNORM(mbp, msg_wseq + 1);

// Reader uses msg_rseq (independent variable)
msg_rseq = MSGBUF_SEQNORM(mbp, msg_rseq + 1);

// No shared cache line!
```

**Benefit**: Writer and reader touch different variables, reducing cache coherency traffic.

### Wraparound Handling

**Detection**:

```c
wseq = mbp->msg_wseq;
rseq = mbp->msg_rseq;
len = MSGBUF_SEQSUB(mbp, wseq, rseq);  // Bytes in buffer

if (len > mbp->msg_size) {
    // Buffer full, advance read sequence to drop old data
    mbp->msg_rseq = MSGBUF_SEQNORM(mbp, wseq - mbp->msg_size);
}
```

**Overflow Behavior**: Oldest messages are silently dropped (same as Linux).

### Data Structure

```c
struct msgbuf {
    struct mtx msg_lock;        // Spinlock for synchronization
    char *msg_ptr;              // Pointer to buffer
    int msg_size;               // Buffer size in bytes
    int msg_seqmod;             // Sequence modulus (size * 16)
    u_int msg_wseq;             // Write sequence number
    u_int msg_rseq;             // Read sequence number
    u_int msg_cksum;            // Checksum (validity check)
    u_int msg_flags;            // State flags (e.g., MSGBUF_NEEDNL)
    int msg_lastpri;            // Last priority level (for formatting)
    int msg_magic;              // Magic number (buffer validity)
};
```

### Buffer Sizing

**Default**: 96 KB (as of FreeBSD 12)

- Tunable via kernel config: `options MSGBUF_SIZE=262144` (256 KB)
- Persists across reboots if memory region preserved

---

## Comparative Analysis

| Feature             | Linux `printk_ringbuffer`          | FreeBSD `msgbuf`                          |
| ------------------- | ---------------------------------- | ----------------------------------------- |
| **Rings**           | 3 rings (desc, text, info)         | 1 ring (byte buffer)                      |
| **Locking**         | Lockless (per-CPU atomic CAS)      | Spinlock (`MTX_SPIN`)                     |
| **Readers**         | Multiple concurrent readers        | Single reader (or serialized)             |
| **Writers**         | Per-CPU synchronization            | Spinlock-protected                        |
| **NMI-safe**        | Yes (lockless design)              | Partially (spinlocks can deadlock in NMI) |
| **ABA Prevention**  | ID field in descriptor             | Sequence modulus 16× buffer size          |
| **Metadata**        | Separate descriptor ring           | Inline flags + checksum                   |
| **Complexity**      | High (state machine, 3 rings)      | Low (sequence numbers, 1 buffer)          |
| **Performance**     | Extremely high concurrency         | Good for moderate concurrency             |
| **Memory Overhead** | Higher (descriptors + text + info) | Lower (just buffer + metadata)            |
| **Timestamp**       | Per-record in descriptor           | Can be added (recent enhancement)         |

---

## Design Lessons for MCR Logging

### 1. Sequence Numbers vs. Pointers

**Lesson from FreeBSD**: Use **sequence numbers** instead of shared read/write pointers to avoid cache line contention.

**MCR Application**:

```rust
pub struct RingBuffer {
    entries: Box<[LogEntry]>,
    capacity: usize,
    write_seq: AtomicU64,   // Monotonic sequence (never wraps with u64)
    read_seq: AtomicU64,    // Monotonic sequence
    overruns: AtomicU64,
}

// Writer:
let seq = self.write_seq.fetch_add(1, Ordering::Relaxed);
let pos = seq as usize % self.capacity;
self.entries[pos] = entry;

// Reader:
let seq = self.read_seq.load(Ordering::Relaxed);
let pos = seq as usize % self.capacity;
let entry = self.entries[pos];
self.read_seq.fetch_add(1, Ordering::Relaxed);
```

**Advantage**: With `u64` sequences on 64-bit systems, no wraparound concerns (would take 584 years at 1 billion logs/second).

### 2. State Machine for Entry Validity

**Lesson from Linux**: Use atomic state transitions to signal when entries are ready for reading.

**MCR Application**:

```rust
pub struct LogEntry {
    state: AtomicU8,  // 0=empty, 1=writing, 2=ready
    timestamp: u64,
    // ... rest of fields
}

// Writer:
entry.state.store(1, Ordering::Release);  // Writing
// Fill entry fields
entry.state.store(2, Ordering::Release);  // Ready

// Reader:
if entry.state.load(Ordering::Acquire) == 2 {
    // Safe to read
}
```

**Benefit**: Reader can detect partially-written entries and skip them.

### 3. Lockless SPSC for Data Plane

**Lesson from Both**: For single-producer single-consumer (io_uring thread → consumer thread), can achieve lockless operation.

**MCR Application**:

- Each data plane worker (per-core) has **SPSC** ring buffer
- Use `Ordering::Relaxed` for writes (no other writers)
- Use `Ordering::Acquire`/`Release` only for coordination with consumer
- No CAS needed (single producer guaranteed by architecture)

### 4. Memory Barriers Are Critical

**Lesson from Linux**: Explicit memory barriers prevent reading stale data.

**MCR Application**:

```rust
// Writer:
entry.timestamp = now;
entry.message = msg;
atomic::fence(Ordering::Release);  // Ensure all writes visible
entry.state.store(READY, Ordering::Release);

// Reader:
let state = entry.state.load(Ordering::Acquire);
if state == READY {
    atomic::fence(Ordering::Acquire);  // Ensure all reads see latest
    let timestamp = entry.timestamp;
    let message = entry.message;
}
```

### 5. Overflow Handling: Drop vs. Pressure

**Lesson from Both**: Both kernels drop old messages on overflow (preserve latency).

**MCR Options**:

1. **Drop old** (kernel style): Increment `overruns`, drop message
2. **Drop new**: Increment `drops`, skip logging (preserve history)
3. **Backpressure**: Block writer until space available (not viable for data plane)

**Recommendation**: Drop old for data plane (latency-critical), optionally backpressure for control plane.

### 6. Separate Metadata from Data

**Lesson from Linux**: Separating descriptors from text data enables:

- Efficient metadata scanning without reading full messages
- Variable-length messages without complex allocation
- Fast filtering by severity/facility before reading message text

**MCR Consideration**: Our fixed 512-byte entries don't need this, but if we support variable-length messages in the future, could adopt Linux's approach.

### 7. Per-CPU Buffers Avoid Contention

**Lesson from Both**: Linux uses per-CPU writer synchronization, FreeBSD minimizes lock hold time.

**MCR Application**:

- Data plane: **Per-core dedicated buffers** (already in design)
- Control plane: **Shared buffer with MPSC** (lower frequency, acceptable)
- Each buffer sized for expected log volume (65K for ingress, 4K for supervisor)

---

## Recommended Ring Buffer Design for MCR

Based on kernel analysis, here's the recommended approach:

### Data Plane (io_uring threads): **Lockless SPSC**

```rust
pub struct DataPlaneRingBuffer {
    entries: Box<[LogEntry]>,
    capacity: usize,          // Power of 2
    write_seq: AtomicU64,     // Monotonic, never wraps (u64)
    read_seq: AtomicU64,      // Monotonic
    overruns: AtomicU64,      // Count dropped messages
}

impl DataPlaneRingBuffer {
    pub fn write(&self, entry: LogEntry) {
        let seq = self.write_seq.fetch_add(1, Ordering::Relaxed);
        let pos = (seq as usize) & (self.capacity - 1);  // Fast modulo for power of 2

        // Check if overwriting unread entry
        let read_seq = self.read_seq.load(Ordering::Acquire);
        if seq >= read_seq + self.capacity as u64 {
            self.overruns.fetch_add(1, Ordering::Relaxed);
        }

        // Write entry
        self.entries[pos].state.store(WRITING, Ordering::Relaxed);
        self.entries[pos] = entry;
        atomic::fence(Ordering::Release);
        self.entries[pos].state.store(READY, Ordering::Release);
    }

    pub fn read(&self) -> Option<LogEntry> {
        let read_seq = self.read_seq.load(Ordering::Relaxed);
        let write_seq = self.write_seq.load(Ordering::Acquire);

        if read_seq >= write_seq {
            return None;  // Buffer empty
        }

        let pos = (read_seq as usize) & (self.capacity - 1);

        // Wait for entry to be ready (writer might be mid-write)
        loop {
            let state = self.entries[pos].state.load(Ordering::Acquire);
            if state == READY {
                break;
            }
            std::hint::spin_loop();  // Rare contention, spin briefly
        }

        let entry = self.entries[pos].clone();
        self.read_seq.fetch_add(1, Ordering::Release);
        Some(entry)
    }
}
```

### Control Plane (async tasks): **MPSC with CAS**

```rust
pub struct ControlPlaneRingBuffer {
    entries: Box<[LogEntry]>,
    capacity: usize,
    write_seq: AtomicU64,   // Multiple writers use CAS
    read_seq: AtomicU64,
    overruns: AtomicU64,
}

impl ControlPlaneRingBuffer {
    pub fn write(&self, entry: LogEntry) {
        // Try to reserve a slot (CAS loop)
        let seq = loop {
            let current = self.write_seq.load(Ordering::Relaxed);
            if self.write_seq.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed
            ).is_ok() {
                break current;
            }
            std::hint::spin_loop();
        };

        let pos = (seq as usize) & (self.capacity - 1);

        // Check for overrun (same as SPSC)
        let read_seq = self.read_seq.load(Ordering::Acquire);
        if seq >= read_seq + self.capacity as u64 {
            self.overruns.fetch_add(1, Ordering::Relaxed);
        }

        // Write entry (same as SPSC)
        self.entries[pos] = entry;
        atomic::fence(Ordering::Release);
        self.entries[pos].state.store(READY, Ordering::Release);
    }
}
```

---

## Performance Implications

### Expected Latency

| Operation               | Data Plane (SPSC)   | Control Plane (MPSC) |
| ----------------------- | ------------------- | -------------------- |
| Write (no contention)   | ~50-100 ns          | ~100-200 ns          |
| Write (with contention) | N/A (single writer) | ~500 ns - 2 µs       |
| Read                    | ~50-100 ns          | ~100-200 ns          |

**Comparison**:

- Linux kernel `printk`: ~100-500 ns (lockless, highly optimized)
- FreeBSD `msgbuf`: ~200-800 ns (spinlock, simpler)
- MCR target: < 100 ns for data plane (achievable with SPSC)

### Memory Bandwidth

**Per log entry**: 512 bytes
**Expected rates**:

- Data plane ingress: 100,000 - 1,000,000 logs/sec (with rate limiting)
- Control plane: 1,000 - 10,000 logs/sec

**Bandwidth** (worst case):

- Data plane: 512 MB/sec (1M logs/sec × 512 bytes)
- Control plane: 5 MB/sec

**L3 Cache**: ~30 MB (typical server CPU)

- Ring buffer fits in cache if ≤ 60,000 entries (~30 MB)
- Recommendation: 65,536 entries = 32 MB (close to cache size, good balance)

---

## Conclusion

### What We Learned from Kernels

1. **FreeBSD's Sequence Number Trick**: Eliminates reader-writer pointer sharing → adopt for MCR
2. **Linux's Lockless State Machine**: Enables multi-reader concurrency → adapt for MPSC control plane
3. **Per-CPU Isolation**: Eliminates contention → already in MCR design (per-core data plane buffers)
4. **Memory Barriers Are Essential**: Prevents stale reads → use `Ordering::Acquire`/`Release` carefully
5. **Drop on Overflow**: Preserve latency over completeness → adopt for data plane

### MCR Design Summary

- **Data Plane**: Lockless SPSC per-core, sequence numbers, state machine, ~50-100ns latency
- **Control Plane**: MPSC with CAS, shared buffer, ~100-500ns latency
- **Buffer Sizes**: 65,536 entries for data plane, 4,096 for control plane
- **Overflow**: Drop old messages, track overruns counter
- **Memory**: ~50-100 MB total (4-core system)

**Result**: Kernel-inspired design optimized for MCR's specific workload characteristics.
