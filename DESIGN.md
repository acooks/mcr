# MCR Design Document

**Status**: Draft - Major Refactor in Progress
**Date**: 2025-11-14
**Version**: 2.0 (io_uring-based architecture)

## Executive Summary

This document describes the architectural redesign of the Multicast Relay (MCR) application, transitioning from a complex multi-threaded system with custom IPC mechanisms to a simplified io_uring-based event-driven architecture. This refactor addresses critical performance regressions, eliminates entire classes of bugs, and dramatically reduces code complexity.

## Problem Statement

### Performance Regression (88% throughput loss)

Recent "optimizations" degraded performance from 85k pps to 10k pps in high-throughput scenarios:

1. **Per-packet syscall overhead**: The ingress→egress signaling mechanism wrote to an eventfd for every single packet, introducing 250,000+ syscalls/second at high rates
2. **Blocking event loops**: Both ingress and egress used `submit_and_wait(1)` on every iteration, adding context switch overhead
3. **Complex synchronization**: Multiple channels, eventfds, and lock-free queues created coordination overhead

### Robustness Issues

The system suffered from several structural problems:

1. **TOCTOU startup deadlock**: Workers could start before supervisor was ready to accept connections
2. **Shutdown hangs**: Egress thread could deadlock waiting for final packets
3. **Resource leaks**: Shared memory segments persisted after crashes
4. **Race conditions**: Empty-to-non-empty queue signaling had inherent race conditions

### Complexity Burden

The codebase contained thousands of lines of custom infrastructure:

- Custom shared memory ring buffer logging system
- MPSC channels + eventfd bridge for command passing
- Lock-free queue + eventfd for packet forwarding
- Tokio async runtime in supervisor, io_uring in workers

## Design Principles

### 1. Simplicity Through Unification

**Principle**: Use a single mechanism (io_uring) for all I/O operations.

**Rationale**: Every additional IPC mechanism adds complexity, potential bugs, and coordination overhead. By standardizing on io_uring, we eliminate entire classes of synchronization issues.

**Impact**:
- Delete ~2000 lines of custom shared memory logging
- Delete crossbeam queue + eventfd infrastructure
- Delete MPSC channel bridge code
- Single event loop per thread/process

### 2. Kernel-Managed State

**Principle**: Let the kernel manage as much state as possible.

**Rationale**: The kernel's event notification mechanisms (io_uring, pipes, Unix sockets) are well-tested, debugged, and optimized. Custom synchronization primitives are error-prone and require deep expertise to get right.

**Impact**:
- Replace crossbeam::SegQueue with kernel pipes
- Replace eventfd wakeup with io_uring events
- Replace shared memory with Unix sockets

### 3. Zero-Copy Where Possible

**Principle**: Minimize data copying in the fast path.

**Rationale**: At 250k+ pps, every byte copied is CPU time wasted. We can pass buffer references through pipes instead of copying packet data.

**Impact**:
- Ingress writes buffer metadata (not packet data) to pipe
- Egress reads metadata and retrieves buffer from shared pool
- Packet data stays in original buffer until sent

### 4. Fail-Fast Error Handling

**Principle**: Prefer panics over silent failures in worker threads.

**Rationale**: Worker threads are isolated processes. If they encounter unrecoverable errors, it's better to crash and restart than to continue in a corrupted state.

**Impact**:
- Use `?` operator liberally in workers
- Supervisor monitors workers and restarts on failure
- No complex error recovery in fast path

## Architecture Overview

### Process Model

```
┌─────────────────────────────────────────────────────────────┐
│                       Supervisor                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │         io_uring Event Loop                        │    │
│  │  - Unix socket (control client connections)       │    │
│  │  - Pipe read (worker log output)                  │    │
│  │  - Unix socket write (commands to workers)        │    │
│  │  - Timer (health checks, restarts)                │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
│  Spawns:                                                     │
│  ┌──────────────────┐  ┌──────────────────┐               │
│  │  Data Plane      │  │  Control Plane   │               │
│  │  Worker          │  │  Worker          │               │
│  └──────────────────┘  └──────────────────┘               │
└─────────────────────────────────────────────────────────────┘
```

### Data Plane Worker (Single Process, Two Threads)

```
┌─────────────────────────────────────────────────────────────┐
│                   Data Plane Worker Process                  │
│                                                              │
│  ┌──────────────────────────┐  ┌─────────────────────────┐ │
│  │   Ingress Thread         │  │   Egress Thread         │ │
│  │  ┌────────────────────┐  │  │  ┌──────────────────┐  │ │
│  │  │ io_uring Loop      │  │  │  │ io_uring Loop    │  │ │
│  │  │ - AF_PACKET recv   │──┼──┼─>│ - Pipe read      │  │ │
│  │  │ - Unix socket read │  │  │  │ - AF_PACKET send │  │ │
│  │  │   (commands)       │  │  │  │ - Unix socket    │  │ │
│  │  │ - Pipe write       │──┼──┼─>│   read (cmds)    │  │ │
│  │  │   (to egress)      │  │  │  │                  │  │ │
│  │  └────────────────────┘  │  │  └──────────────────┘  │ │
│  └──────────────────────────┘  └─────────────────────────┘ │
│           │                              │                   │
│           └──────────────┬───────────────┘                   │
│                          │                                   │
│                    Shared Buffer Pool                        │
│                  (crossbeam::SegQueue)                       │
└─────────────────────────────────────────────────────────────┘
```

## Detailed Design: Phase 1 - Inter-Thread Communication

### Current Design (To Be Replaced)

**Ingress → Egress Communication**:
```rust
// Ingress thread
let work_item = EgressWorkItem { buffer, payload_len, dest_addr, interface_name };
egress_queue.push(work_item);  // crossbeam::SegQueue
eventfd.write(1)?;             // Wake egress thread

// Egress thread
ring.submit_and_wait(1)?;      // Block waiting for eventfd
while let Some(item) = queue.pop() {
    // Process item
}
```

**Problems**:
1. Every packet triggers an eventfd write (syscall overhead)
2. `submit_and_wait(1)` blocks egress, preventing batching
3. Empty-to-non-empty signaling has race conditions
4. Complex error handling for eventfd EAGAIN

### New Design: Pipe-Based Communication

**Key Insight**: We don't need to pass the entire packet through the pipe, just metadata pointing to it in the shared buffer pool.

**Message Format**:
```rust
#[repr(C)]
struct PacketMetadata {
    buffer_ptr: *mut u8,        // 8 bytes - pointer to buffer in shared pool
    payload_len: u16,           // 2 bytes
    dest_port: u16,             // 2 bytes
    dest_ip: u32,               // 4 bytes (IPv4)
    iface_name_len: u8,         // 1 byte
    iface_name: [u8; 15],       // 15 bytes (max interface name)
}                               // Total: 32 bytes
```

**Ingress Flow**:
```rust
// Parse packet, match rule, get buffer from pool
let metadata = PacketMetadata {
    buffer_ptr: buffer.as_ptr() as *mut u8,
    payload_len: len as u16,
    dest_ip: dest_addr.ip(),
    dest_port: dest_addr.port(),
    iface_name_len: iface.len() as u8,
    iface_name: /* copy interface name */,
};

// Submit non-blocking write to pipe via io_uring
let write_op = opcode::Write::new(pipe_fd, &metadata as *const _ as *const u8, 32);
ring.submission().push(&write_op)?;
ring.submit()?;  // Non-blocking! Kernel will write when ready
```

**Egress Flow**:
```rust
// Submit persistent read on pipe
let read_op = opcode::Read::new(pipe_fd, metadata_buf.as_mut_ptr(), 32);
ring.submission().push(&read_op)?;

loop {
    ring.submit_and_wait(1)?;  // Wait for ANY completion (packet send OR pipe read)

    for cqe in ring.completion() {
        match cqe.user_data() {
            PIPE_READ => {
                let metadata = parse_metadata(metadata_buf);
                let buffer = unsafe { reconstruct_buffer(metadata.buffer_ptr) };
                queue_packet_for_send(buffer, metadata);

                // Re-submit persistent pipe read
                ring.submission().push(&read_op)?;
            }
            PACKET_SEND => {
                // Handle send completion
            }
        }
    }
}
```

### Trade-offs

**Advantages**:
1. **Zero-copy**: Packet data stays in original buffer
2. **Batching**: io_uring naturally batches operations
3. **No per-packet syscalls**: Write is asynchronous
4. **Simpler error handling**: Kernel manages pipe buffer

**Disadvantages**:
1. **Unsafe code**: Must carefully manage buffer lifetime
2. **Fixed message size**: 32 bytes per packet (minor overhead at high rates)
3. **Pipe buffer limits**: Must handle EAGAIN if pipe fills (rare)

**Decision**: The performance benefits and simplicity gains far outweigh the disadvantages. The unsafe code is localized and can be carefully audited.

## Detailed Design: Phase 2 - Supervisor-Worker IPC

### Current Design (To Be Replaced)

**Command Flow**:
```
Supervisor (tokio) → Unix Socket → Worker (tokio bridge) → MPSC Channel → eventfd → io_uring loop
```

**Problems**:
1. Tokio in supervisor, io_uring in worker (two runtimes)
2. MPSC channel + eventfd bridge adds latency
3. Complex error handling across async boundaries

### New Design: Direct Unix Socket

**Supervisor Side** (io_uring):
```rust
// Supervisor event loop
loop {
    ring.submit_and_wait(1)?;

    for cqe in ring.completion() {
        match cqe.user_data() {
            WORKER_SOCKET_WRITE => {
                // Command sent to worker
            }
            CONTROL_CLIENT_READ => {
                // Got command from control client
                let command = parse_command(buf);
                // Submit write to worker socket
                ring.submission().push(&write_op)?;
            }
        }
    }
}
```

**Worker Side** (io_uring):
```rust
// Worker event loop
loop {
    ring.submit_and_wait(1)?;

    for cqe in ring.completion() {
        match cqe.user_data() {
            COMMAND_SOCKET_READ => {
                let command = parse_command(buf);
                match command {
                    AddRule(rule) => add_rule_to_table(rule),
                    Shutdown => break,
                }
                // Re-submit persistent read
                ring.submission().push(&read_op)?;
            }
            PACKET_RECV => {
                // Handle packet
            }
        }
    }
}
```

### Trade-offs

**Advantages**:
1. **Single runtime**: io_uring everywhere
2. **Lower latency**: No MPSC/eventfd bridge
3. **Simpler code**: Direct socket communication

**Disadvantages**:
1. **More unsafe code**: Unix socket handling in io_uring
2. **Loss of tokio ergonomics**: Must manually manage state machine

**Decision**: Consistency and performance are more important than tokio ergonomics. The state machine is straightforward.

## Detailed Design: Phase 3 - Logging

### Current Design (To Be Replaced)

**Shared Memory Ring Buffers**:
- Worker writes logs to SPSC ring buffer in `/dev/shm/mcr_*`
- Supervisor mmaps and reads from ring buffers
- Complex synchronization, cleanup, and collision handling

**Problems**:
1. ~2000 lines of custom code
2. Shared memory leaks on crash (survives SIGKILL)
3. PID-based naming to avoid collisions
4. Complex mmap lifecycle management

### New Design: Pipe to stderr

**Worker Side**:
```rust
// All logging goes to stderr (FD 2)
eprintln!("[Ingress] Received {} packets", count);
```

**Supervisor Side** (process spawn):
```rust
let (pipe_read, pipe_write) = nix::unistd::pipe()?;

let child = Command::new("./multicast_relay")
    .arg("worker")
    .pre_exec(move || {
        // Redirect stderr to pipe
        nix::unistd::dup2(pipe_write, 2)?;
        Ok(())
    })
    .spawn()?;

// Supervisor reads from pipe_read via io_uring
let read_op = opcode::Read::new(pipe_read, log_buf.as_mut_ptr(), 8192);
ring.submission().push(&read_op)?;
```

**Supervisor Event Loop**:
```rust
match cqe.user_data() {
    WORKER_LOG_READ => {
        // Got log data from worker
        let log_text = String::from_utf8_lossy(log_buf);
        eprintln!("[Worker-{}] {}", worker_id, log_text);

        // Re-submit persistent read
        ring.submission().push(&read_op)?;
    }
}
```

### Trade-offs

**Advantages**:
1. **Delete 2000+ lines**: Entire shared memory system gone
2. **No resource leaks**: Pipes cleaned up by kernel
3. **Standard interface**: All Rust logging just works
4. **No collisions**: Each worker has unique pipe

**Disadvantages**:
1. **Slightly higher overhead**: Per-log-line write vs batched ring buffer
2. **Less structured**: Text logs instead of binary ring buffer

**Decision**: The simplicity and robustness gains are overwhelming. Log overhead is negligible compared to packet processing.

## Performance Analysis

### Before Refactor (Current State)

**Baseline 50k pps test**: ✅ Passes
**Chain 3-hop 250k pps test**: ❌ Fails (10k pps - 88% regression)

**Bottlenecks**:
1. Per-packet eventfd writes: 250,000 syscalls/sec
2. `submit_and_wait(1)` blocking: Context switches on every iteration
3. Lock-free queue polling overhead

### After Refactor (Expected)

**Baseline 50k pps test**: ✅ Should still pass
**Chain 3-hop 250k pps test**: 🎯 Target >150k pps (minimum), ideally 200k+ pps

**Improvements**:
1. **No per-packet syscalls**: Pipe writes are asynchronous
2. **Natural batching**: io_uring processes multiple events per `submit_and_wait()`
3. **Reduced coordination**: Kernel manages wakeups

**Target Performance**:
- 200k+ pps sustained (vs 85k historical best)
- <10 microseconds per-packet latency
- <5% buffer exhaustion under load

## Migration Strategy

### Phase 1: Inter-Thread Communication (Ingress → Egress)

**Goal**: Replace crossbeam + eventfd with pipe

**Steps**:
1. Create pipe in `data_plane_integrated.rs`
2. Pass write end to ingress, read end to egress
3. Define `PacketMetadata` struct
4. Update ingress to write metadata to pipe (io_uring)
5. Update egress to read metadata from pipe (io_uring)
6. Delete `EgressQueueWithWakeup` and `crossbeam::SegQueue`

**Testing**: Run `baseline_50k.sh` - must still pass

### Phase 2: Supervisor-Worker IPC

**Goal**: Remove MPSC/eventfd bridge

**Steps**:
1. Remove tokio bridge task in `worker/mod.rs`
2. Pass Unix socket directly to ingress/egress
3. Submit persistent read on socket in both loops
4. Handle commands directly in completion handler
5. Migrate supervisor to io_uring (or keep tokio - TBD)

**Testing**: Run `data_plane_e2e.sh` - must handle AddRule/Shutdown

### Phase 3: Logging

**Goal**: Replace shared memory with pipes

**Steps**:
1. Create pipe before spawning worker
2. Redirect worker stderr to pipe write end
3. Supervisor reads from pipe read end (io_uring)
4. Delete `src/logging/ringbuffer.rs`
5. Delete `src/logging/integration.rs`
6. Simplify `src/logging/consumer.rs`

**Testing**: Verify logs appear correctly, no resource leaks

## Open Questions

### 1. Buffer Lifetime Management

**Question**: How do we safely pass buffer pointers through the pipe?

**Options**:
A. **Manual lifetime tracking**: Ingress increments refcount, egress decrements
B. **Buffer IDs instead of pointers**: Use integer IDs, lookup in shared map
C. **Mem::forget pattern**: Ingress forgets buffer, egress reconstructs from pointer

**Recommendation**: Option C (Mem::forget) - simplest, zero overhead, matches existing ManagedBuffer pattern

### 2. Supervisor Runtime

**Question**: Should supervisor use io_uring or keep tokio?

**Options**:
A. **Keep tokio**: Easier async code for non-critical path
B. **Migrate to io_uring**: Consistency, but more complex
C. **Hybrid**: tokio for HTTP, io_uring for worker IPC

**Recommendation**: Option A initially - supervisor is not in fast path. Can migrate later if needed.

### 3. Error Handling Strategy

**Question**: When should workers panic vs return errors?

**Guideline**:
- **Panic**: Unrecoverable errors (memory corruption, FD exhaustion)
- **Return Error**: Transient issues (network errors, full buffers)
- **Log and Continue**: Expected conditions (no rule match, filtered packets)

### 4. Pipe Buffer Sizing

**Question**: How big should the ingress→egress pipe be?

**Analysis**:
- Default pipe buffer: 64KB (on Linux)
- Each metadata: 32 bytes
- Capacity: 2048 packets buffered
- At 250k pps: 8ms of buffering

**Recommendation**: Start with default (64KB), increase via `F_SETPIPE_SZ` if needed

## Success Criteria

### Correctness

- [ ] `baseline_50k.sh` passes consistently
- [ ] `chain_3hop.sh` achieves >150k pps sustained
- [ ] No packet loss under sustained load
- [ ] No resource leaks (valgrind, /dev/shm empty after exit)
- [ ] Graceful shutdown (SIGTERM handled correctly)

### Performance

- [ ] >200k pps on chain_3hop test
- [ ] <10 microseconds p99 latency
- [ ] <5% buffer exhaustion under load
- [ ] Linear scaling with number of hops

### Maintainability

- [ ] <10,000 lines of code total (vs 12,000+ currently)
- [ ] Zero unsafe code outside buffer management
- [ ] All IPC via standard kernel mechanisms
- [ ] No custom synchronization primitives

## Future Considerations

### Multi-Core Scaling

Current design: 1 ingress + 1 egress thread per worker

**Future**: Could scale to N ingress threads with RSS (Receive Side Scaling):
- Kernel distributes packets across N AF_PACKET sockets
- Each ingress writes to shared egress pipe
- Single egress drains pipe and sends

### Hardware Offload

**XDP (eXpress Data Path)**:
- Could replace AF_PACKET for even lower latency
- Requires BPF program for packet filtering
- Allows bypassing kernel network stack entirely

### DPDK

**Alternative**: Replace kernel network stack with DPDK
- 10M+ pps possible
- Complete control over NICs
- Loses kernel benefits (routing, firewall integration)

**Decision**: Stay with kernel for now - io_uring + AF_PACKET should achieve 200k+ pps

## Conclusion

This refactor simplifies the MCR architecture by eliminating custom IPC mechanisms in favor of standard kernel primitives managed through a unified io_uring interface. The expected outcomes are:

1. **Performance**: 2-3x improvement over historical best (85k → 200k+ pps)
2. **Robustness**: Elimination of TOCTOU bugs, resource leaks, and race conditions
3. **Maintainability**: ~2000 fewer lines of complex code to maintain

The phased approach allows us to validate each change incrementally while maintaining a working system at each step.
