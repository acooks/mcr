# ADR 001: Data Plane Buffer Management Strategy

**Status:** Accepted
**Date:** 2025-12-03
**Context:** Evaluation of zero-copy ingress mechanisms (PACKET_MMAP, IORING_OP_RECV_ZC) vs. current implementation.

## Context

The MCR data plane currently uses `io_uring` with `AF_PACKET` sockets. Ingress packets are copied from kernel memory into userspace-managed buffers (via `BufferPool`). These buffers are then wrapped in `Arc<[u8]>` to enable zero-copy fan-out to multiple egress destinations.

A proposal was made to migrate to `PACKET_MMAP` (TPACKET_V3) or `IORING_OP_RECV_ZC` to achieve true zero-copy ingress (Kernel → Userspace).

## Analysis

1. **Correctness of Current Implementation:**
   - **Mechanism:** `src/worker/unified_loop.rs` correctly uses `opcode::Recv` with buffers from `src/worker/buffer_pool.rs`.
   - **The Copy:** The kernel *does* copy packet data during the `recv` syscall. This is the only data copy in the pipeline.
   - **Fan-Out:** Once in userspace, the `Arc<[u8]>` mechanism ensures no further copies occur regardless of the fan-out factor (1-to-N).
   - **Safety:** The `ManagedBuffer` drop implementation ensures buffers are returned to the pool only when the last reference (`Arc`) is dropped. This safely handles the "slow egress" scenario where one output might hold onto a buffer longer than others.

2. **Complexity of Zero-Copy Alternatives:**
   - **Buffer Lifetime Conflict:** Both `PACKET_MMAP` and `RECV_ZC` use kernel-owned ring buffers. To support fan-out, we would need to hold a "lock" or reference on a ring slot until *all* egress operations for that packet complete.
   - **Head-of-Line (HoL) Blocking Risk:** If a single egress destination is slow/congested, it would pin the underlying kernel ring slot. If enough slots are pinned, the ingress ring fills up, causing packet drops for *all* flows, even healthy ones.
   - **Mitigation Costs:** Solving this requires copying data out of the ring for fan-out (negating the zero-copy benefit) or implementing complex reference-counted ring allocators that fight against the kernel's ring recycling logic.

3. **Performance Reality:**
   - At the target 1-10Gbps speeds, the cost of a single `memcpy` (~1400 bytes) is negligible compared to the architectural complexity of zero-copy buffer management. The current `io_uring` batching already mitigates the syscall overhead, which is the primary bottleneck.

## Decision

**We will RETAIN the current `io_uring` + `BufferPool` implementation.**

- **Reject `PACKET_MMAP`:** It relies on older APIs, requires a hybrid polling model that breaks the unified event loop, and introduces significant complexity for fan-out.
- **Defer `IORING_OP_RECV_ZC`:** While architecturally cleaner than `PACKET_MMAP`, it suffers from the same buffer lifetime/HoL blocking issues for multicast fan-out and imposes a strict kernel requirement (Linux 6.0+).

## Consequences

- **Benefit:** The architecture remains simple, unified, and safe from Head-of-Line blocking caused by slow consumers.
- **Trade-off:** We accept the CPU cost of one memory copy per packet on ingress.
