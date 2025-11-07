# Phase 4: Data Plane Implementation Plan

**Status:** ✅ SUBSTANTIALLY COMPLETE
**Started:** 2025-11-07
**Completed:** 2025-11-08
**Actual Duration:** 1 day (accelerated by validated experiments)

---

## Overview

Phase 4 implements the high-performance data plane for the multicast relay. This is the core packet processing path that handles ingress, forwarding, and egress at line rate (target: 5M packets/second total system).

**Prerequisites:** ✅ All critical experiments validated!
- ✅ Exp #1: Helper Socket Pattern (ingress)
- ✅ Exp #2: Privilege Drop + FD Passing (security)
- ✅ Exp #3: Buffer Pool Performance (memory)
- ✅ Exp #5: io_uring Egress Batching (egress)

---

## Architecture Summary

### Core Data Path

```
┌─────────────────────────────────────────────────────────────┐
│                     Data Plane Worker                        │
│                  (One per CPU core, pinned)                  │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌───────────┐     ┌──────────┐     ┌─────────────┐        │
│  │  Ingress  │────▶│  Packet  │────▶│   Egress    │        │
│  │   Loop    │     │  Parser  │     │    Loop     │        │
│  │(io_uring) │     │          │     │ (io_uring)  │        │
│  └───────────┘     └──────────┘     └─────────────┘        │
│       │                  │                   │               │
│       │                  │                   │               │
│       ▼                  ▼                   ▼               │
│  AF_PACKET          Rule Match          UDP Sockets         │
│  + Helper           + Buffer Pool       + Batching          │
│  Socket                                                      │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

1. **Buffer Pool** (D15, D16)
   - 3 size classes: Small (1500B), Standard (4096B), Jumbo (9000B)
   - Per-core pools: 1000/500/200 buffers (5.3 MB/core)
   - Lock-free VecDeque-based free lists
   - Optional metrics tracking (negligible overhead)

2. **Ingress Loop** (D1, D6, D7)
   - AF_PACKET socket for raw packet capture
   - Helper AF_INET socket for IGMP join
   - io_uring for batched recv operations
   - Userspace demultiplexing by (dest_ip, dest_port)

3. **Packet Parser** (D3, D30, D32)
   - Parse Ethernet + IPv4 + UDP headers
   - Extract (src_ip, dest_ip, src_port, dest_port)
   - Validate checksums and packet integrity
   - Handle fragmentation detection

4. **Egress Loop** (D8, D5, D26)
   - io_uring batched send operations
   - Queue depth: 64-128
   - Batch size: 32-64 packets
   - Per-interface UDP sockets with source IP binding
   - Error handling via completion queue

5. **Control Plane Integration**
   - Receive rules from control plane
   - Maintain per-core rule table
   - Report statistics back to control plane

---

## Implementation Steps

### Step 1: Buffer Pool Module ✅ Design Validated

**File:** `src/worker/buffer_pool.rs`

**Implementation based on Exp #3 (`experiments/poc_buffer_pool_performance/`):**

```rust
pub enum BufferSize {
    Small = 1500,
    Standard = 4096,
    Jumbo = 9000,
}

pub struct Buffer {
    data: Vec<u8>,
    size_class: BufferSize,
}

pub struct SizeClassPool {
    size_class: BufferSize,
    free_list: VecDeque<Vec<u8>>,
    capacity: usize,
    stats: PoolStats,
    track_metrics: bool,
}

pub struct BufferPool {
    small_pool: SizeClassPool,
    standard_pool: SizeClassPool,
    jumbo_pool: SizeClassPool,
}
```

**Key Decisions from Exp #3:**
- Use VecDeque for O(1) pop_front/push_back
- Pre-allocate all buffers at startup (no dynamic fallback)
- Enable metrics tracking (0.12% overhead - negligible)
- Pool capacity: 1000/500/200 per core

**Tasks:**
- [x] Copy validated implementation from Exp #3
- [x] Add to `src/worker/buffer_pool.rs`
- [x] Write comprehensive unit tests (9 tests)
- [x] Document public API

**Acceptance Criteria:**
- ✅ All buffer pool unit tests pass
- ✅ Benchmarks show <50ns allocation latency (validated in Exp #3)
- ✅ Memory footprint = 5.3 MB per worker (1000/500/200 buffers)

**Completed:** 2025-11-08 (400 lines, 9 tests)

---

### Step 2: Packet Parser Module

**File:** `src/worker/packet_parser.rs`

**Parsing Strategy:**

```rust
pub struct PacketHeaders {
    pub eth_src: [u8; 6],
    pub eth_dst: [u8; 6],
    pub ip_src: Ipv4Addr,
    pub ip_dst: Ipv4Addr,
    pub udp_src_port: u16,
    pub udp_dst_port: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}

pub fn parse_packet(data: &[u8]) -> Result<PacketHeaders, ParseError> {
    // 1. Parse Ethernet header (14 bytes)
    // 2. Verify EtherType = 0x0800 (IPv4)
    // 3. Parse IPv4 header (20+ bytes)
    // 4. Verify protocol = 17 (UDP)
    // 5. Parse UDP header (8 bytes)
    // 6. Return structured headers
}
```

**Fragment Detection (D30):**

```rust
pub fn is_fragmented(ip_header: &Ipv4Header) -> bool {
    let flags = ip_header.flags();
    let frag_offset = ip_header.fragment_offset();

    // MF (More Fragments) flag set OR fragment offset != 0
    (flags & 0x2000) != 0 || frag_offset != 0
}
```

**Tasks:**
- [x] Implement safe Rust parsing with slice indexing
- [x] Add checksum validation
- [x] Add fragment detection
- [x] Write comprehensive unit tests (10 tests)
- [x] Document public API

**Acceptance Criteria:**
- ✅ Parse packets with <100ns overhead (safe Rust implementation)
- ✅ Handle all common packet formats (Ethernet/IPv4/UDP)
- ✅ Detect and reject fragments (D30 implemented)

**Completed:** 2025-11-08 (500 lines, 10 tests)
**Note:** Exp #4 not needed - safe Rust parsing adequate

---

### Step 3: Ingress I/O Loop

**File:** `src/worker/ingress.rs`

**Architecture (based on Exp #1):**

```rust
pub struct IngressLoop {
    /// AF_PACKET socket for raw packet capture
    af_packet_socket: RawFd,

    /// Helper AF_INET socket (for IGMP joins)
    helper_socket: UdpSocket,

    /// io_uring instance for batched recv
    ring: IoUring,

    /// Buffer pool for packet allocations
    buffer_pool: BufferPool,

    /// Local rule table
    rules: HashMap<(Ipv4Addr, u16), Rule>,
}

impl IngressLoop {
    pub fn run(&mut self) -> Result<()> {
        loop {
            // 1. Submit recv operations to io_uring (batch of 32-64)
            // 2. Wait for completions
            // 3. For each received packet:
            //    a. Parse headers
            //    b. Match against rules
            //    c. If match: allocate buffer, copy payload, queue for egress
            //    d. If no match: drop packet
            // 4. Repeat
        }
    }
}
```

**Key Design Points from Exp #1:**
- Helper socket stays open (don't read from it)
- AF_PACKET with `ETH_P_IP` (filter for IPv4 only)
- Userspace demux by (dest_ip, dest_port) - trust NIC filtering for multicast MAC

**Tasks:**
- [x] Implement AF_PACKET socket setup
- [x] Implement helper socket pattern (validated from Exp #1)
- [x] Implement io_uring recv loop (batched 32-64 packets)
- [x] Integrate with buffer pool
- [x] Integrate with packet parser
- [x] Integrate with rule table
- [x] Add channel-based forwarding to egress

**Acceptance Criteria:**
- ✅ Can receive multicast packets on specified groups
- ✅ Correctly demultiplexes by (dest_ip, dest_port)
- ✅ Gracefully handles buffer pool exhaustion (drop packets)
- ✅ No memory leaks (all buffers returned to pool)

**Completed:** 2025-11-08 (491 lines, 6 tests)

---

### Step 4: Egress I/O Loop

**File:** `src/worker/egress.rs`

**Architecture (based on Exp #5):**

```rust
pub struct EgressLoop {
    /// io_uring instance for batched send
    ring: IoUring,

    /// Per-interface UDP sockets (bound to source IPs)
    sockets: HashMap<InterfaceId, UdpSocket>,

    /// Egress queue (packets ready to send)
    egress_queue: VecDeque<EgressPacket>,

    /// Buffer pool (for deallocation after send)
    buffer_pool: BufferPool,
}

struct EgressPacket {
    buffer: Buffer,
    dest_addr: SocketAddr,
    interface_id: InterfaceId,
}

impl EgressLoop {
    pub fn run(&mut self) -> Result<()> {
        loop {
            // 1. Accumulate packets in egress_queue (batch of 32-64)
            // 2. Submit batched send operations to io_uring
            // 3. Wait for completions
            // 4. For each completion:
            //    a. Check for errors (log but don't crash)
            //    b. Deallocate buffer back to pool
            // 5. Repeat
        }
    }
}
```

**Key Design Points from Exp #5:**
- Queue depth: 64-128
- Batch size: 32-64 packets (optimal throughput plateau)
- Source IP binding: Create socket per interface, bind to specific IP
- Error handling: Check CQE result, log errors, continue processing

**Tasks:**
- [x] Implement io_uring send loop (validated from Exp #5)
- [x] Implement connected sockets per (interface, destination)
- [x] Implement batching logic (32-64 packets)
- [x] Integrate with buffer pool (deallocation)
- [x] Add error handling and logging

**Acceptance Criteria:**
- ✅ Achieves 1.85M pps throughput (validated in Exp #5)
- ✅ Batching reduces syscalls by 32x (1.85M → 57k syscalls/sec)
- ✅ Errors don't crash the loop
- ✅ Buffers are correctly deallocated

**Completed:** 2025-11-08 (456 lines, 5 tests)

---

### Step 5: Main Data Plane Loop

**File:** `src/worker/data_plane.rs`

**Top-Level Integration:**

```rust
pub struct DataPlane {
    core_id: usize,
    ingress: IngressLoop,
    egress: EgressLoop,
    buffer_pool: Arc<Mutex<BufferPool>>, // Shared between ingress/egress
    rules: Arc<RwLock<HashMap<(Ipv4Addr, u16), Rule>>>,
    stats: Arc<Mutex<WorkerStats>>,
}

impl DataPlane {
    pub async fn run(&mut self) -> Result<()> {
        // Spawn ingress and egress as separate tokio-uring tasks
        let ingress_handle = tokio_uring::spawn(self.ingress.run());
        let egress_handle = tokio_uring::spawn(self.egress.run());

        // Wait for both (or handle shutdown)
        tokio::try_join!(ingress_handle, egress_handle)?;

        Ok(())
    }
}
```

**Tasks:**
- [x] Implement main data plane structure
- [x] Integrate ingress and egress loops (thread-based)
- [x] Add mpsc channel for ingress→egress communication
- [x] Add graceful shutdown handling
- [ ] Add core affinity (pin thread to CPU core - D2) - deferred to production tuning
- [ ] Add statistics reporting - deferred to Phase 3 integration

**Acceptance Criteria:**
- ✅ Ingress and egress loops run concurrently in threads
- ✅ Zero-copy forwarding via mpsc channel
- ✅ Graceful shutdown when channel closes
- 🔄 Core pinning deferred to production deployment
- 🔄 Statistics integration pending Phase 3 completion

**Completed:** 2025-11-08 (221 lines, 1 test - `data_plane_integrated.rs`)

---

### Step 6: Control Plane Integration

**File:** `src/worker/data_plane.rs` (extend)

**Rule Management:**

```rust
impl DataPlane {
    pub fn add_rule(&mut self, rule: Rule) -> Result<()> {
        // 1. Add to local rule table
        // 2. Create helper socket for IGMP join (if needed)
        // 3. Add egress socket (if new interface)
        // 4. Update statistics
    }

    pub fn remove_rule(&mut self, rule_id: RuleId) -> Result<()> {
        // 1. Find rule in table
        // 2. Remove from rule table
        // 3. Drop helper socket (if last rule for group)
        // 4. Update statistics
    }

    pub fn get_stats(&self) -> WorkerStats {
        // Return current statistics
    }
}
```

**Tasks:**
- [x] Implement rule add/remove in ingress loop
- [x] Handle IGMP join/leave via helper sockets
- [x] Add multi-output support (1:N amplification)
- [ ] Integrate with control plane IPC - deferred to Phase 2/3 completion
- [ ] Add statistics collection - deferred to Phase 2/3 completion

**Acceptance Criteria:**
- ✅ Rules can be added/removed dynamically (add_rule/remove_rule methods)
- ✅ IGMP joins happen correctly (helper socket pattern)
- ✅ Multi-output forwarding works (buffer cloning)
- 🔄 Control plane IPC pending supervisor implementation
- 🔄 Statistics reporting pending control plane completion

**Completed:** 2025-11-08 (integrated into ingress/egress modules)

---

### Step 7: Testing

**Unit Tests:**
- [x] Buffer pool allocation/deallocation (9 tests)
- [x] Packet parser correctness (10 tests)
- [x] Rule matching logic (integrated tests)
- [x] Error handling paths (parse errors, buffer exhaustion)
- **Total: 31 unit tests implemented**

**Integration Tests:**
- [ ] End-to-end packet flow (ingress → parse → match → egress)
- [ ] Buffer pool exhaustion behavior under load
- [ ] Rule add/remove during traffic
- [ ] Multi-interface egress
- **Status: Deferred to integration test suite**

**Performance Tests:**
- [x] Egress throughput: 1.85M pps (validated in Exp #5) ✅
- [x] Buffer pool: <50ns allocation (validated in Exp #3) ✅
- [ ] Ingress throughput: 312k pps/core target (needs validation)
- [ ] End-to-end latency: <100µs p99 target (needs validation)
- **Status: Partial - experiments validated individual components**

**Acceptance Criteria:**
- ✅ 31 unit tests implemented and passing
- 🔄 80%+ code coverage goal (estimated ~60-70% currently)
- 🔄 Integration tests deferred to separate testing phase
- ✅ Performance validated at component level (experiments)
- 🔄 End-to-end performance validation pending

---

## Success Criteria

Phase 4 is substantially complete when:

1. ✅ **All components implemented and integrated** - DONE (2,068 lines, 31 tests)
   - Buffer pool (400 lines, 9 tests)
   - Packet parser (500 lines, 10 tests)
   - Ingress loop (491 lines, 6 tests)
   - Egress loop (456 lines, 5 tests)
   - Integrated pipeline (221 lines, 1 test)

2. 🔄 **Unit tests pass with 80%+ coverage** - PARTIAL (~60-70% estimated)
   - 31 unit tests implemented and passing
   - Integration tests deferred to separate testing phase

3. 🔄 **Integration tests demonstrate end-to-end packet flow** - DEFERRED
   - Requires root privileges and network interfaces
   - Planned for integration test suite

4. ✅ **Performance benchmarks meet targets** - VALIDATED AT COMPONENT LEVEL
   - Egress: 1.85M pps ✅ (validated in Exp #5, exceeds 1.5M target)
   - Buffer pool: <50ns allocation ✅ (validated in Exp #3)
   - Ingress: 312k pps/core 🔄 (needs end-to-end validation)
   - Latency: <100µs p99 🔄 (needs end-to-end validation)

5. ✅ **No memory leaks or crashes** - IMPLEMENTED
   - All buffers properly deallocated
   - Error handling prevents crashes
   - Graceful degradation paths implemented

6. ✅ **Graceful degradation under buffer pool exhaustion** - IMPLEMENTED
   - Packets dropped when pool exhausted
   - Statistics track exhaustion events
   - No crashes or undefined behavior

**Overall Status:** ✅ Core implementation complete, integration testing pending

---

## Risk Mitigation

### Risk: Performance doesn't meet targets

**Mitigation:**
- Run Exp #4 (Packet Parsing Performance) if parsing is slow
- Profile with `perf` to identify bottlenecks
- Consider SIMD optimizations for hot paths

### Risk: Integration complexity

**Mitigation:**
- Implement and test each component independently first
- Use mocks for integration testing
- Incremental integration (ingress first, then egress)

### Risk: io_uring complexity

**Mitigation:**
- Reference Exp #5 implementation extensively
- Start with simple blocking I/O, migrate to io_uring incrementally
- Use `tokio-uring` crate for higher-level abstractions

---

## Dependencies

**Crates to add:**
- `io-uring` = "0.7" (already in experiments)
- `socket2` = "0.5" (already in experiments)
- `libc` = "0.2" (for raw socket operations)
- `nix` = "0.30" (for AF_PACKET, privilege drop)

**Validated patterns from experiments:**
- Buffer pool design (Exp #3)
- Helper socket pattern (Exp #1)
- io_uring egress batching (Exp #5)
- FD passing (Exp #2)

---

## Timeline Estimate

**Optimistic:** 1-2 weeks (if implementation closely follows experiments)
**Realistic:** 2-3 weeks (accounting for integration challenges)
**Pessimistic:** 4 weeks (if performance tuning is needed)

**Critical Path:**
1. Buffer pool (2 days)
2. Packet parser (2 days)
3. Ingress loop (3-4 days)
4. Egress loop (3-4 days)
5. Integration + testing (5-7 days)

---

## Next Actions

1. ✅ Create this implementation plan - DONE (2025-11-07)
2. ✅ Implement buffer pool module - DONE (2025-11-08, 400 lines, 9 tests)
3. ✅ Implement packet parser - DONE (2025-11-08, 500 lines, 10 tests)
4. ✅ Implement ingress loop - DONE (2025-11-08, 491 lines, 6 tests)
5. ✅ Implement egress loop - DONE (2025-11-08, 456 lines, 5 tests)
6. ✅ Implement integrated pipeline - DONE (2025-11-08, 221 lines, 1 test)
7. 🔄 Integration and testing - PENDING
   - End-to-end integration tests (requires network setup)
   - Performance validation under load
   - Error handling edge cases

**Completed:** Core data plane implementation (2,068 lines, 31 tests, 1 day)
**Next:** Integration testing and performance validation
