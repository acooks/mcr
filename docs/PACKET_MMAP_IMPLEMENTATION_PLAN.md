# PACKET_MMAP Implementation Plan

## Status

**Interim fix implemented:** SO_RCVBUF is now set to 16MB on the AF_PACKET socket
(see `src/worker/unified_loop.rs`). This provides adequate buffering when
`net.core.rmem_max` is tuned appropriately (via `scripts/setup_kernel_tuning.sh`).

PACKET_MMAP remains the recommended long-term solution for true zero-copy operation.

## Overview

Replace the current AF_PACKET + io_uring recv() approach with PACKET_MMAP (TPACKET_V3)
for zero-copy packet receive. This eliminates the socket buffer bottleneck entirely.

## Current Architecture

```
NIC → Kernel Driver → Socket Buffer → recv() syscall → User Buffer → MCR Processing
                           ↑
                    (bottleneck: 212KB-16MB)
```

**Problems with current approach:**
- Packets are copied from kernel to userspace via recv()
- Socket buffer size limits burst tolerance
- Each packet requires a syscall (even with io_uring batching)
- SO_RCVBUF is limited by net.core.rmem_max sysctl

## Target Architecture

```
NIC → Kernel Driver → PACKET_MMAP Ring Buffer (shared memory) → MCR Processing
                              ↑
                    (configurable: 64MB+, zero-copy)
```

**Benefits:**
- Zero-copy: kernel writes directly to mmap'd ring buffer
- No socket buffer involved
- Configurable ring size (not limited by rmem_max)
- Batch processing of multiple packets per poll
- Used by tcpdump, Wireshark, DPDK AF_PACKET, etc.

## Implementation Steps

### Phase 1: Core TPACKET_V3 Implementation

**File: `src/worker/packet_ring.rs` (new)**

1. **Define ring buffer structures:**
   ```rust
   pub struct PacketRing {
       fd: RawFd,
       ring: *mut u8,
       ring_size: usize,
       block_size: usize,
       block_nr: usize,
       frame_size: usize,
       current_block: usize,
   }
   ```

2. **Implement ring setup:**
   ```rust
   impl PacketRing {
       pub fn new(interface: &str, block_size: usize, block_nr: usize) -> Result<Self> {
           // 1. Create AF_PACKET socket
           let fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

           // 2. Set TPACKET_V3
           let version = TPACKET_V3;
           setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version);

           // 3. Configure ring
           let req = tpacket_req3 {
               tp_block_size: block_size,      // e.g., 1MB
               tp_block_nr: block_nr,          // e.g., 64 blocks = 64MB
               tp_frame_size: TPACKET_ALIGN(TPACKET3_HDRLEN + MAX_PACKET_SIZE),
               tp_frame_nr: 0,                 // Calculated by kernel
               tp_retire_blk_tov: 100,         // Block timeout in ms
               tp_sizeof_priv: 0,
               tp_feature_req_word: 0,
           };
           setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req);

           // 4. mmap the ring
           let ring = mmap(
               null_mut(),
               block_size * block_nr,
               PROT_READ | PROT_WRITE,
               MAP_SHARED,
               fd,
               0,
           );

           // 5. Bind to interface
           bind(fd, &sockaddr_ll { ... });

           Ok(Self { fd, ring, ... })
       }
   }
   ```

3. **Implement packet iteration:**
   ```rust
   impl PacketRing {
       /// Poll for available packets, returns iterator over packet data
       pub fn poll(&mut self, timeout_ms: i32) -> Result<PacketIter<'_>> {
           // Use poll() or io_uring poll to wait for packets
           // Then iterate over ready blocks/frames
       }

       /// Release a block back to kernel after processing
       pub fn release_block(&mut self, block_idx: usize) {
           let block = self.get_block(block_idx);
           block.hdr.block_status = TP_STATUS_KERNEL;
       }
   }

   pub struct PacketIter<'a> {
       ring: &'a mut PacketRing,
       current_block: usize,
       current_frame: usize,
   }

   impl<'a> Iterator for PacketIter<'a> {
       type Item = &'a [u8];

       fn next(&mut self) -> Option<Self::Item> {
           // Walk through blocks, checking TP_STATUS_USER
           // For each frame in block, return packet data
           // Skip to next block when current exhausted
       }
   }
   ```

### Phase 2: Integration with Unified Loop

**File: `src/worker/unified_loop.rs` (modify)**

1. **Replace socket-based receive with ring-based:**
   ```rust
   pub struct UnifiedDataPlane {
       // Remove: recv_socket: Socket,
       packet_ring: PacketRing,  // Add this
       send_socket: Socket,
       ring: IoUring,
       // ... rest unchanged
   }
   ```

2. **Modify event loop:**
   ```rust
   fn run_event_loop(&mut self) {
       loop {
           // Poll packet ring for incoming packets
           for packet in self.packet_ring.poll(0)? {
               self.process_ingress_packet(packet);
           }

           // Submit/complete io_uring operations for egress
           self.process_egress_completions();

           // If no work, wait on combined poll
           if no_packets && no_completions {
               self.wait_for_events();
           }
       }
   }
   ```

3. **Hybrid polling strategy:**
   ```rust
   fn wait_for_events(&mut self) {
       // Option A: Use io_uring IORING_OP_POLL_ADD on packet ring fd
       // Option B: Use poll() with both packet ring fd and io_uring fd
       // Option C: Use timerfd for periodic polling
   }
   ```

### Phase 3: Configuration and Tuning

**File: `src/lib.rs` (modify)**

1. **Add CLI options:**
   ```rust
   #[clap(long, default_value = "64")]
   ring_block_count: usize,

   #[clap(long, default_value = "1048576")]  // 1MB
   ring_block_size: usize,
   ```

2. **Add environment variable overrides:**
   ```rust
   // MCR_RING_BLOCK_COUNT=128
   // MCR_RING_BLOCK_SIZE=2097152
   ```

### Phase 4: PACKET_FANOUT Integration

1. **Ensure PACKET_FANOUT still works with PACKET_MMAP:**
   - Set PACKET_FANOUT after ring setup
   - Each worker gets its own ring
   - Kernel distributes packets across worker rings

2. **Test multi-worker scenario:**
   ```bash
   ./multicast_relay supervisor --num-workers 4 --interface eth0
   ```

## File Changes Summary

| File | Change |
|------|--------|
| `src/worker/packet_ring.rs` | NEW - TPACKET_V3 ring buffer implementation |
| `src/worker/mod.rs` | Add `mod packet_ring;` |
| `src/worker/unified_loop.rs` | Replace recv_socket with packet_ring |
| `src/lib.rs` | Add ring configuration CLI options |
| `Cargo.toml` | Add `libc` features if needed |

## Testing Plan

1. **Unit tests for PacketRing:**
   - Ring creation and teardown
   - Packet iteration
   - Block release

2. **Integration tests:**
   - Compare packet counts with current implementation
   - Verify no packet loss at 100k, 500k, 1M pps
   - Multi-worker fanout test

3. **Performance benchmarks:**
   - Measure packets/second throughput
   - Measure CPU usage per packet
   - Compare latency distribution

## Rollout Strategy

1. **Feature flag:** `--use-packet-mmap` (default: false initially)
2. **Gradual rollout:** Test in staging before enabling by default
3. **Fallback:** Keep SO_RCVBUF code path as fallback

## References

- [Linux PACKET_MMAP documentation](https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt)
- [TPACKET_V3 header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h)
- [libpcap TPACKET_V3 implementation](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-linux.c)
- [DPDK AF_PACKET PMD](https://github.com/DPDK/dpdk/blob/main/drivers/net/af_packet/rte_eth_af_packet.c)

## Estimated Effort

- Phase 1 (Core implementation): 2-3 days
- Phase 2 (Integration): 1-2 days
- Phase 3 (Configuration): 0.5 days
- Phase 4 (FANOUT + testing): 1-2 days
- **Total: 5-8 days**

## Success Criteria

1. Zero packet loss at 1M pps on loopback/veth
2. CPU usage reduced by 20%+ compared to recv() approach
3. Latency P99 reduced by 50%+
4. All existing tests pass
5. No increase in code complexity for packet processing logic
