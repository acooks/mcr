# Performance Fixes Needed for Option 4 Unified Loop

**Date:** 2025-11-18
**Status:** ACTION REQUIRED
**Target:** Achieve 307k pps egress (PHASE4 baseline)

---

## Critical Issues Identified

The performance regression analysis (PERFORMANCE_FIX_2025-11-16.md) identified two **critical configuration issues** that are still present in the unified loop:

### Issue 1: Insufficient io_uring Queue Depth ❌

**Current Configuration:**
```rust
// src/worker/unified_loop.rs:94
impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            queue_depth: 128,  // ← TOO SMALL!
            num_recv_buffers: 32,
            send_batch_size: 32,
            track_stats: true,
        }
    }
}
```

**Problem:**
- 128 entries is insufficient for 300k+ pps throughput
- At 300k pps, each packet needs ~3.3µs to process
- With 128 queue depth, we can only have 128 operations in flight
- This creates artificial backpressure

**Impact Calculation:**
```
Target: 307k pps
Queue depth: 128 operations
Max throughput: 128 ops / (3.3µs per op) = ~38k ops/sec = 38k pps

Current queue depth limits us to 38k pps!
```

**Evidence:**
- PHASE4 benchmark experiments showed optimal performance at 512-1024 queue depth
- High-throughput network applications typically use 512-2048 queue depth
- The EGRESS_REGRESSION_ANALYSIS explicitly called this out

**Fix Required:**
```rust
impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            queue_depth: 1024,  // ← Increase to 1024
            num_recv_buffers: 32,
            send_batch_size: 64,  // Also increase batch size
            track_stats: true,
        }
    }
}
```

---

### Issue 2: Untuned UDP Socket Send Buffers ❌

**Current Code:**
```rust
// src/worker/unified_loop.rs:737-743
fn create_connected_udp_socket(source_ip: Ipv4Addr, dest_addr: SocketAddr) -> Result<OwnedFd> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(source_ip.into(), 0).into())?;
    socket.connect(&dest_addr.into())?;
    Ok(socket.into())  // ← NO SO_SNDBUF SETTING!
}
```

**Problem:**
- Default kernel UDP send buffer is typically 208 KB
- At 307k pps with 1400-byte packets = 430 MB/s
- Default buffer can only hold ~150 packets = 0.5ms worth of data
- When buffer fills, kernel blocks or drops packets

**Impact:**
- Kernel blocks io_uring send operations when buffer full
- Causes buffer pool exhaustion (86% in tests)
- Limits throughput to ~100k pps

**Fix Required:**
```rust
fn create_connected_udp_socket(source_ip: Ipv4Addr, dest_addr: SocketAddr) -> Result<OwnedFd> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    // Set large send buffer for high throughput (4 MB)
    socket.set_send_buffer_size(4 * 1024 * 1024)?;

    socket.bind(&SocketAddr::new(source_ip.into(), 0).into())?;
    socket.connect(&dest_addr.into())?;
    Ok(socket.into())
}
```

**Why 4 MB:**
```
Target: 307k pps × 1400 bytes = 430 MB/s
At 4 MB buffer: 4MB / 430MB/s = ~9.3ms worth of packets
This provides sufficient buffering for bursty traffic
```

---

## Additional Optimizations

### 3. Increase Batch Size

**Current:**
```rust
send_batch_size: 32,
```

**Recommended:**
```rust
send_batch_size: 64,  // or even 128
```

**Rationale:**
- Larger batches reduce io_uring syscall overhead
- Better amortization of submission costs
- More efficient use of queue depth

---

### 4. Check Receive Buffer Pre-Posting

**Current:**
```rust
num_recv_buffers: 32,
```

**Question:** Is 32 enough for 690k pps ingress?

**Analysis:**
- At 690k pps, each buffer is used for ~46µs
- With 32 buffers, we process a new batch every ~46µs
- io_uring needs time to process completions and submit new receives
- May need to increase to 64 for better pipelining

**Recommendation:** Start with current 32, increase if ingress drops

---

## Performance Prediction

### Current (broken) configuration:
```
queue_depth: 128
SO_SNDBUF: default (~208 KB)
batch_size: 32

Bottleneck: Queue depth limits to ~38k pps
Actual: ~97k pps (still hitting other limits)
```

### After fixes:
```
queue_depth: 1024
SO_SNDBUF: 4 MB
batch_size: 64

Expected: 300k+ pps (PHASE4 levels)
Reasoning:
- Queue depth supports 300k+ pps
- Socket buffer prevents kernel blocking
- Larger batches reduce syscall overhead
```

---

## Implementation Plan

### Step 1: Apply Configuration Changes

**File:** `src/worker/unified_loop.rs`

```rust
impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            queue_depth: 1024,      // Increased from 128
            num_recv_buffers: 32,   // Keep current (stable)
            send_batch_size: 64,    // Increased from 32
            track_stats: true,
        }
    }
}
```

### Step 2: Add Socket Buffer Tuning

**File:** `src/worker/unified_loop.rs`

```rust
fn create_connected_udp_socket(source_ip: Ipv4Addr, dest_addr: SocketAddr) -> Result<OwnedFd> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    // Tune socket for high throughput
    // Set 4 MB send buffer (configurable via env var)
    let send_buffer_size = std::env::var("MCR_SOCKET_SNDBUF")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4 * 1024 * 1024);  // Default 4 MB

    socket.set_send_buffer_size(send_buffer_size)
        .context("Failed to set SO_SNDBUF")?;

    socket.bind(&SocketAddr::new(source_ip.into(), 0).into())?;
    socket.connect(&dest_addr.into())?;
    Ok(socket.into())
}
```

### Step 3: Make Configuration Tunable

**File:** `src/worker/data_plane_integrated.rs`

```rust
pub fn run_unified_data_plane(
    config: DataPlaneConfig,
    ingress_channels: IngressChannelSet,
    _egress_channels: EgressChannelSet,
    logger: Logger,
) -> Result<()> {
    // ... existing code ...

    // Create unified data plane configuration
    let mut unified_config = UnifiedConfig::default();

    // Allow tuning via environment variables
    if let Ok(depth) = std::env::var("MCR_IO_URING_DEPTH") {
        if let Ok(d) = depth.parse() {
            unified_config.queue_depth = d;
        }
    }

    if let Ok(batch) = std::env::var("MCR_SEND_BATCH_SIZE") {
        if let Ok(b) = batch.parse() {
            unified_config.send_batch_size = b;
        }
    }

    logger.info(
        Facility::DataPlane,
        &format!("Unified config: queue_depth={}, send_batch={}",
            unified_config.queue_depth,
            unified_config.send_batch_size)
    );

    // ... rest of function ...
}
```

### Step 4: Ensure Kernel Limits Allow Large Buffers

**Check system limits:**
```bash
# Check current max
sysctl net.core.wmem_max

# If less than 4 MB, increase it
sudo sysctl -w net.core.wmem_max=16777216  # 16 MB
sudo sysctl -w net.core.wmem_default=4194304  # 4 MB
```

**Make permanent (optional):**
```bash
echo "net.core.wmem_max = 16777216" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_default = 4194304" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Testing Plan

### Test 1: Baseline (current broken config)
```bash
cargo build --release --bins
sudo tests/data_plane_pipeline_veth.sh 2>&1 | tee results_baseline.txt
```

**Expected:** ~97k pps egress, 86% buffer exhaustion

### Test 2: With fixes applied
```bash
# Apply code changes
cargo build --release --bins

# Ensure kernel limits set
sudo sysctl -w net.core.wmem_max=16777216

# Run test
sudo tests/data_plane_pipeline_veth.sh 2>&1 | tee results_fixed.txt
```

**Expected:** ~300k+ pps egress, <40% buffer exhaustion

### Test 3: Tuning experiments
```bash
# Try different queue depths
for depth in 256 512 1024 2048; do
    echo "Testing queue_depth=$depth"
    MCR_IO_URING_DEPTH=$depth sudo tests/data_plane_pipeline_veth.sh 2>&1 | tee results_depth_$depth.txt
done

# Try different batch sizes
for batch in 32 64 128 256; do
    echo "Testing send_batch=$batch"
    MCR_SEND_BATCH_SIZE=$batch sudo tests/data_plane_pipeline_veth.sh 2>&1 | tee results_batch_$batch.txt
done
```

---

## Expected Outcomes

### Success Criteria
✅ Egress throughput ≥ 300k pps (match PHASE4)
✅ Buffer exhaustion < 40% (acceptable range)
✅ Ingress maintains ~690k pps (no regression)
✅ No packet drops or errors

### If Still Bottlenecked

**Additional investigations:**
1. **CPU pinning** - Pin worker to dedicated core
2. **NUMA** - Ensure worker on same NUMA node as NIC
3. **Packet size** - Verify 1400 byte payloads aren't causing issues
4. **Kernel version** - Check if io_uring performance differs
5. **Profile with perf** - Find remaining hotspots

---

## Root Cause: Why These Were Missed

The Option 4 unified loop was designed to eliminate the **cross-thread bottleneck**, but it still needs the same **kernel-level tuning** that the two-thread model required:

1. ✅ Eliminated SegQueue bottleneck
2. ✅ Eliminated eventfd overhead
3. ✅ Eliminated context switches
4. ❌ But kept small io_uring queue (128 vs 1024)
5. ❌ And didn't tune socket buffers (SO_SNDBUF)

**The unified loop is architecturally sound, just under-provisioned!**

---

## Priority

🔴 **CRITICAL** - Apply fixes immediately

These are not optimizations, these are **required configuration** for high-throughput operation. The current configuration is fundamentally incapable of achieving target performance.

---

## Files to Modify

1. ✏️ `src/worker/unified_loop.rs` - UnifiedConfig default, create_connected_udp_socket
2. ✏️ `src/worker/data_plane_integrated.rs` - Add environment variable tuning (optional)
3. 📝 `TESTING.md` - Document kernel tuning requirements

---

## References

- **PERFORMANCE_FIX_2025-11-16.md** - Identified these exact issues
- **EGRESS_REGRESSION_ANALYSIS_2025-11-16.md** - Root cause analysis
- **experiments/poc_io_uring_egress/benches/** - Benchmark data showing optimal configs
