# Mutex to Lock-Free Buffer Pool Migration Plan

**Status**: 🔄 Planning Phase
**Created**: 2025-11-13
**Priority**: 🔴 HIGH (Performance Critical)

---

## Executive Summary

The data plane currently uses a **Mutex-based buffer pool** by default, which creates contention in the packet processing fast path. A **lock-free backend** exists but is behind a feature flag and not well-tested. This document outlines the plan to migrate to the lock-free backend as the default.

---

## Current State Analysis

### Mutex Usage in Fast Path

The mutex is used in the buffer pool for packet buffer allocation:

**Location**: `src/worker/buffer_pool.rs` (lines 80, 59)
```rust
// Mutex-based buffer pool
let buffer_pool = Arc::new(std::sync::Mutex::new(BufferPool::with_capacities(...)));

// Every packet allocation locks the mutex
impl BufferPoolTrait for Arc<Mutex<MutexBufferPool>> {
    fn allocate(&self, size: usize) -> Option<Buffer> {
        self.lock().expect("Mutex poisoned").allocate(size)  // ← LOCK HERE
    }
}
```

**Impact**:
- **Ingress path**: Locks mutex for every incoming packet to allocate buffer
- **Egress path**: Locks mutex when returning buffers (less critical)
- **Contention**: Multiple threads competing for the same lock
- **Performance**: Estimated 100-500ns overhead per packet vs lock-free

### Backend Selection

**File**: `src/worker/data_plane_integrated.rs`

```rust
pub fn run_data_plane(...) -> Result<()> {
    #[cfg(feature = "lock_free_buffer_pool")]
    {
        logger.info(Facility::DataPlane, "Using Lock-Free Backend");
        lock_free_backend::run(config, command_rx, event_fd)
    }
    #[cfg(not(feature = "lock_free_buffer_pool"))]
    {
        logger.info(Facility::DataPlane, "Using Mutex Backend");  // ← CURRENT DEFAULT
        mutex_backend::run(config, command_rx, event_fd)
    }
}
```

**Current**: Mutex backend is the default
**Goal**: Lock-free backend becomes the default

### Lock-Free Backend Status

**Location**: `src/worker/data_plane_integrated.rs` (line 173+)

```rust
#[cfg(feature = "lock_free_buffer_pool")]
mod lock_free_backend {
    // Uses lock-free ring buffer for packet channels
    // Uses lock-free buffer pool
    // Proper implementation exists but is untested
}
```

**Status**:
- ✅ Code exists and compiles
- ❌ Not tested in CI/CD
- ❌ No end-to-end tests run with this feature
- ❓ Unknown production readiness

---

## Test Infrastructure

### End-to-End Tests Requiring Root

All tests in `tests/` directory require `CAP_NET_RAW` (root) for AF_PACKET sockets:

1. **tests/data_plane_e2e.sh** - Basic functionality test
   - Starts supervisor with `sudo`
   - Adds forwarding rule
   - Sends 100 packets via traffic_generator
   - Verifies all packets received

2. **tests/data_plane_pipeline.sh** - Pipeline processing
3. **tests/data_plane_pipeline_veth.sh** - veth pair test
4. **tests/data_plane_performance.sh** - Performance benchmarks
5. **tests/data_plane_debug.sh** - Debug trace logging
6. **tests/scaling_test.sh** - Multi-worker scaling
7. **tests/debug_10_packets.sh** - Minimal packet trace

### Current Test Command

```bash
# Current tests only run mutex backend
sudo -E ./tests/data_plane_e2e.sh
```

### Required: Lock-Free Tests

**Need to add**:
```bash
# Build with lock-free feature
cargo build --features lock_free_buffer_pool

# Run tests with lock-free binary
sudo -E ./tests/data_plane_e2e_lockfree.sh
```

---

## Migration Plan

### Phase 1: Verify Current Mutex Backend ✅

**Goal**: Confirm all tests pass with current mutex backend

**Commands (run as user with sudo)**:
```bash
# Build mutex backend (default)
cargo build --bin multicast_relay --bin control_client --bin traffic_generator

# Run basic e2e test
./tests/data_plane_e2e.sh

# Run pipeline test
./tests/data_plane_pipeline.sh

# Run performance test
./tests/data_plane_performance.sh
```

**Expected**:
- All tests pass
- Logs show "Using Mutex Backend"
- Performance baseline established

**Deliverable**: Baseline performance metrics

---

### Phase 2: Test Lock-Free Backend 🔄

**Goal**: Verify lock-free backend works correctly

**Commands (run as user with sudo)**:
```bash
# Build lock-free backend
cargo build --features lock_free_buffer_pool \
  --bin multicast_relay \
  --bin control_client \
  --bin traffic_generator

# Run same tests
./tests/data_plane_e2e.sh
./tests/data_plane_pipeline.sh
./tests/data_plane_performance.sh
```

**Expected**:
- All tests pass
- Logs show "Using Lock-Free Backend"
- Performance improved vs mutex baseline

**Potential Issues**:
- Buffer pool exhaustion (lock-free may have different allocation patterns)
- Race conditions (unlikely, but possible)
- Memory leaks (buffers not returned properly)

**Deliverable**:
- Test results showing lock-free works
- Performance comparison: mutex vs lock-free

---

### Phase 3: Performance Comparison 📊

**Goal**: Quantify performance improvement

**Test Matrix**:

| Backend | Packet Rate | Latency (p50/p95/p99) | CPU Usage | Memory |
|---------|-------------|----------------------|-----------|--------|
| Mutex   | ?           | ?                    | ?         | ?      |
| Lock-Free | ?         | ?                    | ?         | ?      |

**Commands**:
```bash
# Mutex backend performance
cargo build --release
./tests/data_plane_performance.sh > mutex_results.txt

# Lock-free backend performance
cargo build --release --features lock_free_buffer_pool
./tests/data_plane_performance.sh > lockfree_results.txt

# Compare
diff -u mutex_results.txt lockfree_results.txt
```

**Metrics to Capture**:
- Throughput (packets/second)
- Latency percentiles (p50, p95, p99, p99.9)
- CPU utilization (% per core)
- Memory usage (RSS, buffer pool)
- Lock contention (if possible to measure)

**Expected Improvement**:
- 10-30% higher throughput
- 20-40% lower tail latency (p99, p99.9)
- Lower CPU usage per packet

**Deliverable**: Performance comparison report

---

### Phase 4: Switch Default to Lock-Free 🚀

**Goal**: Make lock-free the default backend

**Changes Required**:

1. **Cargo.toml**: Enable lock-free by default
   ```toml
   [features]
   default = ["lock_free_buffer_pool"]
   lock_free_buffer_pool = []
   mutex_backend = []  # NEW: Optional fallback
   ```

2. **src/worker/data_plane_integrated.rs**: Reverse the cfg logic
   ```rust
   pub fn run_data_plane(...) -> Result<()> {
       #[cfg(not(feature = "mutex_backend"))]  // ← NEW DEFAULT
       {
           logger.info(Facility::DataPlane, "Using Lock-Free Backend");
           lock_free_backend::run(config, command_rx, event_fd)
       }
       #[cfg(feature = "mutex_backend")]  // ← FALLBACK ONLY
       {
           logger.info(Facility::DataPlane, "Using Mutex Backend");
           mutex_backend::run(config, command_rx, event_fd)
       }
   }
   ```

3. **CI/CD**: Update test matrix
   - Add lock-free tests to CI
   - Keep mutex tests as regression check
   - Add performance benchmarks

**Testing**:
```bash
# Default should now be lock-free
cargo build
./tests/data_plane_e2e.sh  # Should show "Using Lock-Free Backend"

# Mutex backend available as opt-in
cargo build --features mutex_backend
./tests/data_plane_e2e.sh  # Should show "Using Mutex Backend"
```

**Deliverable**:
- Lock-free is default
- All tests passing
- CI/CD updated

---

### Phase 5: Cleanup and Documentation 📚

**Goal**: Remove mutex code or document clearly

**Options**:

**Option A: Keep both backends**
- Useful for benchmarking
- Fallback if lock-free has issues
- More code to maintain

**Option B: Remove mutex backend**
- Simpler codebase
- Less testing burden
- No fallback if issues found

**Recommendation**: Keep both for 1-2 releases, then remove mutex if no issues

**Documentation Updates**:
1. **docs/PERFORMANCE.md**: Add lock-free buffer pool details
2. **docs/ARCHITECTURE.md**: Update buffer pool section
3. **README.md**: Mention lock-free as performance feature
4. **CHANGELOG.md**: Document the change

---

## Risk Assessment

### High Risk

1. **Buffer pool exhaustion**: Lock-free may allocate differently
   - **Mitigation**: Extensive testing with varying loads
   - **Monitoring**: Add metrics for buffer pool utilization

2. **Race conditions**: Subtle bugs in lock-free code
   - **Mitigation**: Code review, stress testing
   - **Detection**: Run with TSan (ThreadSanitizer)

### Medium Risk

1. **Performance regression in some scenarios**
   - **Mitigation**: Comprehensive benchmarking
   - **Fallback**: Keep mutex backend available

2. **Increased memory usage**
   - **Mitigation**: Profile memory with different backends
   - **Monitoring**: Track RSS over time

### Low Risk

1. **API compatibility**: Both backends use same traits
2. **Build complexity**: Feature flags well-understood

---

## Testing Checklist

Before switching default to lock-free:

- [ ] All unit tests pass (with lock_free_buffer_pool)
- [ ] All e2e tests pass (with lock_free_buffer_pool)
- [ ] Performance tests show improvement
- [ ] Memory usage is acceptable
- [ ] No buffer pool exhaustion under high load
- [ ] No race conditions detected (TSan clean)
- [ ] Stress test (24+ hours) passes
- [ ] Multi-worker scaling works correctly
- [ ] Graceful shutdown works (buffers returned)
- [ ] Documentation updated

---

## How to Execute This Plan

### For the User (with sudo access)

**Step 1: Verify Mutex Backend Works**
```bash
cd /home/acooks/mcr
cargo build --bin multicast_relay --bin control_client --bin traffic_generator
./tests/data_plane_e2e.sh
```

**Step 2: Test Lock-Free Backend**
```bash
cargo build --features lock_free_buffer_pool \
  --bin multicast_relay --bin control_client --bin traffic_generator
./tests/data_plane_e2e.sh
```

**Step 3: Compare Performance**
```bash
# Run performance test with both backends
./tests/data_plane_performance.sh > mutex_perf.txt
cargo build --release --features lock_free_buffer_pool
./tests/data_plane_performance.sh > lockfree_perf.txt
diff -u mutex_perf.txt lockfree_perf.txt
```

**Step 4: Report Results**
- Did all tests pass?
- What was the performance difference?
- Any errors or unexpected behavior?

### For the Assistant (code changes)

Once test results are available, implement Phase 4 changes based on findings.

---

## Success Criteria

**Minimum**:
- ✅ All tests pass with lock-free backend
- ✅ No performance regression
- ✅ No new bugs introduced

**Ideal**:
- ✅ 20%+ performance improvement
- ✅ Lower tail latency
- ✅ Cleaner code (mutex removed eventually)

---

## Next Steps

1. **User**: Run Phase 1 and Phase 2 tests, report results
2. **Assistant**: Analyze results, implement Phase 4 if successful
3. **User**: Validate Phase 4 changes
4. **Assistant**: Phase 5 cleanup and documentation

---

## References

- **Lock-Free Backend**: `src/worker/data_plane_integrated.rs:173`
- **Mutex Backend**: `src/worker/data_plane_integrated.rs:38`
- **Buffer Pool**: `src/worker/buffer_pool.rs`
- **Test Suite**: `tests/data_plane_*.sh`
- **Performance Design**: `design/RINGBUFFER_IMPLEMENTATION.md`
