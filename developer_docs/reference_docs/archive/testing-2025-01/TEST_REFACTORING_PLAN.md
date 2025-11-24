# Test Refactoring Plan

## Current State Analysis

**Total Tests: 142**
- 121 unit tests (10 seconds runtime)
- 12 integration tests (0.5 seconds runtime)
- 8 network tests requiring root (ignored in tarpaulin)
- 1 proptest (not configured to run)
- 2 tests skipped in tarpaulin (FD safety issues)

**Current Coverage: 53.48%** (969/1812 lines)

---

## Problems Identified

### 1. **Test Redundancy** ⚠️

**Logging Tests (40 total - TOO MANY)**
```
src/logging/consumer.rs:     2 tests  → 30/72 lines (41.7%)
src/logging/entry.rs:        11 tests → 72/82 lines (87.8%)
src/logging/facility.rs:      5 tests → 24/47 lines (51.1%)
src/logging/logger.rs:       11 tests → 88/92 lines (95.7%)
src/logging/macros.rs:        2 tests → 10/10 lines (100%)
src/logging/ringbuffer.rs:    5 tests → 109/124 lines (87.9%)
src/logging/severity.rs:      4 tests → 15/25 lines (60.0%)
```

**Issue:** 40 tests for logging system that already has 80%+ coverage on core modules.
**Action:** Consolidate to ~20 tests focusing on integration between modules.

**Worker Tests (59 total - FRAGMENTED)**
```
src/worker/buffer_pool.rs:    7 tests → 75/123 lines (61.0%)
src/worker/control_plane.rs: 12 tests → 34/52 lines (65.4%)
src/worker/data_plane.rs:     3 tests → 40/42 lines (95.2%)
src/worker/egress.rs:          7 tests → 43/105 lines (41.0%) ← LOW
src/worker/ingress.rs:        11 tests → 81/204 lines (39.7%) ← LOW
src/worker/mod.rs:             3 tests → 56/131 lines (42.7%) ← LOW
src/worker/packet_parser.rs:  10 tests → 73/102 lines (71.6%)
src/worker/stats.rs:           2 tests → 19/19 lines (100%)
src/worker/data_plane_integrated.rs: 12 tests → 0/107 lines (0%) ← ZERO!
```

**Issue:**
- 59 tests but low coverage on ingress/egress/mod (40%)
- 12 tests in data_plane_integrated.rs get 0% coverage (require actual I/O)

**Action:**
- Consolidate unit tests to focus on algorithms
- Add focused I/O integration tests
- Remove redundant tests

**Supervisor Tests (13 total - INCOMPLETE)**
```
src/supervisor.rs: 13 tests → 134/331 lines (40.5%)
```

**Issue:** Only 40% coverage despite 13 tests - many I/O paths untested
**Action:** Add tests for error handling paths, remove redundant happy-path tests

### 2. **Zero Coverage Modules**

**Critical Code with 0% Coverage:**
```
src/worker/data_plane_integrated.rs: 0/107 lines (0%)
  → 12 tests exist but cover nothing (need real sockets)
```

**Why:** Tests are written but require actual I/O that unit tests can't mock.

**Action:** Either:
1. Delete the 12 useless tests
2. OR refactor code to be testable (dependency injection)
3. OR accept 0% and rely on network integration tests

### 3. **Missing Tests**

**Property-based testing:**
- `tests/proptests/packet_parser.rs` exists but not configured to run
- Would add fuzzing coverage

**Integration gaps:**
- Supervisor resilience (stub exists, not implemented)
- Multi-worker coordination
- Error recovery paths

---

## Refactoring Strategy

### Phase 1: Delete Redundant Tests (Target: Remove 30 tests)

**Logging System: 40 → 20 tests**
```
DELETE (low value, redundant):
- logging/entry.rs: Remove 5 tests (keep 6 best tests)
- logging/logger.rs: Remove 4 tests (keep 7 best tests)
- logging/facility.rs: Remove 2 tests (keep 3 best tests)
- logging/ringbuffer.rs: Remove 2 tests (keep 3 best tests)

TOTAL: Delete 13 logging tests
```

**Worker System: 59 → 45 tests**
```
DELETE (0% coverage, no value):
- data_plane_integrated.rs: Remove all 12 tests (they test nothing)

DELETE (redundant):
- buffer_pool.rs: Remove 2 tests (keep 5 best)

TOTAL: Delete 14 worker tests
```

**Control Plane: 12 → 8 tests**
```
DELETE (redundant command handling):
- Remove 4 similar command tests, keep representative ones

TOTAL: Delete 4 control plane tests
```

**Total deletions: ~30 tests**

### Phase 2: Add Missing Coverage (Target: Add 15-20 tests)

**High-ROI additions (each ~2-5% coverage increase):**

1. **Ingress error paths (src/worker/ingress.rs: 39.7% → 60%)**
   ```rust
   // Add 5 tests:
   - test_socket_bind_error()
   - test_interface_not_found()
   - test_multicast_join_failure()
   - test_packet_recv_error()
   - test_rule_update_during_processing()
   ```

2. **Egress error paths (src/worker/egress.rs: 41.0% → 60%)**
   ```rust
   // Add 4 tests:
   - test_socket_create_error()
   - test_send_to_error()
   - test_interface_down()
   - test_destination_unreachable()
   ```

3. **Packet parser edge cases (src/worker/packet_parser.rs: 71.6% → 85%)**
   ```rust
   // Add 3 tests:
   - test_maximum_header_size()
   - test_minimum_valid_packet()
   - test_all_protocol_combinations()
   ```

4. **Buffer pool exhaustion (src/worker/buffer_pool.rs: 61.0% → 75%)**
   ```rust
   // Add 2 tests:
   - test_concurrent_allocation_exhaustion()
   - test_size_class_boundary_conditions()
   ```

5. **Supervisor error handling (src/supervisor.rs: 40.5% → 55%)**
   ```rust
   // Add 4 tests:
   - test_worker_spawn_failure()
   - test_socket_creation_error()
   - test_signal_handling()
   - test_graceful_shutdown_timeout()
   ```

**Enable proptest:**
- Add `[[test]]` section to Cargo.toml for proptests
- Adds fuzzing coverage to packet parser

**Total additions: ~18 tests**

### Phase 3: Consolidate Integration Tests

**Network tests: 8 tests (keep all)**
- These are well-designed and necessary
- NO CHANGES

**Integration tests: 12 → 8 tests**
```
DELETE:
- 6 stats parsing tests (test same thing 3x each)
- These are duplicated across test_basic, test_scaling, test_topologies

ADD:
- 2 tests for end-to-end error scenarios
```

---

## Expected Outcome

### Test Count: 142 → 130 tests
```
Before:
- 121 unit tests
- 12 integration tests
- 8 network tests (ignored)
- 1 proptest (not running)

After:
- 95 unit tests (-26)
- 8 integration tests (-4)
- 8 network tests (same)
- 1 proptest (now running) (+1)
- Total reduction: -12 tests
```

### Coverage: 53.48% → 68-72%
```
Current gaps:
- supervisor.rs: 40.5% → 55% (+15%)
- worker/ingress.rs: 39.7% → 60% (+20%)
- worker/egress.rs: 41.0% → 60% (+19%)
- worker/mod.rs: 42.7% → 55% (+12%)
- worker/packet_parser.rs: 71.6% → 85% (+13%)
- worker/buffer_pool.rs: 61.0% → 75% (+14%)

Total lines added: ~200 lines
From: 969/1812 lines (53.48%)
To: ~1250/1812 lines (69%)
```

### Maintenance Benefits
- ✅ Fewer tests to maintain
- ✅ Faster test runs (fewer redundant tests)
- ✅ Higher coverage (focused on gaps)
- ✅ Better signal-to-noise (remove useless tests)
- ✅ Proptest running (fuzzing coverage)

---

## Implementation Steps

### Step 1: Enable Proptest (5 minutes)
```toml
# Add to Cargo.toml
[[test]]
name = "proptests"
path = "tests/proptests/packet_parser.rs"
```

### Step 2: Delete Redundant Tests (30 minutes)
1. Delete 12 data_plane_integrated tests (0% coverage)
2. Delete 13 redundant logging tests
3. Delete 4 redundant control_plane tests
4. Delete 6 duplicate stats parsing tests

### Step 3: Add High-Value Tests (2-3 hours)
1. Ingress error paths (5 tests)
2. Egress error paths (4 tests)
3. Packet parser edge cases (3 tests)
4. Buffer pool stress (2 tests)
5. Supervisor error handling (4 tests)

### Step 4: Verify and Measure (10 minutes)
```bash
cargo test --lib
cargo tarpaulin
# Expect: 130 tests, 68-72% coverage
```

---

## Specific Files to Modify

### Delete Tests From
1. `src/worker/data_plane_integrated.rs` - Remove all 12 tests (mod tests block)
2. `src/logging/entry.rs` - Remove 5 tests
3. `src/logging/logger.rs` - Remove 4 tests
4. `src/logging/facility.rs` - Remove 2 tests
5. `src/logging/ringbuffer.rs` - Remove 2 tests
6. `src/worker/buffer_pool.rs` - Remove 2 tests
7. `src/worker/control_plane.rs` - Remove 4 tests
8. `tests/integration/common/stats.rs` - Remove duplicate test functions

### Add Tests To
1. `src/worker/ingress.rs` - Add 5 error handling tests
2. `src/worker/egress.rs` - Add 4 error handling tests
3. `src/worker/packet_parser.rs` - Add 3 edge case tests
4. `src/worker/buffer_pool.rs` - Add 2 stress tests
5. `src/supervisor.rs` - Add 4 error handling tests

### Configure
1. `Cargo.toml` - Add proptest [[test]] section

---

## Prioritization

### Must Do (High Impact, Low Effort)
1. ✅ Delete data_plane_integrated.rs tests (0% coverage, waste of time)
2. ✅ Enable proptest (1 line in Cargo.toml)
3. ✅ Add ingress/egress error tests (biggest coverage gaps)

### Should Do (High Impact, Medium Effort)
4. ✅ Delete redundant logging tests
5. ✅ Add packet parser edge cases
6. ✅ Add supervisor error handling

### Nice to Have (Medium Impact)
7. ⚠️ Delete redundant control_plane tests
8. ⚠️ Delete duplicate stats tests
9. ⚠️ Add buffer pool stress tests

---

## Rationale for Deletions

### Why delete data_plane_integrated.rs tests?

**Current state:**
```rust
#[cfg(test)]
mod tests {
    // 12 tests that look like this:
    #[tokio::test]
    async fn test_packet_creation_and_parsing() {
        // Creates mock data
        // Tests pure logic
        // NEVER touches actual I/O
        // Result: 0% coverage of the actual file
    }
}
```

**Problem:** These tests don't test data_plane_integrated.rs at all! They test packet_parser.rs (which already has its own tests).

**Better approach:**
- The network integration tests (`test_basic.rs`, etc.) actually test this module with real I/O
- Keep those 8 tests, delete these 12 useless ones

### Why delete logging tests?

**Current:** 40 tests for 80%+ coverage
**Issue:** Diminishing returns - tests are redundant

**Example redundancy:**
```rust
// logger.rs has:
test_logger_basic()
test_logger_clone()  // Tests same code path
test_logger_with_kvs()  // Tests same code path + kvs
```

Keep the most comprehensive test, delete the others.

---

## Questions to Answer

1. **Should we delete tests with 0% coverage?**
   - YES for data_plane_integrated.rs (12 tests, 0% coverage)
   - They're misleading - appear to test code but don't

2. **What's acceptable test count for 70% coverage?**
   - 95 unit tests is reasonable
   - That's ~0.85 tests per 100 lines of production code
   - Industry standard is 0.5-1.5 tests per 100 lines

3. **Should we prioritize coverage % or test quality?**
   - Quality > quantity
   - 130 good tests with 70% coverage beats 142 tests with 53% coverage

---

## Next Action

**Recommend starting with Quick Wins:**

```bash
# Step 1: Enable proptest (instant win)
echo '[[test]]
name = "proptests"
path = "tests/proptests/packet_parser.rs"' >> Cargo.toml

# Step 2: Delete 0% coverage tests
# Edit src/worker/data_plane_integrated.rs
# Remove #[cfg(test)] mod tests { ... }

# Step 3: Run coverage
cargo tarpaulin

# Expected: +1 test (proptest), -12 tests (deleted), coverage unchanged or slightly higher
```

Then proceed with targeted additions for ingress/egress/supervisor error paths.
