# MCR Test Analysis and Roadmap

**Date:** 2025-01-14
**Status:** Draft
**Purpose:** Comprehensive analysis of the current testing infrastructure, identifying gaps, broken tests, and providing a roadmap for achieving comprehensive, automated testing in the development workflow.

---

## Executive Summary

The MCR project has a **fragmented testing infrastructure** with multiple testing approaches that are not consistently run during development:

- ✅ **107 Rust unit tests** in lib.rs (106 passing, 1 flaky)
- ⚠️ **20 Rust integration tests** (12 passing, 8 ignored - require root)
- ❌ **12 shell script tests** (not integrated into CI, require manual execution)
- ❌ **Coverage: Unknown** (no recent coverage report)

**Key Problems:**
1. Shell scripts are not part of `just check` or CI pipeline
2. Many integration tests are marked `#[ignore]` and never run
3. No automated coverage tracking
4. Tests that require root privileges are skipped in normal development
5. Duplication between shell scripts and Rust integration tests
6. No clear guidance on which tests to run when

**Goal:** Achieve 90%+ code coverage with all tests running automatically in the development workflow.

---

## Testing Tiers (from TESTING.md)

The project follows a formal 3-tier testing strategy:

### Tier 1: Unit Tests (with Mocks)
- **Purpose:** Test pure business logic without privileges/kernel
- **Location:** Inline in `src/` files under `#[cfg(test)]`
- **Execution:** `cargo test --lib`
- **Status:** ✅ **Good** - 106/107 passing (99.1% pass rate)

### Tier 2: Integration Tests (in Network Namespaces)
- **Purpose:** Test component interaction in isolated environments
- **Location:** `tests/integration/*.rs`
- **Execution:** `cargo test --test integration --features integration_test`
- **Status:** ⚠️ **Partial** - 12 passing, 8 ignored

### Tier 3: End-to-End Functional & Performance Tests
- **Purpose:** Validate fully compiled binaries under realistic conditions
- **Location:** `tests/*.sh`, `tests/topologies/*.sh`, `tests/e2e/*.sh`
- **Execution:** Manual - no automation
- **Status:** ❌ **Broken** - not integrated into workflow

---

## Detailed Test Inventory

### 1. Rust Unit Tests (Tier 1)

**Location:** `src/**/*.rs` in `#[cfg(test)]` modules

**Categories:**

#### Logging System Tests (46 tests)
- `logging::consumer` - 7 tests ✅
- `logging::entry` - 11 tests ✅
- `logging::facility` - 5 tests ✅
- `logging::integration` - 3 tests (⚠️ 1 flaky: `test_data_plane_logging`)
- `logging::logger` - 4 tests ✅
- `logging::ringbuffer` - 15 tests ✅
- `logging::severity` - 1 test ✅

#### Supervisor Tests (13 tests)
- `supervisor::tests::test_handle_*` - 9 tests ✅ (command handlers)
- `supervisor::tests::test_supervisor_*` - 4 tests ✅ (lifecycle/resilience)

#### Worker Tests (12 tests)
- `worker::buffer_pool` - 6 tests ✅
- `worker::packet_parser` - 6 tests ✅

#### Other Module Tests (36 tests)
- `control_client` - 3 tests ✅
- `lib.rs` - Various tests ✅
- Network monitor, rule dispatch, etc.

**Total:** 107 tests, **106 passing** (99.1%)

**Known Issue:**
```
FAILED: logging::integration::tests::test_data_plane_logging
Error: EEXIST (shared memory file already exists)
Cause: Test doesn't clean up /dev/shm/mcr_* before running
Fix: Add cleanup at test start
```

---

### 2. Rust Integration Tests (Tier 2)

**Location:** `tests/integration/`

**Structure:**
```
tests/
├── integration.rs          # Main test harness
├── integration/
│   ├── cli.rs             # CLI tests (3 tests) ✅
│   ├── log_level_control.rs  # IPC log level tests (2 tests) ✅
│   ├── rule_management.rs     # E2E rule management (1 test) ✅
│   ├── test_basic.rs          # Basic forwarding (2 tests) ⚠️ IGNORED
│   ├── test_scaling.rs        # Scaling tests (3 tests) ⚠️ IGNORED
│   ├── test_topologies.rs     # Multi-hop tests (3 tests) ⚠️ IGNORED
│   ├── supervisor_resilience.rs  # Worker restart tests (5 tests) ❌ STUBBED
│   └── common/            # Helper modules (6 tests) ✅
│       ├── mod.rs
│       ├── mcr.rs
│       ├── network.rs
│       └── stats.rs
```

**Status:**
- **12 passing** - CLI, log control, stats parsing, rule management
- **8 ignored** - All require root privileges (`#[ignore]` + `#[requires_root]`)
  - `test_single_hop_1000_packets`
  - `test_minimal_10_packets`
  - `test_scale_1000_packets`
  - `test_scale_10000_packets`
  - `test_scale_1m_packets`
  - `test_baseline_2hop_100k_packets`
  - `test_chain_3hop`
  - `test_tree_fanout_1_to_3`

**Problem:** These tests are **never run** in the normal development workflow because:
1. They require root (`sudo`)
2. They're marked `#[ignore]`
3. `just check` doesn't run them
4. Developer doesn't know to run them manually

**Stubbed Tests (not implemented):**
- `supervisor_resilience.rs` - 5 tests exist but are stubs with `#[ignore]`
  - See `tests/integration/IMPLEMENTATION_GUIDE.md` for implementation plan

---

### 3. Shell Script Tests (Tier 3)

**Location:** `tests/*.sh`, `tests/topologies/*.sh`, `tests/e2e/*.sh`

#### Main Test Scripts (tests/)
1. **`data_plane_e2e.sh`** (5.6K) - Complete E2E test with namespace, socat listener
2. **`data_plane_debug.sh`** (3.7K) - Debug test with small packet count
3. **`data_plane_performance.sh`** (4.8K) - Performance benchmarking
4. **`data_plane_pipeline.sh`** (5.6K) - Pipeline validation (loopback)
5. **`data_plane_pipeline_veth.sh`** (7.9K) - Pipeline with veth pairs
6. **`debug_10_packets.sh`** (4.4K) - Minimal debug test
7. **`scaling_test.sh`** (5.2K) - Scaling validation
8. **TEST_STANDARDS.md** - Standards for shell test structure

#### Topology Tests (tests/topologies/)
1. **`baseline_50k.sh`** (5.2K) - 2-hop baseline (50k packets)
2. **`chain_3hop.sh`** (4.5K) - 3-hop chain topology
3. **`tree_fanout.sh`** (6.1K) - Tree with 1-to-3 fanout
4. **`common.sh`** (7.4K) - Shared functions for topology tests

#### E2E Tests (tests/e2e/)
1. **`run_all.sh`** (1.3K) - Runner for all E2E tests
2. **`common.sh`** (6.3K) - Shared E2E test infrastructure

**Status:** ❌ **Not integrated into workflow**
- Not run by `just check`
- Not run by `just test`
- There IS `just test-topologies` but it's not part of main workflow
- Require manual execution with `sudo`
- No indication if they're passing or failing
- Developer doesn't know they exist

**Overlap with Rust Integration Tests:**
- `data_plane_e2e.sh` overlaps with `test_basic.rs`
- `scaling_test.sh` overlaps with `test_scaling.rs`
- `topologies/*.sh` overlap with `test_topologies.rs`

This duplication suggests these should either be:
1. Consolidated (pick Rust or shell, not both)
2. Or clearly differentiated (e.g., shell for performance, Rust for correctness)

---

### 4. Justfile Test Commands

**Current Commands:**

```bash
just check              # Runs: fmt, clippy, build, test, audit, outdated, coverage, unsafe-check
just test               # Runs: cargo test --all-targets --features integration_test
just test-e2e           # Runs: Old E2E test (deprecated, uses simple socat)
just test-topologies    # Runs: All tests/topologies/*.sh (requires root)
just test-topology TEST # Runs: Specific topology test (requires root)
just coverage           # Runs: cargo tarpaulin (generates coverage report)
```

**Problems:**
1. `just check` runs `test` which **only runs non-ignored tests**
2. `just check` does NOT run shell scripts
3. `just test-topologies` is separate and requires root
4. No single command to "run all tests"
5. Coverage report is generated but not enforced

---

## Root Cause Analysis

### Why Tests Are Not Run in Development

**Problem 1: Privilege Requirements**
- Many tests require `CAP_NET_RAW`, `CAP_NET_ADMIN` for network namespaces
- Developers don't want to run `sudo cargo test` routinely
- Tests are marked `#[ignore]` and forgotten

**Problem 2: Fragmentation**
- 3 different test systems (Rust unit, Rust integration, shell scripts)
- No clear guidance on which to run when
- Duplication between Rust and shell tests

**Problem 3: No Enforcement**
- `just check` doesn't fail if ignored tests are broken
- No coverage enforcement
- No requirement to run shell scripts

**Problem 4: Slow Feedback**
- Integration tests with network namespaces are slow
- Developers skip them during rapid iteration
- Tests bitrot

### Why Coverage Is Low

1. **Critical paths not tested:**
   - Data plane packet processing (requires privileges)
   - Supervisor worker lifecycle (requires process spawning)
   - Error recovery paths (hard to trigger)

2. **Tests exist but aren't run:**
   - 8 integration tests ignored
   - 12 shell scripts not automated

3. **No coverage tracking:**
   - `just coverage` generates report but isn't mandatory
   - No enforcement of minimum coverage percentage
   - No visibility into what's untested

---

## Test Quality Assessment

### What's Working Well ✅

1. **Unit test coverage of logging system** - 46 tests, comprehensive
2. **Supervisor command handler tests** - 9 tests cover control plane protocol
3. **Test infrastructure is well-designed:**
   - Network namespace isolation
   - UUID-based socket paths avoid collisions
   - Common helpers in `tests/integration/common/`
   - TEST_STANDARDS.md documents shell script patterns

### What's Broken ❌

1. **Flaky test:** `test_data_plane_logging` - EEXIST error (shared memory cleanup)
2. **Ignored tests never run** - 8 integration tests require root and are skipped
3. **Shell scripts abandoned** - 12 scripts, no automation, unknown status
4. **Stubbed resilience tests** - 5 supervisor_resilience tests are empty stubs
5. **No coverage enforcement** - Unknown what percentage of code is tested

### What's Missing ⚠️

1. **Data plane packet processing tests:**
   - Ingress packet reception
   - Rule matching logic
   - Egress transmission
   - Buffer pool exhaustion handling
   - Error recovery (ENOBUFS, EAGAIN, etc.)

2. **Supervisor lifecycle tests:**
   - Worker crash detection
   - Exponential backoff on repeated failures
   - Rule resynchronization after restart
   - Privilege drop verification

3. **Performance regression tests:**
   - Throughput benchmarks
   - Latency measurements
   - Resource usage tracking

4. **Error injection tests:**
   - Network interface down/up
   - Out of memory scenarios
   - Malformed packets
   - Control plane socket errors

---

## Proposed Solutions

### Solution 1: Unify Test Execution

**Goal:** Single command to run ALL tests (that don't require root)

**Approach:**
1. Keep `just test` for unit + integration tests
2. Create `just test-all` that runs unit + integration + shell scripts
3. Create `just test-root` for tests requiring sudo
4. Update `just check` to fail if any non-root test fails

**Implementation:**
```bash
# Add to justfile

# Run all tests that don't require root
test-all: test
    @echo "--- Running shell script tests (non-root) ---"
    @./tests/run_nonroot_tests.sh

# Run all tests including those requiring root
test-root:
    @echo "--- Running all tests including root-required ---"
    @sudo -E cargo test --all-targets --features integration_test -- --test-threads=1 --include-ignored
    @sudo ./tests/run_all_shell_tests.sh

# Update check to include test-all
check: fmt clippy build test-all audit outdated coverage unsafe-check
    @echo "\n✅ All checks passed!"
```

### Solution 2: Fix Flaky Tests

**Priority 1: Fix test_data_plane_logging**

**Root cause:** Shared memory files from previous test runs

**Fix:**
```rust
// src/logging/integration.rs:304
#[test]
fn test_data_plane_logging() {
    // Clean up any leftover shared memory from previous test runs
    for facility in ["dataplane", "ingress", "egress", "bufferpool"] {
        let _ = std::fs::remove_file(format!("/dev/shm/mcr_dp_c0_{}", facility));
    }

    // Create shared memory (supervisor side)
    let manager = SharedMemoryLogManager::create_for_worker(0, 1024).unwrap();
    // ... rest of test
}
```

### Solution 3: Integrate Root-Required Tests

**Problem:** Tests marked `#[ignore]` never run

**Solution A: Container-based Testing (Recommended)**
- Run tests in Docker/Podman with `--privileged`
- Provides isolation + root without requiring host root
- Can run in CI without security concerns

**Solution B: Separate CI Job**
- Create `just test-ci-root` that runs with sudo
- Run in dedicated CI stage with appropriate permissions
- Document clearly that these tests require elevated privileges

**Solution C: Virtualization**
- Use `unshare --user --net` for rootless namespace tests
- May not work for all kernel features (AF_PACKET)
- Requires kernel support for user namespaces

**Recommendation:** Use Solution A (containers) for CI, Solution B for local development

### Solution 4: Consolidate Duplicate Tests

**Decision Matrix:**

| Test Type | Shell Script | Rust Integration | Recommendation |
|-----------|--------------|------------------|----------------|
| Basic forwarding | `data_plane_e2e.sh` | `test_basic.rs` | **Keep Rust** - easier to maintain, better error messages |
| Scaling | `scaling_test.sh` | `test_scaling.rs` | **Keep Rust** - programmatic scaling parameters |
| Topologies | `topologies/*.sh` | `test_topologies.rs` | **Keep shell** - visual topology, easier to debug |
| Performance | `data_plane_performance.sh` | None | **Keep shell** - specialized for benchmarking |
| Debug | `debug_10_packets.sh` | None | **Keep shell** - manual debugging tool |

**Actions:**
1. Mark deprecated tests with comments
2. Document which test to use for which purpose
3. Remove or archive deprecated tests after migration

### Solution 5: Implement Stubbed Tests

**Priority:** Implement the 5 supervisor resilience tests

**Status:** Implementation guide exists at `tests/integration/IMPLEMENTATION_GUIDE.md`

**Tests to implement:**
1. `test_supervisor_restarts_control_plane_worker()` - 1-2 hours
2. `test_supervisor_resyncs_rules_on_restart()` - 1-2 hours
3. `test_supervisor_applies_exponential_backoff()` - 2-3 hours
4. `test_supervisor_handles_multiple_failures()` - 1-2 hours
5. `test_supervisor_in_namespace()` - 2-3 hours

**Total effort:** ~10 hours

### Solution 6: Enforce Coverage Requirements

**Goal:** Achieve and maintain 90% line coverage

**Approach:**
1. Generate coverage report in CI: `just coverage`
2. Fail build if coverage drops below threshold
3. Require coverage for new code (diff-based coverage)

**Implementation:**
```bash
# Add to justfile
coverage-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo tarpaulin --out xml --output-dir target/tarpaulin --features integration_test
    COVERAGE=$(grep -oP 'line-rate="\K[0-9.]+' target/tarpaulin/cobertura.xml | head -1)
    COVERAGE_PCT=$(echo "$COVERAGE * 100" | bc)
    echo "Current coverage: ${COVERAGE_PCT}%"
    if (( $(echo "$COVERAGE_PCT < 90" | bc -l) )); then
        echo "❌ Coverage below 90% threshold"
        exit 1
    fi
    echo "✅ Coverage meets 90% threshold"

# Update check recipe
check: fmt clippy build test-all audit outdated coverage-check unsafe-check
    @echo "\n✅ All checks passed!"
```

---

## Roadmap

### Phase 1: Stabilize Existing Tests (Week 1)

**Goal:** Get all existing tests passing reliably

- [ ] Fix `test_data_plane_logging` flaky test (1 hour)
- [ ] Run all shell scripts manually, document status (2 hours)
- [ ] Fix any broken shell scripts (4 hours)
- [ ] Clean up stale shared memory in test setup (1 hour)
- [ ] Document which tests require root (1 hour)

**Deliverable:** All non-ignored tests passing

### Phase 2: Integrate Shell Tests (Week 1-2)

**Goal:** Automate shell test execution

- [ ] Create `tests/run_all_shell_tests.sh` wrapper (1 hour)
- [ ] Add `just test-shell` command (30 min)
- [ ] Add shell tests to CI pipeline (2 hours)
- [ ] Document how to run shell tests locally (1 hour)

**Deliverable:** Shell tests run automatically in CI

### Phase 3: Implement Resilience Tests (Week 2)

**Goal:** Implement the 5 stubbed supervisor resilience tests

- [ ] Implement `test_supervisor_restarts_control_plane_worker()` (2 hours)
- [ ] Implement `test_supervisor_resyncs_rules_on_restart()` (2 hours)
- [ ] Implement `test_supervisor_applies_exponential_backoff()` (3 hours)
- [ ] Implement `test_supervisor_handles_multiple_failures()` (2 hours)
- [ ] Implement `test_supervisor_in_namespace()` (3 hours)

**Deliverable:** All supervisor resilience tests passing

### Phase 4: Root-Required Test Integration (Week 3)

**Goal:** Run ignored tests in CI

**Option A: Docker-based (Recommended)**
- [ ] Create Dockerfile for test environment (2 hours)
- [ ] Add CI job to run tests in container (2 hours)
- [ ] Test locally with `docker run --privileged` (1 hour)

**Option B: Sudo-based**
- [ ] Add dedicated CI runner with sudo access (4 hours)
- [ ] Create `just test-ci-root` command (1 hour)
- [ ] Document security considerations (1 hour)

**Deliverable:** All 8 ignored integration tests running in CI

### Phase 5: Coverage Enforcement (Week 3-4)

**Goal:** Achieve 90% code coverage and enforce it

- [ ] Generate baseline coverage report (1 hour)
- [ ] Identify uncovered critical paths (2 hours)
- [ ] Write tests for uncovered data plane code (8 hours)
- [ ] Write tests for uncovered supervisor code (4 hours)
- [ ] Add coverage threshold check to CI (2 hours)
- [ ] Document coverage requirements in CONTRIBUTING.md (1 hour)

**Deliverable:** 90%+ coverage with CI enforcement

### Phase 6: Consolidation and Documentation (Week 4)

**Goal:** Clean up duplicate tests and document testing strategy

- [ ] Identify and remove/deprecate duplicate tests (3 hours)
- [ ] Update TESTING.md with current state (2 hours)
- [ ] Create developer testing guide (2 hours)
- [ ] Add test selection flowchart (1 hour)
- [ ] Archive obsolete test scripts (1 hour)

**Deliverable:** Clear, consolidated testing infrastructure

---

## Success Criteria

When complete, the testing infrastructure will have:

1. ✅ **All tests passing:** 0 broken tests, 0 flaky tests
2. ✅ **All tests automated:** Run via `just check` or `just test-root`
3. ✅ **90%+ code coverage:** Enforced in CI
4. ✅ **No ignored tests:** All tests either run or have clear documentation why not
5. ✅ **CI integration:** All tests run automatically on PR
6. ✅ **Fast feedback:** Unit tests complete in <30s
7. ✅ **Clear documentation:** Developer knows exactly which tests to run when
8. ✅ **No duplication:** Each test has a clear, unique purpose

---

## Appendix A: Test Execution Matrix

| Test Type | Command | Duration | Requires Root | Runs in CI | Status |
|-----------|---------|----------|---------------|------------|--------|
| Rust unit tests | `cargo test --lib` | ~15s | No | Yes | ✅ 106/107 passing |
| Rust integration (non-root) | `cargo test --test integration` | ~1s | No | Yes | ✅ 12/12 passing |
| Rust integration (root) | `cargo test --test integration -- --include-ignored` | ~30s | Yes | No | ⚠️ 8 ignored |
| Shell scripts (basic) | `./tests/data_plane_e2e.sh` | ~10s | Yes | No | ❓ Unknown |
| Shell scripts (scaling) | `./tests/scaling_test.sh` | ~30s | Yes | No | ❓ Unknown |
| Shell scripts (topologies) | `just test-topologies` | ~60s | Yes | No | ❓ Unknown |
| Coverage report | `just coverage` | ~60s | No | No | ⚠️ Not enforced |

## Appendix B: Code Coverage Estimates

**Current estimate based on test counts:**

| Module | Unit Tests | Integration Tests | Estimated Coverage |
|--------|------------|-------------------|-------------------|
| Logging | 46 | 2 | ~90% |
| Supervisor | 13 | 8 (ignored) | ~60% |
| Control Plane | 3 | 1 | ~70% |
| Data Plane | 12 | 8 (ignored) | ~40% ⚠️ |
| Buffer Pool | 6 | 0 | ~80% |
| Packet Parser | 6 | 0 | ~85% |

**Critical gaps:**
- Data plane ingress/egress processing
- Supervisor worker lifecycle management
- Error recovery and resilience paths
- Network interface monitoring

## Appendix C: References

- [`docs/reference/TESTING.md`](./TESTING.md) - Testing philosophy and strategy
- [`tests/integration/IMPLEMENTATION_GUIDE.md`](../../tests/integration/IMPLEMENTATION_GUIDE.md) - Guide for implementing resilience tests
- [`tests/TEST_STANDARDS.md`](../../tests/TEST_STANDARDS.md) - Standards for shell script tests
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) - Contribution guidelines including testing requirements
- [`justfile`](../../justfile) - Available test commands

---

**Last Updated:** 2025-01-14
**Next Review:** After Phase 1 completion
