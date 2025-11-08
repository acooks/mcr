# Testing Implementation Plan

This document provides the concrete implementation plan for the testing philosophy outlined in `TESTING.md`. It defines the test suite's structure, the tools we will use, and a phased approach to restructuring existing tests and expanding coverage.

**Last Updated**: 2025-11-08
**Current Overall Progress**: 65% Complete

## Current Status

| Phase | Status | Progress | Blockers |
|-------|--------|----------|----------|
| Phase 1: Foundational Tooling | ✅ Complete | 100% | None |
| Phase 2: Restructure & Document | 🟢 Nearly Complete | 85% | Test documentation incomplete (~40% of tests) |
| Phase 3: Expand Test Coverage | 🟡 In Progress | 60% | Supervisor resilience tests stubbed, network monitor not started |
| Phase 4: E2E & Performance | 🟡 Started | 20% | Benchmarks templated but not implemented |
| Phase 5: CI Integration | 🟢 Nearly Complete | 75% | Coverage enforcement needed |

**Test Count**: 53 passing + 2 ignored (55 total)
**Coverage**: Not yet measured (baseline needed)
**Recent Progress**: Rule dispatcher fully implemented with 4 tests ✅

## 1. Proposed Test Directory Structure

To bring clarity and align with Rust best practices, the `tests/` directory will be restructured as follows. Unit tests (Tier 1) will continue to reside within their respective modules in `src/` under a `#[cfg(test)]` block.

```
mcr/
├── src/
│   └── supervisor.rs
│       └── #[cfg(test)] mod tests { /* Unit tests here */ }
├── tests/
│   ├── lib.rs                  # Common test helpers and utilities
│   ├── benchmarks/             # Tier 3: Performance benchmarks (Criterion.rs)
│   │   └── forwarding_rate.rs
│   ├── e2e/                    # Tier 3: End-to-end shell script tests (Existing)
│   │   ├── 01_happy_path.t
│   │   └── ...
│   ├── integration/            # Tier 2: Rust-based integration tests
│   │   ├── cli.rs              # Tests for the main binary's CLI parsing and execution
│   │   ├── ipc.rs              # Tests for Supervisor <-> Worker communication
│   │   └── supervisor.rs       # Tests for supervisor lifecycle, resilience, etc.
│   └── proptests/              # Tier 1: Property-based tests
│       └── packet_parser.rs
└── Cargo.toml
```

### Why this structure?

-   **`tests/lib.rs`**: A standard Rust pattern for sharing code between different integration test files.
-   **`tests/integration/`**: Houses all Tier 2 tests, which verify the interaction between different parts of the application. Sub-modules provide clear organization.
-   **`tests/e2e/`**: Unchanged. Continues to house the Tier 3 shell-based tests that run the final binaries.
-   **`tests/benchmarks/`**: Formalizes performance testing as a first-class citizen.
-   **`tests/proptests/`**: Creates a dedicated space for property-based tests, which are fundamentally different from example-based integration tests.

## 2. Known Issues and Technical Debt

### Issue 1: Hardcoded Socket Paths - ✅ RESOLVED

**Resolution**:
- ✅ Created `tests/lib.rs` with UUID-based socket path helpers (commit 918b90f)
- ✅ Tests now use `unique_socket_path()` and `unique_socket_path_with_prefix()`
- ✅ Parallel execution infrastructure hardened

**Remaining Work**:
- Some older tests may still need migration to UUID-based paths
- Consider refactoring supervisor's `run_generic()` to accept socket_path parameter

### Issue 2: Missing tests/lib.rs - ✅ RESOLVED

**Resolution**:
- ✅ Created in commit 918b90f with 135 lines
- ✅ Provides socket path helpers, cleanup utilities, and test constants
- ✅ Has 3 passing unit tests validating the helpers

### Issue 3: Benchmark File Empty - 🟡 PARTIALLY RESOLVED

**Status**: Professional template created (commit 2e25f6f) with 3 benchmark stubs

**Impact**: Templates ready but no actual performance measurements yet

**Remaining Work**: Implement the 3 benchmark functions:
- `benchmark_forwarding_throughput()` - TARGET: >100k packets/sec
- `benchmark_forwarding_latency()` - TARGET: <100μs p99
- `benchmark_control_plane_latency()` - TARGET: <1ms

### Issue 4: Incomplete Test Documentation - 🟡 ONGOING

**Problem**: ~40% of tests lack Purpose/Method/Tier documentation pattern

**Example Good Documentation**: `src/worker/mod.rs:169-178`
**Needs Documentation**: ~20 tests across `tests/integration/`, `src/supervisor.rs`, etc.

**Solution**: Add standardized doc comments following the established pattern

### Issue 5: CI Missing Sequential Test Flag - ✅ RESOLVED

**Resolution**:
- ✅ Updated `.github/workflows/rust.yml` with `--test-threads=1` (commit 2e25f6f)
- ✅ CI now matches local test execution pattern

### Issue 6: No Coverage Measurement - ❌ NEW BLOCKER

**Problem**: Coverage baseline never measured, preventing enforcement

**Impact**: Cannot set CI thresholds, no regression detection

**Solution**:
1. Run `just coverage` to measure baseline
2. Document percentage in TESTING_PLAN.md
3. Add to CI with threshold (baseline - 5%)

**Priority**: HIGH - blocking Phase 5 completion

## 3. Phased Implementation Plan

### Phase 1: Foundational Tooling ✅ COMPLETE

**Completion Criteria:**
- ✅ `cargo-tarpaulin` added and `just coverage` command works
- ✅ `proptest` and `proptest-derive` added to dev-dependencies
- ✅ `build.rs` created to handle tarpaulin cfg warnings

**Status**: Both deliverables complete. Coverage infrastructure ready but not enforced in CI.

### Phase 2: Restructure & Document Existing Tests 🟢 NEARLY COMPLETE (85%)

**Completion Criteria:**
- ✅ Directory structure created (`tests/integration/`, `tests/proptests/`, `tests/benchmarks/`)
- ✅ Unit tests moved to `#[cfg(test)]` modules in source files
- ✅ Some tests have Purpose/Method/Tier documentation (see `src/worker/mod.rs`)
- ✅ `tests/lib.rs` created with UUID-based socket helpers (commit 918b90f)
- ✅ Parallel execution infrastructure hardened
- 🟡 **PARTIAL**: ~40% of tests still lack documentation

**Remaining Work:**
1. ✅ ~~Create `tests/lib.rs` with common test helpers~~ DONE
2. Add Purpose/Method/Tier comments to ~20 undocumented tests
3. Document test fixtures and shared constants

### Phase 3: Expand Test Coverage 🟡 IN PROGRESS (60%)

**Completion Criteria:**
- ✅ IPC integration test created (tests/integration/ipc.rs)
- ✅ Property-based test for packet_parser (tests/proptests/packet_parser.rs)
- ✅ Rule dispatcher fully implemented with 4 tests (commit f34b64d)
- ✅ Supervisor resilience tests stubbed (tests/integration/supervisor_resilience.rs)
- 🟡 **STUBBED**: 5 integration tests for supervisor resilience (need implementation)
- ❌ **NOT STARTED**: Network monitor module

**Remaining Work:**
1. **CRITICAL**: Implement 5 supervisor resilience integration tests (stubbed)
2. **HIGH**: Implement network monitor module (src/supervisor/network_monitor.rs)
3. Add integration tests for:
   - Configuration changes during runtime
   - Error handling and recovery scenarios
   - Metrics collection and reporting
4. Expand property-based test coverage to other parsers/validators

### Phase 4: Formalize E2E & Performance Testing 🟡 STARTED (20%)

**Completion Criteria:**
- ❌ E2E scripts have comprehensive comments
- 🟡 **TEMPLATED**: Benchmark suite has professional templates (commit 2e25f6f)
- ❌ Performance baselines not yet measured

**Recent Progress:**
- ✅ Created benchmark template with 3 stubs (forwarding_rate.rs)
- ✅ E2E test structure in place (tests/e2e/)

**Remaining Work:**
1. **HIGH**: Implement criterion benchmarks for:
   - Packet forwarding throughput (TARGET: >100k packets/sec)
   - End-to-end latency (TARGET: <100μs p99)
   - Control plane command latency (TARGET: <1ms)
   - Buffer pool allocation/deallocation performance
2. Run benchmarks and document performance baselines
3. Set up regression detection thresholds
4. Add inline comments to E2E shell scripts

### Phase 5: CI Integration 🟢 NEARLY COMPLETE (75%)

**Completion Criteria:**
- ✅ CI workflow runs fmt, clippy, build, test, audit, outdated
- ✅ Tests run with `integration_test` feature flag
- ✅ Tests use `--test-threads=1` flag (commit 2e25f6f)
- ❌ **MISSING**: Coverage enforcement not in CI
- ❌ **MISSING**: Benchmark regression detection

**Recent Progress:**
- ✅ Fixed `.github/workflows/rust.yml` to use `--test-threads=1`
- ✅ All blocking CI issues resolved

**Remaining Work:**
1. **MEDIUM**: Add coverage step to CI:
   - Run `cargo tarpaulin` in CI
   - Set failure threshold (baseline - 5%)
   - Generate coverage report artifact
2. **MEDIUM**: Document baseline coverage percentage
3. **LOW**: Add benchmark comparison step (after benchmarks implemented)
4. Set up GitHub Actions artifacts for coverage reports

## 4. Immediate Next Actions (Priority Order)

### Priority 1: Critical Gaps (Must Fix This Sprint)

1. **✅ DONE: Create tests/lib.rs** ~~[30 minutes]~~
   - ✅ Socket path helper: `unique_socket_path()` using UUID
   - ✅ Test cleanup helper: `cleanup_socket(path)`
   - ✅ Common constants and fixtures

2. **Implement Supervisor Resilience Tests** [2-3 days] **← HIGHEST PRIORITY**
   - See detailed implementation guide in tests/integration/supervisor_resilience.rs
   - Remove `#[ignore]` from 5 test stubs
   - Implement helper functions (start_supervisor, kill_worker, is_process_running)
   - Validates core resilience promise (D18, D23)
   - **Dependencies**: Requires `list-workers` command (✅ DONE in commit b12611d)

3. **Measure and Document Coverage Baseline** [30 minutes] **← BLOCKING PHASE 5**
   - Run `just coverage`
   - Document current percentage in TESTING_PLAN.md
   - Add coverage step to CI with threshold
   - Set realistic improvement target (current + 10%)

4. **✅ DONE: Fix CI Test Command** ~~[5 minutes]~~
   - ✅ Added `--test-threads=1` to `.github/workflows/rust.yml`

### Priority 2: Foundation Work (This Month)

5. **Implement Network Monitor Module** [2-3 days]
   - Complete `start_monitoring()` with Netlink socket setup
   - Complete `handle_interface_event()` decision logic
   - Add integration test with real Netlink (feature-gated)
   - Design references: D19-D21

6. **Implement Benchmark Suite** [2-3 days]
   - Populate 3 benchmark stubs in tests/benchmarks/forwarding_rate.rs
   - Run and document performance baselines
   - Add regression detection to CI

7. **Add Test Documentation** [3-4 hours]
   - Document ~20 undocumented tests with Purpose/Method/Tier
   - Follow pattern from src/worker/mod.rs:169-178
   - Focus on tests/integration/* and src/supervisor.rs tests
