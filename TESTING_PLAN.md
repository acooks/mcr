# Testing Implementation Plan

This document provides the concrete implementation plan for the testing philosophy outlined in `TESTING.md`. It defines the test suite's structure, the tools we will use, and a phased approach to restructuring existing tests and expanding coverage.

**Last Updated**: 2025-11-08
**Current Overall Progress**: 52% Complete

## Current Status

| Phase | Status | Progress | Blockers |
|-------|--------|----------|----------|
| Phase 1: Foundational Tooling | ✅ Complete | 100% | None |
| Phase 2: Restructure & Document | 🟡 In Progress | 70% | Missing tests/lib.rs, incomplete documentation |
| Phase 3: Expand Test Coverage | 🟡 In Progress | 50% | Namespace-based tests not started |
| Phase 4: E2E & Performance | ❌ Not Started | 0% | Empty benchmarks/forwarding_rate.rs |
| Phase 5: CI Integration | 🟡 In Progress | 60% | No coverage enforcement, missing --test-threads=1 |

**Test Count**: 46 tests passing (sequential execution required)
**Coverage**: Not yet measured (baseline needed)

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

### Issue 1: Hardcoded Socket Paths (High Priority)

**Problem**: Tests use hardcoded socket path `/tmp/multicast_relay_control.sock`, causing:
- Test failures when run in parallel
- Requirement for `--test-threads=1` workaround (documented in `src/supervisor.rs:305-318`)
- Flaky tests under load

**Impact**: Cannot run tests in parallel, slower CI/CD pipeline

**Solution**:
1. Refactor `run_generic()` in supervisor to accept `socket_path` as a parameter
2. Use UUID-based paths in tests: `/tmp/test_supervisor_{uuid}.sock`
3. Update `tests/lib.rs` with a `unique_socket_path()` helper function

**Tracked in**: src/supervisor.rs:305-318 comments

### Issue 2: Missing tests/lib.rs (High Priority)

**Problem**: No shared test utilities despite the directory structure proposing it.

**Impact**: Code duplication, harder to maintain consistent test patterns

**Solution**: Create `tests/lib.rs` with:
- Socket path generation utilities
- Common setup/teardown helpers
- Shared test fixtures and constants
- Test documentation template helpers

### Issue 3: Empty Benchmark File (Critical)

**Problem**: `tests/benchmarks/forwarding_rate.rs` exists but is empty.

**Impact**: No performance regression detection, Tier 3 testing incomplete

**Solution**: Implement criterion benchmarks for:
- Packet forwarding throughput
- Control plane command latency
- Buffer pool operations

### Issue 4: Incomplete Test Documentation (Medium Priority)

**Problem**: Integration tests lack the Purpose/Method/Tier documentation pattern.

**Example Good Documentation**: `src/worker/mod.rs:169-178`
**Needs Documentation**: Most files in `tests/integration/`

**Solution**: Add standardized doc comments to all test functions

### Issue 5: CI Missing Sequential Test Flag (Medium Priority)

**Problem**: `.github/workflows/rust.yml` doesn't use `--test-threads=1` flag.

**Impact**: CI may have intermittent failures due to socket contention

**Solution**: Update CI test command to match justfile pattern

## 3. Phased Implementation Plan

### Phase 1: Foundational Tooling ✅ COMPLETE

**Completion Criteria:**
- ✅ `cargo-tarpaulin` added and `just coverage` command works
- ✅ `proptest` and `proptest-derive` added to dev-dependencies
- ✅ `build.rs` created to handle tarpaulin cfg warnings

**Status**: Both deliverables complete. Coverage infrastructure ready but not enforced in CI.

### Phase 2: Restructure & Document Existing Tests 🟡 IN PROGRESS (70%)

**Completion Criteria:**
- ✅ Directory structure created (`tests/integration/`, `tests/proptests/`, `tests/benchmarks/`)
- ✅ Unit tests moved to `#[cfg(test)]` modules in source files
- ✅ Some tests have Purpose/Method/Tier documentation (see `src/worker/mod.rs`)
- ❌ **MISSING**: `tests/lib.rs` for shared utilities
- 🟡 **PARTIAL**: Integration test documentation incomplete

**Remaining Work:**
1. Create `tests/lib.rs` with common test helpers
2. Add Purpose/Method/Tier comments to all integration tests
3. Document test fixtures and shared constants

### Phase 3: Expand Test Coverage 🟡 IN PROGRESS (50%)

**Completion Criteria:**
- ✅ IPC integration test created (tests/integration/ipc.rs)
- ✅ Property-based test for packet_parser (tests/proptests/packet_parser.rs)
- ❌ **MISSING**: Namespace-based supervisor restart tests
- ❌ **MISSING**: Additional integration test coverage

**Remaining Work:**
1. Build namespace-based test for supervisor worker restart verification
2. Add integration tests for:
   - Configuration changes during runtime
   - Error handling and recovery scenarios
   - Metrics collection and reporting
3. Expand property-based test coverage to other parsers/validators

### Phase 4: Formalize E2E & Performance Testing ❌ NOT STARTED (0%)

**Completion Criteria:**
- ❌ E2E scripts have comprehensive comments
- ❌ **CRITICAL**: Benchmark suite implemented in tests/benchmarks/forwarding_rate.rs
- ❌ Performance baselines documented

**Blocking Issues:**
- tests/benchmarks/forwarding_rate.rs is currently empty (see Known Issues #3)

**Remaining Work:**
1. Implement criterion benchmarks for:
   - Packet forwarding throughput (packets/sec)
   - End-to-end latency (microseconds)
   - Control plane command latency
   - Buffer pool allocation/deallocation performance
2. Document performance baselines and regression thresholds
3. Add inline comments to E2E shell scripts

### Phase 5: CI Integration 🟡 IN PROGRESS (60%)

**Completion Criteria:**
- ✅ CI workflow runs fmt, clippy, build, test, audit, outdated
- ✅ Tests run with `integration_test` feature flag
- ❌ **MISSING**: Tests don't use `--test-threads=1` flag (may cause flakes)
- ❌ **MISSING**: Coverage enforcement not in CI
- ❌ **MISSING**: Benchmark regression detection

**Remaining Work:**
1. Update `.github/workflows/rust.yml`:
   - Add `--test-threads=1` to test command
   - Add coverage step with failure threshold
   - Add benchmark comparison step
2. Document baseline coverage percentage
3. Set up GitHub Actions artifacts for coverage reports

## 4. Immediate Next Actions (Priority Order)

### Priority 1: Critical Gaps (Must Fix Now)

1. **Create tests/lib.rs** [30 minutes]
   - Socket path helper: `unique_socket_path()` using UUID
   - Test cleanup helper: `cleanup_socket(path)`
   - Common constants and fixtures
   - Documentation template examples

2. **Implement Benchmark Suite** [2-3 hours]
   - Populate tests/benchmarks/forwarding_rate.rs
   - Add basic throughput benchmark
   - Add latency benchmark
   - Document baselines

3. **Fix CI Test Command** [5 minutes]
   - Add `--test-threads=1` to `.github/workflows/rust.yml`
   - Prevents intermittent failures from socket contention

### Priority 2: Foundation Work (This Week)

4. **Measure and Document Coverage Baseline** [30 minutes]
   - Run `just coverage`
   - Document current percentage in TESTING_PLAN.md
   - Set realistic target (current + 5-10%)

5. **Add Test Documentation** [2 hours]
   - Document all integration tests with Purpose/Method/Tier
   - Follow pattern from src/worker/mod.rs:169-178
   - Focus on tests/integration/* files

6. **Fix Socket Path Issue** [3-4 hours]
   - Refactor supervisor's `run_generic()` to accept socket_path parameter
   - Update all test call sites to use `unique_socket_path()`
   - Remove `--test-threads=1` requirement
   - Update documentation
