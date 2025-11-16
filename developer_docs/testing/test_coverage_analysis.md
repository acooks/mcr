# MCR Test Coverage & Testing Strategy Analysis

## Current Test Statistics (as of 2025-11-16)

### Unit Tests
- **Total unit tests**: 106 (all passing)
- **Test markers**: 112 `#[test]` functions
- **Test modules**: 23 `#[cfg(test)]` modules
- **Source LoC**: ~10,236 lines across core modules

### Integration Tests
- **Integration test files**: 6 active modules
- **Deferred tests**: 7 (supervisor resilience - needs API rewrite)
- **Removed**: 6 tests (redundant or broken)

### End-to-End & Performance Tests
- **Bash scripts**: 10+ test scripts
- **Performance tests**: Multi-stream scaling, compare with socat
- **Topology tests**: Chain (3-hop), tree fanout, baseline tests

---

## Test Coverage by Component

### ✅ **Well-Covered Components**

#### 1. Packet Parser (`src/worker/packet_parser.rs`)
- **768 LoC, ~20 unit tests**
- Coverage: Checksum validation, fragmentation, invalid packets, edge cases
- **Property tests**: `tests/proptests/packet_parser.rs`
- **Strength**: Excellent low-level coverage with proptest fuzzing

#### 2. Logging System (`src/logging/`)
- **~2,000 LoC, ~15 unit tests**
- Coverage: Ring buffer (SPSC/MPSC), log levels, async/blocking consumers
- **Strength**: Comprehensive concurrency testing

#### 3. Control Plane (`src/worker/control_plane.rs`)
- **428 LoC, ~14 unit tests**
- Coverage: All IPC commands (add/remove rules, get stats, log levels)
- **Strength**: Complete command handler coverage
- **Integration**: `tests/integration/rule_management.rs` tests E2E propagation

#### 4. Stats & Monitoring (`src/worker/stats.rs`)
- **144 LoC, 2 unit tests**
- Coverage: Stats aggregator, monitoring task
- **Strength**: Task coordination tested

---

### ⚠️ **Partially Covered Components**

#### 1. Supervisor (`src/supervisor.rs`)
- **1,540 LoC, ~0 active unit tests**
- **Critical Gap**: Worker management, health checks, rule dispatch
- **Why**: Tests were removed as "redundant" but integration tests don't fully replace them
- **Deferred**: 7 resilience tests need API rewrite

**Missing Coverage:**
- Worker restart logic (exponential backoff)
- Multi-worker scenarios
- Concurrent request handling
- Error recovery paths
- Log consumer task spawning

#### 2. Data Plane Worker (`src/worker/mod.rs`, `data_plane*.rs`)
- **~1,043 LoC, ~2 unit tests**
- **Critical Gap**: Actual packet processing loop
- Integration tests cover E2E but not internal state management

**Missing Coverage:**
- Buffer pool exhaustion handling
- Queue overflow scenarios
- Wakeup strategy transitions
- io_uring error handling
- Worker lifecycle edge cases

#### 3. Ingress/Egress (`src/worker/ingress.rs`, `egress.rs`)
- **1,393 LoC combined, ~2 unit tests**
- **Critical Gap**: Main packet processing paths

**Missing Coverage:**
- AF_PACKET socket error handling
- PACKET_FANOUT behavior
- Queue full scenarios
- Stats counter overflow
- Network interface failures

#### 4. Adaptive Wakeup (`src/worker/adaptive_wakeup.rs`)
- **293 LoC, 1 unit test** (just `test_spin_is_noop_signal`)
- **Critical Gap**: Hybrid strategy switching logic

**Missing Coverage:**
- Eventfd blocking/signaling
- Rate calculation and threshold crossing
- Strategy transition scenarios
- Concurrent signal() and wait() calls

---

### ❌ **Untested Components**

#### 1. Network Monitor (`src/supervisor/network_monitor.rs`)
- **452 LoC, 0 tests**
- Watches for interface state changes via netlink
- **Risk**: Silent failures in network monitoring

#### 2. Rule Dispatch (`src/supervisor/rule_dispatch.rs`)
- **389 LoC, 0 tests**
- Distributes rules to workers
- **Risk**: Incorrect rule routing

#### 3. Buffer Pool (`src/worker/buffer_pool.rs`)
- **147 LoC, 0 tests in main code**
- **Note**: Has experimental exhaustion test in PoC directory
- **Risk**: Memory leaks, allocation failures

#### 4. Command Reader (`src/worker/command_reader.rs`)
- **216 LoC, 3 tests**
- **Weakness**: Only tests partial frame handling, not full protocol

---

## Testing Strategy Weaknesses

### 1. **Integration Test Philosophy Issues**

**Problem**: Integration tests were intentionally kept minimal, moving logic to unit tests. But for supervisor, unit tests were then removed as "redundant", leaving gaps.

**From `tests/integration.rs` comments:**
```
// REMOVED: supervisor.rs - redundant with unit tests in src/supervisor.rs
// DEFERRED: supervisor_resilience.rs - needs complete rewrite for current supervisor API
```

**Result**: Supervisor has almost no test coverage despite being 1,540 LoC of critical process management code.

### 2. **Missing Coverage for Multi-Worker Scenarios**

**Issue**: Most tests use `--num-workers 1`. Multi-worker bugs (discovered in performance testing) are not caught by test suite.

**Example weaknesses:**
- Worker fanout group ID conflicts
- AF_PACKET PACKET_FANOUT_CPU behavior with >1 worker
- Concurrent rule updates across workers
- Worker restarts with inflight rules

### 3. **Error Path Coverage Gap**

**Unit tests heavily favor happy path:**
- Packet parser: Great error coverage
- Everything else: Minimal error injection

**Missing:**
- Syscall failures (socket(), bind(), io_uring_setup())
- Memory allocation failures
- IPC channel failures
- Network interface disappearing mid-operation

### 4. **Concurrency Testing Weakness**

**Only 2 concurrency tests:**
1. `logging::ringbuffer::tests::test_mpsc_concurrent`
2. `logging::logger::tests::test_log_registry_mpsc`

**Missing concurrency testing:**
- Supervisor handling simultaneous worker failures
- Multiple control clients issuing concurrent commands
- Data plane workers processing overlapping rules
- Stats collection during rule changes

### 5. **Performance Regression Detection**

**Current approach**: Manual bash scripts for performance testing
- Not integrated with CI/CD
- No automated regression detection
- Results not tracked over time

**Bash scripts exist but aren't programmatic:**
- `tests/performance/compare_socat_chain.sh`
- `tests/performance/multi_stream_scaling.sh`

### 6. **Property-Based Testing Underutilized**

**Only 1 proptest module:** `tests/proptests/packet_parser.rs`

**Could benefit from proptests:**
- Rule matching logic (random IPs/ports)
- Stats aggregation (random packet counts)
- Buffer pool allocation patterns
- Log level combinations

---

## Test Infrastructure Weaknesses

### 1. **Coverage Tooling**
- **Just fixed**: Type mismatches preventing `cargo tarpaulin`
- **Unknown**: Actual line/branch coverage percentages
- **No CI integration** for coverage tracking

### 2. **Test Isolation**
- Some bash scripts don't clean up on failure
- Hardcoded paths like `/tmp/mcr_test.sock` can conflict
- Network namespaces sometimes leak

### 3. **Test Documentation**
- Many bash scripts lack header comments
- Integration test organization improved recently but still evolving
- No test plan document

### 4. **Flakiness**
- Network tests require root (expected)
- Timing-dependent tests use hardcoded sleeps
- Some tests assume interface availability (lo, veth)

---

## Recommendations (Prioritized)

### High Priority

1. **Restore Supervisor Unit Tests**
   - At minimum: Worker restart, health check, rule dispatch
   - Don't rely solely on deferred integration tests

2. **Add Multi-Worker Integration Tests**
   - 2 workers, concurrent traffic
   - Worker failure during traffic
   - Rule updates with >1 worker

3. **Error Injection Testing**
   - Mock syscalls for error paths
   - Simulate resource exhaustion
   - Network interface failures

4. **Enable Coverage Reporting**
   - Run `cargo tarpaulin` in CI
   - Set coverage thresholds (start at current %, improve over time)
   - Track coverage trends

### Medium Priority

5. **Expand Property Tests**
   - Rule matching with random inputs
   - Stats aggregation fuzzing
   - Buffer pool stress testing

6. **Concurrency Testing**
   - Use `loom` for data structure testing
   - Stress test supervisor with concurrent commands
   - Multi-threaded stats collection

7. **Performance Regression Suite**
   - Convert bash scripts to benchmarks
   - Use `criterion` for microbenchmarks
   - Automated threshold checking

### Low Priority

8. **Test Infrastructure**
   - Generate unique socket paths (UUID-based)
   - Improve cleanup on test failures
   - Document test requirements

9. **Chaos Testing**
   - Randomly kill workers during operation
   - Inject random delays
   - Corrupt IPC messages

---

## Specific Gaps to Address

| Component | Current | Needed | Risk |
|-----------|---------|--------|------|
| Supervisor | 0 tests | 10-15 tests | **CRITICAL** |
| Data Plane Loop | 2 tests | 8-10 tests | **HIGH** |
| Network Monitor | 0 tests | 5 tests | MEDIUM |
| Rule Dispatch | 0 tests | 5 tests | MEDIUM |
| Adaptive Wakeup | 1 test | 6 tests | MEDIUM |
| Buffer Pool | 0 tests | 4 tests | MEDIUM |
| Ingress/Egress | 2 tests | 10 tests | HIGH |

---

## Conclusion

**Strengths:**
- Excellent packet parser coverage with property testing
- Good logging system testing
- Comprehensive control plane command coverage
- Integration tests verify key E2E flows

**Critical Weaknesses:**
- Supervisor has almost zero test coverage (1,540 LoC)
- Multi-worker scenarios largely untested
- Error paths and edge cases undertested
- No automated performance regression detection
- Concurrency testing minimal

**Immediate Actions:**
1. Add supervisor unit tests (worker management critical path)
2. Create multi-worker integration test
3. Enable coverage reporting with `cargo tarpaulin`
4. Document coverage gaps and track improvement
