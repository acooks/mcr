# Test Coverage Improvement Plan

## Current Status

Based on comprehensive analysis (see `/tmp/test_coverage_analysis.md`), the MCR codebase has:

- **106 unit tests** across various modules
- **6 integration test modules** (with some deferred/removed)
- **10+ E2E bash scripts** for performance and integration testing

### Critical Gaps Identified

1. **Supervisor Module**: ~0 unit tests despite 1,540 LoC (CRITICAL risk)
2. **Multi-worker scenarios**: Largely untested (HIGH risk)
3. **Error paths**: Minimal coverage of failure scenarios (MEDIUM risk)
4. **Concurrency**: Limited testing of race conditions (MEDIUM risk)

## Pragmatic Improvement Strategy

### Immediate Actions (This Week)

**Goal**: Establish baseline and add highest-impact tests

1. **Establish Coverage Baseline**
   ```bash
   cargo tarpaulin --out Html --output-dir coverage
   ```
   - Document current line/branch coverage percentages
   - Identify specific uncovered critical paths
   - Commit baseline report to git

2. **Add 3-5 Critical Supervisor Tests**

   Start with these high-impact tests in `src/supervisor.rs`:

   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[tokio::test]
       async fn test_worker_restart_on_failure() {
           // Test that failed workers are automatically restarted
       }

       #[tokio::test]
       async fn test_control_plane_initialization() {
           // Test CP worker spawns and registers correctly
       }

       #[tokio::test]
       async fn test_data_plane_worker_spawn() {
           // Test DP worker creation with correct fanout settings
       }
   }
   ```

3. **Document Current State**
   - Mark this plan as "STARTED"
   - Note baseline coverage percentage
   - Track which tests are added

### Medium-Term Actions (This Month)

**Goal**: Cover critical multi-worker scenarios and improve infrastructure

4. **Add Multi-Worker Integration Test**

   Create `tests/integration/multi_worker_basic.rs`:
   ```rust
   // Test: 1 CP + 2 DP workers processing rules simultaneously
   // Validates: fanout group IDs, concurrent rule processing, no packet duplication
   ```

5. **Convert One E2E Script to Rust Benchmark**

   Pick the simplest bash script (e.g., `baseline_50k.sh`) and rewrite as:
   - `benches/baseline_throughput.rs` using criterion
   - Benefits: Type safety, easier debugging, performance regression detection

6. **Set Up Coverage Tracking**
   - Add `just coverage` command to run tarpaulin
   - Optional: Add coverage badge to README
   - Document coverage improvement over time

### Long-Term Strategy (Next Quarter)

**Goal**: Incremental, sustainable improvement without heroic effort

7. **Incremental Improvement**
   - Target: +5% coverage per month (realistic, achievable)
   - Focus: One module at a time (supervisor → network_monitor → rule_dispatch)
   - Approach: Add 2-3 tests per week

8. **Make Testing Easier**
   - Create test helper utilities:
     ```rust
     // tests/helpers/mod.rs
     fn create_test_supervisor() -> WorkerManager { ... }
     fn mock_unix_stream_pair() -> (UnixStream, UnixStream) { ... }
     fn create_test_namespace() -> Result<TestNetNs> { ... }
     ```
   - Document testing patterns in `docs/testing/patterns.md`

9. **Protect Critical Paths**
   - Require tests for:
     - New worker types
     - Changes to supervisor lifecycle
     - IPC protocol modifications
   - Add test requirements to PR template

## What NOT to Do

❌ **Don't attempt 100% coverage** - Diminishing returns, unsustainable
❌ **Don't rewrite all bash tests** - They work, provide value as-is
❌ **Don't block development** - Tests should enable, not prevent, progress
❌ **Don't test every error path** - Focus on realistic failure scenarios
❌ **Don't make perfect the enemy of good** - Ship incremental improvements

## Start With Just ONE Thing

Pick exactly one of these to start TODAY:

### Option A: See the Numbers (15 minutes)
```bash
cargo tarpaulin --out Html --output-dir coverage
firefox coverage/index.html  # or your browser
```
This shows actual coverage percentages and uncovered lines.

### Option B: Highest Impact Test (30 minutes)
Add `test_worker_restart_on_failure()` to `src/supervisor.rs`. This one test covers the most critical supervisor functionality.

### Option C: Document Only (5 minutes)
Just run tarpaulin and document the baseline coverage percentage in this file. No code changes needed.

## Success Metrics

- **Week 1**: Baseline established, 3+ supervisor tests added
- **Month 1**: Multi-worker test passing, coverage tracking in CI
- **Quarter 1**: +15% total coverage, testing patterns documented
- **Ongoing**: New features include tests, coverage trend positive

## Notes

- This is a **living document** - update as priorities change
- Coverage is a **means**, not an **end** - focus on valuable tests
- Progress over perfection - celebrate small wins
- If stuck, start smaller - even one test is progress

---

**Status**: IN PROGRESS (Baseline established 2025-11-16)
**Baseline Coverage**: **34.03%** (803/2360 lines covered)
**Last Updated**: 2025-11-16
**Next Review**: 2025-11-23

## Baseline Coverage Breakdown (2025-11-16)

Key findings from cargo tarpaulin:

### Well-Covered Modules (>50% coverage)
- `logging/macros.rs`: 100% (10/10 lines)
- `worker/stats.rs`: 100% (18/18 lines)
- `worker/packet_parser.rs`: 94% (99/105 lines) ✓
- `worker/data_plane.rs`: 95% (40/42 lines) ✓
- `logging/entry.rs`: 88% (72/82 lines)
- `logging/consumer.rs`: 82% (73/89 lines)
- `logging/ringbuffer.rs`: 78% (179/229 lines)
- `logging/logger.rs`: 77% (96/124 lines)
- `control_client.rs`: 81% (59/73 lines)
- `command_reader.rs`: 77% (20/26 lines)

### Critically Under-Covered Modules (<10% coverage)
- **`supervisor.rs`: 9.5% (37/390 lines)** ⚠️ HIGHEST PRIORITY
- **`worker/ingress.rs`: 0% (0/366 lines)** ⚠️ CRITICAL
- **`worker/egress.rs`: 0% (0/230 lines)** ⚠️ CRITICAL
- **`worker/data_plane_integrated.rs`: 0% (0/79 lines)**
- **`worker/buffer_pool.rs`: 5% (3/57 lines)**
- **`worker/adaptive_wakeup.rs`: 3% (2/71 lines)**
- **`main.rs`: 0% (0/51 lines)**
- `worker/mod.rs`: 8% (10/133 lines)
- `worker/control_plane.rs`: 53% (36/68 lines) - Room for improvement
- `logging/mod.rs`: 0% (0/8 lines)

### Coverage Report
- HTML report available at: `coverage/tarpaulin-report.html`
- Command to regenerate: `cargo tarpaulin --out html --output-dir coverage`

### Next Steps
1. ✅ Baseline established (34.03%)
2. 🔄 Add 3-5 critical supervisor tests (targeting 20%+ supervisor coverage)
3. ⏳ Add ingress/egress worker tests
4. ⏳ Aim for 40% total coverage by end of week 1
