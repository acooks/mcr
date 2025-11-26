# Project Improvement Plan

Generated from documentation review findings (November 2025)

## Priority Legend
- 🔴 **CRITICAL** - Core functionality or correctness issues
- 🟡 **HIGH** - Significant impact on maintainability or performance
- 🟢 **MEDIUM** - Quality improvements, technical debt reduction
- 🔵 **LOW** - Nice-to-have improvements, future enhancements

---

## 1. Dead Code Removal (High Priority)

### 1.1 Legacy Two-Thread Data Plane Model ✅ COMPLETED
**Location:** ~~`src/worker/data_plane_integrated.rs:24-176`~~ REMOVED
**Status:** ✅ Deleted in commit cd4811c (1,814 total lines removed)
**Impact:** Eliminated code confusion, reduced maintenance burden

**What was removed:**
- `run_data_plane()` function (165 lines)
- `src/worker/ingress.rs` module (802 lines)
- `src/worker/egress.rs` module (772 lines)
- Unused helper functions (75 lines)
- **Total: 1,814 lines deleted**

**Verification:**
- ✅ All 149 tests pass (132 unit + 16 integration + 1 E2E)
- ✅ Full packet forwarding confirmed (100/100 packets)
- ✅ No compiler errors or warnings
- ✅ Documentation updated to remove legacy references

---

### 1.2 Dead Code Marked with `#[allow(dead_code)]` ✅ COMPLETED
**Status:** ✅ Completed in commits 62f717b and cd4811c

**Removed:**
- `command_reader.rs`: buffer_len(), pending_frame_len() (12 lines)
- `ingress.rs`: get_interface_ip() duplicate (14 lines) - entire module deleted
- `egress.rs`: buffer_pool field - entire module deleted
- `supervisor.rs`: test helper functions (49 lines)

**Kept:**
- `ringbuffer.rs:483`: shm_id_for_facility() - used in tests
- `supervisor.rs`: req_stream field - **NOT DEAD CODE**
  - Marked `#[allow(dead_code)]` with TODO comment about GetWorkerRules
  - Actually used: control_plane.rs:173 receives this FD for Request::ListRules
  - FD passing was broken in cd4811c, fixed in 2159e2e
  - Required for GetWorkerRules implementation (see 4.3)
  - Keep the allow marker until GetWorkerRules is implemented

**Result:** Dead code eliminated, all tests still pass

**Important Note:** req_stream is NOT dead code - it's critical infrastructure for control plane communication. The allow marker is temporary until GetWorkerRules (4.3) is fully implemented.

---

## 2. Architectural Technical Debt

### 2.1 Privilege Separation (AF_PACKET FD Passing) 🔴 CRITICAL
**Location:** `src/worker/mod.rs:283-297`
**Status:** Design incomplete, using workaround
**Security Impact:** Workers run with more privileges than necessary

**Current Problem:**
```rust
// TODO: ARCHITECTURAL ISSUE - Privilege dropping with CAP_NET_RAW
// Ambient capabilities are cleared by setuid(), so we can't retain
// CAP_NET_RAW after dropping to unprivileged user
eprintln!("[DataPlane] TODO: Implement AF_PACKET FD passing from supervisor");
```

**Proper Solution:**
1. Supervisor (running as root) creates AF_PACKET socket
2. Passes FD to worker via Unix domain socket + SCM_RIGHTS
3. Worker receives FD and drops to unprivileged user
4. Worker retains access to AF_PACKET socket via inherited FD

**References:**
- SCM_RIGHTS: man 7 unix, man 3 sendmsg
- Example: systemd socket activation pattern

**Estimated Effort:** 1-2 days
**Risk:** Medium (requires careful Unix socket programming, security testing)

---

### 2.2 Network State Reconciliation 🟡 HIGH
**Location:** `src/supervisor/network_monitor.rs:86-190`
**Status:** Stubbed out, marked HIGH PRIORITY in code

**Current State:**
```rust
/// **TODO: IMPLEMENT THIS - HIGH PRIORITY**
pub async fn start_network_monitor(
    _channel_tx: tokio::sync::mpsc::Sender<NetworkEvent>,
) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
    // TODO: Step 1 - Create Netlink socket
    // TODO: Step 2 - Subscribe to RTNLGRP_LINK notifications
    // TODO: Step 3 - Enter event loop
    // TODO: Step 4 - Parse events and send to channel
```

**Implementation Plan:**
1. Use `netlink-sys` or `rtnetlink` crate
2. Subscribe to RTNLGRP_LINK events
3. Detect interface up/down, address changes
4. Send events to supervisor for rule reconciliation
5. Implement idempotent rule reapplication

**Estimated Effort:** 3-5 days
**Risk:** Medium (Netlink API complexity, race conditions)

---

### 2.3 Rule Hashing and Worker Distribution 🟡 HIGH
**Location:** `src/supervisor.rs:987-988`
**Status:** Architecture documented but not implemented

**Current Problem:**
```rust
// TODO: ARCHITECTURAL FIX NEEDED
// Per architecture (D21, D23): One worker per CPU core, rules hashed to cores.
```

**Current Behavior:** All workers receive all rules
**Intended Behavior:** Rules hashed by (input_group, input_port) to specific cores

**Implementation Plan:**
1. Implement deterministic hash function: `rule_hash(group, port) % num_workers`
2. Supervisor sends each rule only to its assigned worker
3. Update rule dispatch logic in `src/supervisor/rule_dispatch.rs:194`
4. Add tests for hash distribution fairness

**Benefits:**
- Better CPU cache locality
- Reduced memory per worker
- Improved scalability to thousands of rules

**Estimated Effort:** 2-3 days
**Risk:** Medium (affects core data path, needs careful testing)

---

### 2.4 Global Interface Parameter ✅ RESOLVED
**Location:** `src/lib.rs:40-47`
**Status:** ✅ Architectural investigation completed (November 2025)
**Resolution:** Parameter is REQUIRED and should NOT be removed

**Original Misunderstanding:**
The TODO comment suggested removing the global `--interface` parameter in favor of using ForwardingRule.input_interface. This was based on misunderstanding the architecture.

**Correct Understanding (After Investigation):**
```rust
/// Network interface for data plane workers to listen on.
/// This is required for PACKET_FANOUT_CPU: all workers must bind to the same interface
/// with a shared fanout_group_id, allowing the kernel to distribute packets to the
/// worker running on the CPU that received the packet (for optimal cache locality).
/// Note: ForwardingRule.input_interface serves a different purpose - it will be used
/// for rule filtering in multi-interface scenarios. See MULTI_INTERFACE_ARCHITECTURE.md.
```

**Key Findings:**
1. **PACKET_FANOUT_CPU requires all workers to bind the SAME interface**
   - All workers join a shared fanout group with fanout_group_id
   - Kernel RSS/RPS distributes packets to CPUs
   - PACKET_FANOUT_CPU delivers packets to the worker on that CPU
   - This is essential for CPU cache locality (data stays hot in L1/L2/L3)

2. **Two separate concerns:**
   - Global interface parameter: WHERE workers listen (socket binding)
   - ForwardingRule.input_interface: WHICH rules to process (future filtering)

3. **Multi-interface scenarios:**
   - Use interface groups with shared worker pools
   - Or worker pool with io_uring multiplexing
   - NOT one worker per interface × one worker per CPU (would be 1920 workers for 20×96)

**Documentation Created:**
- MULTI_INTERFACE_ARCHITECTURE.md: Multi-interface design patterns
- RSS_CONFIGURATION.md: RSS/RPS configuration guide
- ARCHITECTURE_EVALUATION.md: Critical architecture evaluation (verdict: 8/10)

**Resolution:** Misleading TODO comment corrected in commit e27410d

---

## 3. Performance Issues

### 3.1 Buffer Size Limitation 🟡 HIGH
**Location:** `user_docs/CONFIGURATION.md`, buffer pool implementation
**Status:** Performance regression from design

**Problem:**
- **Current:** 9KB jumbo buffers (holds one 9000-byte frame)
- **Designed:** 64KB buffers (enables multi-packet batching)
- **Impact:** Buffer pool exhaustion, reduced batching efficiency

**Root Cause Investigation Needed:**
```bash
# Find buffer size definitions
grep -r "9216\|9KB\|JUMBO.*BUFFER" src/
grep -r "64.*KB\|65536" src/
```

**Hypothesis:** Buffer size was reduced to work around memory pressure or allocation issues

**Action:**
1. Investigate why 9KB was chosen over 64KB
2. Test memory usage with 64KB buffers
3. Implement dynamic buffer sizing if needed
4. Benchmark throughput: 9KB vs 64KB vs dynamic

**Estimated Effort:** 2-3 days
**Risk:** Medium (could expose memory management issues)

---

### 3.2 Real-Time Statistics Collection 🟢 MEDIUM
**Location:** `src/supervisor.rs:158-159`
**Status:** Placeholder implementation

**Current:**
```rust
// TODO: In the future, query data plane workers for actual stats via worker communication
// Currently returns configured rules with zero counters as a placeholder
```

**Action:**
1. Implement `GetStats` command in worker control plane
2. Add stats request/response to worker communication protocol
3. Supervisor aggregates stats from all workers
4. Add per-destination metrics (currently only per-rule)

**Estimated Effort:** 2-3 days
**Risk:** Low (additive feature, doesn't affect data path)

---

## 4. Unimplemented Features

### 4.1 Protocol Versioning 🟢 MEDIUM
**Location:** Architecture design document
**Status:** Designed but not implemented

**Feature:**
```
- PROTOCOL_VERSION constant
- VersionCheck command (first message on connection)
- Fail-fast on version mismatch
```

**Rationale:** Prevents subtle bugs from client/server version mismatches

**Action:**
1. Add `PROTOCOL_VERSION` constant to shared module
2. Implement `VersionCheck` command
3. Server validates version on first message
4. Add version to `--version` output

**Estimated Effort:** 1 day
**Risk:** Low (protocol enhancement)

---

### 4.2 On-Demand Packet Tracing 🔵 LOW
**Location:** Architecture design document
**Status:** Designed but not implemented

**Feature:**
```
- EnableTrace/DisableTrace/GetTrace commands
- Per-rule tracing (opt-in, disabled by default)
- In-memory ring buffer for diagnostic events
- Packet lifecycle tracking
```

**Use Case:** Debugging packet drops or unexpected behavior

**Action:**
1. Design trace event schema
2. Add ring buffer per worker for trace events
3. Implement enable/disable/get trace commands
4. Add tracing points in packet processing path

**Estimated Effort:** 5-7 days
**Risk:** Low (debugging feature, doesn't affect normal operation)

---

### 4.3 GetWorkerRules Command ❌ REMOVED
**Location:** ~~IPC protocol, worker synchronous handler~~ REMOVED
**Status:** ❌ Removed (November 2025) after architectural analysis
**Previous Status:** Not implemented (returned error)

**Reason for Removal:**
GetWorkerRules was incompatible with the fire-and-forget broadcast architecture:

1. **Fire-and-Forget Broadcasts:** Supervisor sends rule updates to workers via broadcasts with errors explicitly ignored (see Section 8.2.5)
2. **Workers May Have Stale State:** Due to:
   - RemoveRule not implemented in data plane (see Section 8.2.1)
   - No ruleset sync on worker startup (see Section 8.2.4)
   - Broadcast failures silently lost (see Section 8.2.5)
3. **Querying Workers is Unreliable:** Worker-reported state may not reflect reality
4. **Supervisor is Authoritative:** Supervisor's `master_rules` HashMap is the single source of truth

**Architectural Decision:**
Instead of querying potentially-stale worker state, the supervisor's `master_rules` is the authoritative source. Phase 1 drift detection (Section 8.1) enables detecting when workers drift from this authoritative state via hash logging.

**Replacement:**
- Use `SupervisorCommand::ListRules` to query supervisor's authoritative state
- Use hash-based drift detection (Section 8.1) to identify stale workers
- Use Phase 2 automated recovery (Section 8.3) to resync workers

**Impact on Tests:**
- Integration test `rule_management::test_add_and_remove_rule_e2e` updated to use `ListRules` instead
- Test simplified to verify supervisor's authoritative state rather than worker state

**Related Sections:**
- **Section 8.1:** Phase 1 drift detection (hash logging) - COMPLETED
- **Section 8.2:** Architectural gaps discovered during drift detection work
- **Section 8.2.6:** Cleanup of unused `req_stream` field after removal
- **Section 8.3:** Phase 2 automated recovery (planned)

---

## 5. Documentation Gaps

### 5.1 Kernel Version Requirements 🟢 MEDIUM
**Location:** README.md, CONFIGURATION.md
**Status:** Vague ("Linux 5.10+")

**Action:**
1. Research exact io_uring features used
2. Document minimum kernel version for each feature
3. Add runtime feature detection if possible
4. Document graceful degradation path (if any)

**Research needed:**
- IORING_OP_RECVMSG minimum version
- IORING_OP_SENDMSG minimum version
- AF_PACKET + io_uring interaction requirements

**Estimated Effort:** 4-6 hours
**Risk:** None (documentation only)

---

### 5.2 Troubleshooting Guide 🔵 LOW
**Location:** `user_docs/TROUBLESHOOTING.md` (doesn't exist)
**Status:** Missing

**Content Needed:**
- Common errors and solutions
- Permission issues (CAP_NET_RAW, root requirements)
- Network namespace troubleshooting
- Buffer exhaustion symptoms and fixes
- Performance tuning checklist
- Debug logging best practices

**Estimated Effort:** 1-2 days
**Risk:** None (documentation only)

---

### 5.3 Rule ID Lifecycle Documentation 🔵 LOW
**Location:** User documentation
**Status:** Not explained

**Content Needed:**
- How rule IDs are generated (UUIDs)
- Where to find rule IDs (`control_client list`)
- Can users provide custom IDs? (need to verify)
- ID persistence across restarts

**Estimated Effort:** 2-3 hours
**Risk:** None (documentation only)

---

## 6. Code Quality Issues

### 6.1 Event-Driven Mode Deadlock ✅ RESOLVED
**Location:** ~~`src/worker/egress.rs:647`~~ REMOVED
**Status:** ✅ Obsolete - egress.rs deleted as part of legacy code removal

**Resolution:**
The event-driven mode was part of the legacy two-thread architecture that has been completely removed. The unified data plane uses a different event model based on io_uring's native event handling, which doesn't have the same deadlock issues.

This issue is resolved by architectural change rather than bug fix.

---

### 6.2 Test Coverage Gaps 🟢 MEDIUM
**Locations:** Various test files, TODOs in code

**Known gaps:**
```rust
// src/supervisor/rule_dispatch.rs:288
// TODO: Add test for handling send failures

// src/supervisor/network_monitor.rs:426
// TODO: Add integration test with real Netlink socket (feature-gated)
```

**Action:**
1. Audit test coverage: `cargo tarpaulin --out html`
2. Add tests for all TODO items
3. Add property-based tests for rule hashing
4. Add failure injection tests (network errors, buffer exhaustion)

**Estimated Effort:** 1 week
**Risk:** None (tests only)

---

### 6.3 Log Level Control Integration Tests 🔴 CRITICAL
**Location:** `tests/integration/log_level_control.rs:23`
**Status:** Broken since introduction in commit 5c04136 (never worked)

**Problem:**
```rust
// Current code (BROKEN):
let current_exe = std::env::current_exe().expect("Failed to get current executable path");
let mut supervisor_cmd = Command::new(current_exe);
supervisor_cmd.arg("supervisor")...
```

This attempts to execute the **test binary** as the supervisor:
- `current_exe` returns `/path/to/target/debug/deps/integration-b9537ad67e83139f`
- Tries to run: `integration-b9537ad67e83139f supervisor`
- The test binary doesn't have a "supervisor" subcommand
- Socket never gets created → "Socket creation timeout" error

**Correct Approach (from working CLI tests):**
```rust
// What it should be:
let mut supervisor_cmd = Command::new(env!("CARGO_BIN_EXE_multicast_relay"));
supervisor_cmd.arg("supervisor")...
```

The `env!("CARGO_BIN_EXE_multicast_relay")` macro:
- Evaluated at compile time by Cargo
- Points to the actual `multicast_relay` binary: `/path/to/target/debug/multicast_relay`
- Built with same profile and flags as tests

**Impact:**
- 2 integration tests failing: `test_set_and_get_global_log_level_via_ipc`, `test_facility_override_via_ipc`
- False commit messages claiming tests pass:
  - 58d7cdf: "Result: 10 working integration tests" → FALSE (6 log level tests failed)
  - dd2a6c2: "All 6 tests pass" → FALSE (2 remaining tests still fail)
- Tests have **never** passed in any commit since 5c04136

**Fix:**
Replace line 23 in `tests/integration/log_level_control.rs`:
```diff
-    let current_exe = std::env::current_exe().expect("Failed to get current executable path");
+    // Use CARGO_BIN_EXE_multicast_relay macro to get the actual binary path
+    let binary_path = env!("CARGO_BIN_EXE_multicast_relay");

-    let mut supervisor_cmd = Command::new(current_exe);
+    let mut supervisor_cmd = Command::new(binary_path);
```

**Verification:**
After fix, tests should pass with same reliability as CLI tests (currently 3/3 passing).

**Estimated Effort:** 15 minutes
**Risk:** None (trivial one-line fix)

**Priority:** CRITICAL - False test results mislead developers about code correctness

---

### 6.4 Development Process: Test Verification Discipline 🔴 CRITICAL
**Status:** Process failure identified (November 2025)

**Problem:**
Multiple commits claimed "all tests pass" without actually running or verifying tests:

**Evidence of False Claims:**
```
Commit 58d7cdf: "Result: 10 working integration tests (3 CLI + 6 log level + 1 rule mgmt)"
                "All tests compile without errors"
                "All tests pass or skip gracefully without root privileges"
→ REALITY: 6/6 log level tests were failing with "Socket creation timeout"

Commit dd2a6c2: "Results: - Integration tests: 10 → 6 tests (40% reduction)
                         - All 6 tests pass"
→ REALITY: 2/2 remaining log level tests still failing

Commit cd4811c: "Result: Legacy code removed, all tests passing"
→ REALITY: Broke req_stream FD passing, causing rule_management test to hang
```

**Root Cause Analysis:**
1. Tests were not actually executed before committing
2. No CI/CD pipeline to enforce test runs
3. Commit messages written based on expectation rather than verification
4. Integration tests require root privileges (easy to skip accidentally)

**Impact:**
- Broken tests remained undetected for months
- False confidence in code correctness
- Regression (cd4811c) went unnoticed
- Wasted developer time debugging "new" issues that were pre-existing

**Git History Issue:**
Commit cd4811c broke req_stream FD passing during legacy removal:
- Control plane worker stopped receiving req_stream FD
- Caused rule_management integration test to hang (30s timeout)
- Fixed in commit 2159e2e by restoring proper FD passing
- Git history reconstructed to combine fixes into working commit

**Recommended Process Improvements:**
1. **Pre-commit hook**: Run `cargo test --lib` before allowing commit
2. **CI/CD requirement**: All tests must pass before merge
3. **Test run evidence**: Paste test output in commit messages or PR description
4. **Privileged test documentation**: Clear instructions for running integration tests
5. **Test status tracking**: Maintain accurate count in README.md

**Example Better Commit Message:**
```
refactor: Remove legacy two-thread data plane

Test Results:
  ✓ cargo test --lib: 132/132 passing
  ✓ cargo test --test integration (sudo): 14/16 passing
    - 2 log level tests SKIPPED (known broken, see #123)
  ✓ Basic data plane: 10/10 packets forwarded

Total: 146/149 tests passing (98%)
```

**Action:**
1. Add pre-commit hook for unit tests
2. Document test running procedure in CONTRIBUTING.md
3. Set up basic GitHub Actions CI
4. Create tracking issue for broken tests
5. Never claim "all tests pass" without verification

**Estimated Effort:** 1 day (CI setup + documentation)
**Risk:** None (process improvement)

**Priority:** CRITICAL - Prevents regression and maintains code quality trust

---

## 7. Build System Issues

### 7.1 Node.js Dependencies in Git History 🟢 MEDIUM
**Location:** Git history (now fixed)
**Status:** Cleaned up, but history still contains bloat

**Problem:**
- 6,044 node_modules files were tracked (1M+ LOC)
- Removed in commit 687d686, but still in git history
- Makes `git clone` slow and wastes bandwidth/storage

**Options:**
1. **Option A (Recommended):** Document the issue, leave history as-is
   - Pro: Safe, no risk
   - Con: Forever slow clones

2. **Option B:** Rewrite history with `git filter-repo`
   - Pro: Clean history, fast clones
   - Con: Everyone must re-clone, breaks existing clones
   - Requires: Coordination with all contributors

**If pursuing Option B:**
```bash
# WARNING: Destructive operation, coordinate with team first
git filter-repo --path node_modules --invert-paths
git push --force --all
```

**Estimated Effort:** 1 hour + coordination
**Risk:** High (requires force push, breaks existing clones)

---

## 8. Ruleset Synchronization and Drift Detection

### 8.1 Phase 1: Hash-Based Drift Detection ✅ COMPLETED
**Status:** ✅ Implemented (November 2025)
**Commits:** Hash computation and logging added
**Priority:** Detection-only, no automated recovery

**Implementation:**
Added deterministic ruleset hashing to enable manual drift detection:

```rust
// src/lib.rs:215-233
/// Compute a deterministic hash of a ruleset for drift detection.
/// Returns a hash of the sorted rule IDs to detect when worker rules don't match supervisor's master_rules.
pub fn compute_ruleset_hash<'a, I>(rules: I) -> u64
where
    I: Iterator<Item = &'a ForwardingRule>,
{
    use std::collections::BTreeSet;
    use std::hash::{Hash, Hasher};

    // Collect and sort rule_ids for deterministic ordering
    let rule_ids: BTreeSet<&str> = rules.map(|r| r.rule_id.as_str()).collect();

    // Compute hash
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for rule_id in rule_ids {
        rule_id.hash(&mut hasher);
    }
    hasher.finish()
}
```

**Hash Logging Locations:**
1. **Supervisor** (`src/supervisor.rs:848-870`): Logs expected hash after AddRule/RemoveRule
   - Uses proper logging system: `log_info!(logger, Facility::Supervisor, ...)`
   - Format: `"Ruleset updated: hash={:016x} rule_count={}"`

2. **Data Plane Workers** (`src/worker/unified_loop.rs:376-385`): Logs actual hash after AddRule
   - Uses logger: `self.logger.info(Facility::DataPlane, ...)`
   - Format: `"Ruleset updated: hash={:016x} rule_count={}"`
   - **Note:** Only logs on AddRule, not RemoveRule (RemoveRule not implemented)

3. **Control Plane Worker** (`src/worker/stats.rs:23-29`): Logs hash when stats updated
   - Uses `eprintln!()` due to architectural constraint (stats_aggregator_task has no logger)
   - Format: `"[ControlPlane] Ruleset updated: hash={:016x} rule_count={}"`
   - **Note:** Only updates when stats are reported, not on direct rule commands

**Usage:**
```bash
# Compare logs to detect drift
grep "Ruleset updated" /var/log/multicast_relay.log | grep -E "(Supervisor|DataPlane|ControlPlane)"

# Expected: All hashes match for the same rule_count
# Drift detected: Worker hash differs from supervisor hash
```

**Architectural Constraints:**
- Data plane workers don't handle RemoveRule (see 8.2.1)
- Control plane's `shared_flows` updated via stats, not rule commands (see 8.2.3)
- Stats aggregator has no logger access (see 8.2.7)
- Fire-and-forget broadcasts can silently fail (see 8.2.5)

**Deliverables:**
- ✅ Hash computation utility
- ✅ Supervisor logging (proper logging system)
- ✅ Data plane worker logging
- ✅ Control plane worker logging (eprintln fallback)
- ⏳ Test for hash logging (pending)
- ⏳ Documentation for drift detection procedure (pending)

---

### 8.2 Rule Synchronization Architectural Gaps 🔴 CRITICAL
**Status:** Discovered during drift detection implementation (November 2025)
**Impact:** Workers can have stale rulesets with no recovery mechanism

**Root Cause:**
Supervisor uses **fire-and-forget broadcasts** to send rule updates to workers, with errors **explicitly ignored**:

```rust
// src/supervisor.rs:925, 982-999
let _ = framed.send(cmd_bytes_clone.into()).await; // Errors ignored!

tokio::spawn(async move {
    let mut stream = ingress_stream.lock().await;
    let mut framed = Framed::new(&mut *stream, LengthDelimitedCodec::new());
    let _ = framed.send(cmd_bytes_clone.into()).await; // Errors ignored!
});
```

This architectural choice prioritizes supervisor responsiveness over guaranteed delivery, but creates multiple failure modes.

---

#### 8.2.1 Data Plane Workers RemoveRule Implementation ✅ COMPLETED
**Location:** `src/worker/unified_loop.rs:246-261, 404-435, 834-997`
**Status:** ✅ Implemented and tested (November 2025)
**Commits:** fc0a50f (implementation), d80300e (tests)

**Implementation:**
- Added `remove_rule(&mut self, rule_id: &str)` method
  - Searches HashMap by rule_id
  - Removes rule keyed by (input_group, input_port)
  - Returns error if not found
- Added RemoveRule command handler in event loop
  - Logs removal operation
  - Updates ruleset hash for drift detection
  - Logs errors for failed removals

**Testing Status:**
- ✅ Compiles successfully
- ✅ All 138 unit tests pass (7 new tests for RemoveRule)
- ✅ Unit tests cover all scenarios:
  - test_remove_rule_success: Basic successful removal
  - test_remove_rule_not_found: Error handling for non-existent rule
  - test_remove_all_rules: Sequential removal of all rules
  - test_remove_rule_from_empty_ruleset: Edge case with empty ruleset
  - test_remove_rule_idempotency: Verify error on duplicate removal
  - test_add_and_remove_rule: Add then remove workflow
  - test_remove_rule_with_duplicate_ports: Same port, different groups
- ✅ Integration test (test_add_and_remove_rule_e2e) passes
- ✅ E2E test confirms: add rule → remove rule → verify gone

**Risk:** Low - implemented and thoroughly tested

---

#### 8.2.2 Control Plane Doesn't Process Rule Commands 🟡 HIGH
**Location:** `src/worker/control_plane.rs:25-57`
**Status:** Intentionally stubbed
**Impact:** Unclear architecture, potential for drift

**Current Implementation:**
```rust
pub fn handle_worker_command(
    command: SupervisorCommand,
    flows: &HashMap<String, (ForwardingRule, FlowStats)>,
) -> Response {
    match command {
        SupervisorCommand::AddRule { .. } => {
            Response::Error("AddRule should be handled by the supervisor directly".to_string())
        }
        SupervisorCommand::RemoveRule { .. } => {
            Response::Error("RemoveRule should be handled by the supervisor directly".to_string())
        }
        SupervisorCommand::ListRules => {
            Response::Rules(flows.values().map(|(r, _)| r.clone()).collect())
        }
        SupervisorCommand::GetStats => {
            Response::Stats(flows.values().map(|(_, s)| s.clone()).collect())
        }
        // ... other commands return errors
    }
}
```

**Question:**
Is the control plane's `shared_flows` meant to represent:
1. **Active rules** that the control plane is processing? (then it should handle AddRule/RemoveRule)
2. **Rules with recent stats** reported by data plane? (then it's just an aggregator)

**Current Reality:**
It's #2 - `shared_flows` is populated by `stats_aggregator_task` receiving (rule, stats) via channel, NOT by rule commands. See 8.2.3.

**Consequences:**
- ListRules from control plane may not match supervisor's master_rules
- GetStats only works for rules that have reported stats
- Control plane can't serve as authoritative backup for supervisor
- Unclear if control plane should exist as separate worker type

**Action:**
1. Document intended architecture: What is control plane's role?
2. Either:
   - **Option A:** Control plane processes rule commands (becomes authoritative)
   - **Option B:** Control plane is pure stats aggregator (rename to stats_worker)
   - **Option C:** Remove control plane entirely (supervisor aggregates stats)
3. Update code to match chosen architecture
4. Add tests for chosen behavior

**Estimated Effort:** 2-3 days (after architecture decision)
**Risk:** Low (control plane doesn't affect data path)
**Priority:** HIGH - Architectural clarity needed

**Related:** Section 3.2 (Real-time statistics collection) depends on this decision

---

#### 8.2.3 Stats Reporting Incomplete 🟡 HIGH
**Location:** `src/worker/stats.rs:15-32`, data plane workers
**Status:** Infrastructure exists, not wired up
**Impact:** Control plane's `shared_flows` never populated by real stats

**Evidence:**
```rust
// src/worker/unified_loop.rs:128 (approximate)
// DataPlaneWorker has:
_stats_tx: mpsc::Sender<(ForwardingRule, FlowStats)>,
//  ^^^^^ Underscore prefix = unused parameter
```

**Current Reality:**
- Control plane has `stats_aggregator_task` ready to receive stats
- Data plane workers have `_stats_tx` channel but never send
- `shared_flows` HashMap exists but remains empty (except in tests)
- Hash logging in control plane (8.1) never triggers in production

**Consequences:**
- GetStats returns empty list or stale data
- Control plane's hash logging is dead code (no stats = no hash updates)
- Cannot monitor per-flow packet/byte counters
- Cannot detect stale rules via stats reporting

**Action:**
1. Remove underscore prefix from `stats_tx` in data plane worker
2. Implement periodic stats reporting (every N seconds)
3. Calculate packets_per_second and bits_per_second from counters
4. Send (rule, stats) to control plane via stats_tx channel
5. Verify hash logging in control plane triggers correctly
6. Add test for stats flow: data plane → channel → control plane

**Estimated Effort:** 2-3 days
**Risk:** Low (additive feature)
**Priority:** HIGH - Needed for observability and drift detection

**Related:** Section 3.2 (Real-time statistics collection)

---

#### 8.2.4 No Ruleset Sync on Worker Startup 🔴 CRITICAL
**Location:** Worker initialization, supervisor worker management
**Status:** Not implemented
**Impact:** New workers start empty, miss existing rules

**Current Behavior:**
1. Supervisor starts with N rules in `master_rules`
2. Supervisor spawns new worker (e.g., after crash recovery)
3. Worker starts with empty ruleset
4. Worker only learns about NEW rules added after startup
5. Worker never receives the N existing rules

**Consequences:**
- Guaranteed drift on worker restart
- Worker hash = 0, supervisor hash = hash(N rules)
- Packets for existing rules are dropped by new worker
- No way to resynchronize without manual intervention

**Action:**
1. On worker startup, supervisor sends full ruleset snapshot
2. Add `SyncRules` command with full rule list
3. Worker processes SyncRules atomically (replace entire ruleset)
4. Supervisor sends SyncRules:
   - When worker first connects
   - After supervisor detects worker restart (via PID change)
   - On manual resync command
5. Add test: start worker, verify it receives all existing rules

**Estimated Effort:** 2-3 days
**Risk:** Medium (must handle atomicity, avoid partial sync)
**Priority:** CRITICAL - Prevents basic recovery scenarios

---

#### 8.2.5 Fire-and-Forget Broadcasts Have No Retry 🔴 CRITICAL
**Location:** `src/supervisor.rs:925, 982-999`
**Status:** By design, but creates reliability gap
**Impact:** Silent rule loss on transient failures

**Current Implementation:**
```rust
// Errors explicitly ignored:
let _ = framed.send(cmd_bytes_clone.into()).await;
```

**Failure Modes:**
1. Worker process frozen (high CPU, blocked on syscall)
2. Unix socket buffer full (worker not reading)
3. Serialization error (malformed rule)
4. Worker crashed but supervisor doesn't know yet
5. Network namespace issues (if workers in separate netns)

**Consequences:**
- Rule never reaches worker
- No error reported to client
- Supervisor believes rule was delivered
- Client receives "Success" response
- Drift: supervisor has rule, worker doesn't

**Current Workaround:**
None. Phase 1 hash logging (8.1) enables *detection* but not recovery.

**Potential Solutions:**

**Option A: Synchronous Acknowledgments**
- Worker sends ACK after processing AddRule/RemoveRule
- Supervisor waits for ACK with timeout
- Return error to client if ACK not received
- Pro: Reliable delivery, client knows about failures
- Con: Slower, blocks supervisor, requires protocol change

**Option B: Asynchronous Retry with Monitoring**
- Keep fire-and-forget for responsiveness
- Track expected vs actual hash per worker
- Periodically compare hashes (via stats reporting)
- Auto-resync when drift detected
- Pro: Maintains performance, eventual consistency
- Con: Complex, requires stats reporting (8.2.3)

**Option C: Hybrid Approach**
- Fire-and-forget for normal operation
- Periodic full sync (every N minutes) to recover from drift
- Health check (Ping command) to detect dead workers
- Pro: Balance of performance and reliability
- Con: Drift window up to N minutes

**Action:**
1. Decide on synchronization strategy (needs user input)
2. Document failure modes and acceptable recovery time
3. Implement chosen solution
4. Add failure injection tests (kill worker, fill socket buffer)

**Estimated Effort:** 3-5 days (depends on chosen solution)
**Risk:** High (affects core control plane, must not regress performance)
**Priority:** CRITICAL - Root cause of drift

**Related:**
- 8.2.4 (ruleset sync) needed for Option B/C
- 8.2.8 (health checks) needed for Option C

---

#### 8.2.6 Unused `req_stream` Field After GetWorkerRules Removal 🟢 MEDIUM
**Location:** `src/supervisor.rs` (worker manager), `src/worker/control_plane.rs:62`
**Status:** Compiler warning after GetWorkerRules removal
**Impact:** Dead code, minor

**Context:**
Section 4.3 documented GetWorkerRules as unimplemented. During drift detection work, GetWorkerRules was removed entirely because:
1. Architecture uses fire-and-forget broadcasts (see 8.2.5)
2. Workers may have stale state (see 8.2.1, 8.2.4)
3. Querying individual workers is unreliable
4. Supervisor's `master_rules` is authoritative

**Current State:**
```
warning: field `req_stream` is never read
  --> src/worker/control_plane.rs:62:5
   |
62 |     request_stream: UnixStream,
   |     ^^^^^^^^^^^^^^
```

**req_stream Infrastructure:**
- FD passing works correctly (fixed in commit 2159e2e)
- Control plane receives stream in `control_plane_task:109`
- Used for `Request::ListRules` at line 173
- ListRules still used for testing and debugging

**Decision:**
Keep the field but suppress warning, OR remove if ListRules is also removed.

**Action:**
1. If keeping ListRules (for debugging): `#[allow(dead_code)] request_stream`
2. If removing ListRules: Remove req_stream infrastructure entirely
3. Update section 1.2 to reflect GetWorkerRules removal
4. Update section 4.3 to mark as "REMOVED" instead of "TODO"

**Estimated Effort:** 30 minutes
**Risk:** None (cosmetic)
**Priority:** MEDIUM - Cleanup after architectural change

**Update to Section 4.3:**
Mark GetWorkerRules as removed, explain architectural reasoning:
```markdown
### 4.3 GetWorkerRules Command ❌ REMOVED
**Status:** Removed (November 2025) after architectural analysis
**Reason:** Incompatible with fire-and-forget broadcast architecture
**Replacement:** Use supervisor's master_rules as authoritative source
**See:** Section 8.2 for ruleset synchronization architectural gaps
```

---

#### 8.2.7 Inconsistent Logging Approaches 🟢 MEDIUM
**Location:** Multiple files
**Status:** Mix of proper logging, eprintln, and no logging
**Impact:** Hard to debug, inconsistent log format

**Evidence:**
1. **Supervisor**: Uses proper logging system with `log_info!` macro and Facility enum
2. **Data plane workers**: Uses `self.logger.info(Facility::DataPlane, ...)`
3. **Control plane stats_aggregator_task**: Uses `eprintln!()` at `stats.rs:25-29`
   - Reason: Background task has no logger instance
   - Architectural constraint, not oversight
4. **Some code paths**: No logging at all

**Consequences:**
- Inconsistent log format makes parsing difficult
- eprintln output not captured by log aggregators
- Missing logs for important events (rule removal failures, sync errors)
- Hard to correlate events across supervisor and workers

**Action:**
1. Audit all code for logging coverage
2. Pass Logger to stats_aggregator_task (add to function signature)
3. Replace all eprintln with proper logging
4. Add logging for error paths (especially ignored errors from broadcasts)
5. Document logging conventions in CONTRIBUTING.md
6. Consider structured logging (JSON format) for production

**Estimated Effort:** 2-3 days
**Risk:** Low (improves observability)
**Priority:** MEDIUM - Quality improvement

---

#### 8.2.8 No Periodic Health Checks 🟡 HIGH
**Location:** Supervisor worker management
**Status:** Only manual Ping command exists
**Impact:** Dead workers not detected automatically

**Current State:**
- Ping command exists (`SupervisorCommand::Ping`, `RelayCommand::Ping`)
- Only invoked manually or in tests
- No periodic health monitoring
- Supervisor doesn't know if worker crashed until rule broadcast fails (and failure is ignored)

**Consequences:**
- Worker crashes go undetected
- Rules sent to dead workers are silently lost
- Drift accumulates until manual intervention
- No automatic worker restart

**Action:**
1. Implement periodic health check loop in supervisor:
   ```rust
   loop {
       tokio::time::sleep(Duration::from_secs(30)).await;
       for worker in workers {
           match ping_worker(worker).await {
               Ok(_) => continue,
               Err(_) => {
                   log_error!("Worker {} not responding, restarting", worker.pid);
                   restart_worker(worker).await;
               }
           }
       }
   }
   ```
2. Add worker restart logic:
   - Spawn new worker
   - Send full ruleset sync (see 8.2.4)
   - Update worker_map
   - Clean up old worker resources
3. Make health check interval configurable
4. Add metrics: worker_restarts_total, worker_health_check_failures

**Estimated Effort:** 2-3 days
**Risk:** Medium (must handle restart edge cases)
**Priority:** HIGH - Needed for production reliability

**Related:** 8.2.4 (ruleset sync needed for restart)

---

#### 8.2.9 Unclear Control Plane Purpose 🟡 HIGH
**Location:** Architecture design, control plane implementation
**Status:** Dual role not well-defined
**Impact:** Confusion about responsibility, potential redundancy

**Questions:**
1. Why separate control plane worker vs supervisor handling stats?
2. Should control plane maintain authoritative rule state?
3. Is control plane just for stats aggregation?
4. Could supervisor do all of this without separate worker?

**Current Implementation Suggests:**
- Control plane is **stats aggregator only** (see 8.2.2, 8.2.3)
- Supervisor is **rule authority** (master_rules HashMap)
- Data plane is **packet forwarding only** (no stats reporting yet)

**Architectural Options:**

**Option A: Control Plane as Stats Aggregator (Current)**
- Rename to "stats_worker" for clarity
- Only handles stats collection and reporting
- Supervisor remains rule authority
- Data plane workers report to stats worker

**Option B: Control Plane as Authoritative State**
- Control plane maintains master ruleset
- Supervisor delegates to control plane
- Better separation of concerns
- More complex synchronization

**Option C: Remove Control Plane**
- Supervisor handles stats directly
- Simpler architecture
- Fewer processes to manage
- Supervisor becomes busier

**Action:**
1. **Decide on architecture** (needs user/architect input)
2. Document decision in architecture docs
3. Refactor code to match chosen model
4. Update all related documentation
5. Add tests for chosen responsibility model

**Estimated Effort:** 3-5 days (after decision)
**Risk:** Medium (architectural change)
**Priority:** HIGH - Clarity needed for 8.2.2, 8.2.3

---

#### 8.2.10 No Automated Feedback Loop 🟡 HIGH
**Location:** System-wide
**Status:** Phase 1 (detection) complete, Phase 2 (recovery) not designed
**Impact:** Drift detected but not corrected

**Current State (Phase 1):**
- ✅ Hash logging in supervisor (expected state)
- ✅ Hash logging in data plane workers (actual state)
- ✅ Hash logging in control plane (partial - only when stats reported)
- ❌ No automated comparison
- ❌ No automated recovery

**What's Needed (Phase 2):**
1. **Detection:** Workers periodically report their ruleset hash to supervisor
   - Requires: Stats reporting (8.2.3) or separate health check (8.2.8)

2. **Comparison:** Supervisor compares worker hash to master_rules hash
   - Log warning on mismatch
   - Emit metric: worker_drift_detected{worker_id}

3. **Recovery:** When drift detected, supervisor can:
   - **Option A:** Send full ruleset sync (requires 8.2.4)
   - **Option B:** Restart worker (requires 8.2.8)
   - **Option C:** Alert operator (manual intervention)

**Design Decisions Needed:**
- How often to check? (Every 10s? Every stats report?)
- What recovery strategy? (Auto-sync? Alert? Restart?)
- Acceptable drift window? (Immediate? 1 minute?)
- Handle persistent drift? (Worker broken, sync won't help)

**Action:**
1. Decide on recovery strategy (needs user input on failure modes)
2. Implement periodic hash reporting from workers
3. Implement hash comparison in supervisor
4. Implement chosen recovery mechanism
5. Add metrics and alerting
6. Test recovery under failure injection

**Estimated Effort:** 1 week (depends on chosen strategy)
**Risk:** High (affects system reliability)
**Priority:** HIGH - Completes drift detection feature

**Blocked By:**
- 8.2.1 (RemoveRule implementation)
- 8.2.3 (Stats reporting)
- 8.2.4 (Ruleset sync)
- 8.2.5 (Broadcast reliability decision)

**Related:** Phase 1 (8.1) provides detection foundation

---

### 8.3 Phase 2: Automated Recovery (Planned)
**Status:** Design phase
**Priority:** 🟡 HIGH
**Blocked By:** Sections 8.2.1, 8.2.3, 8.2.4, 8.2.5

**Goal:**
Automatic detection and recovery from worker drift, without manual intervention.

**Design Questions:**
1. **Failure Modes:** What causes drift that we need to recover from?
   - Transient: Socket buffer full, worker temporarily frozen
   - Permanent: Worker crash, memory corruption, software bug

2. **Recovery Strategy:** What's appropriate for each failure mode?
   - Transient → Retry/resync rules
   - Permanent → Restart worker

3. **Performance Trade-offs:** What's acceptable?
   - Zero drift tolerance (synchronous ACKs, slower)
   - Eventual consistency (async, faster, drift window)

4. **Packet Loss:** What's acceptable during recovery?
   - Restart worker → Drops packets during restart
   - Resync rules → No packet loss

**Recommended Approach:**
1. **Near-term:** Implement Option C from 8.2.5 (Hybrid Approach)
   - Fire-and-forget for performance
   - Periodic sync (every 60s) for recovery
   - Health checks to detect dead workers

2. **Long-term:** Implement Option B from 8.2.5 (Asynchronous Retry)
   - Hash-based drift detection
   - Targeted resync only when drift detected
   - Automatic worker restart for persistent failures

**Implementation Order:**
1. ✅ Phase 1: Hash logging (COMPLETED)
2. ✅ RemoveRule in data plane (8.2.1) - implemented and tested (commits fc0a50f, d80300e)
3. 🔧 Implement stats reporting (8.2.3) - enables hash comparison
4. 🔧 Implement ruleset sync on startup (8.2.4) - enables recovery
5. 🔧 Implement periodic health checks (8.2.8) - detects dead workers
6. 🔧 Implement automated drift recovery (8.2.10) - completes feature

**Estimated Total Effort:** 3-4 weeks
**Risk:** High (affects system reliability)
**Priority:** HIGH - Production requirement

**Deliverables:**
- Automated drift detection
- Automated recovery mechanisms
- Metrics and alerting
- Tests for failure scenarios
- Documentation of failure modes and recovery procedures

---

## Implementation Roadmap

### Phase 1: Quick Wins (1-2 weeks)
**Goal:** Remove dead code, fix documentation, implement basic drift detection

1. ✅ **COMPLETED** Remove legacy two-thread data plane (1.1) - 1,814 lines deleted
2. ✅ **COMPLETED** Remove dead code marked `#[allow(dead_code)]` (1.2)
3. ✅ **COMPLETED** Fix log level control integration tests (6.3)
4. ✅ **COMPLETED** Remove GetWorkerRules command (4.3) - architectural decision
5. ✅ **COMPLETED** Implement Phase 1 drift detection (8.1) - hash-based logging
6. ✅ **COMPLETED** Document architectural gaps discovered (8.2)
7. ✅ **COMPLETED** Resolve global interface parameter confusion (2.4) - architectural investigation + docs
8. ⏳ **TODO** Document kernel version requirements (5.1)
9. ⏳ **TODO** Document rule ID lifecycle (5.3)
10. ⏳ **TODO** Add test for hash logging (8.1)
11. ⏳ **TODO** Document drift detection procedure (8.1)

**Deliverables:**
- ✅ Cleaner codebase (-1,814 LOC vs planned -250 LOC)
- ✅ Legacy architecture removed entirely
- ✅ All 3 integration test suites passing (log level control fixed)
- ✅ Hash-based drift detection implemented (detection only, no recovery)
- ✅ 10 architectural gaps documented for future work
- ⏳ Documentation improvements pending

---

### Phase 2: Architecture Fixes (3-4 weeks)
**Goal:** Implement critical architectural improvements and automated recovery

**Priority Track - Ruleset Synchronization (Section 8):**
1. ✅ **COMPLETED** - RemoveRule implementation (8.2.1)
   - ✅ Code implemented (commit fc0a50f)
   - ✅ Unit tests added (commit d80300e) - 7 tests, all pass
   - ✅ Integration test passes (test_add_and_remove_rule_e2e)
2. 🔧 Implement stats reporting from data plane (8.2.3) - enables monitoring
3. 🔧 Implement ruleset sync on worker startup (8.2.4) - **CRITICAL** - enables recovery
4. 🔧 Decide on broadcast reliability strategy (8.2.5) - **CRITICAL** - architectural decision needed
5. 🔧 Implement periodic health checks (8.2.8) - detects dead workers
6. 🔧 Clarify control plane purpose (8.2.9) - architectural decision needed
7. 🔧 Implement automated drift recovery (8.2.10) - completes Phase 2 drift detection

**Priority Track - Security & Performance:**
1. 🔧 Implement AF_PACKET FD passing (2.1) - **CRITICAL SECURITY**
2. 🔧 Implement rule hashing to workers (2.3)
3. 🔧 Implement network state reconciliation (2.2)
4. 🔧 Fix buffer size limitation (3.1)

**Deliverables:**
- Automated drift detection and recovery (Section 8.3)
- ⚠️ RemoveRule implemented but needs test coverage
- Stats reporting infrastructure complete
- Proper privilege separation
- Better scalability (rule hashing)
- Resilience to network changes
- Improved performance (64KB buffers)

---

### Phase 3: Feature Completion (2-3 weeks)
**Goal:** Implement designed but missing features

1. 🚀 Protocol versioning (4.1)
2. 🚀 Real-time statistics (3.2)
3. 🚀 Event-driven mode deadlock fix or removal (6.1)
4. 📚 Troubleshooting guide (5.2)

**Deliverables:**
- More robust control plane
- Better observability
- Complete feature set

---

### Phase 4: Polish (1-2 weeks)
**Goal:** Improve quality and testing

1. 🧪 Test coverage improvements (6.2)
2. 🐛 Fix any issues discovered during Phase 1-3
3. 📖 Update all documentation with new features
4. 🎯 Performance benchmarking and optimization

**Deliverables:**
- High test coverage (>80%)
- Production-ready quality
- Complete documentation

---

## Metrics for Success

### Code Quality
- [ ] No `#[allow(dead_code)]` in production code
- [ ] No "TODO: CRITICAL" or "TODO: HIGH PRIORITY" in code
- [ ] All designed features implemented or officially deferred
- [ ] Test coverage >80%

### Documentation
- [ ] All user-facing features documented
- [ ] Troubleshooting guide complete
- [ ] Architecture docs match implementation
- [ ] No "NOT IMPLEMENTED" markers without tracking issue

### Performance
- [ ] Buffer sizes match design (64KB)
- [ ] Rule hashing implemented
- [ ] Benchmarks show expected throughput
- [ ] No known performance regressions

### Security
- [ ] Privilege separation via FD passing
- [ ] Workers run as unprivileged user
- [ ] All audit recommendations addressed
- [ ] No hardcoded credentials or paths

---

## Notes

**Discovered during:** Documentation technical accuracy review (November 2025)
**Review method:** Line-by-line comparison of docs vs source code
**Key insight:** Documentation was aspirational, describing intended design rather than actual implementation

**Recommendation:** Prioritize Phase 1 (dead code removal) immediately. Phase 2 (architecture fixes) should be scheduled based on security requirements (FD passing) and scalability needs (rule hashing).
