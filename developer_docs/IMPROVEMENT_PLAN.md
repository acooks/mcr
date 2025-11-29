# Project Improvement Plan

Consolidated November 2025. Completed items archived.

## Priority Legend
- 🔴 **CRITICAL** - Core functionality or correctness issues
- 🟡 **HIGH** - Significant impact on maintainability or performance
- 🟢 **MEDIUM** - Quality improvements, technical debt reduction
- 🔵 **LOW** - Nice-to-have improvements, future enhancements

---

## Critical Priority (🔴)

### 1. Privilege Separation (AF_PACKET FD Passing)
**Location:** `src/worker/mod.rs:275-289`
**Status:** Design incomplete, using workaround
**Security Impact:** Workers run with more privileges than necessary

**Proper Solution:**
1. Supervisor (running as root) creates AF_PACKET socket
2. Passes FD to worker via Unix domain socket + SCM_RIGHTS
3. Worker receives FD and drops to unprivileged user
4. Worker retains access to AF_PACKET socket via inherited FD

**References:** SCM_RIGHTS: man 7 unix, man 3 sendmsg
**Effort:** 1-2 days

---

### 2. Test Verification Discipline
**Status:** Process failure identified

**Problem:** Multiple commits claimed "all tests pass" without verification.

**Recommended Process:**
1. Pre-commit hook: Run `cargo test --lib` before commit
2. CI/CD requirement: All tests must pass before merge
3. Test run evidence: Paste test output in commit messages
4. Never claim "all tests pass" without verification

**Effort:** 1 day (CI setup + documentation)

---

## High Priority (🟡)

### 3. Network State Reconciliation
**Location:** `src/supervisor/network_monitor.rs:86-190`
**Status:** Stubbed out

**Implementation Plan:**
1. Use `netlink-sys` or `rtnetlink` crate
2. Subscribe to RTNLGRP_LINK events
3. Detect interface up/down, address changes
4. Send events to supervisor for rule reconciliation

**Effort:** 3-5 days

---

### 4. Rule Hashing and Worker Distribution
**Location:** `src/supervisor.rs:987-988`
**Status:** Architecture documented but not implemented

**Current:** All workers receive all rules
**Intended:** Rules hashed by (input_group, input_port) to specific cores

**Implementation:**
1. Implement: `rule_hash(group, port) % num_workers`
2. Supervisor sends each rule only to its assigned worker
3. Add tests for hash distribution fairness

**Effort:** 2-3 days

---

### 5. Buffer Size Limitation
**Location:** Buffer pool implementation
**Status:** Performance regression from design

- **Current:** 9KB jumbo buffers
- **Designed:** 64KB buffers (multi-packet batching)

**Action:**
1. Investigate why 9KB was chosen over 64KB
2. Test memory usage with 64KB buffers
3. Benchmark throughput: 9KB vs 64KB

**Effort:** 2-3 days

---

### 6. Control Plane Architecture Clarity
**Location:** `src/worker/control_plane.rs`
**Status:** Dual role not well-defined

**Question:** What is control plane's role?
- **Option A:** Stats aggregator only (rename to stats_worker)
- **Option B:** Authoritative state holder
- **Option C:** Remove entirely (supervisor handles stats)

**Effort:** 2-3 days after decision

---

### 7. Automated Drift Recovery (Phase 2)
**Status:** Phase 1 (detection) complete, Phase 2 (recovery) not designed

**What's Needed:**
1. Workers periodically report ruleset hash to supervisor
2. Supervisor compares worker hash to master_rules hash
3. Recovery: Send full ruleset sync or restart worker

**Effort:** 1 week

---

## Medium Priority (🟢)

### 8. Protocol Versioning
**Status:** Designed but not implemented

**Action:**
1. Add `PROTOCOL_VERSION` constant
2. Implement `VersionCheck` command
3. Server validates version on first message

**Effort:** 1 day

---

### 9. Test Coverage Gaps
**Locations:** Various test files

**Known gaps:**
- `src/supervisor/rule_dispatch.rs:288` - test for handling send failures
- `src/supervisor/network_monitor.rs:426` - integration test with real Netlink

**Effort:** 1 week

---

### 10. Inconsistent Logging Approaches
**Location:** Multiple files

- Supervisor: Uses proper logging system
- Data plane: Uses `self.logger.info()`
- Control plane stats_aggregator: Uses `eprintln!()`

**Action:** Pass Logger to stats_aggregator_task, replace all eprintln

**Effort:** 2-3 days

---

### 11. Node.js Dependencies in Git History
**Status:** Cleaned up, but history still contains bloat (6,044 files)

**Options:**
- **Option A:** Document issue, leave history as-is (recommended)
- **Option B:** Rewrite history with `git filter-repo` (breaks existing clones)

---

### 12. Integration Test Stubs
**Location:** `tests/integration/supervisor_resilience.rs`

**Missing critical tests:**
- `test_supervisor_resyncs_rules_on_restart()` - **Line 283** (CRITICAL)
- `test_supervisor_in_namespace()` - **Line 471** (needs root)

**Effort:** 2 days

---

## Low Priority (🔵)

### 13. On-Demand Packet Tracing
**Status:** Designed but not implemented

**Feature:** EnableTrace/DisableTrace/GetTrace commands, per-rule tracing

**Effort:** 5-7 days

---

### 14. Troubleshooting Guide
**Location:** `user_docs/TROUBLESHOOTING.md` (doesn't exist)

**Content Needed:**
- Common errors and solutions
- Permission issues
- Buffer exhaustion symptoms
- Performance tuning checklist

**Effort:** 1-2 days

---

### 15. Benchmark Implementations
**Location:** `tests/benchmarks/forwarding_rate.rs:49-151`
**Status:** Skeleton exists, implementations are placeholders

**Effort:** 1 week

---

## Implementation Roadmap

### Near-term (1-2 weeks)
1. Rule resync integration test (#12) - 1 day
2. Control plane architecture decision (#6) - 2-3 days

### Medium-term (3-4 weeks)
1. AF_PACKET FD passing (#1) - CRITICAL SECURITY
2. Rule hashing to workers (#4)
3. Network state reconciliation (#3)
4. Buffer size investigation (#5)

### Long-term
1. Automated drift recovery (#7)
2. Protocol versioning (#8)
3. Complete test coverage (#9)
4. Packet tracing (#13)

---

## Completed Items (Archived)

The following were completed in November 2025:
- Legacy two-thread data plane removal (1,814 lines deleted)
- Dead code cleanup
- Global interface parameter documentation
- Real-time statistics collection (pipe-based IPC)
- Kernel version requirements documentation
- Rule ID lifecycle documentation
- Hash-based drift detection (Phase 1)
- RemoveRule implementation in data plane
- Ruleset sync on worker startup (SyncRules command)
- Periodic ruleset sync (every 5 minutes)
- GetWorkerRules command removal (architectural decision)
- Log level control integration tests (fixed: env!("CARGO_BIN_EXE_multicast_relay"))
- Periodic health checks (every 250ms with auto-restart + SyncRules)
