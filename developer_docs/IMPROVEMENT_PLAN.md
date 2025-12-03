# Project Improvement Plan

Last updated: December 2025

## Priority Legend

- 🔴 **CRITICAL** - Security or correctness issues
- 🟡 **HIGH** - Significant impact on maintainability or performance
- 🟢 **MEDIUM** - Quality improvements, technical debt
- 🔵 **LOW** - Nice-to-have, future enhancements

---

## 🔴 Critical

### Privilege Separation (AF_PACKET FD Passing)

**Location:** `src/worker/mod.rs:275-289`
**Issue:** Workers run with more privileges than necessary

Supervisor should create AF_PACKET socket and pass FD via SCM_RIGHTS, allowing workers to drop all privileges after receiving the FD.

**Effort:** 1-2 days

---

## 🟡 High Priority

### Network State Reconciliation

**Location:** `src/supervisor/network_monitor.rs` (stubbed)

Use `rtnetlink` crate to subscribe to RTNLGRP_LINK events. Detect interface up/down and address changes, trigger rule reconciliation.

**Effort:** 3-5 days

### Rule Hashing to Workers

**Location:** `src/supervisor.rs:987-988`

Currently all workers receive all rules. Implement `rule_hash(group, port) % num_workers` to distribute rules to specific cores.

**Effort:** 2-3 days

### Automated Drift Recovery

Phase 1 (detection) complete. Phase 2 needs: workers report ruleset hash, supervisor compares and triggers sync/restart on mismatch.

**Effort:** 1 week

---

## 🟢 Medium Priority

### Test Coverage Gaps

- `tests/integration/supervisor_resilience.rs` - namespace test (`#[ignore]`, needs root)

**Effort:** 2-3 days

### Buffer Size / PACKET_MMAP [REJECTED]

Proposal to use `PACKET_MMAP` for zero-copy ingress has been **rejected** due to architectural complexity and head-of-line blocking risks. See `developer_docs/decisions/001_buffer_management_strategy.md`.

Current strategy: Continue using `io_uring` with copy-based ingress and `Arc` fan-out.

---

## 🔵 Low Priority

### On-Demand Packet Tracing

EnableTrace/DisableTrace/GetTrace commands for per-rule debugging.

**Effort:** 5-7 days

### Troubleshooting Guide

Create `user_docs/TROUBLESHOOTING.md` with common errors, permission issues, buffer exhaustion symptoms, performance tuning.

**Effort:** 1-2 days

### Benchmark Implementations

**Location:** `tests/benchmarks/forwarding_rate.rs:49-151` (skeleton only)

**Effort:** 1 week

### Git History Cleanup (Optional)

Node.js dependencies removed but history bloated (6,044 files). Recommend documenting rather than rewriting history.

---

## Roadmap

**Near-term:** Test coverage gaps

**Medium-term:** AF_PACKET FD passing, Rule hashing, Network reconciliation

**Long-term:** Drift recovery, Packet tracing, Benchmarks

---

## Completed (Archived)

**December 2025:**

- **REJECTED:** PACKET_MMAP / Zero-Copy Ingress (ADR 001)
- Data Plane Fan-Out (`Arc<[u8]>` based zero-copy sharing)
- Protocol versioning (`PROTOCOL_VERSION`, `GetVersion` command)
- Consistent logging in stats.rs (replaced `eprintln!` with Logger)

**November 2025:**

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
- GetWorkerRules command removal
- Log level control integration tests
- Periodic health checks (250ms with auto-restart + SyncRules)
- Test verification discipline (pre-commit hook)
