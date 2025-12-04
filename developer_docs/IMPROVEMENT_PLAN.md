# Project Improvement Plan

Last updated: December 2025

## Priority Legend

- 🔴 **CRITICAL** - Security or correctness issues
- 🟡 **HIGH** - Significant impact on maintainability or performance
- 🟢 **MEDIUM** - Quality improvements, technical debt
- 🔵 **LOW** - Nice-to-have, future enhancements

---

## 🔴 Critical

*No critical issues currently.*

---

## 🟡 High Priority

### Multi-Interface Architecture

**Design:** `developer_docs/plans/MULTI_INTERFACE_DESIGN.md`

Single mcrd daemon managing workers for multiple interfaces with:

- JSON5 config file support
- Two-state config model (running/startup)
- Dynamic worker spawning
- Unified CLI (mcrd/mcrctl/mcrgen)

**Effort:** 2-3 weeks

### Network State Reconciliation

**Status:** Not implemented (stubbed code was removed)

Use `rtnetlink` crate to subscribe to RTNLGRP_LINK events. Detect interface up/down and address changes, trigger rule reconciliation.

**Effort:** 3-5 days

### Automated Drift Recovery

Phase 1 (detection) complete. Phase 2 needs: workers report ruleset hash, supervisor compares and triggers sync/restart on mismatch.

**Effort:** 1 week

---

## 🟢 Medium Priority

### Test Coverage Gaps

- `tests/integration/supervisor_resilience.rs:406` - namespace test (`#[ignore]`, needs root)

**Effort:** 2-3 days

### Binary Renaming

Rename binaries to conventional names:

- `mcrd` → `mcrd` (daemon)
- `mcrctl` → `mcrctl` (control CLI)
- `mcrgen` → `mcrgen` (testing tool)

**Effort:** 1 day (part of multi-interface work)

### Buffer Size for Jumbo Frames

**Issue:** Current buffer pool is undersized for jumbo frames (9000+ bytes).

The fixed buffer sizes in the buffer pool don't accommodate jumbo frames. Need to either:

- Add a jumbo buffer tier to the pool
- Make buffer sizes configurable
- Detect MTU at startup and size accordingly

**Related:** PACKET_MMAP proposal was **rejected** (see `developer_docs/decisions/001_buffer_management_strategy.md`). Current strategy continues using `io_uring` with copy-based ingress.

**Effort:** 1-2 days

---

## 🔵 Low Priority

### On-Demand Packet Tracing

EnableTrace/DisableTrace/GetTrace commands for per-rule debugging.

**Effort:** 5-7 days

### Troubleshooting Guide

Create `user_docs/TROUBLESHOOTING.md` with common errors, permission issues, buffer exhaustion symptoms, performance tuning.

**Effort:** 1-2 days

### Benchmark Implementations

**Location:** `tests/benchmarks/forwarding_rate.rs` (skeleton with TODOs)

**Effort:** 1 week

### Git History Cleanup (Optional)

Node.js dependencies removed but history bloated (6,044 files). Recommend documenting rather than rewriting history.

---

## Roadmap

**Near-term:** Multi-interface architecture, AF_PACKET FD passing

**Medium-term:** Network reconciliation, Drift recovery

**Long-term:** Packet tracing, Benchmarks

---

## Completed (Archived)

**December 2025:**

- **AF_PACKET FD Passing & Privilege Separation** - Supervisor creates AF_PACKET sockets with PACKET_FANOUT_CPU, passes via SCM_RIGHTS; workers drop to nobody:nobody (uid=65534)
- Control plane worker removal (vestigial code from earlier design)
- Dead code cleanup: `ipc.rs`, `data_plane.rs`, `stats.rs` modules removed
- Flaky `log_level_control` test fix (TOCTOU race with shared socket)
- Dead Intel RSS link removal from documentation
- Misleading `#[allow(dead_code)]` annotations fixed
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
