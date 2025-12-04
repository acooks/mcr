# Project Improvement Plan

Last updated: December 2025

## Priority Legend

- **CRITICAL** - Security or correctness issues
- **HIGH** - Significant impact on maintainability or performance
- **MEDIUM** - Quality improvements, technical debt
- **LOW** - Nice-to-have, future enhancements

---

## HIGH Priority

### Network State Reconciliation

Use `rtnetlink` crate to subscribe to RTNLGRP_LINK events. Detect interface up/down and address changes, trigger rule reconciliation.

### Automated Drift Recovery

Phase 1 (detection) complete. Phase 2 needs: workers report ruleset hash, supervisor compares and triggers sync/restart on mismatch.

---

## MEDIUM Priority

### Buffer Size for Jumbo Frames

Current buffer pool is undersized for jumbo frames (9000+ bytes). Options: add jumbo buffer tier, make sizes configurable, or detect MTU at startup.

**Related:** PACKET_MMAP proposal was **rejected** (see `developer_docs/decisions/001_buffer_management_strategy.md`).

### Disabled Integration Tests

Two tests in `tests/integration/supervisor_resilience.rs` are disabled:

- Line 270: `test_supervisor_applies_exponential_backoff` - needs `run_generic` function or rewrite
- Line 407: `test_supervisor_in_namespace` - unimplemented skeleton, requires root

---

## LOW Priority

### On-Demand Packet Tracing

EnableTrace/DisableTrace/GetTrace commands for per-rule debugging.

### Troubleshooting Guide

Create `user_docs/TROUBLESHOOTING.md` with common errors, permission issues, buffer exhaustion symptoms, performance tuning.

### Benchmark Implementations

Location: `tests/benchmarks/forwarding_rate.rs` (skeleton with TODOs)

---

## Roadmap

**Near-term:** Network reconciliation, Drift recovery

**Long-term:** Packet tracing, Benchmarks

---

## Completed (December 2025)

- **Multi-Interface Architecture**: JSON5 config file support (`--config`), mcrctl config commands (show/load/save/check), multi-interface worker management, dynamic worker spawning
- **Binary renaming**: `multicast_relay` → `mcrd`, `control_client` → `mcrctl`, `traffic_generator` → `mcrgen`
- **Hash-based rule IDs**: Computed from input tuple (interface, group, port) for stability across reloads
- **AF_PACKET FD Passing & Privilege Separation**: Workers drop to nobody:nobody (uid=65534)
- Test cleanup: Removed 26 redundant/broken test files
- Documentation consolidation
- Control plane worker removal
- Dead code cleanup (`ipc.rs`, `data_plane.rs`, `stats.rs`)
- Flaky `log_level_control` test fix
- **REJECTED:** PACKET_MMAP / Zero-Copy Ingress (ADR 001)
- Data Plane Fan-Out (`Arc<[u8]>` zero-copy)
- Protocol versioning (`GetVersion` command)

## Completed (November 2025)

- Legacy two-thread data plane removal (1,814 lines deleted)
- Real-time statistics collection (pipe-based IPC)
- Hash-based drift detection (Phase 1)
- RemoveRule implementation
- SyncRules on worker startup
- Periodic health checks (250ms with auto-restart)
