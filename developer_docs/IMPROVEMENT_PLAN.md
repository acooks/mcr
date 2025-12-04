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

### Dynamic Worker Idle Cleanup

Design spec: dynamic workers should exit after grace period of inactivity.

- Track last rule timestamp per dynamic interface
- Check in periodic sync loop (300s interval)
- Gracefully shut down workers with no rules after configurable timeout
- **Test:** `test_dynamic_worker_cleanup_after_idle`

### Buffer Size for Jumbo Frames

Current buffer pool is undersized for jumbo frames (9000+ bytes). Options: add jumbo buffer tier, make sizes configurable, or detect MTU at startup.

**Related:** PACKET_MMAP proposal was **rejected** (see `developer_docs/decisions/001_buffer_management_strategy.md`).

### Multi-Interface Test Coverage

Remaining tests needed:

- `test_config_load_merge_vs_replace` - Verify `--replace` flag behavior

**Implemented** (in `tests/integration/multi_interface.rs`):

- `test_config_startup_spawns_workers_for_interface`
- `test_dynamic_worker_spawn_on_add_rule`
- `test_multiple_rules_same_interface`
- `test_remove_rule_by_name`
- `test_remove_rule_by_name_not_found`
- `test_config_preserves_rule_names`
- `test_multiple_ingress_interfaces` - Tests config with rules for 2 different input interfaces (veth pairs)
- `test_dynamic_spawn_for_new_interface` - Tests dynamic worker spawn when adding rule for new interface

### CLI Missing Features

The `--name` option for `mcrctl add` is not yet implemented (TODO in `src/control_client.rs:178`). Rules can have names via JSON5 config but not via CLI.

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

- **Multi-Interface Architecture (Complete)**:
  - JSON5 config file support (`--config`)
  - Interfaces derived from rules in config
  - Workers spawned per interface at startup
  - Per-interface fanout_group_id assignment
  - Dynamic worker spawning for runtime AddRule
  - `mcrctl config show/load/check/save` commands
  - Startup config path tracking for `mcrctl save` without args
  - Pinning configuration applied from config (workers spawn on specified cores)
  - Rule naming: `name` field in ForwardingRule, `RemoveRuleByName` implemented
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
