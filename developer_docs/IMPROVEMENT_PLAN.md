# Project Improvement Plan

Last updated: December 2025

## Priority Legend

- **CRITICAL** - Security or correctness issues
- **HIGH** - Significant impact on maintainability or performance
- **MEDIUM** - Quality improvements, technical debt
- **LOW** - Nice-to-have, future enhancements

---

## Documentation Improvements

### HIGH Priority

- **Create `user_docs/TROUBLESHOOTING.md`**:
  - Centralize troubleshooting steps currently scattered across `GUIDE.md`, `OPERATIONAL_GUIDE.md`, and `QUICK_TEST.md`.
  - Covers: Permission issues (Capabilities), Buffer exhaustion (`buf_exhaust`), Kernel tuning verification, firewall issues.
- **Document CLI Limitations**:
  - Explicitly note that `mcrctl add` does not yet support the `--name` flag.
  - Direct users to use the JSON5 configuration file for named rules.

### MEDIUM Priority

- **Consolidate `user_docs/QUICK_TEST.md`**:
  - This file is currently an orphan and points to developer scripts.
  - Action: Merge relevant content into `user_docs/GUIDE.md` under a "Verification" section or move to `developer_docs/testing/`.
- **Enhance Developer Docs Navigation**:
  - Update `developer_docs/README.md` to provide better visibility and links to the `developer_docs/testing/` subdirectory.
- **JSON5 Configuration Reference**:
  - Create a dedicated section in `REFERENCE.md` defining the full JSON5 schema, including optional fields like `pinning` and `name`, which are currently only shown in examples.

---

## HIGH Priority (Code)

### Network State Reconciliation

Use `rtnetlink` crate to subscribe to RTNLGRP_LINK events. Detect interface up/down and address changes, trigger rule reconciliation.

### Automated Drift Recovery

Phase 1 (detection) complete. Phase 2 needs: workers report ruleset hash, supervisor compares and triggers sync/restart on mismatch.

---

## MEDIUM Priority (Code)

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

### Troubleshooting Guide (See Documentation Section)

*Moved to Documentation Improvements section.*

### Benchmark Implementations

Location: `tests/benchmarks/forwarding_rate.rs` (skeleton with TODOs)

---

## Roadmap

**Near-term:** Network reconciliation, Drift recovery, Documentation consolidation

**Long-term:** Packet tracing, Benchmarks

---

## Completed (December 2025)

- **Documentation Overhaul**:
  - Restructured User Guide (Prerequisites, Deployment Options).
  - Clarified "Hybrid Architecture" and VPN support in Reference/Architecture docs.
  - Added "Log Management" to Operational Guide.
  - Fixed Markdown linting issues.
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
