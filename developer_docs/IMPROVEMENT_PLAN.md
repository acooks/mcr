# Project Improvement Plan

Last updated: December 2025

## Priority Legend

- **CRITICAL** - Security, correctness, or major undocumented features
- **HIGH** - Significant impact on maintainability or user experience
- **MEDIUM** - Quality improvements, technical debt
- **LOW** - Nice-to-have, future enhancements

---

## Documentation & API Parity (New Critical Section)

### CRITICAL: Undocumented Features

The following features are implemented in the code but missing from `REFERENCE.md`:

- **`mcrctl config load --replace`**: The code supports a `--replace` flag to overwrite the current ruleset instead of merging. The docs only mention "merging".
  - *Source:* `src/control_client.rs:73`
- **Logging Facilities**: The code defines 12 distinct logging facilities (e.g., `BufferPool`, `PacketParser`, `Security`, `Network`), but the docs only mention `DataPlane` in passing. Users cannot effectively filter logs without this list.
  - *Source:* `src/logging/facility.rs:9`
- **Pinning Configuration**: The JSON5 `pinning` field (mapping interfaces to CPU cores) is shown in an example but its schema and behavior are not formally defined.

### HIGH: Architecture Documentation Gaps

- **Shared Memory Logging**: The architecture documentation (`ARCHITECTURE.md`) explains the "Unified Loop" but fails to detail the cross-process logging architecture (`SharedSPSCRingBuffer`). This is a complex, critical subsystem that needs a dedicated section.

### HIGH: User Experience & Troubleshooting

- **Troubleshooting Guide**: Create `user_docs/TROUBLESHOOTING.md`.
  - Must cover: Kernel tuning verification (`sysctl`), Buffer exhaustion symptoms, Capability issues (`CAP_NET_RAW`).
- **CLI vs Config Feature Matrix**: Explicitly document that rule *names* are currently supported only in JSON config, not the CLI (TODO in `src/control_client.rs`).

---

## Code Improvements

### HIGH Priority

#### Network State Reconciliation

Use `rtnetlink` crate to subscribe to `RTNLGRP_LINK` events. Detect interface up/down and address changes, trigger rule reconciliation.

#### Automated Drift Recovery

Phase 1 (detection) complete. Phase 2 needs: workers report ruleset hash, supervisor compares and triggers sync/restart on mismatch.

### MEDIUM Priority

#### Dynamic Worker Idle Cleanup

Design spec: dynamic workers should exit after grace period of inactivity.

- Track last rule timestamp per dynamic interface
- Check in periodic sync loop (300s interval)
- Gracefully shut down workers with no rules
- **Test:** `test_dynamic_worker_cleanup_after_idle`

#### Buffer Size for Jumbo Frames

Current buffer pool is undersized for jumbo frames (9000+ bytes). Options: add jumbo buffer tier or detect MTU at startup.

#### Multi-Interface Test Coverage

- `test_config_load_merge_vs_replace` - Verify `--replace` flag behavior

### LOW Priority

#### On-Demand Packet Tracing

EnableTrace/DisableTrace/GetTrace commands for per-rule debugging.

#### Benchmark Implementations

Location: `tests/benchmarks/forwarding_rate.rs`

---

## Roadmap

**Near-term:** Documentation Parity (Facilities, Replace flag), Network Reconciliation
**Long-term:** Packet tracing, Benchmarks

---

## Completed (December 2025)

- **Documentation Overhaul**:
  - Restructured User Guide (Prerequisites, Deployment Options).
  - Clarified "Hybrid Architecture" and VPN support.
  - Added "Log Management" to Operational Guide.
- **Multi-Interface Architecture**:
  - JSON5 config file support (`--config`)
  - Dynamic worker spawning for runtime AddRule
  - `mcrctl config show/load/check/save` commands
  - Pinning configuration applied from config
  - Rule naming (`name` field)
- **Binary renaming**: `mcrd`, `mcrctl`, `mcrgen`
- **Hash-based rule IDs**
- **AF_PACKET FD Passing & Privilege Separation**
- **REJECTED:** PACKET_MMAP / Zero-Copy Ingress (ADR 001)
- **Protocol versioning** (`GetVersion` command)
