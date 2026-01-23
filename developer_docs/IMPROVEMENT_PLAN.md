# Project Improvement Plan

Last updated: January 2026

## Overview

This is the master roadmap for MCR development. It consolidates all planned work from individual plan documents and tracks completion status.

## Priority Legend

- **CRITICAL** - Security, correctness, or blocking issues
- **HIGH** - Significant impact on maintainability or user experience
- **MEDIUM** - Quality improvements, technical debt
- **LOW** - Nice-to-have, future enhancements

---

## Recently Completed

### Control Plane Integration (January 2026)

Implemented external control plane APIs for overlay/mesh network integration:

- **External Neighbor API:** Inject PIM neighbors from external routing daemons (Babel, OSPF)
- **RPF Provider API:** Static RPF entries for overlay topologies
- **Event Subscription API:** Push notifications for IGMP/PIM/MSDP state changes
- **Namespace Documentation:** Deployment guide for network namespace environments

**Status:** Complete (93%) - External RPF socket protocol intentionally deferred
**Plan:** [plans/archive/CONTROL_PLANE_INTEGRATION.md](plans/archive/CONTROL_PLANE_INTEGRATION.md)

### MSDP Protocol Support (January 2026)

Implemented Multicast Source Discovery Protocol (RFC 3618):

- **State Machine:** Peer states, SA cache management, mesh group support
- **TCP Layer:** Connection management with RFC 3618 collision resolution
- **Protocol Integration:** PIM-to-MSDP and MSDP-to-PIM notifications, SA flooding
- **CLI Commands:** `msdp peers`, `msdp sa-cache`, `msdp add-peer`, etc.

**Status:** Complete (95%) - Integration tests deferred
**Plan:** [plans/archive/MSDP_IMPLEMENTATION.md](plans/archive/MSDP_IMPLEMENTATION.md)

### Multi-Interface Architecture (December 2025)

Redesigned MCR for multiple input interfaces from a single daemon:

- **Configuration:** JSON5 format with pinning and rules
- **Worker Model:** Dynamic spawning, per-interface fanout groups
- **Two-State Config:** Running config vs startup config model
- **CLI:** Full mcrctl command set (23/25 commands)

**Status:** Complete (94%) - Minor CLI polish remaining
**Plan:** [plans/archive/MULTI_INTERFACE_DESIGN.md](plans/archive/MULTI_INTERFACE_DESIGN.md)

### PIM-SM and IGMP Protocol Support (January 2026)

- **IGMPv2 Querier:** Querier election, group membership tracking, RFC 2236 timers
- **PIM-SM:** Neighbor discovery, DR election, (*,G) and (S,G) state machines
- **Multicast RIB:** Unified abstraction merging static rules with protocol-learned routes
- **IGMP-MRIB Integration:** Automatic fanout when hosts join multicast groups

### Logging Subsystem Cleanup (January 2026)

- Removed ~600 lines of dead code (unused ring buffers)
- Fixed log level propagation to workers
- Added per-facility log level control

---

## Remaining Work

### HIGH Priority

#### 1. Fix CAP_CHOWN in Capabilities Documentation

**Source:** CAPABILITIES_AND_PACKAGING plan gap
**Impact:** Users may set insufficient permissions

The plan specified 4 capabilities but only 3 are documented:

| File | Issue |
|------|-------|
| `user_docs/REFERENCE.md` (line 232) | Missing CAP_CHOWN in setcap command |
| `user_docs/SECURITY.md` (line 92) | Missing CAP_CHOWN in setcap example |
| `packaging/systemd/mcrd.service` (lines 13-14) | Missing CAP_CHOWN in AmbientCapabilities |

**Action:** Add CAP_CHOWN to all three files.

#### 2. Split supervisor.rs (6,050 lines)

**Source:** REFACTORING_PLAN
**Impact:** Maintainability bottleneck

Proposed structure:

```text
src/supervisor/
├── mod.rs                  # Orchestration (~500 lines)
├── protocol_state.rs       # ProtocolState struct and methods
├── event_handlers.rs       # handle_igmp/pim/msdp_event
├── worker_manager.rs       # Supervisor, Worker, InterfaceWorkers
├── timer_manager.rs        # TimerState, ProtocolTimerManager
└── command_handler.rs      # handle_supervisor_command
```

**Plan:** [plans/REFACTORING_PLAN.md](plans/REFACTORING_PLAN.md)

#### 3. Network State Reconciliation

**Source:** Original IMPROVEMENT_PLAN
**Impact:** Resilience to network changes

- Detect when interfaces go down or change IP
- Use `rtnetlink` crate in supervisor to monitor network events
- Gracefully handle interface flaps

#### 4. Decouple Protocols from MRIB

**Source:** REFACTORING_PLAN
**Impact:** Testability, maintainability

Protocol handlers should return results instead of directly mutating MRIB. Define `ProtocolHandler` trait for cleaner separation.

### MEDIUM Priority

#### 5. Audit unwrap()/expect() Usage (654 occurrences)

**Source:** REFACTORING_PLAN
**Impact:** Production stability

| File | Count |
|------|-------|
| supervisor.rs | 86 |
| protocols/msdp.rs | 96 |
| protocols/pim.rs | 80 |
| control_client.rs | 80 |

Focus on packet parsing paths where malformed data could cause panics.

#### 6. Add MSDP Integration Tests

**Source:** MSDP_IMPLEMENTATION Phase 5
**Impact:** Test coverage

Missing tests:

- Peer connection establishment (active/passive)
- Keepalive exchange
- SA message exchange
- Mesh group flood suppression
- Peer timeout and reconnection

#### 7. Implement Lazy Socket Creation

**Source:** REFACTORING_PLAN, supervisor.rs TODO
**Impact:** Scalability on multi-interface systems

Workers currently create all AF_PACKET sockets upfront. Implement lazy creation triggered by rule additions.

#### 8. Add CLI --name Options

**Source:** MULTI_INTERFACE_DESIGN gap
**Impact:** User experience

- `mcrctl add --name <NAME>` - Supervisor supports it, CLI has TODO
- `mcrctl remove --name <NAME>` - RemoveRuleByName exists but not wired

#### 9. Consolidate Config Validation

**Source:** REFACTORING_PLAN
**Impact:** Code quality

Create `src/validation.rs` with reusable validators instead of 7 separate validation functions.

#### 10. Reorganize Worker Module

**Source:** REFACTORING_PLAN
**Impact:** Code organization

Split `unified_loop.rs` (1,273 lines) and `packet_parser.rs` (1,404 lines) into focused submodules.

### LOW Priority

#### 11. Add require_mcrd_caps! Macro

**Source:** CAPABILITIES_AND_PACKAGING Phase 4.2
**Impact:** Test convenience

Create test macro that checks for root OR required capabilities (not just root).

#### 12. Add Capability Section to OPERATIONAL_GUIDE.md

**Source:** CAPABILITIES_AND_PACKAGING Phase 1.2
**Impact:** Documentation completeness

Document capability-based deployment as recommended production approach.

#### 13. Dynamic Worker Idle Cleanup

**Source:** Original IMPROVEMENT_PLAN
**Impact:** Resource efficiency

Shut down workers with 0 rules after configurable idle timeout.

#### 14. Jumbo Frame Support

**Source:** Original IMPROVEMENT_PLAN
**Impact:** Feature completeness

Add 9KB buffer slab to BufferPool for jumbo frame support.

#### 15. On-Demand Packet Tracing

**Source:** Original IMPROVEMENT_PLAN
**Impact:** Debugging capability

Add `TraceRule` command to log sampled packets for debugging.

#### 16. Consolidate Display Implementations

**Source:** REFACTORING_PLAN
**Impact:** Code quality

10 repetitive Display implementations could use `strum` crate or string constants.

#### 17. Create Shared Test Fixtures

**Source:** REFACTORING_PLAN
**Impact:** Test maintainability

Extract common test helpers to `tests/common/` module.

#### 18. Standardize API Naming

**Source:** REFACTORING_PLAN
**Impact:** Consistency

Establish and enforce naming conventions (e.g., `group_address` vs `group` vs `group_addr`).

---

## Documentation Gaps

### Undocumented Features

- `mcrctl config load <file> --replace` - Not in REFERENCE.md
- `pinning` JSON object - No formal definition

### Missing Troubleshooting

- MSDP-specific troubleshooting guide

---

## Plan Document Status

| Plan | Status | Location |
|------|--------|----------|
| CONTROL_PLANE_INTEGRATION | **Archived** (93%) | plans/archive/ |
| MSDP_IMPLEMENTATION | **Archived** (95%) | plans/archive/ |
| MULTI_INTERFACE_DESIGN | **Archived** (94%) | plans/archive/ |
| CAPABILITIES_AND_PACKAGING | **Active** (89%) | plans/ |
| REFACTORING_PLAN | **Active** (0%) | plans/ |

---

## Roadmap

### Phase 1: Critical Fixes (1-2 weeks)

1. Fix CAP_CHOWN in capabilities documentation
2. Add CLI --name options
3. Begin supervisor.rs split

### Phase 2: Code Quality (3-4 weeks)

1. Complete supervisor.rs refactoring
2. Audit critical unwrap() calls
3. Decouple protocols from MRIB
4. Add MSDP integration tests

### Phase 3: Features & Polish (5-6 weeks)

1. Network state reconciliation
2. Lazy socket creation
3. Consolidate config validation
4. Documentation updates

### Phase 4: Nice-to-Have (ongoing)

1. Jumbo frame support
2. Packet tracing
3. Test infrastructure improvements
4. API naming standardization
