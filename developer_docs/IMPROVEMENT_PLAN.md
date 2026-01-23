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

### CLI --name Options (January 2026)

- `mcrctl add --name <NAME>` - Name rules for easier management
- `mcrctl remove --name <NAME>` - Remove rules by name

### Supervisor Module Refactoring (January 2026)

Split the 6,050-line supervisor.rs into focused submodules:

```text
src/supervisor/
├── mod.rs                  # Main orchestration, ProtocolState (3,196 lines)
├── command_handler.rs      # Pure command parsing and validation (1,572 lines)
├── worker_manager.rs       # Worker lifecycle, spawn, restart with backoff (745 lines)
├── timer_manager.rs        # Protocol timer scheduling with priority queue (172 lines)
├── socket_helpers.rs       # AF_PACKET socket creation and FD passing (206 lines)
└── event_subscription.rs   # Event broadcast channel management (49 lines)
```

**Status:** Complete - All 309 unit tests, 61 integration tests, and topology tests pass.

### Protocol Handler Decoupling (January 2026)

Refactored protocol event handlers to return explicit actions instead of directly mutating MRIB:

- **MribAction enum:** AddIgmpMembership, RemoveIgmpMembership, AddStarGRoute, RemoveStarGRoute, AddSgRoute, RemoveSgRoute
- **ProtocolHandlerResult:** Unified result type with timers, mrib_actions, and notifications
- **Handler migration:** IGMP, PIM, MSDP, and Timer handlers all return results
- **Centralized application:** process_event() applies actions after handlers return

```text
src/supervisor/
├── actions.rs              # MribAction enum and ProtocolHandlerResult (NEW)
└── mod.rs                  # Updated handlers + apply_mrib_actions(), emit_notifications()
```

**Status:** Complete - All 313 unit tests pass. Handlers are now pure functions.
**Plan:** [plans/archive/REFACTORING_PLAN.md](plans/archive/REFACTORING_PLAN.md) (Section 2)

---

## Remaining Work

### CRITICAL Priority

#### 1. Protocol Packet Transmission Infrastructure

**Source:** PROTOCOL_IMPLEMENTATION_GAP_ANALYSIS (January 2026)
**Impact:** PIM and IGMP control plane completely non-functional

The protocol architecture only supports receiving packets. There is no mechanism for handlers to request packet transmission.

Missing:

- `OutgoingPacket` type in `actions.rs`
- `outgoing_packets` field in `ProtocolHandlerResult`
- Packet send loop in supervisor
- IP header construction for raw sockets

**Report:** [reports/PROTOCOL_IMPLEMENTATION_GAP_ANALYSIS.md](reports/PROTOCOL_IMPLEMENTATION_GAP_ANALYSIS.md)

#### 2. PIM Hello Send/Receive

**Source:** PROTOCOL_IMPLEMENTATION_GAP_ANALYSIS
**Impact:** No PIM neighbor discovery, DR election broken

- `hello_timer_expired()` schedules timers but doesn't build/send Hello packets
- `PimHelloBuilder` exists but is only used in tests
- Neighbor discovery completely non-functional

#### 3. PIM Route to MRIB Integration

**Source:** PROTOCOL_IMPLEMENTATION_GAP_ANALYSIS
**Impact:** PIM routes never become forwarding rules

- `process_join_prune()` results discarded (no MRIB actions generated)
- (*,G) and (S,G) routes exist in PIM state but not in MRIB
- `upstream_interface` never set in route state

### HIGH Priority

#### 4. Network State Reconciliation

**Source:** Original IMPROVEMENT_PLAN
**Impact:** Resilience to network changes

- Detect when interfaces go down or change IP
- Use `rtnetlink` crate in supervisor to monitor network events
- Gracefully handle interface flaps

### MEDIUM Priority

#### 5. Audit unwrap()/expect() Usage

**Source:** REFACTORING_PLAN
**Impact:** Production stability

| File | Count |
|------|-------|
| protocols/msdp.rs | 96 |
| protocols/pim.rs | 80 |
| control_client.rs | 80 |
| supervisor/mod.rs | ~70 |
| supervisor/command_handler.rs | ~16 |

Focus on packet parsing paths where malformed data could cause panics.

#### 6. Add Protocol Integration Tests

**Source:** MSDP_IMPLEMENTATION Phase 5, PROTOCOL_IMPLEMENTATION_GAP_ANALYSIS
**Impact:** Test coverage

No integration tests exist for control plane protocols. Missing:

**MSDP:**

- Peer connection establishment (active/passive)
- Keepalive exchange
- SA message exchange
- Mesh group flood suppression

**PIM:**

- Hello exchange between routers
- Neighbor discovery and DR election
- Join/Prune message processing

**IGMP:**

- Querier election
- Membership report handling

**End-to-End:**

- IGMP join → PIM Join → RP → MSDP SA flow

#### 7. Implement Lazy Socket Creation

**Source:** REFACTORING_PLAN, supervisor.rs TODO
**Impact:** Scalability on multi-interface systems

Workers currently create all AF_PACKET sockets upfront. Implement lazy creation triggered by rule additions.

#### 8. Consolidate Config Validation

**Source:** REFACTORING_PLAN
**Impact:** Code quality

Create `src/validation.rs` with reusable validators instead of 7 separate validation functions.

#### 9. Reorganize Worker Module

**Source:** REFACTORING_PLAN
**Impact:** Code organization

Split `unified_loop.rs` (1,273 lines) and `packet_parser.rs` (1,404 lines) into focused submodules.

### LOW Priority

#### 10. Add require_mcrd_caps! Macro

**Source:** CAPABILITIES_AND_PACKAGING Phase 4.2
**Impact:** Test convenience

Create test macro that checks for root OR required capabilities (not just root).

#### 11. Add Capability Section to OPERATIONAL_GUIDE.md

**Source:** CAPABILITIES_AND_PACKAGING Phase 1.2
**Impact:** Documentation completeness

Document capability-based deployment as recommended production approach.

#### 11. Dynamic Worker Idle Cleanup

**Source:** Original IMPROVEMENT_PLAN
**Impact:** Resource efficiency

Shut down workers with 0 rules after configurable idle timeout.

#### 12. Jumbo Frame Support

**Source:** Original IMPROVEMENT_PLAN
**Impact:** Feature completeness

Add 9KB buffer slab to BufferPool for jumbo frame support.

#### 13. On-Demand Packet Tracing

**Source:** Original IMPROVEMENT_PLAN
**Impact:** Debugging capability

Add `TraceRule` command to log sampled packets for debugging.

#### 14. Consolidate Display Implementations

**Source:** REFACTORING_PLAN
**Impact:** Code quality

10 repetitive Display implementations could use `strum` crate or string constants.

#### 15. Create Shared Test Fixtures

**Source:** REFACTORING_PLAN
**Impact:** Test maintainability

Extract common test helpers to `tests/common/` module.

#### 16. Standardize API Naming

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

All development plans have been consolidated into this document. Original plans are archived for reference.

| Plan | Status | Location |
|------|--------|----------|
| CONTROL_PLANE_INTEGRATION | **Archived** (93%) | plans/archive/ |
| MSDP_IMPLEMENTATION | **Archived** (95%) | plans/archive/ |
| MULTI_INTERFACE_DESIGN | **Archived** (97%) | plans/archive/ |
| CAPABILITIES_AND_PACKAGING | **Archived** (89%) | plans/archive/ |
| REFACTORING_PLAN | **Archived** (100% HIGH) | plans/archive/ |

---

## Roadmap

### Phase 1: Infrastructure ✓ COMPLETE

1. ✓ Add CLI --name options
2. ✓ Split supervisor.rs into submodules
3. ✓ Decouple protocols from MRIB
4. ✓ Fix MSDP connection timer scheduling

### Phase 2: Protocol I/O (CRITICAL)

1. Add outgoing packet infrastructure to supervisor
2. Wire up PIM Hello packet transmission
3. Wire up IGMP Query packet transmission
4. Fix PIM route → MRIB integration
5. Add protocol integration tests

### Phase 3: Code Quality

1. Audit critical unwrap() calls
2. Network state reconciliation
3. Reorganize worker module

### Phase 4: Features & Polish

1. Lazy socket creation
2. Consolidate config validation
3. Documentation updates

### Phase 5: Nice-to-Have (ongoing)

1. Jumbo frame support
2. Packet tracing
3. Test infrastructure improvements
4. API naming standardization
