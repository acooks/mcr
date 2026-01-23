# Protocol Implementation Gap Analysis

Date: January 2026

## Executive Summary

MCR's control plane protocols (PIM-SM, MSDP, IGMP) have state machines implemented but critical I/O pathways are missing or broken. The data plane forwarding works correctly, but automatic multicast routing via protocols is non-functional.

## Status by Component

| Component | State Machine | Packet Rx | Packet Tx | MRIB Integration | Tests |
|-----------|--------------|-----------|-----------|------------------|-------|
| **Data Plane** | N/A | Working | Working | N/A | Integration |
| **IGMP Rx** | Complete | Working | - | Working | Unit only |
| **IGMP Tx (Queries)** | Complete | - | **MISSING** | - | None |
| **PIM Hello Rx** | Complete | Working | - | - | Unit only |
| **PIM Hello Tx** | Complete | - | **MISSING** | - | None |
| **PIM Join/Prune Rx** | Complete | Working | - | **BROKEN** | Unit only |
| **PIM Join/Prune Tx** | Partial | - | **MISSING** | - | None |
| **PIM Register** | Partial | Working | **MISSING** | **BROKEN** | Unit only |
| **MSDP State Machine** | Complete | Working | Working | Working | Unit only |
| **MSDP TCP Sessions** | Complete | Working | Working | - | None |

## Critical Issues

### Issue 1: MSDP Connection Timers Not Scheduled (FIXED)

**Status:** Fixed in commit `bba92f1`

Timers from `add_peer()` were discarded, preventing TCP connection attempts.

### Issue 2: No Outgoing Packet Infrastructure

**Status:** Not implemented

**Problem:** The protocol architecture only supports receiving packets. There is no mechanism for protocol handlers to request packet transmission.

**Missing:**

```rust
// In actions.rs - needs to be added
pub struct OutgoingPacket {
    pub interface: String,
    pub destination: Ipv4Addr,
    pub protocol: u8,  // 2=IGMP, 103=PIM
    pub payload: Vec<u8>,
}

// In ProtocolHandlerResult - needs to be added
pub outgoing_packets: Vec<OutgoingPacket>,
```

**Impact:**

- PIM Hello packets never sent → No neighbor discovery
- IGMP Queries never sent → Querier functionality broken
- PIM Join/Prune never sent → Can't build multicast trees

### Issue 3: PIM Routes Not Added to MRIB

**Status:** Not implemented

**Problem:** When PIM processes Join/Prune messages, routes are created in PIM state (`pim_state.star_g`, `pim_state.sg`) but never added to the MRIB.

**Location:** `src/supervisor/mod.rs` lines 583-601

```rust
let _ = self.pim_state.process_join_prune(...);  // Result discarded!
```

**Impact:**

- (*,G) and (S,G) routes never reach MRIB
- `compile_forwarding_rules()` never sees PIM routes
- Data plane never receives rules from PIM

### Issue 4: Upstream Interface Never Set

**Status:** Not implemented

**Problem:** PIM routes need `upstream_interface` to be compiled into forwarding rules, but this field is never populated.

**Location:** `src/protocols/pim.rs`

- `StarGState` initialized with `upstream_interface: None`
- `SGState` initialized with `upstream_interface: None`
- No code path sets these fields

**Impact:**

- Even if routes were in MRIB, no forwarding rules generated
- RPF lookup not implemented

### Issue 5: IGMP Doesn't Trigger PIM Joins

**Status:** Not implemented

**Problem:** When IGMP reports a new group membership, the PIM state machine should initiate a Join toward the RP. This linkage doesn't exist.

**Expected Flow:**

```text
IGMP Report (new group) → Check if (*,G) exists → If not, send (*,G) Join to RP
```

**Current Flow:**

```text
IGMP Report → Add to MRIB → Done (no PIM interaction)
```

## Test Coverage Gap

### Current Test Coverage

| Test Type | Protocols Covered | Notes |
|-----------|------------------|-------|
| Unit tests (313) | IGMP, PIM, MSDP state machines | Complete |
| Integration tests | Data plane only | No protocol I/O |
| Topology tests | Data plane forwarding | No control plane |
| Performance tests | Data plane throughput | No protocol load |

### Missing Tests

1. **MSDP Integration Tests** (already in IMPROVEMENT_PLAN)
   - Peer connection establishment
   - SA message exchange
   - Keepalive handling

2. **PIM Integration Tests** (NEW)
   - Hello exchange between routers
   - Neighbor discovery and DR election
   - Join/Prune message processing
   - Route installation verification

3. **IGMP Integration Tests** (NEW)
   - Querier election
   - Membership report handling
   - Group timeout behavior

4. **End-to-End Protocol Tests** (NEW)
   - IGMP join → PIM Join → RP → MSDP SA → Remote PIM
   - Full multicast tree establishment

## Implementation Roadmap

### Phase 1: Outgoing Packet Infrastructure (HIGH PRIORITY)

1. Add `OutgoingPacket` type to `actions.rs`
2. Add `outgoing_packets` field to `ProtocolHandlerResult`
3. Add `send_outgoing_packets()` method in supervisor
4. Wire up IP header construction for raw sockets
5. Test with PIM Hello packets

**Effort:** ~8 hours

### Phase 2: PIM Hello Send (HIGH PRIORITY)

1. Modify `hello_timer_expired()` to build and return Hello packet
2. Add PIM Hello to outgoing packet queue in timer handler
3. Test neighbor discovery between two MCR instances

**Effort:** ~4 hours

### Phase 3: PIM Route → MRIB Integration (HIGH PRIORITY)

1. Modify `handle_pim_event()` to generate MRIB actions from Join/Prune
2. Implement upstream interface determination (static RPF first)
3. Test route installation from Join messages

**Effort:** ~6 hours

### Phase 4: IGMP Query Send (MEDIUM PRIORITY)

1. Wire up `query_timer_expired()` to send Query packets
2. Test querier functionality

**Effort:** ~3 hours

### Phase 5: IGMP → PIM Trigger (MEDIUM PRIORITY)

1. When IGMP adds new membership, check PIM state
2. If no (*,G) exists, trigger Join toward RP
3. Test end-to-end flow

**Effort:** ~4 hours

### Phase 6: Protocol Integration Tests (HIGH PRIORITY)

1. Create `tests/integration/protocol_pim.rs`
2. Create `tests/integration/protocol_msdp.rs`
3. Create `tests/integration/protocol_igmp.rs`
4. Create multi-router topology test

**Effort:** ~10 hours

## Files Requiring Changes

| File | Changes Needed |
|------|----------------|
| `src/supervisor/actions.rs` | Add `OutgoingPacket`, update `ProtocolHandlerResult` |
| `src/supervisor/mod.rs` | Add packet send loop, fix Join/Prune handling |
| `src/protocols/pim.rs` | Return packets from timer handlers |
| `src/protocols/igmp.rs` | Return packets from query handler |
| `tests/integration/protocol_*.rs` | New test files |

## Verification Criteria

1. **PIM Hello:** `mcrctl pim neighbors` shows discovered neighbors
2. **PIM Routes:** `mcrctl pim routes` shows learned (*,G) and (S,G) routes
3. **MSDP Sessions:** `mcrctl msdp peers` shows Established state
4. **IGMP Querier:** tcpdump shows outgoing IGMP queries
5. **End-to-End:** Traffic flows through protocol-learned routes

## References

- RFC 7761 - PIM-SM
- RFC 3618 - MSDP
- RFC 2236 - IGMPv2
- IMPROVEMENT_PLAN.md - Item 3 (MSDP Integration Tests)
