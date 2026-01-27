# Protocol Topology Test Design

This document describes integration tests to validate PIM-SM and MSDP functional
completeness for Community and Fabric layer deployments.

## Test Categories

| Category | Layer | Purpose |
|----------|-------|---------|
| PIM Neighbor Discovery | Fabric | Validate Hello exchange and neighbor table |
| PIM Tree Building | Fabric | Validate Join/Prune and forwarding state |
| PIM Source Registration | Fabric | Validate Register/Register-Stop to RP |
| IGMP Integration | Fabric | Validate IGMP membership triggers PIM joins |
| MSDP Peering | Community | Validate TCP session establishment |
| MSDP SA Exchange | Community | Validate SA propagation between RPs |
| Anycast-RP | Community | Validate MSDP mesh group for RP redundancy |

---

## Test Infrastructure

### Network Namespace Topology Builder

Each test creates isolated network namespaces connected via veth pairs.

### Common Test Utilities Needed

```rust
/// Topology builder for multi-node tests
struct TopologyBuilder {
    nodes: HashMap<String, TestNode>,
    links: Vec<(String, String, Ipv4Network)>,
}

impl TopologyBuilder {
    /// Create a node with MCR running
    fn add_node(&mut self, name: &str, config: Config) -> &mut Self;

    /// Connect two nodes with a veth pair
    fn connect(&mut self, node_a: &str, node_b: &str, network: &str) -> &mut Self;

    /// Build and start all nodes
    async fn build(&self) -> Topology;
}
```

---

## Category 1: PIM Neighbor Discovery Tests

### Test 1.1: Two-Node PIM Hello Exchange

**Configuration:**

- Node A: PIM enabled on veth interface, DR priority 100
- Node B: PIM enabled on veth interface, DR priority 200

**Validation Steps:**

1. Start both MCR instances with PIM enabled
2. Wait up to 35 seconds (Hello interval + margin)
3. Query `mcrctl pim neighbors` on both nodes
4. **Assert:** Node A sees Node B as neighbor (10.0.0.2)
5. **Assert:** Node B sees Node A as neighbor (10.0.0.1)
6. **Assert:** Node B is elected DR (higher priority)

**Tests PIM Hello send/receive functionality.**

---

### Test 1.2: Three-Node DR Election

**Validation Steps:**

1. Start all three MCR instances
2. Wait for neighbor formation
3. **Assert:** All nodes see each other as neighbors
4. **Assert:** Node B (DR=200) is DR on all nodes
5. Kill Node B
6. Wait for neighbor timeout (3.5 * hello_interval)
7. **Assert:** Node C (DR=150) becomes new DR

**Tests DR election and neighbor expiry.**

---

### Test 1.3: External Neighbor Injection

**Validation Steps:**

1. Start Node A and Node B with PIM enabled
2. On Node B: `mcrctl pim add-external-neighbor --address 10.0.0.99 --interface veth0`
3. Query neighbors on Node B
4. **Assert:** Node B sees 10.0.0.99 as external neighbor
5. **Assert:** External neighbor participates in DR election
6. Remove external neighbor
7. **Assert:** Neighbor no longer in table

**Tests external neighbor API for FRR/Babel integration.**

---

## Category 2: PIM Tree Building Tests

### Test 2.1: RPT Join Propagation

**Configuration:**

- All nodes: PIM enabled, static RP = Node R for 239.0.0.0/8
- Node D: IGMP querier enabled

**Validation Steps:**

1. Start all MCR instances
2. Wait for PIM neighbors to form
3. Inject IGMP join for 239.1.1.1 on Node D
4. Wait for Join propagation (up to 60 seconds)
5. Query mroute on Node R
6. **Assert:** (*,239.1.1.1) entry exists with downstream to Node D
7. Query mroute on Node D
8. **Assert:** (*,239.1.1.1) entry exists with upstream to Node R

**Tests PIM Join/Prune to MRIB integration.**

---

### Test 2.2: SPT Switchover

**Validation Steps:**

1. Establish RPT as in Test 2.1
2. Start sending multicast from Source
3. Verify traffic flows via RP initially
4. Wait for SPT threshold (implementation dependent)
5. **Assert:** (S,G) entry created on Node D
6. **Assert:** Traffic now flows directly Source to Receiver

**Tests SPT switchover mechanism.**

---

### Test 2.3: Prune Propagation

**Topology:** Same as Test 2.1

**Validation Steps:**

1. Establish tree as in Test 2.1
2. Inject IGMP leave for 239.1.1.1 on Node D
3. Wait for Prune propagation
4. **Assert:** (*,239.1.1.1) removed from Node R
5. **Assert:** (*,239.1.1.1) removed from Node D

**Tests PIM Prune processing.**

---

## Category 3: PIM Source Registration Tests

### Test 3.1: Register to RP

**Configuration:**

- Node S: PIM enabled, designated as first-hop router
- Node R: Configured as RP for 239.0.0.0/8

**Validation Steps:**

1. Start MCR on both nodes
2. Wait for PIM neighbor formation
3. Start multicast source on Node S for 239.1.1.1
4. **Assert:** Node S sends PIM Register to RP
5. **Assert:** RP creates (S,G) state
6. **Assert:** RP sends Register-Stop (if no receivers)

**Tests PIM Register encapsulation and handling.**

---

### Test 3.2: Register Suppression

**Validation Steps:**

1. Complete Test 3.1
2. Verify Register-Stop received at Node S
3. **Assert:** Node S suppresses Register messages
4. Wait for Register suppression timeout
5. **Assert:** Node S sends Register probe (null Register)

**Tests Register state machine.**

---

## Category 4: IGMP Integration Tests

### Test 4.1: IGMP Membership to PIM Join

**Validation Steps:**

1. Start MCR with PIM and IGMP querier enabled
2. Inject IGMP Membership Report for 239.1.1.1
3. **Assert:** IGMP group appears in `mcrctl igmp groups`
4. **Assert:** (*,G) entry created in mroute
5. **Assert:** PIM Join sent toward RP

**Tests IGMP to PIM integration.**

---

### Test 4.2: IGMP Querier Election

**Validation Steps:**

1. Start both MCR instances with IGMP querier enabled
2. Wait for query exchange
3. **Assert:** Lower IP (Router A) becomes querier
4. **Assert:** Router B stops sending queries (Other Querier Present)

**Tests IGMP querier election.**

---

## Category 5: MSDP Peering Tests

### Test 5.1: Basic MSDP TCP Session

**Configuration:**

- RP 1: MSDP enabled, peer = 10.0.0.2
- RP 2: MSDP enabled, peer = 10.0.0.1

**Validation Steps:**

1. Start both MCR instances with MSDP enabled
2. Wait up to 60 seconds for TCP connection
3. Query `mcrctl msdp peers` on both nodes
4. **Assert:** Peer state is "established" or "active" on both
5. **Assert:** Uptime > 0

**Tests MSDP TCP session establishment.**

---

### Test 5.2: MSDP Keepalive Exchange

**Validation Steps:**

1. Establish MSDP session as in Test 5.1
2. Wait for 2 * keepalive_interval (default 60s)
3. **Assert:** Session still established
4. **Assert:** No hold timer expiry

**Tests MSDP keepalive mechanism.**

---

### Test 5.3: MSDP Session Recovery

**Validation Steps:**

1. Establish MSDP session as in Test 5.1
2. Kill RP 2 MCR instance
3. Wait for hold timer expiry on RP 1 (default 75s)
4. **Assert:** Peer state changes to "disabled" or "connecting"
5. Restart RP 2
6. Wait for reconnection
7. **Assert:** Session re-established

**Tests MSDP session recovery.**

---

## Category 6: MSDP SA Exchange Tests

### Test 6.1: SA Propagation

**Validation Steps:**

1. Start all MCR instances
2. Establish MSDP session between RP 1 and RP 2
3. Register active source 10.1.1.1 for 239.1.1.1 at RP 1
4. Wait for SA propagation
5. Query SA cache on RP 2
6. **Assert:** SA entry exists: source=10.1.1.1, group=239.1.1.1, origin_rp=RP1

**Tests MSDP SA message exchange.**

---

### Test 6.2: SA Cache Expiry

**Validation Steps:**

1. Complete Test 6.1
2. Stop the source at RP 1
3. Wait for SA hold time (default 60s per SA)
4. **Assert:** SA entry removed from RP 2 cache

**Tests MSDP SA cache timeout.**

---

### Test 6.3: SA Flood Avoidance (Mesh Group)

**Configuration:**

- All RPs: MSDP mesh group "anycast-rp"

**Validation Steps:**

1. Start all MCR instances with mesh group configured
2. Establish all MSDP sessions
3. Inject SA at RP 1
4. **Assert:** RP 2 receives SA from RP 1
5. **Assert:** RP 3 receives SA from RP 1
6. **Assert:** RP 2 does NOT flood SA to RP 3 (mesh group rule)

**Tests MSDP mesh group flood avoidance.**

---

## Category 7: Anycast-RP Tests

### Test 7.1: Anycast-RP with MSDP Synchronization

**Configuration:**

- Both RPs: Anycast address 192.0.2.1
- MSDP mesh group for SA synchronization

**Validation Steps:**

1. Start all MCR instances
2. Establish MSDP mesh between RP 1 and RP 2
3. Source registers to RP 1 (closer)
4. **Assert:** SA propagated to RP 2 via MSDP
5. Receiver 2 joins group
6. **Assert:** RP 2 can build tree using SA from MSDP
7. **Assert:** Traffic reaches Receiver 2

**Tests full Anycast-RP + MSDP integration.**

---

## Category 8: End-to-End Integration Tests

### Test 8.1: Complete Multicast Flow

**Validation Steps:**

1. Start all MCR instances
2. Wait for PIM neighbors to form
3. Receiver joins 239.1.1.1 via IGMP
4. Wait for RPT to build (Join propagation)
5. Source starts sending to 239.1.1.1
6. **Assert:** Traffic reaches Receiver via RPT
7. **Assert:** Correct packet count at Receiver
8. Verify forwarding rules created automatically

**Tests complete PIM-SM data path.**

---

### Test 8.2: Multi-Domain with MSDP

**Validation Steps:**

1. Start all MCR instances
2. Establish MSDP between RP A and RP B
3. Receiver joins in Domain B
4. Source starts in Domain A
5. **Assert:** SA propagated via MSDP
6. **Assert:** Receiver in Domain B receives traffic
7. **Assert:** Correct inter-domain forwarding

**Tests cross-domain multicast with MSDP.**

---

## Test Matrix Summary

| Test ID | Category | PIM | MSDP | IGMP | Automatic Rules |
|---------|----------|-----|------|------|-----------------|
| 1.1 | Neighbor | Y | | | |
| 1.2 | Neighbor | Y | | | |
| 1.3 | Neighbor | Y | | | |
| 2.1 | Tree | Y | | | Y |
| 2.2 | Tree | Y | | | Y |
| 2.3 | Tree | Y | | | Y |
| 3.1 | Register | Y | | | |
| 3.2 | Register | Y | | | |
| 4.1 | IGMP | Y | | Y | Y |
| 4.2 | IGMP | | | Y | |
| 5.1 | Peering | | Y | | |
| 5.2 | Peering | | Y | | |
| 5.3 | Peering | | Y | | |
| 6.1 | SA | | Y | | |
| 6.2 | SA | | Y | | |
| 6.3 | SA | | Y | | |
| 7.1 | Anycast | Y | Y | | Y |
| 8.1 | E2E | Y | | Y | Y |
| 8.2 | E2E | Y | Y | Y | Y |

---

## Implementation Priority

### Phase 1: Foundation (validates current fixes)

- Test 1.1: Two-Node PIM Hello Exchange
- Test 4.2: IGMP Querier Election
- Test 5.1: Basic MSDP TCP Session

### Phase 2: Core Functionality (validates pending work)

- Test 1.2: Three-Node DR Election
- Test 2.1: RPT Join Propagation
- Test 6.1: SA Propagation

### Phase 3: Integration (validates full system)

- Test 4.1: IGMP Membership to PIM Join
- Test 7.1: Anycast-RP with MSDP Synchronization
- Test 8.1: Complete Multicast Flow

### Phase 4: Advanced Scenarios

- Test 2.2: SPT Switchover
- Test 3.1: Register to RP
- Test 8.2: Multi-Domain with MSDP

---

## Expected Test Results Given Current MCR State

| Test | Expected Result | Blocking Issue |
|------|----------------|----------------|
| 1.1 | **PASS** | PIM Hello now wired up |
| 1.2 | **PASS** | DR election works |
| 1.3 | **PASS** | External neighbor API fixed |
| 2.1 | **FAIL** | Join/Prune to MRIB not wired |
| 2.2 | **FAIL** | SPT not implemented |
| 2.3 | **FAIL** | Prune to MRIB not wired |
| 3.1 | **UNKNOWN** | Register handling untested |
| 4.1 | **FAIL** | IGMP to PIM Join not wired |
| 4.2 | **PASS** | IGMP Query now wired up |
| 5.1 | **PARTIAL** | TCP may fail to bind port 639 |
| 6.1 | **UNKNOWN** | Depends on TCP session |
| 7.1 | **FAIL** | Multiple blocking issues |
| 8.1 | **FAIL** | Tree building broken |
| 8.2 | **FAIL** | Multiple blocking issues |

---

## Next Steps

1. Implement `TopologyBuilder` test infrastructure
2. Start with Phase 1 tests to validate current functionality
3. Use test failures to identify and fix remaining gaps
4. Iterate through phases as functionality is completed
