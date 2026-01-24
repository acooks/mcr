# PIM-SM Implementation Plan

## Executive Summary

PIM-SM is ~35% complete. Core state machines work but routes never reach the forwarding plane. This plan addresses the gaps in 5 phases over approximately 15-20 hours of implementation work.

## Current State

| Component | Status | Issue |
|-----------|--------|-------|
| Hello send/receive | ✅ Working | Timer-driven, packets sent |
| DR election | ✅ Working | Lower IP wins |
| Neighbor discovery | ✅ Working | Expiry timers work |
| Join/Prune parsing | ✅ Working | Messages parsed correctly |
| (*,G) state machine | ✅ Working | State tracked internally |
| (S,G) state machine | ✅ Working | State tracked internally |
| Static RP config | ✅ Working | Longest-prefix match |
| RPF infrastructure | ✅ Working | Static/External providers |
| **Join/Prune → MRIB** | ❌ Broken | Result discarded at mod.rs:634 |
| **upstream_interface** | ❌ Broken | Always None, no RPF lookup |
| **Join/Prune sending** | ❌ Missing | TODO at mod.rs:1119 |
| **Register-Stop** | ❌ Missing | RP never responds |
| **Assert** | ❌ Missing | No forwarder election |

## Phase 1: PIM Route → MRIB Integration (Critical)

**Goal:** Make received Join/Prune messages create forwarding rules.

**Estimated effort:** 4-6 hours

### Task 1.1: Capture Join/Prune Results

**File:** `src/supervisor/mod.rs`
**Location:** Lines 630-641

**Current code:**

```rust
if let Some((upstream, joins, prunes, holdtime)) = parse_pim_join_prune(&payload) {
    let _ = self.pim_state.process_join_prune(  // ❌ Result discarded!
        &interface,
        upstream,
        &joins,
        &prunes,
        Duration::from_secs(holdtime as u64),
    );
}
```

**Change to:**

```rust
if let Some((upstream, joins, prunes, holdtime)) = parse_pim_join_prune(&payload) {
    let timers = self.pim_state.process_join_prune(
        &interface,
        upstream,
        &joins,
        &prunes,
        Duration::from_secs(holdtime as u64),
    );
    result.add_timers(timers);

    // Create MRIB actions for joins
    let now = Instant::now();
    let expiry = now + Duration::from_secs(holdtime as u64);

    for (source_opt, group) in &joins {
        match source_opt {
            None => {
                // (*,G) join - shared tree
                if let Some(rp) = self.pim_state.config.get_rp_for_group(*group) {
                    let upstream_iface = self.pim_state.lookup_rpf(rp)
                        .map(|rpf| rpf.upstream_interface.clone());

                    let mut route = StarGRoute::new(*group, rp);
                    route.upstream_interface = upstream_iface;
                    route.downstream_interfaces.insert(interface.clone());
                    route.expires_at = Some(expiry);
                    result.add_action(MribAction::AddStarGRoute(route));
                }
            }
            Some(source) => {
                // (S,G) join - source tree
                let upstream_iface = self.pim_state.lookup_rpf(*source)
                    .map(|rpf| rpf.upstream_interface.clone());

                let mut route = SGRoute::new(*source, *group);
                route.upstream_interface = upstream_iface;
                route.downstream_interfaces.insert(interface.clone());
                route.expires_at = Some(expiry);
                result.add_action(MribAction::AddSgRoute(route));
            }
        }
    }

    // Handle prunes - remove downstream interfaces
    for (source_opt, group) in &prunes {
        match source_opt {
            None => {
                result.add_action(MribAction::RemoveStarGDownstream {
                    group: *group,
                    interface: interface.clone(),
                });
            }
            Some(source) => {
                result.add_action(MribAction::RemoveSgDownstream {
                    source: *source,
                    group: *group,
                    interface: interface.clone(),
                });
            }
        }
    }
}
```

### Task 1.2: Add New MRIB Actions

**File:** `src/supervisor/actions.rs`

Add new action variants for downstream removal:

```rust
pub enum MribAction {
    // ... existing variants ...

    /// Remove a downstream interface from (*,G) route
    RemoveStarGDownstream { group: Ipv4Addr, interface: String },

    /// Remove a downstream interface from (S,G) route
    RemoveSgDownstream { source: Ipv4Addr, group: Ipv4Addr, interface: String },
}
```

### Task 1.3: Implement Action Handlers

**File:** `src/supervisor/mod.rs` in `apply_mrib_actions()`

Add handlers for new actions:

```rust
MribAction::RemoveStarGDownstream { group, interface } => {
    if let Some(route) = self.mrib.get_star_g_route_mut(group) {
        route.downstream_interfaces.remove(&interface);
        if route.downstream_interfaces.is_empty() {
            self.mrib.remove_star_g_route(group);
        }
    }
}
MribAction::RemoveSgDownstream { source, group, interface } => {
    if let Some(route) = self.mrib.get_sg_route_mut(source, group) {
        route.downstream_interfaces.remove(&interface);
        if route.downstream_interfaces.is_empty() {
            self.mrib.remove_sg_route(source, group);
        }
    }
}
```

### Task 1.4: Add MRIB Accessor Methods

**File:** `src/mroute.rs`

Add mutable accessors if not present:

```rust
pub fn get_star_g_route_mut(&mut self, group: Ipv4Addr) -> Option<&mut StarGRoute> {
    self.star_g_routes.get_mut(&group)
}

pub fn get_sg_route_mut(&mut self, source: Ipv4Addr, group: Ipv4Addr) -> Option<&mut SGRoute> {
    self.sg_routes.get_mut(&(source, group))
}
```

### Task 1.5: Test Phase 1

Create test in `tests/integration/topology.rs`:

```rust
#[tokio::test]
async fn test_pim_join_creates_route() {
    // Setup: Two PIM routers, one receiver
    // Action: Receiver sends IGMP join, downstream router sends PIM Join
    // Verify: Upstream router has (*,G) route with downstream interface
}
```

## Phase 2: Join/Prune Message Transmission

**Goal:** Send Join/Prune messages upstream toward RP/source.

**Estimated effort:** 4-5 hours

### Task 2.1: Create PimJoinPruneBuilder

**File:** `src/protocols/pim.rs`

```rust
/// Builder for PIM Join/Prune messages (RFC 7761 Section 4.9.5)
pub struct PimJoinPruneBuilder {
    upstream_neighbor: Ipv4Addr,
    holdtime: u16,
    groups: Vec<JoinPruneGroup>,
}

struct JoinPruneGroup {
    group: Ipv4Addr,
    joins: Vec<EncodedSource>,
    prunes: Vec<EncodedSource>,
}

struct EncodedSource {
    address: Ipv4Addr,
    wildcard: bool,   // W bit - (*,G) vs (S,G)
    rpt: bool,        // R bit - RPT bit
}

impl PimJoinPruneBuilder {
    pub fn new(upstream_neighbor: Ipv4Addr, holdtime: u16) -> Self {
        Self {
            upstream_neighbor,
            holdtime,
            groups: Vec::new(),
        }
    }

    pub fn add_star_g_join(&mut self, group: Ipv4Addr, rp: Ipv4Addr) {
        // Add (*,G) join with W=1, R=1
    }

    pub fn add_sg_join(&mut self, source: Ipv4Addr, group: Ipv4Addr) {
        // Add (S,G) join with W=0, R=0
    }

    pub fn add_star_g_prune(&mut self, group: Ipv4Addr, rp: Ipv4Addr) {
        // Add (*,G) prune
    }

    pub fn add_sg_prune(&mut self, source: Ipv4Addr, group: Ipv4Addr) {
        // Add (S,G) prune
    }
}

impl PacketBuilder for PimJoinPruneBuilder {
    fn build(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // PIM header: version=2, type=3 (Join/Prune)
        packet.push(0x23);  // Version 2, Type 3
        packet.push(0x00);  // Reserved
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder

        // Encoded unicast address (upstream neighbor)
        packet.push(1);  // Address family: IPv4
        packet.push(0);  // Encoding type
        packet.extend_from_slice(&self.upstream_neighbor.octets());

        // Reserved + Num groups + Holdtime
        packet.push(0);
        packet.push(self.groups.len() as u8);
        packet.extend_from_slice(&self.holdtime.to_be_bytes());

        // Encode each group
        for group in &self.groups {
            // Encoded group address
            packet.push(1);  // Address family
            packet.push(0);  // Encoding type
            packet.push(0);  // Reserved
            packet.push(32); // Mask length
            packet.extend_from_slice(&group.group.octets());

            // Join count + Prune count
            packet.extend_from_slice(&(group.joins.len() as u16).to_be_bytes());
            packet.extend_from_slice(&(group.prunes.len() as u16).to_be_bytes());

            // Encode joins
            for src in &group.joins {
                self.encode_source(&mut packet, src);
            }

            // Encode prunes
            for src in &group.prunes {
                self.encode_source(&mut packet, src);
            }
        }

        // Calculate and set checksum
        let checksum = pim_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        packet
    }
}
```

### Task 2.2: Implement Join/Prune Timer Handler

**File:** `src/supervisor/mod.rs`

**Location:** Lines 1115-1120

```rust
TimerType::PimJoinPrune { interface, group } => {
    // Look up route for this group
    if let Some(route) = self.pim_state.star_g.get(&group) {
        // Only send if we have downstream interfaces on this interface
        if route.downstream_interfaces.contains(&interface) {
            // Find upstream neighbor
            if let Some(upstream_iface) = &route.upstream_interface {
                if let Some(iface_state) = self.pim_state.get_interface(upstream_iface) {
                    // Get DR as upstream neighbor
                    if let Some(dr) = iface_state.get_dr() {
                        let mut builder = PimJoinPruneBuilder::new(
                            dr.address,
                            (self.pim_state.config.join_prune_holdtime.as_secs() * 3) as u16,
                        );
                        builder.add_star_g_join(group, route.rp);

                        result.send_packet(OutgoingPacket {
                            protocol: ProtocolType::Pim,
                            interface: upstream_iface.clone(),
                            destination: dr.address,  // Unicast to upstream
                            source: None,
                            data: builder.build(),
                        });
                    }
                }
            }

            // Reschedule timer
            result.add_timer(TimerRequest {
                timer_type: TimerType::PimJoinPrune { interface, group },
                fire_at: now + self.pim_state.config.join_prune_period,
                replace_existing: true,
            });
        }
    }
}
```

### Task 2.3: Schedule Initial Join/Prune Timers

When a route is created, schedule the first Join/Prune timer.

**File:** `src/supervisor/mod.rs` in Phase 1 join handling

Add after creating route:

```rust
// Schedule Join/Prune refresh timer
if let Some(upstream) = &route.upstream_interface {
    result.add_timer(TimerRequest {
        timer_type: TimerType::PimJoinPrune {
            interface: upstream.clone(),
            group: *group,
        },
        fire_at: now + Duration::from_secs(60), // t_periodic
        replace_existing: true,
    });
}
```

## Phase 3: IGMP → PIM Triggered Joins

**Goal:** When IGMP membership appears, trigger PIM Join toward RP.

**Estimated effort:** 3-4 hours

### Task 3.1: Add IGMP Membership Event Handler

**File:** `src/supervisor/mod.rs` in `handle_igmp_event()`

After adding IGMP membership to MRIB:

```rust
IgmpEvent::MembershipReport { interface, group, source } => {
    // ... existing MRIB update ...

    // Trigger PIM Join if PIM is enabled
    if self.pim_enabled {
        if let Some(rp) = self.pim_state.config.get_rp_for_group(group) {
            // Check if we already have a (*,G) route
            if !self.mrib.has_star_g_route(group) {
                // Create (*,G) Join toward RP
                let upstream_iface = self.pim_state.lookup_rpf(rp)
                    .map(|rpf| rpf.upstream_interface.clone());

                let mut route = StarGRoute::new(group, rp);
                route.upstream_interface = upstream_iface.clone();
                route.downstream_interfaces.insert(interface.clone());
                route.expires_at = Some(now + Duration::from_secs(210));
                result.add_action(MribAction::AddStarGRoute(route));

                // Schedule Join/Prune timer
                if let Some(upstream) = upstream_iface {
                    result.add_timer(TimerRequest {
                        timer_type: TimerType::PimJoinPrune {
                            interface: upstream,
                            group,
                        },
                        fire_at: now,  // Send immediately
                        replace_existing: false,
                    });
                }
            } else {
                // Route exists, just add downstream interface
                result.add_action(MribAction::AddStarGDownstream {
                    group,
                    interface: interface.clone(),
                });
            }
        }
    }
}
```

### Task 3.2: Add AddStarGDownstream Action

**File:** `src/supervisor/actions.rs`

```rust
/// Add a downstream interface to existing (*,G) route
AddStarGDownstream { group: Ipv4Addr, interface: String },
```

### Task 3.3: Handle IGMP Leave → PIM Prune

When last member leaves, send PIM Prune:

```rust
IgmpEvent::MembershipExpired { interface, group } => {
    // ... existing removal ...

    // Check if this was the last receiver for this group
    let remaining = self.mrib.get_igmp_interfaces_for_group(group);
    if remaining.is_empty() && self.pim_enabled {
        // No more receivers, send Prune
        if let Some(route) = self.mrib.get_star_g_route(group) {
            // Schedule immediate Prune
            if let Some(upstream) = &route.upstream_interface {
                // ... build and send Prune ...
            }
        }
    }
}
```

## Phase 4: Register/Register-Stop (RP Functionality)

**Goal:** Complete RP-side Register handling.

**Estimated effort:** 3-4 hours

### Task 4.1: Create RegisterStopBuilder

**File:** `src/protocols/pim.rs`

```rust
pub struct PimRegisterStopBuilder {
    group: Ipv4Addr,
    source: Ipv4Addr,
}

impl PacketBuilder for PimRegisterStopBuilder {
    fn build(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // PIM header: version=2, type=2 (Register-Stop)
        packet.push(0x22);
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        // Encoded group
        packet.push(1);  // Family
        packet.push(0);  // Encoding
        packet.push(0);  // Reserved
        packet.push(32); // Mask
        packet.extend_from_slice(&self.group.octets());

        // Encoded source
        packet.push(1);
        packet.push(0);
        packet.extend_from_slice(&self.source.octets());

        // Set checksum
        let checksum = pim_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        packet
    }
}
```

### Task 4.2: Send Register-Stop on Register Receipt

**File:** `src/supervisor/mod.rs` in Register handler

```rust
PimEvent::PacketReceived { msg_type: PIM_REGISTER, .. } => {
    // ... existing parsing ...

    // Check if we're the RP for this group
    if Some(self.pim_state.config.router_id) == self.pim_state.config.get_rp_for_group(group) {
        // We are the RP - create (S,G) state
        let mut route = SGRoute::new(source, group);
        route.downstream_interfaces = self.mrib.get_igmp_interfaces_for_group(group);
        result.add_action(MribAction::AddSgRoute(route));

        // Send Register-Stop to first-hop router
        let builder = PimRegisterStopBuilder::new(group, source);
        result.send_packet(OutgoingPacket {
            protocol: ProtocolType::Pim,
            interface: interface.clone(),
            destination: src_ip,  // Unicast back to sender
            source: None,
            data: builder.build(),
        });
    }
}
```

## Phase 5: Testing & Validation

**Goal:** Comprehensive test coverage for PIM-SM.

**Estimated effort:** 3-4 hours

### Test Cases

1. **test_pim_star_g_join_propagation**
   - Receiver joins group via IGMP
   - Verify (*,G) route created
   - Verify Join sent toward RP

2. **test_pim_sg_route_creation**
   - RP receives Register
   - Verify (S,G) route created
   - Verify Register-Stop sent

3. **test_pim_prune_on_leave**
   - Last receiver leaves
   - Verify Prune sent upstream
   - Verify route removed

4. **test_pim_join_prune_refresh**
   - Route created
   - Wait for refresh interval
   - Verify Join resent

5. **test_pim_upstream_interface_selection**
   - Configure RPF routes
   - Verify correct upstream selected

6. **test_pim_multipath_rpf**
   - Multiple paths to RP
   - Verify consistent path selection

## Implementation Order

```text
Phase 1: Route → MRIB (CRITICAL - enables forwarding)
    ↓
Phase 3: IGMP → PIM (enables receiver-driven trees)
    ↓
Phase 2: Join/Prune sending (enables multi-hop trees)
    ↓
Phase 4: Register-Stop (completes RP functionality)
    ↓
Phase 5: Testing
```

## Success Criteria

After implementation:

- [ ] IGMP join triggers PIM (*,G) state
- [ ] (*,G) routes appear in MRIB with correct interfaces
- [ ] (S,G) routes appear in MRIB with correct interfaces
- [ ] Join/Prune messages sent upstream
- [ ] Register messages trigger Register-Stop
- [ ] Routes expire correctly
- [ ] Prunes remove downstream interfaces
- [ ] Multi-hop tree building works
- [ ] All Phase 1 topology tests still pass
- [ ] New PIM topology tests pass

## Files Modified

| File | Changes |
|------|---------|
| `src/supervisor/mod.rs` | Join/Prune→MRIB, IGMP→PIM trigger, Register-Stop |
| `src/supervisor/actions.rs` | New MribAction variants |
| `src/protocols/pim.rs` | PimJoinPruneBuilder, PimRegisterStopBuilder |
| `src/mroute.rs` | Mutable route accessors |
| `tests/integration/topology.rs` | New PIM tree building tests |

## Dependencies

- Phase 1 has no dependencies (can start immediately)
- Phase 2 depends on Phase 1 (needs routes to know what to refresh)
- Phase 3 depends on Phase 1 (needs route creation infrastructure)
- Phase 4 depends on Phase 2 (uses similar builder pattern)
- Phase 5 depends on all previous phases

## Risk Mitigation

1. **RPF lookup failures:** Default to no upstream if RPF unavailable
2. **Timer storms:** Rate-limit Join/Prune sending
3. **State explosion:** Limit max routes per group
4. **Backward compatibility:** All existing tests must pass
