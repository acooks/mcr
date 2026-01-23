# Control Plane Integration API Plan

## Overview

This document describes the implementation plan for external control plane integration APIs in MCR. These APIs enable MCR to work with overlay networks, mesh routing protocols, and external control systems that maintain their own neighbor discovery and routing information.

## Problem Statement

MCR's current PIM-SM implementation assumes:

1. **Neighbor discovery via PIM Hello** - 30s period with 105s timeout before neighbors are considered valid
2. **RPF via kernel routing table** - Upstream interfaces determined by kernel's unicast routes
3. **Polling-based state queries** - No push notifications for membership changes

These assumptions fail for overlay/mesh deployments where:

- An external routing protocol (e.g., Babel, OSPF) already tracks neighbors with sub-second convergence
- The kernel routing table doesn't reflect overlay topology (tunnels, encrypted links)
- Real-time membership events are needed for policy engines

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              External Control Plane                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ Routing Daemon  │  │ Neighbor Monitor│  │ Forwarding Policy Engine    │  │
│  │ (Babel/OSPF)    │  │ (mesh agent)    │  │ (subscription consumer)     │  │
│  └────────┬────────┘  └────────┬────────┘  └─────────────┬───────────────┘  │
│           │                    │                         │                   │
│           │ RPF queries        │ Neighbor inject         │ Event subscribe  │
│           ▼                    ▼                         ▼                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                     MCR Control Socket API                               ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────────────┐ ││
│  │  │ RPF Provider │  │ Neighbor API │  │ Event Subscription Manager    │ ││
│  │  │ Interface    │  │              │  │                                │ ││
│  │  └──────┬───────┘  └──────┬───────┘  └────────────────┬───────────────┘ ││
│  └─────────┼─────────────────┼───────────────────────────┼─────────────────┘│
└────────────┼─────────────────┼───────────────────────────┼──────────────────┘
             │                 │                           │
             ▼                 ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MCR Supervisor                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────────┐ │
│  │   PIM State      │  │   IGMP State     │  │   MRIB                     │ │
│  │   (neighbors,    │  │   (membership,   │  │   (routes, rules)          │ │
│  │    routes)       │  │    querier)      │  │                            │ │
│  └──────────────────┘  └──────────────────┘  └────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Current Implementation Analysis

### PIM Neighbor Management

**Location:** `src/protocols/pim.rs` (lines 176-357), `src/supervisor.rs` (lines 304-515)

**Current behavior:**

- Neighbors discovered exclusively via PIM Hello exchange
- `PimNeighbor` struct tracks: address, interface, expires_at, dr_priority, generation_id
- Neighbor validity based on holdtime (default 105s)
- DR election runs on neighbor add/remove

**Gap:** No mechanism to inject neighbors from external sources. Join/Prune processing currently does NOT validate that the sender is a known neighbor (see `pim.rs` line 532 where `_upstream_neighbor` is unused).

### RPF Check Implementation

**Location:** `src/mroute.rs` (lines 29-200), `src/protocols/pim.rs` (lines 374-467)

**Current behavior:**

- MCR does NOT query the kernel routing table
- `upstream_interface` field in StarGRoute/SGRoute must be explicitly set
- RPF is implicit: packets accepted only on the configured upstream interface
- No automatic upstream determination from routing lookups

**Gap:** No API to query external routing daemon for RPF information. The `upstream_interface` field exists but has no dynamic source.

### IGMP Membership and Control API

**Location:** `src/protocols/igmp.rs` (lines 153-316), `src/supervisor.rs` (lines 959-979, 3497-3600)

**Current behavior:**

- Membership tracked per-interface in `InterfaceIgmpState.groups` HashMap
- `IgmpGroupInfo` exposed via `GetIgmpGroups` command (request/response)
- Control socket uses JSON-serialized commands over Unix domain socket
- No event streaming or push notification mechanism

**Gap:** External consumers must poll for membership state. No subscription mechanism for real-time events.

## Implementation Phases

### Phase 1: External Neighbor API

**Goal:** Allow external sources to inject and manage PIM neighbors.

**New Types (`src/lib.rs`):**

```rust
/// Source of a PIM neighbor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NeighborSource {
    /// Discovered via PIM Hello exchange
    PimHello,
    /// Injected by external control plane
    External { tag: String },
}

/// External neighbor injection request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalNeighbor {
    pub address: Ipv4Addr,
    pub interface: String,
    /// Optional DR priority (defaults to 1)
    pub dr_priority: Option<u32>,
    /// Optional tag for tracking source
    pub tag: Option<String>,
}
```

**New Commands (`src/lib.rs`):**

- [x] `AddExternalNeighbor { neighbor: ExternalNeighbor }` - Inject neighbor
- [x] `RemoveExternalNeighbor { address: Ipv4Addr, interface: String }` - Remove injected neighbor
- [x] `ListExternalNeighbors` - List externally-managed neighbors
- [x] `ClearExternalNeighbors { interface: Option<String> }` - Remove all external neighbors

**State Changes (`src/protocols/pim.rs`):**

- [x] Add `source: NeighborSource` field to `PimNeighbor`
- [x] External neighbors stored in existing `neighbors` HashMap (distinguished by source field)
- [x] External neighbors have no expiry timer (managed by external source)
- [x] External neighbors participate in DR election
- [x] Added `is_valid_neighbor()` to check both Hello-learned and external neighbors

**CLI Commands (`src/control_client.rs`):**

- [x] `pim add-neighbor --address <IP> --interface <IFACE> [--priority <N>] [--tag <TAG>]`
- [x] `pim remove-neighbor --address <IP> --interface <IFACE>`
- [x] `pim external-neighbors`
- [x] `pim clear-neighbors [--interface <IFACE>]`

**Behavior:**

1. External neighbors are immediately valid for Join/Prune processing
2. If a Hello is received from an external neighbor, it transitions to PimHello source
3. If an external neighbor is removed while Hello-learned, it reverts to Hello-learned state
4. DR election includes external neighbors with their specified priority

### Phase 2: External RPF Provider API

**Goal:** Allow external routing daemons to provide RPF information.

**New Types (`src/lib.rs`):**

```rust
/// RPF lookup result from external provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpfInfo {
    /// Interface toward the source
    pub upstream_interface: String,
    /// Next-hop neighbor toward the source (optional)
    pub upstream_neighbor: Option<Ipv4Addr>,
    /// Metric/preference (lower is better)
    pub metric: Option<u32>,
}

/// RPF provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpfProvider {
    /// No RPF check (accept from any interface)
    Disabled,
    /// Static upstream interface per source/group
    Static,
    /// Query external Unix socket
    External { socket_path: String },
}
```

**New Commands (`src/lib.rs`):**

- [x] `SetRpfProvider { provider: RpfProvider }` - Configure RPF source
- [x] `GetRpfProvider` - Query current RPF configuration
- [x] `QueryRpf { source: Ipv4Addr }` - Manual RPF query (for debugging)
- [x] `AddRpfRoute { source: Ipv4Addr, rpf: RpfInfo }` - Static RPF entry
- [x] `RemoveRpfRoute { source: Ipv4Addr }` - Remove static RPF entry
- [x] `ListRpfRoutes` - List all static RPF entries
- [x] `ClearRpfRoutes` - Clear all static RPF entries

**External RPF Protocol:**

Request (MCR → External):

```json
{"query": "rpf", "source": "10.1.0.5"}
```

Response (External → MCR):

```json
{"upstream_interface": "veth-peer3", "upstream_neighbor": "10.2.0.1", "metric": 100}
```

Note: External socket protocol implementation deferred - static RPF entries are sufficient for initial integration.

**State Changes:**

- [x] Add `rpf_provider: RpfProvider` to `PimConfig`
- [x] Add `static_rpf: HashMap<Ipv4Addr, RpfInfo>` to `PimState`
- [x] Implemented `lookup_rpf()` and `check_rpf()` methods
- [ ] Cache external RPF lookups with configurable TTL (deferred)

**CLI Commands:**

- [x] `pim set-rpf --provider <disabled|static|/path/to/socket>`
- [x] `pim get-rpf`
- [x] `pim query-rpf --source <IP>`
- [x] `pim add-rpf-route --source <IP> --interface <IFACE> [--neighbor <IP>] [--metric <N>]`
- [x] `pim remove-rpf-route --source <IP>`
- [x] `pim list-rpf-routes`
- [x] `pim clear-rpf-routes`

**Integration Points:**

- [ ] `process_join_prune()` - Validate RPF for received Joins (deferred)
- [ ] `create_sg_route()` - Set upstream_interface from RPF lookup (deferred)
- [ ] `process_sa_message()` (MSDP) - RPF check for SA origin (deferred)

### Phase 3: Event Subscription API

**Goal:** Enable push notifications for protocol state changes.

**New Types (`src/lib.rs`):**

```rust
/// Event types that can be subscribed to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    /// IGMP membership changes (join/leave)
    IgmpMembership,
    /// PIM neighbor changes (up/down)
    PimNeighbor,
    /// PIM route changes (add/remove)
    PimRoute,
    /// MSDP SA cache changes
    MsdpSaCache,
}

/// Event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolEventNotification {
    IgmpMembershipChange {
        interface: String,
        group: Ipv4Addr,
        action: MembershipAction,
        reporter: Option<Ipv4Addr>,
        timestamp: u64,
    },
    PimNeighborChange {
        interface: String,
        neighbor: Ipv4Addr,
        action: NeighborAction,
        source: NeighborSource,
        timestamp: u64,
    },
    PimRouteChange {
        route_type: RouteType,
        group: Ipv4Addr,
        source: Option<Ipv4Addr>,
        action: RouteAction,
        timestamp: u64,
    },
    MsdpSaCacheChange {
        source: Ipv4Addr,
        group: Ipv4Addr,
        rp: Ipv4Addr,
        action: SaCacheAction,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MembershipAction { Join, Leave }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NeighborAction { Up, Down }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteAction { Add, Remove, Update }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SaCacheAction { Add, Remove, Refresh }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteType { StarG, SG }
```

**New Commands (`src/lib.rs`):**

- [x] `Subscribe { events: Vec<EventType> }` - Subscribe to event types
- [x] `Unsubscribe { subscription_id: SubscriptionId }` - Unsubscribe from events
- [x] `ListSubscriptions` - List active subscriptions

**Architecture:**

```text
┌────────────────────────────────────────────────────────────┐
│                     Supervisor                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            EventSubscriptionManager                   │  │
│  │  subscribers: HashMap<SocketAddr, HashSet<EventType>> │  │
│  │  event_tx: broadcast::Sender<ProtocolEventNotification>│  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                 │
│            ┌──────────────┴──────────────┐                 │
│            ▼                             ▼                  │
│  ┌──────────────────┐         ┌──────────────────┐        │
│  │ IGMP State       │         │ PIM State        │        │
│  │ (emits events)   │         │ (emits events)   │        │
│  └──────────────────┘         └──────────────────┘        │
└────────────────────────────────────────────────────────────┘
            │
            │ broadcast to subscribers
            ▼
┌────────────────────────────────────────────────────────────┐
│  Client 1 (subscribed: IgmpMembership)                     │
│  Client 2 (subscribed: PimNeighbor, PimRoute)              │
│  Client 3 (subscribed: all)                                │
└────────────────────────────────────────────────────────────┘
```

**Implementation:**

- [x] Add `EventSubscriptionManager` to supervisor
- [x] Modify control socket to support persistent connections for subscribers
- [x] Add event emission hooks in IGMP/PIM/MSDP state machines
- [x] Use `tokio::sync::broadcast` for efficient multi-subscriber delivery
- [x] Add configurable event buffer size (256 events default)
- [x] Handle backpressure via broadcast channel lag warnings

**Wire Format:**

Subscription request:

```json
{"command": "Subscribe", "events": ["IgmpMembership", "PimNeighbor"]}
```

Event notification (server → client):

```json
{"event": "IgmpMembershipChange", "interface": "eth0", "group": "239.1.1.1", "action": "Join", "reporter": "10.0.0.5", "timestamp": 1706012345}
```

### Phase 4: Configuration and Documentation

**Goal:** Document namespace behavior and add configuration options.

**Configuration (`src/config.rs`):**

```rust
/// Control plane integration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    /// RPF provider configuration
    pub rpf_provider: RpfProvider,
    /// Allow external neighbor injection
    pub external_neighbors_enabled: bool,
    /// Event subscription buffer size
    pub event_buffer_size: usize,
    /// External RPF cache TTL in seconds
    pub rpf_cache_ttl: u64,
}
```

**Namespace Documentation:**

- [x] Document that MCR works correctly in network namespaces
- [x] Document control socket path configuration for namespaced deployments
- [x] Add example systemd unit with namespace support
- [x] Document multiple-instance deployment patterns

See: [NAMESPACE_DEPLOYMENT.md](../NAMESPACE_DEPLOYMENT.md) and [examples/mcrd-namespace.service](../../examples/mcrd-namespace.service)

**CLI Additions:**

- [x] `mcrctl config control-plane` - Show integration config
- [x] `mcrctl pim set-rpf --provider <disabled|static|/path/to/socket>` (already implemented in Phase 2)

## Implementation Order

| Phase | Feature | Priority | Complexity | Dependencies |
|-------|---------|----------|------------|--------------|
| 1 | External Neighbor API | High | Medium | None |
| 2 | External RPF Provider | High | High | Phase 1 (for RPF neighbor lookup) |
| 3 | Event Subscription API | Medium | High | None |
| 4 | Configuration & Docs | Low | Low | Phases 1-3 |

## Testing Strategy

### Phase 1 Tests

- [ ] Add external neighbor, verify in neighbor list
- [ ] External neighbor participates in DR election
- [ ] Remove external neighbor, verify removal
- [ ] Hello from external neighbor transitions source type
- [ ] Join/Prune accepted from external neighbor

### Phase 2 Tests

- [ ] Static RPF route lookup
- [ ] External RPF provider query/response
- [ ] RPF cache hit/miss behavior
- [ ] RPF validation in Join processing
- [ ] RPF failure handling (timeout, invalid response)

### Phase 3 Tests

- [ ] Subscribe to single event type
- [ ] Subscribe to multiple event types
- [ ] Unsubscribe from event types
- [ ] Event delivery to multiple subscribers
- [ ] Subscriber disconnect handling
- [ ] Event buffer overflow behavior

## Security Considerations

1. **External neighbor injection** - Only accept from authenticated control socket connections
2. **RPF provider socket** - Validate socket path exists and has correct permissions
3. **Event subscriptions** - Rate limit event delivery to prevent DoS
4. **Input validation** - Validate all external input (IP addresses, interface names)

## Current Status

- **Phase 1:** Complete
- **Phase 2:** Complete (external socket protocol deferred)
- **Phase 3:** Complete
- **Phase 4:** Complete

## Completed Deliverables

1. `ControlPlaneConfig` struct in `src/config.rs` with validation
2. Config wired to supervisor initialization (RPF provider, event buffer size)
3. CLI command `mcrctl config control-plane` to show control plane configuration
4. Namespace deployment documentation: `developer_docs/NAMESPACE_DEPLOYMENT.md`
5. Example systemd template unit: `examples/mcrd-namespace.service`

## Future Work

1. Implement external RPF socket protocol (currently only static RPF entries supported)
2. Add RPF cache with configurable TTL for external lookups
3. Integration testing for namespace deployments
