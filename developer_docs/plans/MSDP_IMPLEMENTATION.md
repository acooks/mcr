# MSDP Implementation Plan

## Overview

This document describes the implementation plan for MSDP (Multicast Source Discovery Protocol, RFC 3618) support in MCR. MSDP enables inter-domain multicast by allowing PIM-SM domains to share information about active multicast sources.

## Purpose

MSDP solves the problem of multicast source discovery across PIM-SM domains:

- Receivers in one domain can learn about sources in other domains
- Enables inter-domain multicast without requiring a shared RP
- Commonly used for Anycast-RP deployments within a single domain

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                         Supervisor                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ IGMP FSM    │  │ PIM-SM FSM  │  │ MSDP FSM    │              │
│  │ (per-iface) │  │ (global)    │  │ (global)    │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         └────────────────┴────────────────┘                      │
│                          │                                       │
│                 ┌────────┴────────┐                              │
│                 │ Multicast RIB   │                              │
│                 │ (*,G) and (S,G) │                              │
│                 └────────┬────────┘                              │
│                          │                                       │
│  ┌───────────────────────┼───────────────────────┐              │
│  │ Raw Sockets           │  TCP Connections      │              │
│  │ (IGMP/PIM)            │  (MSDP port 639)      │              │
│  └───────────────────────┴───────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Phases

### Phase 0: Foundation (COMPLETE)

**Goal:** Establish configuration, types, and CLI framework.

- [x] Add `MsdpConfig` and `MsdpPeerConfig` to `src/config.rs`
- [x] Add config validation (unicast addresses, hold_time > keepalive, no duplicates)
- [x] Add `SupervisorCommand` variants: `GetMsdpPeers`, `GetMsdpSaCache`, `AddMsdpPeer`, `RemoveMsdpPeer`, `ClearMsdpSaCache`
- [x] Add `Response` variants: `MsdpPeers`, `MsdpSaCache`
- [x] Add `MsdpPeerInfo` and `MsdpSaCacheInfo` types to `src/lib.rs`
- [x] Add CLI commands to `src/control_client.rs`: `msdp peers`, `msdp sa-cache`, `msdp add-peer`, `msdp remove-peer`, `msdp clear-sa-cache`

### Phase 1: State Machine (COMPLETE)

**Goal:** Implement core MSDP protocol logic.

- [x] Create `src/protocols/msdp.rs` with:
  - [x] `MsdpPeerState` enum (Disabled, Connecting, Established, Active)
  - [x] `MsdpPeer` struct with connection state and statistics
  - [x] `MsdpPeerConfig` for per-peer configuration
  - [x] `SaCacheEntry` for SA cache entries (local and learned)
  - [x] `MsdpState` for global state (peers, SA cache, mesh groups)
  - [x] `MsdpEvent` enum for state machine events
  - [x] `MsdpGlobalConfig` for global settings
- [x] Implement SA cache management:
  - [x] Add/remove/refresh entries
  - [x] Expiry tracking
  - [x] Local vs learned source distinction
- [x] Implement mesh group logic:
  - [x] Track mesh group membership
  - [x] Flood suppression within mesh groups
- [x] Implement message parsing:
  - [x] `MsdpHeader` parsing (type, length)
  - [x] `MsdpSaMessage` parsing (entry count, RP address, source/group pairs)
- [x] Implement message building:
  - [x] `MsdpSaBuilder` for SA messages
  - [x] `MsdpKeepaliveBuilder` for keepalive messages
- [x] Add timer types to `src/protocols/mod.rs`:
  - [x] `MsdpConnectRetry`
  - [x] `MsdpKeepalive`
  - [x] `MsdpHold`
  - [x] `MsdpSaCacheExpiry`
- [x] Add unit tests for state machine logic

### Phase 2: TCP Layer (COMPLETE)

**Goal:** Implement TCP connection management.

- [x] Create `src/protocols/msdp_tcp.rs` with:
  - [x] `MsdpConnection` for individual peer connections
  - [x] `MsdpConnectionManager` for managing all connections
- [x] Implement connection establishment:
  - [x] Active connections (we initiate to lower-IP peers)
  - [x] Passive connections (accept from higher-IP peers)
  - [x] RFC 3618 collision resolution (higher IP initiates)
- [x] Implement message I/O:
  - [x] Buffered reading with message framing
  - [x] `send_keepalive()` and `send_sa()` methods
  - [x] `flood_sa()` for sending to multiple peers
- [x] Implement TCP listener:
  - [x] `start_msdp_listener()` function
  - [x] Accept loop with stop channel
- [x] Add unit tests for TCP layer

### Phase 3: Supervisor Integration (COMPLETE)

**Goal:** Wire MSDP into the supervisor's event loop.

- [x] Add `MsdpState` to `ProtocolState` struct
- [x] Add `msdp_enabled` flag
- [x] Implement `enable_msdp()` to initialize from config
- [x] Implement `handle_msdp_event()` for all `MsdpEvent` variants
- [x] Add `ProtocolEvent::Msdp` variant
- [x] Add MSDP to protocol subsystem initialization check
- [x] Implement MSDP timer handling in `handle_timer_expired()`:
  - [x] `MsdpConnectRetry`: Send connect command to TCP runner
  - [x] `MsdpKeepalive`: Send keepalive command, update stats
  - [x] `MsdpHold`: Send disconnect command, close peer
  - [x] `MsdpSaCacheExpiry`: Remove expired SA entry
- [x] Implement command responses with real data:
  - [x] `GetMsdpPeers`: Return `msdp_state.peers` as `MsdpPeerInfo` vec
  - [x] `GetMsdpSaCache`: Return `msdp_state.sa_cache` as `MsdpSaCacheInfo` vec
- [x] Wire command actions to protocol state:
  - [x] `AddMsdpPeer`: Directly add peer to `msdp_state`
  - [x] `RemoveMsdpPeer`: Directly remove peer from `msdp_state`
  - [x] `ClearMsdpSaCache`: Clear SA cache directly
- [x] Wire `MsdpTcpRunner` into supervisor:
  - [x] Create `MsdpTcpCommand` enum for TCP operations
  - [x] Implement `MsdpTcpRunner` task for connection management
  - [x] Start TCP listener when MSDP enabled
  - [x] Spawn connection reader tasks for each peer
  - [x] Handle incoming connections with collision resolution
  - [x] Connect timer events to TCP command channel

### Phase 4: Protocol Integration (TODO)

**Goal:** Integrate MSDP with PIM-SM for full functionality.

- [ ] **PIM-to-MSDP notifications:**
  - [ ] When PIM registers a new local source (S,G), notify MSDP
  - [ ] Generate `MsdpEvent::LocalSourceActive` when source detected
  - [ ] Generate `MsdpEvent::LocalSourceInactive` when source expires
- [ ] **SA flooding:**
  - [ ] When SA received from peer, flood to other peers (respecting mesh groups)
  - [ ] When local source active, originate SA to all peers
  - [ ] Implement `get_flood_peers()` filtering in actual flood path
- [ ] **RPF check for received SAs:**
  - [ ] Implement peer-RPF validation (accept SA only from RPF neighbor toward origin RP)
  - [ ] Use routing table or static configuration for RPF lookup
- [ ] **MSDP-to-PIM notifications:**
  - [ ] When SA learned for group with local receivers, trigger PIM (S,G) join
  - [ ] Create (S,G) state in MRIB from learned SAs
- [ ] **SA-Request/Response (optional):**
  - [ ] Implement SA-Request message parsing/building
  - [ ] Respond to SA-Request with cached SAs for requested group

### Phase 5: Testing and Documentation (TODO)

**Goal:** Comprehensive testing and documentation.

- [ ] Add integration tests:
  - [ ] Peer connection establishment (active/passive)
  - [ ] Keepalive exchange
  - [ ] SA message exchange
  - [ ] Mesh group flood suppression
  - [ ] Peer timeout and reconnection
- [ ] Update `developer_docs/ARCHITECTURE.md` Section 6 with MSDP documentation
- [ ] Add MSDP configuration examples to README or docs
- [ ] Add troubleshooting guidance for common MSDP issues

## Message Format Reference (RFC 3618)

### Header (3 bytes)

```text
 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Type       |           Length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Message Types

| Type | Value | Description |
|------|-------|-------------|
| SA | 1 | Source-Active announcement |
| SA-Request | 2 | Request SA for specific group |
| SA-Response | 3 | Response with SA data |
| Keepalive | 4 | Session maintenance |

### SA Message Format

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Entry Count |              RP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         RP Address (cont)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Reserved    | Sprefix Len   |  Group Address ...            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Timer Reference (RFC 3618)

| Timer | Default | Purpose |
|-------|---------|---------|
| ConnectRetry | 30s | Retry interval after connection failure |
| Keepalive | 60s | Send keepalive if no other message sent |
| Hold | 75s | Peer considered dead if no message received |
| SA Cache | 60s | SA entry expiry (refreshed on receipt) |

## Configuration Example

```yaml
msdp:
  enabled: true
  local_address: 10.0.0.1
  keepalive_interval: 60
  hold_time: 75
  peers:
    - address: 10.0.0.2
      description: "Remote RP"
      mesh_group: "anycast-rp"
    - address: 10.0.0.3
      description: "Backup RP"
      mesh_group: "anycast-rp"
```

## CLI Commands

```bash
# Show peer status
mcrctl msdp peers

# Show SA cache
mcrctl msdp sa-cache

# Add a peer dynamically
mcrctl msdp add-peer --address 10.0.0.4 --description "New peer" --mesh-group "anycast-rp"

# Remove a peer
mcrctl msdp remove-peer --address 10.0.0.4

# Clear SA cache
mcrctl msdp clear-sa-cache
```

## Current Status

- **Phase 0:** Complete
- **Phase 1:** Complete
- **Phase 2:** Complete
- **Phase 3:** Complete
- **Phase 4:** Not Started
- **Phase 5:** Not Started

## Next Steps

1. Begin Phase 4 PIM integration:
   - Add source notification from PIM to MSDP when local sources detected
   - Implement SA flooding on receipt (use `MsdpTcpCommand::FloodSa`)
   - Add RPF check for received SAs

2. Phase 5 Testing and Documentation:
   - Add integration tests for peer connections
   - Update ARCHITECTURE.md with MSDP documentation
