# MCR Protocol Capabilities

This document describes MCR's multicast protocol support, including IGMP, PIM-SM, and MSDP, and how they integrate with static forwarding rules.

## Overview

MCR supports three complementary approaches to multicast forwarding:

| Approach | Use Case | Configuration |
|----------|----------|---------------|
| **Static Rules** | Known, fixed forwarding paths | `rules: [...]` in config |
| **IGMP** | Local receiver discovery | `igmp: { enabled: true }` |
| **PIM-SM** | Dynamic inter-router routing | `pim: { enabled: true }` |
| **MSDP** | Cross-domain source discovery | `msdp: { peers: [...] }` |

These can be used independently or combined for hybrid deployments.

---

## Static Rules

Static rules define explicit forwarding paths that are always active.

### Configuration

```json5
{
  rules: [
    {
      name: "video-feed",
      input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
      outputs: [
        { interface: "eth1", group: "239.1.1.1", port: 5000 },
        { interface: "eth2", group: "239.2.2.2", port: 6000 }  // NAT supported
      ]
    }
  ]
}
```

### CLI Management

```bash
# Add a rule
mcrctl add --input-interface eth0 --input-group 239.1.1.1 --input-port 5000 \
           --outputs 239.1.1.1:5000:eth1,239.2.2.2:6000:eth2

# List rules
mcrctl list

# Remove by name
mcrctl remove --name video-feed
```

### When to Use

- Fixed source-to-destination mappings
- Bypass RPF checks
- Multicast NAT (group/port translation)
- Guaranteed forwarding paths

---

## IGMP (Internet Group Management Protocol)

MCR implements IGMPv2 for discovering local multicast receivers.

### Features

| Feature | Status | Description |
|---------|--------|-------------|
| IGMPv2 Querier | Supported | Sends periodic membership queries |
| Membership Reports | Supported | Tracks group joins from hosts |
| Leave Processing | Supported | Removes groups when hosts leave |
| Query Interval | Configurable | Default 125 seconds |
| Interface Selection | Configurable | Enable per-interface |

### Configuration

```json5
{
  igmp: {
    enabled: true,
    querier_interfaces: ["eth1", "eth2"],  // Interfaces to query
    query_interval: 125                     // Seconds between queries
  }
}
```

### CLI Commands

```bash
# View tracked groups
mcrctl igmp groups

# Example output:
# Interface  Group        Members  Last Report
# eth1       239.1.1.1    2        5s ago
# eth1       239.255.0.1  1        45s ago
# eth2       239.1.1.1    1        12s ago
```

### How IGMP Integrates with Forwarding

When IGMP learns that receivers exist on an interface, MCR can add that interface as an output for matching traffic:

1. Host on `eth1` sends IGMP Join for `239.1.1.1`
2. MCR records: "eth1 has receivers for 239.1.1.1"
3. If a static rule or PIM route matches `239.1.1.1`, `eth1` is added as output

---

## PIM-SM (Protocol Independent Multicast - Sparse Mode)

MCR implements PIM-SM for dynamic multicast routing between routers.

### Features

| Feature | Status | Description |
|---------|--------|-------------|
| Hello/Neighbor Discovery | Supported | Discovers adjacent PIM routers |
| DR Election | Supported | Elects Designated Router per interface |
| (*,G) Joins | Supported | Shared tree joins toward RP |
| (S,G) Joins | Supported | Source-specific tree joins |
| Static RP | Supported | Manual RP configuration |
| Bootstrap (BSR) | Not yet | Dynamic RP discovery |
| Assert | Not yet | Duplicate forwarder resolution |

### Configuration

```json5
{
  pim: {
    enabled: true,
    interfaces: [
      { name: "eth0", dr_priority: 100 },  // Higher = more likely DR
      { name: "eth1", dr_priority: 50 },
      { name: "eth2" }                      // Default priority: 1
    ],
    static_rp: [
      { rp: "10.0.0.1", group: "239.0.0.0/8" }  // RP for all 239.x.x.x
    ],
    hello_interval: 30,       // Seconds between hellos
    hello_holdtime: 105       // Neighbor timeout
  }
}
```

### CLI Commands

```bash
# View PIM neighbors
mcrctl pim neighbors

# Example output:
# Interface  Neighbor     DR Priority  Uptime   Holdtime
# eth0       10.0.0.2     100          5m 23s   95s
# eth1       10.1.0.5     1            2h 15m   102s

# View multicast routes
mcrctl mroute

# Example output:
# Type   Group        Source      Upstream    Downstream
# (*,G)  239.1.1.1    -           eth0        [eth1, eth2]
# (S,G)  239.1.1.1    192.168.1.5 eth0        [eth1]
```

### PIM Operation

1. **Neighbor Discovery**: PIM routers exchange Hello messages to discover each other
2. **DR Election**: On multi-access networks, one router is elected Designated Router
3. **Join/Prune**: When receivers appear (via IGMP), PIM sends Joins toward the RP
4. **Forwarding**: Traffic flows down the shared tree (*,G) or source tree (S,G)

---

## MSDP (Multicast Source Discovery Protocol)

MCR implements MSDP for sharing source information between PIM domains.

### Features

| Feature | Status | Description |
|---------|--------|-------------|
| TCP Peering | Supported | Establishes sessions with remote peers |
| SA Messages | Supported | Advertises active sources |
| SA Cache | Supported | Caches learned sources |
| Mesh Groups | Not yet | Full-mesh peer optimization |
| SA Filtering | Not yet | Policy-based SA acceptance |

### Configuration

```json5
{
  msdp: {
    enabled: true,
    local_address: "10.0.0.1",        // Source address for peering
    peers: [
      { address: "10.1.0.1", as_number: 65001 },
      { address: "10.2.0.1", as_number: 65002 }
    ],
    sa_holdtime: 75,                  // Seconds to keep learned SAs
    connect_retry_interval: 30        // Seconds between connection attempts
  }
}
```

### CLI Commands

```bash
# View MSDP peers
mcrctl msdp peers

# Example output:
# Peer        State        AS      Uptime    SAs Received
# 10.1.0.1    Established  65001   2h 15m    42
# 10.2.0.1    Connecting   65002   -         0

# View SA cache
mcrctl msdp sa-cache

# Example output:
# Source       Group        Origin RP   Learned    Expires
# 192.168.1.5  239.1.1.1    10.1.0.1    5m ago     70s
# 192.168.2.8  239.255.0.1  10.2.0.1    2s ago     75s
```

### MSDP Operation

1. **Peer Establishment**: MCR connects to configured MSDP peers via TCP
2. **SA Origination**: When MCR's RP learns a new source, it sends SA to peers
3. **SA Reception**: Received SAs are cached and can trigger (S,G) joins
4. **Source Discovery**: Remote receivers can join sources learned via MSDP

---

## Hybrid Deployments: Static + Dynamic Rules

MCR supports combining static rules with dynamic protocol learning. This enables powerful hybrid deployments.

### Additive Semantics

When a static rule and PIM (*,G) route match the same group, their outputs are **merged**:

```text
Static rule:  eth0:239.1.1.1:5000 → [eth1]
PIM (*,G):    upstream=eth2, downstream=[eth3, eth4]

Compiled result:
  eth0:5000 → [eth1, eth3, eth4]   (static + PIM merged)
  eth2:0    → [eth3, eth4]         (pure protocol route)
```

### Use Cases for Hybrid Deployment

#### 1. Guaranteed Base + Dynamic Extension

Ensure traffic always reaches critical receivers while allowing dynamic receivers to join:

```json5
{
  rules: [{
    name: "critical-feed",
    input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
    outputs: [
      { interface: "eth1", group: "239.1.1.1", port: 5000 }  // Always on
    ]
  }],

  pim: {
    enabled: true,
    interfaces: [
      { name: "eth0" },  // Upstream
      { name: "eth2" },  // Dynamic receivers here
      { name: "eth3" }   // And here
    ],
    static_rp: [{ rp: "10.0.0.1", group: "239.0.0.0/8" }]
  }
}
```

**Result**: eth1 always receives traffic; eth2/eth3 receive when PIM learns receivers.

#### 2. RPF Bypass + Protocol Learning

Use static rules to bypass RPF on the ingress path, then let PIM handle distribution:

```json5
{
  rules: [{
    name: "rpf-bypass",
    input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
    outputs: [
      { interface: "eth-internal", group: "239.1.1.1", port: 5000 }
    ]
  }],

  pim: {
    enabled: true,
    interfaces: [
      { name: "eth-internal" },  // Receives from static rule
      { name: "lan1" },
      { name: "lan2" }
    ]
  }
}
```

**Result**: Static rule injects traffic past RPF; PIM distributes to LANs.

#### 3. Multicast NAT + Dynamic Receivers

Translate group addresses while supporting dynamic receivers:

```json5
{
  rules: [{
    name: "nat-feed",
    input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
    outputs: [
      { interface: "eth1", group: "239.100.1.1", port: 5000 }  // Translated
    ]
  }],

  igmp: {
    enabled: true,
    querier_interfaces: ["eth1"]  // Track receivers on translated group
  }
}
```

---

## Interface Capability Detection

MCR automatically detects whether interfaces support multicast (IFF_MULTICAST flag).

### Warnings for Non-Multicast Interfaces

When enabling IGMP or PIM on interfaces that lack multicast support, MCR logs a warning:

```text
WARNING: IGMP on gre0: Interface gre0 does not support multicast: point-to-point interface without multicast support
```

### Interface Types

| Interface Type | IFF_MULTICAST | Notes |
|----------------|---------------|-------|
| Ethernet (eth0) | Yes | Full multicast support |
| VETH pairs | Yes | Full multicast support |
| Bridge ports | Yes | Full multicast support |
| GRE tunnels | Varies | Depends on configuration |
| IPIP tunnels | No | Point-to-point only |
| WireGuard | No | Point-to-point only |

### Checking Interface Capabilities

```bash
# Check interface flags
ip link show eth0 | grep -o 'MULTICAST'

# Expected output for multicast-capable:
# MULTICAST
```

---

## Viewing Compiled Routes

The `mcrctl mroute` command shows the final compiled forwarding rules:

```bash
mcrctl mroute

# Output shows merged static + protocol rules:
# Source          Input Interface  Outputs
# Static Rules:
#   239.1.1.1:5000  eth0           → eth1:239.1.1.1:5000, eth3:239.1.1.1:5000
#
# Protocol Routes:
#   (*,G) 239.1.1.1  eth2          → eth3, eth4
#   (S,G) 239.1.1.1  eth0          → eth3
```

---

## Configuration Example: Complete Hybrid Setup

```json5
{
  // Static rules for guaranteed paths and NAT
  rules: [
    {
      name: "primary-feed",
      input: { interface: "upstream", group: "239.1.1.1", port: 5000 },
      outputs: [
        { interface: "critical-receiver", group: "239.1.1.1", port: 5000 }
      ]
    }
  ],

  // IGMP for local receiver discovery
  igmp: {
    enabled: true,
    querier_interfaces: ["lan1", "lan2"],
    query_interval: 125
  },

  // PIM for inter-router communication
  pim: {
    enabled: true,
    interfaces: [
      { name: "upstream", dr_priority: 1 },
      { name: "lan1", dr_priority: 100 },
      { name: "lan2", dr_priority: 100 }
    ],
    static_rp: [
      { rp: "10.0.0.1", group: "239.0.0.0/8" }
    ]
  },

  // MSDP for cross-domain source discovery (optional)
  msdp: {
    enabled: true,
    local_address: "10.0.0.5",
    peers: [
      { address: "10.1.0.1", as_number: 65001 }
    ]
  }
}
```

---

## Summary

| Feature | Static Rules | IGMP | PIM-SM | MSDP |
|---------|--------------|------|--------|------|
| Manual control | Yes | - | - | - |
| RPF bypass | Yes | - | - | - |
| Group/port NAT | Yes | - | - | - |
| Local receiver discovery | - | Yes | - | - |
| Inter-router routing | - | - | Yes | - |
| Cross-domain sources | - | - | - | Yes |
| Dynamic membership | - | Yes | Yes | - |
| Additive with static | - | Yes | Yes | - |

MCR's protocol support enables flexible deployments from simple static forwarding to complex multi-domain PIM/MSDP networks, with the ability to combine approaches for hybrid solutions.
