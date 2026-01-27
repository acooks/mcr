# Head-End Replication (HER) Roadmap

## Overview

This document describes the planned capability for MCR to perform **Head-End Replication (HER)** - converting multicast traffic to unicast for delivery over non-multicast-capable network paths.

### The Vision

MCR as a **multicast-to-unicast gateway** at the network edge:

```text
                            ┌─────────────────┐
   Multicast Source         │                 │  Multicast LAN
        │                   │                 │  ═══════════════►  [Receiver A]
        ▼                   │      MCR        │                     239.1.1.1
   ═══════════════          │   (Branch Pt)   │
   239.1.1.1:5000  ──────►  │                 │  P2P Tunnel (no mcast)
                            │                 │  ───────────────────►  [Receiver B]
                            │                 │    unicast UDP to      10.2.0.5:5000
                            └─────────────────┘    10.2.0.5
```

### Why This Matters

1. **Extend multicast reach** to non-multicast networks (tunnels, VPNs, cloud)
2. **Zero encapsulation overhead** - just change destination IP, no AMT/GRE wrapping
3. **Protocol integration** - PIM/IGMP can trigger unicast replication automatically
4. **Standard UDP receivers** - no special software needed on receiving end

---

## Current State

### What Works Now

MCR already has the foundation for HER:

1. **Forwarding layer supports unicast**: The `create_connected_udp_socket()` function only sets `IP_MULTICAST_IF` when `dest.is_multicast()` - unicast destinations work unchanged.

2. **Interface capability detection**: MCR detects `IFF_MULTICAST` flag and warns when enabling protocols on non-multicast interfaces.

3. **Additive static + dynamic rules**: Static rules merge with PIM (*,G) routes, allowing hybrid forwarding.

4. **rtnetlink dependency**: Already present for tunnel endpoint discovery.

### Current Limitation

`OutputDestination` only supports multicast group addresses:

```rust
// Current: src/lib.rs:155-160
pub struct OutputDestination {
    pub group: Ipv4Addr,      // Always multicast
    pub port: u16,
    pub interface: String,
}
```

No field exists to override the destination IP for unicast replication.

---

## Proposed Implementation

### Phase 1: Manual HER via Static Rules

**Goal**: Allow explicit unicast destinations in static rule outputs.

#### Data Structure Changes

```rust
// Proposed: src/lib.rs
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct OutputDestination {
    pub group: Ipv4Addr,
    pub port: u16,
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicast_dest: Option<Ipv4Addr>,  // NEW: override destination IP
}
```

#### Configuration Support

```json5
{
  rules: [{
    name: "hybrid-feed",
    input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
    outputs: [
      // Normal multicast output
      { interface: "eth1", group: "239.1.1.1", port: 5000 },

      // HER to tunnel endpoint
      { interface: "gre0", group: "239.1.1.1", port: 5000,
        unicast_dest: "10.2.0.5" }
    ]
  }]
}
```

#### CLI Support

```bash
mcrctl add --input-interface eth0 --input-group 239.1.1.1 --input-port 5000 \
           --outputs 239.1.1.1:5000:eth1,239.1.1.1:5000:gre0@10.2.0.5
                                                        ^^^^^^^^^^^
                                                        unicast override
```

#### Forwarding Worker Changes

```rust
// In process_received_packet() - src/worker/unified_loop.rs
let targets: Vec<ForwardingTarget> = rule
    .outputs
    .iter()
    .map(|output| {
        let dest_port = if output.port == 0 { original_port } else { output.port };

        // NEW: Use unicast_dest if specified, otherwise use multicast group
        let dest_ip = output.unicast_dest.unwrap_or(output.group);

        ForwardingTarget {
            payload_offset: headers.payload_offset,
            payload_len: headers.payload_len,
            dest_addr: SocketAddr::new(dest_ip.into(), dest_port),
            interface_name: output.interface.clone(),
        }
    })
    .collect();
```

**Complexity**: Low - localized changes to data structures and one line in forwarding.

---

### Phase 2: Automatic Tunnel Endpoint Discovery

**Goal**: Auto-detect unicast destinations for point-to-point tunnel interfaces.

#### Design

When PIM or IGMP adds a non-multicast interface as output:

1. Check if interface has `IFF_POINTOPOINT` flag
2. Query netlink for tunnel remote endpoint
3. Automatically use that endpoint as `unicast_dest`

#### Implementation

```rust
// New function in src/supervisor/socket_helpers.rs
pub async fn get_tunnel_endpoint(interface_name: &str) -> Result<Option<Ipv4Addr>> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let mut links = handle.link().get()
        .match_name(interface_name.to_string())
        .execute();

    if let Some(link) = links.try_next().await? {
        // Parse tunnel-specific attributes
        for attr in link.attributes {
            match attr {
                // GRE tunnel
                LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        if let LinkInfo::Data(LinkInfoData::Gre(gre)) => {
                            for gre_attr in gre {
                                if let LinkInfoGre::Remote(remote) = gre_attr {
                                    return Ok(Some(remote));
                                }
                            }
                        }
                        // Similar for IPIP, SIT, etc.
                    }
                }
                _ => {}
            }
        }
    }
    Ok(None)
}
```

#### Integration with MRIB

```rust
// In mroute.rs, when adding protocol-learned outputs
fn add_output_for_interface(&mut self, interface: &str, group: Ipv4Addr, port: u16) {
    let unicast_dest = if !self.is_multicast_capable(interface) {
        // Try to discover tunnel endpoint
        self.tunnel_endpoints.get(interface).copied()
    } else {
        None
    };

    self.outputs.push(OutputDestination {
        group,
        port,
        interface: interface.to_string(),
        unicast_dest,
    });
}
```

**Complexity**: Medium - requires netlink integration and MRIB changes.

---

### Phase 3: Auto-HER for Non-Multicast PIM Interfaces

**Goal**: When PIM learns downstream interfaces that lack multicast capability, automatically enable HER.

#### Behavior

```text
Scenario:
- PIM neighbor on tunnel0 (no IFF_MULTICAST)
- IGMP join arrives for 239.1.1.1 via that neighbor
- MCR creates (*,G) with downstream=[tunnel0]

Current behavior:
- MCR warns about non-multicast interface
- Packets sent to multicast address on tunnel0 (may not work)

Proposed behavior:
- MCR detects tunnel0 lacks IFF_MULTICAST
- MCR discovers tunnel0 remote endpoint: 10.5.0.2
- MCR automatically configures HER to 10.5.0.2
- Packets sent as unicast UDP to 10.5.0.2:port
```

#### Configuration

```json5
{
  pim: {
    enabled: true,
    interfaces: [
      { name: "eth0" },
      { name: "tunnel0", auto_her: true }  // Enable auto-HER for this interface
    ]
  }
}
```

Or globally:

```json5
{
  forwarding: {
    auto_her_for_p2p_tunnels: true  // Auto-HER on all P2P non-multicast interfaces
  }
}
```

**Complexity**: Medium - requires interface capability tracking and automatic output modification.

---

### Phase 4: Multiple Unicast Destinations per Interface

**Goal**: Support one logical interface with multiple unicast recipients (e.g., hub-and-spoke VPN).

#### Use Case

```text
Central MCR with WireGuard VPN to multiple branch offices:

    Branch A (10.1.0.5)  ←──┐
    Branch B (10.2.0.5)  ←──┼── wg0 interface ←── 239.1.1.1 traffic
    Branch C (10.3.0.5)  ←──┘
```

#### Configuration

```json5
{
  rules: [{
    input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
    outputs: [
      { interface: "wg0", unicast_dest: "10.1.0.5", port: 5000 },
      { interface: "wg0", unicast_dest: "10.2.0.5", port: 5000 },
      { interface: "wg0", unicast_dest: "10.3.0.5", port: 5000 }
    ]
  }]
}
```

**Complexity**: Low with Phase 1 - just multiple outputs with same interface.

---

### Phase 5: Dynamic Unicast Registration (Future)

**Goal**: Allow remote hosts to register for multicast streams over unicast.

#### Approaches

1. **REST API Registration**:

   ```bash
   curl -X POST http://mcr:8080/api/register \
     -d '{"group": "239.1.1.1", "port": 5000, "unicast_dest": "10.5.0.50"}'
   ```

2. **AMT-style Protocol**: Implement RFC 7450 Automatic Multicast Tunneling for standard interoperability.

3. **IGMP Proxy over Unicast**: Encapsulate IGMP in unicast UDP for remote hosts.

**Complexity**: High - requires new protocol implementation or API.

---

## Design Considerations

### Packet Handling Questions

| Question | Proposed Answer |
|----------|-----------------|
| **Port handling** | Preserve original port by default; allow override in config |
| **TTL handling** | Reset to 64 for unicast (configurable) |
| **Source IP** | Use egress interface IP (standard UDP behavior) |
| **Checksum** | Recalculate UDP checksum with new dest IP |

### Failure Handling

| Scenario | Behavior |
|----------|----------|
| Unicast dest unreachable | Log warning, continue sending (UDP fire-and-forget) |
| Tunnel endpoint changes | Periodic re-discovery (configurable interval) |
| Interface down | Remove from output list (existing behavior) |

### Performance Considerations

- **Socket caching**: Key by `(interface, dest_addr)` - already handles mixed multicast/unicast
- **Zero-copy**: Same `Arc<[u8]>` payload shared across all outputs
- **io_uring batching**: Unicast sends batch identically to multicast

---

## Implementation Priority

| Phase | Feature | Value | Effort | Priority |
|-------|---------|-------|--------|----------|
| 1 | Manual HER via unicast_dest | High | Low | **P0** |
| 2 | Tunnel endpoint discovery | Medium | Medium | P1 |
| 3 | Auto-HER for PIM interfaces | High | Medium | P1 |
| 4 | Multiple unicast per interface | Medium | Low | P2 |
| 5 | Dynamic registration | Low | High | P3 |

---

## Testing Strategy

### Unit Tests

```rust
#[test]
fn test_output_destination_with_unicast_override() {
    let output = OutputDestination {
        group: "239.1.1.1".parse().unwrap(),
        port: 5000,
        interface: "gre0".to_string(),
        unicast_dest: Some("10.2.0.5".parse().unwrap()),
    };

    // Forwarding should use unicast_dest
    let dest = output.unicast_dest.unwrap_or(output.group);
    assert_eq!(dest, "10.2.0.5".parse::<Ipv4Addr>().unwrap());
}
```

### Integration Tests

```bash
# tests/topologies/her_tunnel.sh
# 1. Create IPIP tunnel (no multicast support)
# 2. Configure MCR with HER to tunnel endpoint
# 3. Send multicast traffic
# 4. Verify unicast packets arrive at tunnel peer
```

### Topology Test Scenario

```text
┌─────────────────────────────────────────────────────────────┐
│  Network Namespace: test_her                                │
│                                                             │
│  ┌─────────┐     ┌─────────┐     ┌─────────┐               │
│  │ Source  │     │   MCR   │     │Receiver │               │
│  │         │     │         │     │         │               │
│  │ veth_s ─┼─────┼─ eth0   │     │  veth_r │               │
│  └─────────┘     │         │     └────┬────┘               │
│                  │  ipip0 ─┼──────────┘                    │
│                  │ (P2P)   │   unicast to 10.2.0.2         │
│                  └─────────┘                               │
└─────────────────────────────────────────────────────────────┘

Source sends: 239.1.1.1:5000 on veth_s
MCR receives on eth0, does HER via ipip0
Receiver gets: unicast UDP from MCR to 10.2.0.2:5000
```

---

## Related Work

### AMT (RFC 7450)

Automatic Multicast Tunneling - standard protocol for multicast-to-unicast gateway. More complex than MCR's approach but provides:

- Discovery protocol (anycast to find gateway)
- Encapsulation (UDP tunnel with AMT header)
- IGMP/MLD relay

MCR's HER is simpler (no encapsulation) but less feature-complete.

### PIM over GRE

Traditional approach for multicast over non-multicast links. Requires:

- GRE tunnel configuration
- PIM neighbor on tunnel
- Full multicast stack at both ends

MCR's HER works with dumb UDP receivers - no multicast stack needed.

### VXLAN/GENEVE Multicast

Overlay networks with built-in multicast support. Heavyweight compared to MCR's targeted HER approach.

---

## Conclusion

Head-End Replication extends MCR's value proposition significantly:

- **Phase 1** (manual HER) provides immediate value with minimal code changes
- **Phases 2-3** (auto-discovery) reduce operational burden for tunnel deployments
- **Phases 4-5** enable more sophisticated hub-and-spoke and dynamic scenarios

The key insight is that MCR's forwarding layer already handles unicast correctly - we just need to expose that capability through configuration and automation.
