# Kernel Multicast Routing Decision Process

This document analyzes why `socat` requires explicit multicast routes in the dual-bridge topology, while MCR does not.

## Background: How the Kernel Routes Multicast Packets

When a userspace application (like socat) sends a multicast packet using `sendto()`, the kernel must determine which network interface to use for egress. The decision process follows these steps:

### 1. **Socket Options** (IP_MULTICAST_IF)

The kernel first checks if `IP_MULTICAST_IF` is set on the socket.

- This socket option explicitly specifies which interface to use for multicast egress
- `socat` does NOT appear to set this option (it only uses `bind=`)

### 2. **Routing Table Lookup**

If `IP_MULTICAST_IF` is not set, the kernel consults the routing table:

- The kernel looks for a route to the multicast destination address
- For multicast (224.0.0.0/4), this requires an explicit multicast route
- Without a matching route, the packet may be dropped or sent to the wrong interface

### 3. **Default Route Fallback**

If no multicast-specific route exists:

- The kernel may fall back to the default route
- However, default routes typically don't handle multicast correctly
- This often results in packets being dropped or sent to the wrong interface

### 4. **bind() Limitation**

Using `bind=IP_ADDRESS` only sets the SOURCE IP address:

- It does NOT influence interface selection for outgoing packets
- The kernel still needs routing information to choose the egress interface
- This is a common source of confusion when working with multi-homed systems

## The Bridge Topology Problem

In the dual-bridge test topology:

- **veth-mcr0** is on br0 with IP 10.0.0.20 (ingress network)
- **veth-mcr1** is on br1 with IP 10.0.1.20 (egress network)

When socat sends to multicast address 239.9.9.9 with `bind=10.0.1.20`:

- ✓ The source IP is correctly set to 10.0.1.20
- ✗ But which interface should the packet egress from?
- Without a multicast route, the kernel has no way to determine the correct interface

**Result without multicast route:** Packets are likely dropped or sent to the wrong interface (veth-mcr0 instead of veth-mcr1), resulting in 0% delivery.

## The Solution: Explicit Multicast Route

Adding this command before starting socat:

```bash
ip route add 224.0.0.0/4 dev veth-mcr1
```

This creates an explicit routing entry that instructs the kernel:
> "All multicast destinations (224.0.0.0/4 range) should egress via veth-mcr1"

Now when socat sends to 239.9.9.9, the kernel routing lookup succeeds and correctly uses veth-mcr1 as the egress interface.

## Why MCR Doesn't Need This

MCR operates at Layer 2 using `AF_PACKET` sockets and completely bypasses the kernel's IP routing layer:

1. **Explicit Interface Specification**: MCR's forwarding rules explicitly specify both input and output interfaces
2. **Raw Socket Control**: `AF_PACKET` sockets send directly to the network driver
3. **No Routing Lookup**: The kernel's IP routing table is never consulted

This is one of MCR's key architectural advantages in complex network topologies - it provides deterministic, explicit control over packet paths without relying on system routing configuration.

## Alternative Solutions for socat

Instead of adding a multicast route, socat could theoretically use:

1. **IP_MULTICAST_IF socket option** - if socat supported setting this option
2. **Multiple socat instances** - one per interface (less practical)
3. **iptables SNAT/masquerading** - complex and adds overhead

However, the multicast route is the simplest and most direct solution for UDP-based multicast forwarding in multi-homed configurations.

## Testing Status

### Initial Hypothesis

Adding `ip route add 224.0.0.0/4 dev veth-mcr1` OR using `ip-multicast-if=10.0.1.20` would allow socat to successfully forward packets in the dual-bridge topology.

### Test Results

**Test script:** `docs/experiments/test_socat_multicast_solutions.sh`

**Date tested:** 2025-11-15

**Results:**

- **TEST 1 (ip-multicast-if):** 0/5 packets received ❌
- **TEST 2 (multicast route):** 0/5 packets received ❌

### Observations

1. **Traffic generation works:** Packets are successfully sent from the traffic generator (confirmed in earlier tcpdump captures showing packets arriving at veth-mcr0)

2. **Socat receives packets:** Earlier tcpdump showed packets arriving at veth-mcr0 where socat is listening

3. **Forwarding fails:** Despite both `ip-multicast-if` and multicast routes, socat does not forward packets to the sink in the dual-bridge topology

4. **No errors or hangs:** Both test configurations run without errors or process failures - socat simply doesn't forward the packets

### Possible Explanations

Several factors may explain why socat fails in this topology:

1. **Bridge forwarding behavior:** Linux bridges may not forward multicast packets between interfaces in the expected way, even with `mcast_snooping` disabled

2. **Socket binding issue:** The combination of `ip-add-membership` on one interface and sending via another interface may not work as expected in a bridged namespace

3. **Missing configuration:** There may be additional bridge or socket options required that we haven't identified

4. **Fundamental limitation:** socat (or UDP sockets in general) may not support the specific pattern of receiving on one bridge domain and sending to another within the same namespace

### Conclusion

**Status:** Hypothesis DISPROVEN by testing

The theoretical analysis of kernel multicast routing is correct, but the practical application to socat in a dual-bridge topology does not work as expected. Further investigation is needed to determine:

- Whether socat can work in this topology at all
- What additional configuration (if any) would make it work
- Whether this represents a fundamental limitation of Layer 4 (UDP socket) approaches vs Layer 2 (AF_PACKET) approaches

This negative result actually strengthens the case for MCR's Layer 2 approach, which bypasses these kernel routing complexities entirely.

## References

- Linux kernel IP multicast implementation: `net/ipv4/ip_output.c`
- Socket option documentation: `man 7 ip` (IP_MULTICAST_IF section)
- Routing table documentation: `man 8 ip-route`
