# Experimental Scripts and Documentation

This directory contains experimental scripts and analyses used during the development of MCR's performance tests and documentation.

## Summary of Key Findings (2025-11-15)

### socat Multicast Relay Capability
- ✅ **socat CAN relay multicast** - Has necessary socket options and address types
- ⚠️ **Topology matters** - Works in artificial 3-namespace isolated topology
- ❌ **Fails in MCR's topology** - Gets 0% delivery in single-namespace dual-bridge multi-homed setup
- ❓ **Real-world applicability unclear** - Success in test topology doesn't translate to production use case

### Testing Issues Identified
1. **Wrong topology** - Initial tests used 3 isolated namespaces, not MCR's single-namespace dual-bridge architecture
2. **Repeatability concerns** - Background processes, incomplete cleanup, verification gaps
3. **Validation needed** - Some "disabled" settings weren't actually disabled, just commented
4. **MCR test also fails** - Even MCR got 0% in some dual-bridge tests, suggesting test infrastructure issues

### Recommendation
The experiments show socat has multicast relay capabilities, but further work needed to:
- Fix/validate the dual-bridge test infrastructure
- Create proper multi-homed test matching MCR's actual topology
- Determine if socat can work in realistic production scenarios

## Purpose

These scripts are not part of the main test suite, but serve as:
- **Proof-of-concept experiments** that validate hypotheses about network behavior
- **Learning tools** that demonstrate specific networking concepts
- **Documentation** of the research and discovery process behind MCR's design decisions
- **⚠️ Historical record** of what was tested, including failed approaches and limitations

## Contents

### Core Analysis

#### [`multicast_routing_analysis.md`](multicast_routing_analysis.md)
Detailed analysis of the Linux kernel's multicast routing decision process and why userspace multicast relays like `socat` require specific configuration in multi-homed scenarios.

**Key findings:**
- Explains the kernel's decision tree for multicast egress interface selection
- Documents the `bind()` vs `IP_MULTICAST_IF` distinction
- Explains why MCR's Layer 2 approach bypasses these issues entirely

### Experimental Scripts

#### [`test_socat_single_bridge.sh`](test_socat_single_bridge.sh)
**Hypothesis tested:** socat can forward multicast packets across a single bridge with proper configuration.

**Topology:**
```
src-ns (10.0.1.1) <-veth-> relay-ns (10.0.1.2 | 10.0.2.1) <-veth-> sink-ns (10.0.2.2)
```

**Test approach:**
- Source sends multicast packets to 239.255.0.1:5001
- socat in relay-ns joins multicast group 239.255.0.1 on veth-relay0
- socat forwards to DIFFERENT multicast group 239.255.0.2 via veth-relay1
- Sink receives on 239.255.0.2:5001

**Socat command:**
```bash
socat -u \
  UDP4-RECV:5001,ip-add-membership=239.255.0.1:veth-relay0,reuseaddr \
  UDP4-SEND:239.255.0.2:5001,ip-multicast-if=10.0.2.1,reuseaddr
```

**Test results (2025-11-15):**
- ✅ **SUCCESS in 3-namespace topology** - 5/5 packets delivered (100%)
- socat successfully receives packets on ingress interface
- socat forwards packets to egress interface
- All packets arrive at sink

**⚠️ CRITICAL LIMITATION:**
This test uses an **artificial 3-namespace topology** (src-ns, relay-ns, sink-ns) which does NOT match MCR's actual use case. MCR uses a **single namespace with dual bridges** and a **multi-homed relay process**. When socat is tested in MCR's actual topology, it achieves **0% delivery**, suggesting this test's success may not be applicable to real-world scenarios.

**Requirements tested (3-namespace topology only):**
1. ✅ **Different multicast groups** - REQUIRED (0/5 with same address)
2. ✅ **Multicast route in relay** - REQUIRED (0/5 without route)
3. ❌ **IP forwarding** - NOT required (5/5 without, though testing had verification issues)
4. ❓ **Source multicast route** - NOT required in single-interface scenario (may be required in multi-homed)

**Known issues:**
- Topology doesn't match MCR's dual-bridge, single-namespace architecture
- Some requirement tests may have had disabled settings not actually applied
- Results don't translate to MCR's actual use case (socat gets 0% in real topology)
- Repeatability concerns due to background process interference

**Status:** ⚠️ **Limited applicability** - While socat works in this isolated 3-namespace test, it fails in MCR's actual topology. Further investigation needed.

#### [`test_socat_multicast_solutions.sh`](test_socat_multicast_solutions.sh)
**Hypothesis tested:** In a dual-bridge topology with multi-homed relay, `socat` requires explicit interface configuration for multicast egress.

**Tested solutions:**
1. Using the `ip-multicast-if=<address>` socket option
2. Adding a system-wide multicast route: `ip route add 224.0.0.0/4 dev <interface>`

**Test results (2025-11-15):**
- **Both solutions failed** - 0/5 packets delivered in dual-bridge topology
- Traffic generation confirmed working (packets arrive at socat's ingress interface)
- No errors or crashes - socat simply doesn't forward packets
- See `multicast_routing_analysis.md` for detailed analysis

**What this reveals:**
1. The dual-bridge topology presents challenges beyond simple multicast routing
2. socat (Layer 4/UDP sockets) may have fundamental limitations in this topology
3. Neither `ip-multicast-if` nor multicast routes are sufficient to make socat work
4. This strengthens the case for MCR's Layer 2 (AF_PACKET) approach

**Current status:**
This experiment shows what **doesn't** work, which is valuable for understanding the limitations of Layer 4 approaches. The `tests/performance/compare_socat_bridge.sh` test has been updated with the attempted fixes, but may still show 0% delivery for socat pending further investigation.

#### [`debug_bridge_packets.sh`](debug_bridge_packets.sh)
Debugging script that uses `tcpdump` to visualize packet flow through the dual-bridge topology. Useful for troubleshooting multicast forwarding issues.

**Usage:**
```bash
sudo ./debug_bridge_packets.sh
```

This script captures packets on multiple interfaces simultaneously to show where packets are being forwarded or dropped in the relay pipeline.

## Relationship to Main Test Suite

The findings from these experiments are applied in:
- **`tests/performance/compare_socat_bridge.sh`**: Uses `ip-multicast-if` based on proof from `test_socat_multicast_solutions.sh`
- **`tests/performance/compare_socat_chain.sh`**: Benefits from the routing analysis in `multicast_routing_analysis.md`
- **`docs/MCR_vs_socat.md`**: Documents the architectural differences discovered through these experiments

## Background Research

The analysis in this directory draws from:
- Linux kernel source code (`net/ipv4/ip_output.c`, multicast routing implementation)
- Reverse Path Forwarding (RPF) behavior documented in [this blog post](https://www.rationali.st/blog/the-curious-case-of-the-disappearing-multicast-packet.html)
- `man 7 ip` and `man 7 socket` documentation
- Empirical testing with network namespaces and bridges

## Running Experiments

All scripts in this directory:
- Require root privileges (`sudo`)
- Create isolated network namespaces (safe to run)
- Clean up after themselves (via `trap` handlers)
- Are self-contained and documented

To run any experiment:
```bash
sudo ./script_name.sh
```

## Contributing

When adding new experiments:
1. Add clear headers explaining the hypothesis being tested
2. Include cleanup handlers to remove namespace artifacts
3. Document findings in this README
4. Link to related code in the main test suite that uses the findings
