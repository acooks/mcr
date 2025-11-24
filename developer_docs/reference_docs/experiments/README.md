# Experiments and Findings

This directory contains historical scripts and analyses used to investigate complex behaviors, validate architectural hypotheses, and guide the design of MCR.

**Note:** The scripts herein are for research and are not part of the main, supported test suite. The primary, up-to-date testing workflow is defined in `developer_docs/testing/PRACTICAL_TESTING_GUIDE.md`.

---

## Summary of Key Findings

The experiments in this directory have produced several critical insights that directly shaped MCR's architecture and roadmap.

1. **MCR Outperforms `socat` at High Load:**
    - In sustained, high-rate, single-stream tests (150k pps), MCR demonstrates **3.3% higher throughput** than a process-per-stream `socat` equivalent. While both tools show packet loss at this load, MCR's performance advantage is clear.
    - _Source: [High_Density_Stream_Test.md](./High_Density_Stream_Test.md)_

2. **Discovery of the Multi-Worker Duplication Bug:**
    - The high-density performance test was the first to uncover the critical bug where running MCR with more than one worker (`--num-workers > 1`) caused massive packet duplication (a 1.28x factor).
    - This finding directly led to the implementation of the `PACKET_FANOUT` architecture, which is a cornerstone of MCR's multi-core scaling.
    - _Source: [High_Density_Stream_Test.md](./High_Density_Stream_Test.md)_

3. **`socat` Fails in Realistic Topologies:**
    - While `socat` can be made to relay multicast in simple, artificial 3-namespace "chain" topologies, it **consistently fails** with 0% packet delivery in MCR's more realistic single-namespace, dual-bridge topology.
    - This proves that `socat` is not a viable alternative for MCR's target use cases without significant, and as-yet-undiscovered, configuration. This validates the need for MCR's Layer 2 (`AF_PACKET`) approach.
    - _Source: [multicast_routing_analysis.md](./multicast_routing_analysis.md), [SESSION_NOTES_2025-11-15.md](./SESSION_NOTES_2025-11-15.md)_

---

## Document Catalog

### Core Analyses & Plans

- **[High_Density_Stream_Test.md](./High_Density_Stream_Test.md):**
  - **Purpose:** A test plan and result summary for a high-rate (150k pps), single-stream benchmark comparing MCR and `socat`.
  - **Key Outcome:** Proved MCR's single-worker performance advantage and, crucially, discovered the multi-worker packet duplication bug.

- **[multicast_routing_analysis.md](./multicast_routing_analysis.md):**
  - **Purpose:** A deep-dive analysis of the Linux kernel's multicast routing decision process.
  - **Key Outcome:** Explains _why_ Layer 4 tools like `socat` fail in multi-homed, single-namespace environments and validates the architectural choice of MCR's Layer 2 `AF_PACKET` model to bypass these issues.

- **[SESSION_NOTES_2025-11-15.md](./SESSION_NOTES_2025-11-15.md):**
  - **Purpose:** Raw notes from the research session that investigated `socat`'s capabilities.
  - **Key Outcome:** Documents the discovery that `socat`'s success is highly dependent on the network topology.

### Supporting Experimental Scripts

The following scripts were used to generate the findings in the analysis documents. They require `sudo` and create their own network namespaces.

- `test_socat_single_bridge.sh`: A successful test of `socat` in an artificial 3-namespace topology.

- `test_socat_multicast_solutions.sh`: A failed test attempting to make `socat` work in the realistic dual-bridge topology.

- `debug_bridge_packets.sh`: A `tcpdump`-based utility for visualizing packet flow in the dual-bridge setup.

- Other `test_*.sh` scripts: Various permutations for testing specific kernel behaviors like RPF and IP forwarding.

## Practical `socat` Command Patterns

While `socat` may not be suitable for MCR's primary use cases, these experiments documented its capabilities. Here are working `socat` command patterns for multicast relay in simpler topologies:

### Simple 1-to-1 Multicast Relay

```bash

socat -u \

  UDP4-RECV:5001,ip-add-membership=239.255.0.1:veth-relay0,reuseaddr \

  UDP4-SEND:239.255.0.2:5001,ip-multicast-if=10.0.2.1,reuseaddr

```

### `socat` Relay Command (Chain Topology)

This command was used for comparative performance testing in a simple chain topology.

```bash

socat -u \

  UDP4-RECV:5001,ip-add-membership=239.1.1.1:veth1,reuseaddr,bind=10.0.0.2 \

  UDP4-SEND:239.10.1.1:6001,ip-multicast-if=10.0.1.1

```

These patterns are preserved for historical context and as a reference for `socat`'s capabilities.
