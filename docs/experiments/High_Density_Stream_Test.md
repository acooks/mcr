# Experiment Plan: High-Density Stream Translation

**Author:** Gemini AI Assistant
**Date:** 2025-11-14
**Status:** Proposed

### **1. Objective**

To design and document a performance and scalability benchmark that clearly demonstrates the architectural strengths of MCR over simpler tools like `socat`. This experiment will focus on a realistic, high-density use case: relaying a large number of concurrent, medium-rate multicast streams.

This test is specifically designed to highlight MCR's advantages in:
*   **Resource Efficiency:** Handling many streams within a single, multi-core application vs. one process per stream.
*   **Scalability:** Managing a high aggregate packet rate distributed across many flows.
*   **Dynamic Configuration:** Adding a large number of forwarding rules to a live service.

### **2. Test Scenario: High-Density Stream Translation**

This scenario simulates a common use case for an RPF-solving relay, such as an IPTV headend or financial market data distributor.

*   **Workload:**
    *   **Number of Streams:** 50 independent multicast streams.
    *   **Per-Stream Rate:** 3,000 packets per second (pps).
    *   **Aggregate Rate:** 50 streams * 3,000 pps = **150,000 pps**.
*   **Translation:** Each stream is forwarded one-to-one to a new destination group, simulating a source address translation to solve the RPF problem.
    *   `239.1.1.1:5001` -> `239.10.1.1:6001`
    *   `239.1.1.2:5002` -> `239.10.1.2:6002`
    *   ...and so on for 50 unique streams.

### **3. Network Topology**

The experiment will use the robust **dual-bridge topology** to simulate two distinct network segments (e.g., an "ingress LAN" and an "egress LAN"), with the relay process acting as the router between them. This ensures a realistic test of forwarding between interfaces.

*   **`br0` (Ingress Network):** Connects 50 Traffic Generators and the MCR/`socat` ingress interface.
*   **`br1` (Egress Network):** Connects the MCR/`socat` egress interface and 50 Sinks.

### **4. Implementation Plan**

A new test script, `tests/performance/high_density_streams.sh`, will be created to automate this experiment. It will be based on the existing `compare_socat_bridge.sh` script but modified for this new scenario.

**Key Implementation Steps:**

1.  **Topology Setup:** The script will programmatically create the dual-bridge topology. It will create **51 `veth` pairs** for the egress side (1 for the relay's egress + 50 for the sinks) and connect them all to `br1`.

2.  **MCR Test Run:**
    *   Start a **single MCR supervisor process**, configured to use multiple worker cores (e.g., `--num-workers 4`).
    *   In a loop, execute the `control_client add` command **50 times** to dynamically configure all 50 forwarding rules.
    *   In parallel, start **50 `traffic_generator` processes** in the background, each sending one of the 50 streams.
    *   Wait for all generators to finish, then gracefully shut down MCR.
    *   Validate the results by parsing MCR's `FINAL` stats. The key metrics will be `ingress matched` (should be ~1.5M) and `egress sent` (should also be ~1.5M).

3.  **`socat` Test Run:**
    *   In a loop, start **50 `socat` sink processes** in the background to receive the traffic.
    *   In a second loop, start **50 `socat` relay processes** in the background, one for each of the 50 stream translations.
    *   In parallel, start the same **50 `traffic_generator` processes**.
    *   Wait for all processes to complete.
    *   Validate the results by counting the total number of packets received across all 50 sink output files.

### **5. Expected Outcome & Comparison Points**

This experiment will provide a clear, multi-faceted comparison that highlights MCR's strengths:

| Metric                  | MCR                                                                                             | `socat`                                                                                             |
| ----------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **Process Count**       | **1 Supervisor** (+ N workers)                                                                  | **100 processes** (50 relays + 50 sinks)                                                            |
| **Resource Overhead**   | **Low.** A single application with a managed pool of threads.                                   | **Very High.** 100 competing processes, leading to significant memory and scheduler overhead.       |
| **Configuration**       | **Dynamic & Centralized.** 50 rules are added to one running service.                           | **Static & Distributed.** 50 separate relay processes must be launched and managed.                 |
| **Performance**         | **High.** Expected to handle the 150k pps aggregate load with minimal to no packet loss.         | **Low.** Expected to suffer significant packet loss due to context-switching and socket buffer contention. |

This test will demonstrate that while `socat` is excellent for simple tasks, MCR is a superior solution for complex, high-density scenarios, showcasing its efficiency as a scalable platform for managing multicast workflows.
