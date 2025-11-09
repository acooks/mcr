## Answer 7: What is the plan for enterprise features like High Availability (HA)?

**Conclusion:** MCR V1 does not have built-in HA features, which is a significant gap for mission-critical use cases. The V2 strategy must address this with a clear roadmap, leveraging standard industry practices for network service availability.

### Analysis:

The lack of a clear HA story is a major weakness for the Broadcast and OT personas, where downtime has a high cost.

1.  **Standard HA Patterns:** High availability for network services is a well-solved problem. The common patterns are:
    *   **Active-Passive Failover:** An identical, idle MCR instance monitors the active instance. If the active instance fails, the passive one takes over its IP address and begins relaying traffic. This is typically managed with a heartbeat mechanism using a tool like `keepalived`.
    *   **Active-Active Load Balancing:** Multiple MCR instances run simultaneously, sharing the workload. A load balancer distributes traffic between them and automatically removes failed instances from the pool. This provides both HA and scalability.

2.  **Implementation via Orchestration:** These HA patterns do not necessarily need to be coded into MCR itself. They can be implemented at the infrastructure and orchestration layer.
    *   **Protocols:** First Hop Redundancy Protocols (FHRPs) like VRRP can be used to manage a virtual IP address that floats between two MCR servers. `keepalived` is the standard Linux tool for this.
    *   **Load Balancers:** Hardware or software load balancers can be placed in front of a cluster of MCR instances.

3.  **MCR's Role:** To support these patterns, MCR needs to provide one key feature: a **health check API endpoint**. This is a simple HTTP endpoint (e.g., `/healthz`) that external tools like `keepalived` or a load balancer can poll. If the endpoint doesn't return a `200 OK` status, the monitoring tool knows the instance is unhealthy and can trigger a failover.

**Strategic Implication:** The V2 strategy must address HA head-on.
*   **Acknowledge the Gap:** State clearly that V1 is for non-critical use cases, but HA is the top priority for enterprise adoption.
*   **Define the Roadmap:** The product roadmap must include the development of a `/healthz` API endpoint as a near-term priority.
*   **Provide Documentation:** The project must provide clear, detailed tutorials and reference architectures on how to configure an Active-Passive HA cluster using MCR and `keepalived`. This demonstrates a clear path to production-readiness and builds confidence with enterprise users.
