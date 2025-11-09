## Answer 14: Does the HA roadmap account for state synchronization?

**Conclusion:** No, the V2 roadmap's focus on a simple `/healthz` endpoint only supports basic active-passive failover and is insufficient for true, seamless high availability. A mission-critical HA solution requires automatic state synchronization.

### Analysis:

1.  **The Limitation of Health Checks:** A `/healthz` endpoint allows an external tool (like `keepalived`) to detect a failure and redirect traffic to a standby instance. However, it does not address the problem of **state**. When the standby instance takes over, it has no knowledge of the relays that were configured on the primary instance. This would require manual intervention to re-apply the configuration, causing a significant service outage.

2.  **The Need for State Synchronization:** For seamless failover, the configuration state (the list of active relays) must be synchronized between the active and passive nodes in real-time. When the passive node becomes active, it must instantly know which relays to create and begin forwarding traffic.

3.  **Architectural Solutions for State Sync:**
    *   **External Shared State:** This is the most robust and common pattern. The MCR instances themselves remain stateless, but they read their configuration from an external, highly-available key-value store like **etcd** or **Consul**.
        *   When an admin creates a relay via the API on the active MCR node, the node writes that configuration to the shared `etcd` cluster.
        *   All MCR nodes (active and passive) "watch" the `etcd` cluster for changes and dynamically update their internal forwarding rules.
        *   If the active node fails, the passive node is already fully configured and can take over instantly.
    *   **Active-Active with Gossip Protocol:** A more complex but potentially more resilient approach where all nodes are active and share state directly with each other using a gossip protocol. This is likely over-engineering for MCR's initial enterprise offering.

**Strategic Implication:** The V3 product roadmap must be updated to reflect this deeper understanding of HA.
*   **Phase 2 Feature (Professional):** The `/healthz` endpoint remains a valuable feature for simple failover scenarios.
*   **Phase 3 Feature (Enterprise):** The roadmap must include **"High Availability with State Synchronization"** as a key feature for the Enterprise edition.
*   **Architectural Choice:** The strategy should explicitly state that the chosen architecture will be based on an **external key-value store (like etcd)**. This is a standard, proven pattern that avoids reinventing the wheel and aligns with modern cloud-native practices. This demonstrates a credible path to delivering true, mission-critical HA.
