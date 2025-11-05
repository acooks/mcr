# Multicast Relay - Development Log

This document tracks the development plan, decisions, and actions taken on the `multicast_relay` project. Its purpose is to ensure the development process is auditable and recoverable.

## Project Roadmap

*This roadmap will be collaboratively developed.*

1.  **Stabilize the Baseline:** Fix all compilation errors and warnings to establish a clean, verifiable starting point where `cargo test` passes.
2.  *(Further steps to be defined)*

## Chronological Log of User Prompts & Context

*This section contains the verbatim user prompts and provided context in the order they were given to establish an accurate history of requirements.*

### Prompt 1
"I want to create a multicast relay application that can receive a specified multicast group and retransmit the UDP payload to the same group, but from a local interface. The purpose is to be able to deal with unroutable multicast traffic. For example, see https://www.rationali.st/blog/the-curious-case-of-the-disappearing-multicast-packet.html. This multicast forwading application will be security sensitive and performance sensitive and must be able to be reconfigurable to add and remove forwarding rules at run time. It must also track the data rates for each of the flows intependently. I would also like to have the option to do head-end-replication as well as DTLS. Let's scope out a plan for this application."

### Context 1
User provided a link for context within the first prompt: https://www.rationali.st/blog/the-curious-case-of-the-disappearing-multicast-packet.html

### Prompt 2
"we need a real-time flow monitor function. We need to make architectural choices that minimise dynamic memory allocation. We need to make architectural choices that minimise system calls. We need to make choices that allow efficient processing of millions of packets per second. We need instrumentation to track the resource usage. We need functional tests to show that we can process 50 multicast streams at 5 million packets per second."

### Prompt 3
"can you create a message queue and collect the flow measurements from all workers in a queue? Would that help to avoid a problem where many writers are trying to obtain the same lock in order to update the performance data? can you make this application stand-alone, so that I don't need prometheus in order to view the performance metrics? could you please create some unit tests? could you you please create a README file?"

### Context 2
User provided a link to a GitHub repository for additional context: https://github.com/acooks/linux_multicast_snat_experiments

### Prompt 4
"Can you reconsider all my inputs in this session and reformulate a plan to design, implement, test, document this project? You may have to think about the design a bit more. And it seems like you haven't tried to compile anything or run any tests. Start by thinking about a good design. What is a good specification? Can you record that specification?"

---
*Log continues from this point.*

### 2025-11-05 (Continued) - Architectural Design Discussion

**Topic:** High-Performance Ingress Path.

**Analysis:**
*   Evaluated standard `AF_INET` sockets, `AF_PACKET`, and XDP/eBPF.
*   `AF_INET` was deemed too high-overhead due to context switching, memory copies, and the kernel's IP stack processing.
*   XDP was deemed unsuitable as `XDP_REDIRECT` cannot modify packet contents (i.e., change the source IP), which is a core requirement.
*   `AF_PACKET` was identified as the best approach to bypass the kernel IP stack and RPF checks.

**Topic:** CPU Affinity and Cache Locality.

**Analysis:**
*   Recognized that a default multi-threaded scheduler would cause expensive cross-core cache misses.
*   The goal is to ensure a packet is processed in userspace on the same CPU core that handled its arrival in the kernel.

**Topic:** Mapping Multicast Groups to Sockets and CPUs.

**Analysis:**
*   The "one socket per rule" model was rejected as it is not scalable and breaks the core pinning strategy.
*   The "one socket per core with userspace demultiplexing" model was adopted as the correct high-performance pattern.

**Topic:** Hardware vs. Software Filtering.

**Analysis:**
*   Recognized that relying on BPF alone is inefficient. The primary filter should be the NIC's hardware MAC address filter.
*   Using `PACKET_ADD_MEMBERSHIP` on an `AF_PACKET` socket is insufficient as it does not trigger the necessary IGMP Joins to upstream switches.

**Tentative Design Decisions Recorded:**

*   **D1 (Revised):** The core forwarding engine will be built using `AF_PACKET` sockets integrated with the `tokio` runtime.
*   **D2:** The application will be architected for core affinity, creating multiple single-threaded `tokio` runtimes, each pinned to a specific CPU core.
*   **D3:** The application will use a "one socket per core" model with userspace demultiplexing (hash map lookup) to associate packets with forwarding rules.
*   **D4 (Revised):** The application will rely on the NIC's hardware MAC address filtering. No additional BPF filter will be used.
*   **D5:** Packet forwarding will involve constructing a new IP/UDP packet in userspace to change the source IP, with the egress path using standard `UdpSocket`s.
*   **D6 (The Helper Socket Pattern):** For each required multicast group, a standard `AF_INET` "helper" socket will be created and used *only* to send the IGMP Join and program the NIC's MAC address filter. The data path will not use this socket.

**Topic:** High-Performance Ingress Path (Continued) - `io_uring` Integration.

**Analysis:**
*   Recognized that the `tokio` runtime is the appropriate choice for asynchronous I/O in Rust.
*   `io_uring` was identified as the state-of-the-art Linux asynchronous I/O interface, capable of eliminating system call overhead and enabling native batching of I/O operations.

**Tentative Design Decisions Recorded (Continued):}

*   **D7:** The application will be built using the `tokio-uring` runtime. The core packet receiving loop will submit multiple `recv` operations to the `io_uring` submission queue in batches and reap results from the completion queue. This is a fundamental architectural choice for peak performance.

**Topic:** Egress Path with `io_uring`.

**Analysis:**
*   Extended the `io_uring` strategy to the egress path to maintain consistent high performance.
*   Confirmed that `AF_INET` sockets are still appropriate for sending, as the kernel should handle Layer 2 and routing for outgoing packets.

**Tentative Design Decisions Recorded (Continued):

*   **D8:** The egress path will leverage `io_uring`. Outgoing packets will be constructed in userspace and submitted to the `io_uring` submission queue via batched `sendto` operations on standard `AF_INET` `UdpSocket`s.

**Topic:** Control Plane Design.

**Analysis:**
*   Re-evaluated the control plane protocol (JSON vs. binary) and communication mechanism (single vs. per-core sockets).
*   JSON was chosen for testability, convenience, and interoperability over raw performance for this non-data-plane interface.
*   A single, centralized Unix Domain Socket was chosen for simplicity and manageability.

**Tentative Design Decisions Recorded (Continued):

*   **D9 (Revised and Finalized):** The control plane will use a **JSON** protocol for serializing commands and responses over the single Unix Domain Socket.

### 2025-11-05 (Continued) - Adversarial Design Review

**Adversarial Question 1: Hotspot Vulnerability**
*   **Question:** What is the strategy for handling a traffic "hotspot" where a single, high-volume multicast group lands on one core, potentially saturating it while other cores remain underutilized?
*   **Answer:** The strategy is "Observe, Don't Act." The initial design will not implement an automatic hotspot mitigation strategy. Instead, it will rely on a robust, core-aware monitoring system to make any potential single-core saturation observable to the operator. Statistics reporting will be enhanced to include per-core packet rates and CPU utilization metrics.

**Design Decision Recorded:**
*   **D10:** The initial design will not implement an automatic hotspot mitigation strategy. Instead, it will rely on a robust, core-aware monitoring system to make any potential single-core saturation observable to the operator. The statistics reporting will be enhanced to include per-core packet rates and CPU utilization metrics. This provides the necessary visibility to manage the known architectural limitation.

**Adversarial Question 2: Rule Scalability**
*   **Question:** The design uses a core-local hash map for forwarding rules. What is the performance degradation curve as the number of rules scales into the tens of thousands, impacting both memory footprint and lookup latency?
*   **Answer:**
    *   **Memory Footprint:** Scales linearly (`O(n)`). At 100,000 rules, memory usage is estimated at ~10 MB per core, which is negligible.
    *   **Lookup Latency:** Average `O(1)` (constant time) for `HashMap`. Degradation is expected to be flat for a very large number of rules, with occasional step-like increases during internal rehashes. Worst-case `O(n)` for collisions is highly unlikely with a good hash function.
    *   **Mitigation:** Faster hashers (FxHash, AHash) or specialized data structures (tries) are options if profiling shows a bottleneck, but are not initially warranted.

**Adversarial Question 2 (Follow-up): Perfect Hash Function Feasibility**
*   **Question:** We know the range of potential keys. Can we use a perfect hash function?
*   **Answer:** No, a Perfect Hash Function (PHF) is not suitable. PHFs require a static, known-at-construction-time keyset. Our application's core requirement is dynamic rule reconfigurability (add/remove rules at runtime). The computational cost and disruption of constantly rebuilding a PHF for a dynamic keyset would negate its lookup benefits and add immense complexity.

**Design Decision Recorded:**
*   **D11:** The initial design will use the standard `std::collections::HashMap` with its default `SipHash` hasher for the core-local rule lookup table. This provides necessary flexibility for dynamic rule sets with excellent average-case performance.

**Adversarial Question 3: Backpressure Blindness**
*   **Question:** By bypassing the kernel's IP/UDP stack on ingress (`AF_PACKET`), the application is blind to network congestion signals. How does the system handle backpressure without the kernel's queuing disciplines, and can it contribute to network collapse under load?
*   **Initial Answer (Flawed):** Attempted to describe backpressure mechanisms, including "stopping reading from ingress" and "IGMP Leave/Join," conflating UDP multicast with closed-loop TCP congestion control.
*   **User Correction:** "I don't fully agree with your analysis and answer. For UDP Multicast, there is no effective backpressure mechanism, because there is no return channel. It is not a closed control loop, unless the higher layer application implements one, like for DDS."
*   **Revised Answer (Focus on Load Shedding):** Acknowledged that UDP multicast is open-loop. The problem is not about creating backpressure, but about implementing a sane, observable, and efficient load-shedding strategy when the relay is overloaded.
    *   **Strategy:** "Intelligent & Observable Load Shedding."
    *   **Primary Drop Point:** The NIC's hardware receive ring buffer.
    *   **Observability:** Monitor and report `tp_drops` from `AF_PACKET` sockets.
    *   **Preventing Bufferbloat:** Enforce strict limits on internal in-flight egress queues; stop submitting `recv` operations to `io_uring` if egress is congested.

**Design Decision Recorded:**
*   **D12 (Revised):** The application will not attempt to create backpressure. Instead, it will implement an **intelligent and observable load-shedding strategy.** The NIC's hardware receive ring buffer is the designated primary point for dropping packets under load. The application will monitor and expose the kernel's `tp_drops` counter for each `AF_PACKET` socket as a key health metric (`drops_per_second`). It will enforce a strict limit on its internal in-flight egress queue, and when this limit is reached, it will temporarily stop reading from the ingress `AF_PACKET` socket, thus allowing the NIC to handle the drops efficiently.

**Adversarial Question 3 (Follow-up): The Need for QoS**
*   **User Statement:** "Yes. And it also highlights that we will need to design a QoS mechanism into this application. Expect it to evolve at a future point in time. We will need good telemetry for this mechanism. As a first thought, we would need to see per-second traffic class distributions. We would have to pay careful attention to the DSCP markers in the IP headers and factor in classification and prioritisation based on both DSCP as well as statically configured maps from a specific (S,G) to a particular class. And class and priority may or may not be a one-to-one mapping."
*   **Analysis:** This introduces requirements for policy-driven load shedding, integrating with DSCP, flexible classification/prioritization, and detailed per-class telemetry.
    *   **Classification:** Assign packets to `TrafficClass` based on DSCP or `ForwardingRule` override.
    *   **Prioritization:** Map `TrafficClass` to `PriorityLevel` for internal queueing.
    *   **Telemetry:** Report per-`TrafficClass` metrics (packets, bytes, drops).

**Design Decision Recorded:**
*   **D13 (Revised - Advanced QoS):** The application will implement an advanced, observable QoS system. Packets will be assigned to an internal `TrafficClass` based on either the DSCP value in their IP header or a static override defined in the `ForwardingRule`. A configurable, many-to-one mapping will translate a packet's `TrafficClass` into a `PriorityLevel`, which determines which internal processing queue it is placed in. The monitoring system will track and expose detailed, per-`TrafficClass` metrics, including packets, bytes, and drops per second. The design will be modular to allow for future evolution of the QoS policies.

**Adversarial Question 4: Control Plane Bottleneck**
*   **Question:** The control plane is a single, centralized task. Could a high frequency of configuration changes or a flood of statistical queries from monitoring tools become a bottleneck that starves the data plane of commands?
*   **Analysis:** Yes, the design is vulnerable. `AddRule`/`RemoveRule` commands are fast, non-blocking operations. However, `GetStats`/`ListRules` commands are slow, synchronous, blocking operations. They require the control plane to query every data plane thread and wait for all responses. A flood of these queries could block the control plane, preventing it from processing new configuration changes in a timely manner.
*   **Mitigation Strategy:** Decouple the slow process of gathering statistics from the fast process of serving a client request. This is achieved by introducing a new, dedicated `StatsAggregator` task.
    *   Data plane threads will proactively *push* their full state (rules and stats) to the aggregator on a fixed, regular interval (e.g., 1s). This is a non-blocking operation for the data plane.
    *   The `StatsAggregator` maintains a cached, up-to-date, system-wide view of the application's state.
    *   When the `ControlPlane` receives a `GetStats` or `ListRules` request, it makes a fast, non-blocking query to the `StatsAggregator` for the latest cached data.
*   **Outcome:** This makes `GetStats`/`ListRules` nearly instantaneous from the control plane's perspective, ensuring it remains responsive. The small amount of data staleness (<= the push interval) is an acceptable trade-off for system stability.

**Design Decision Recorded:**
*   **D14:** The application will decouple statistics aggregation from the control plane's request/response loop. A dedicated `StatsAggregator` task will be created. Data plane threads will proactively push their state to the aggregator on a fixed interval. The `ControlPlane` task will query this aggregator to serve `GetStats` and `ListRules` requests, ensuring the control plane remains non-blocking and responsive to configuration changes.

**Adversarial Question 5: Jumbo Frame Penalty**
*   **Question:** Packet reconstruction involves a memory copy of the payload. For large datagrams like jumbo frames (9000 bytes), has the performance cost of this copy been justified against more complex zero-copy alternatives?
*   **Initial Answer (Flawed):** Proposed a zero-copy egress using scatter-gather I/O (`sendmsg` via `io_uring`), arguing it eliminates the memory copy bottleneck.
*   **User Correction/Objection:** "I'm not sure that this added complexity will pay off. I think it will become quite a complex thing to manage when QoS comes into play and memory fragmentation will be tricky to deal with."
*   **Re-evaluation & Revised Answer (Pragmatic Retreat to Memory Copy):**
    *   **Analysis of Zero-Copy Costs:** Acknowledged that zero-copy introduces significant complexity:
        *   **Buffer Lifecycle Management:** Tightly couples ingress and egress buffers, as receive buffers cannot be released until corresponding send operations complete.
        *   **QoS Conflict:** Creates head-of-line blocking for QoS, where low-priority egress congestion could stall high-priority ingress, as buffers cannot be released out of order.
        *   **Increased State Machine Complexity:** Makes the data plane state machine vastly more complex and prone to bugs.
    *   **Analysis of Memory Copy Benefits:**
        *   **Decoupling:** Immediately frees receive buffers, decoupling ingress from egress.
        *   **Simplified QoS:** Enables clean, robust implementation of priority queues without head-of-line blocking.
        *   **Robustness:** Simpler state management leads to a more robust and debuggable system.
        *   **Performance Cost:** While a memory copy consumes bandwidth (~4.5 GB/s per core for jumbo frames at 500k pps), this is within modern CPU capabilities and is a known, measurable cost. The complexity cost of zero-copy is a greater risk.

**Design Decision Recorded:**
*   **D5 (Reverted to Original, with Justification):** The packet forwarding logic will involve a **userspace memory copy of the payload**. An incoming packet's payload will be copied from the `AF_PACKET` ring buffer into a new, core-local buffer. This immediately frees the `AF_PACKET` buffer for reuse, decoupling ingress from egress. The new packet will then be constructed (headers + copied payload) and sent via `io_uring` `sendto` operations. This design is explicitly chosen to **simplify the architecture, reduce state management complexity, and enable a clean, robust implementation of QoS priority queuing.** The known performance cost of the memory copy is accepted as a trade-off for this architectural simplicity and robustness.

**Adversarial Question 6: Buffer Management and Memory Allocation**
*   **Question:** The design involves copying the payload for each packet and potentially managing multiple priority queues. How will memory for these buffers be managed to minimize dynamic allocations and avoid fragmentation, especially under sustained high load with varying packet sizes?
*   **Analysis:** Naive, per-packet dynamic allocation (`Vec::with_capacity`) is a performance anti-pattern that would cause massive lock contention and system call overhead.
*   **Mitigation Strategy:** Implement a **core-local, multi-size buffer pool**.
    *   **Pre-allocation:** At startup, each core-pinned thread pre-allocates a large number of fixed-size buffers, organized into pools based on size classes (e.g., Small, Standard, Jumbo).
    *   **Lock-Free Operation:** Each core manages its own pools independently. Runtime "allocations" and "deallocations" are simple, lock-free pop/push operations on a queue.
    *   **Pool Exhaustion:** If a pool runs out of buffers, incoming packets requiring that size are dropped. The system must *never* fall back to dynamic allocation, as this would introduce unpredictable latency.
*   **Observability Requirement:** Pool exhaustion and buffer utilization are critical health metrics. The monitoring system must provide detailed, per-core, per-pool telemetry.

**Design Decision Recorded:**
*   **D15 (Buffer Pool Management):** The application will use a **core-local, multi-size buffer pool** for managing packet payloads. Each core-pinned thread will pre-allocate and manage its own independent pools of fixed-size buffers. Runtime buffer operations will be lock-free. If a specific buffer pool is exhausted, incoming packets requiring that size will be dropped.
*   **D16 (Buffer Pool Observability):** The monitoring system must expose detailed, per-core, per-pool metrics to the control plane. For each pool (e.g., `core-0-jumbo`), the following metrics must be available:
    *   `pool_size`: The total number of buffers configured for the pool.
    *   `buffers_in_use`: The current number of buffers checked out from the pool.
    *   `exhaustion_events_total`: A counter that increments every time a request for a buffer from this pool fails.

**Adversarial Question 7: IGMP Membership Flapping**
*   **Question:** The "helper sockets" trigger IGMP joins. What prevents the kernel from pruning these memberships if it detects no application is actively reading from those sockets, causing the NIC to stop receiving traffic?
*   **Analysis:** The kernel's IGMP membership is tied to the socket's lifecycle, not its activity. The real risk is the kernel wasting resources processing packets for the unread socket buffer.
*   **Mitigation Strategy:** Minimize the helper socket's resource footprint by setting its receive buffer (`SO_RCVBUF`) to the lowest possible value. The resulting UDP errors from buffer overflow are an acknowledged and observable side effect.

**Design Decision Recorded:**
*   **D17 (Helper Socket Resource Management):** The application will minimize the resource footprint of the "helper sockets." Upon creation, each helper socket will have its `SO_RCVBUF` (receive buffer size) set to the lowest possible value allowed by the kernel. The application will not actively read from the helper sockets.

**Adversarial Question 8: Core Fault Isolation**
*   **Question:** If a single data plane thread panics and crashes due to a malformed packet or bug, what is the blast radius? Are its forwarding rules lost, and does the system attempt to automatically restart the failed thread?
*   **Analysis:** In the current design, a panic in a data plane thread results in: (1) Loss of all forwarding rules assigned to that core, (2) Inconsistent state for the Control Plane and Statistics Aggregator, and (3) No automatic restart. This is not a resilient architecture.
*   **Mitigation Strategy:** Implement a "Supervisor Pattern."
    *   The main application thread acts as a supervisor, monitoring child data plane threads.
    *   The supervisor maintains the canonical, master list of all forwarding rules.
    *   Upon detecting a child thread panic, the supervisor automatically restarts the failed thread, pins it to the correct core, and re-provisions it with its assigned rules from the master list.
*   **Outcome:** Contained blast radius, no rule loss, and automatic self-healing, significantly improving system resilience.

**Design Decision Recorded:**
*   **D18 (Supervisor Pattern for Resilience):** The application will implement a supervisor pattern. The main application thread will act as the supervisor, responsible for the lifecycle of the data plane threads. The supervisor will maintain the canonical, master list of all forwarding rules. It will monitor its child threads for panics. Upon detecting a failure, it will automatically restart the failed thread and re-provision it with the correct set of forwarding rules from its master list.

**Adversarial Question 9: Hardware/Driver Failure**
*   **Question:** How does the system handle common, transient events like a virtual interface being reconfigured by another process, or a physical interface losing and regaining its carrier?
*   **Initial Answer (Flawed):** Proposed a full system restart for driver crashes, which was too heavy-handed for common network events.
*   **User Correction:** Clarified that more common scenarios are virtual interface churn or link state flapping, requiring a more granular approach.
*   **Revised Answer (Hierarchical, Event-Driven Re-synchronization):** Adopted a nuanced approach using a Netlink socket for real-time network state changes.
    *   **Link Flapping (`UP`/`DOWN`):** Rules are gracefully paused/resumed. Status is observable.
    *   **Interface Deletion (`DELIF`):** Rules dependent on the interface are moved to an "unresolved" state.
    *   **Interface Appearance (`NEWIF`):** Supervisor automatically scans "unresolved" rules and activates any that can now be satisfied.
    *   **Full Restart:** Reserved for truly catastrophic, unrecoverable scenarios.
*   **Outcome:** Robust, resilient, and idempotent handling of network interface events with minimal disruption.

**Design Decision Recorded:**
*   **D19 (Final - Idempotent Network State Reconciliation):** The supervisor will maintain the master rule list with states like "active" and "unresolved." It will use a Netlink socket to listen for all network state changes (`UP`, `DOWN`, `DELIF`, `NEWIF`). When an interface appears, the supervisor will automatically scan its "unresolved" rules and activate any that can now be satisfied. Rules will be gracefully paused and resumed as their underlying interfaces lose and regain carrier. Rules dependent on a deleted interface will be moved to the "unresolved" state, to be automatically re-activated if the interface reappears later.

**Adversarial Question 10: DDoS Amplification Risk**
*   **Question:** The system is designed to bypass RPF checks. What safeguards prevent a misconfiguration from turning the relay into an unwitting amplifier in a DDoS attack, forwarding spoofed traffic to a victim?
*   **Initial Answer (Flawed):** Proposed strict multicast-only egress (D20), which contradicted the head-end replication requirement.
*   **User Correction 1:** Highlighted the explicit requirement for head-end replication to unicast destinations, making strict multicast-only egress unacceptable.
*   **Second Answer (Flawed):** Proposed Source-Specific Multicast (SSM) forwarding (D20 Revised), which was too restrictive for scenarios like DDS where multiple sources send to the same group.
*   **User Correction 2:** Emphasized the need to support multiple sources to the same group (e.g., DDS) and clarified that ingress is on trusted network interfaces.
*   **Re-evaluation & Final Answer (Trust and QoS):** Acknowledged that the threat model is a trusted network segment, mitigating external DDoS amplification. The risk shifts to accidental overload of a unicast destination due to misconfiguration. This risk is fully mitigated by the existing advanced QoS design (D13), which allows for the classification and rate-limiting/prioritized dropping of high-bandwidth flows. No additional security-specific mechanisms are required for this threat, given the trusted network assumption.

**Design Decision Recorded:**
*   **D20 (Revised - Trust and QoS):** The risk of DDoS amplification from external, malicious actors is considered mitigated by the operational requirement that the relay's ingress interfaces are connected only to physically secured, trusted network segments. The risk of accidental overload of a unicast destination due to misconfiguration is fully mitigated by the existing advanced QoS design (D13), which allows for the classification and rate-limiting/prioritized dropping of high-bandwidth flows. No additional security-specific mechanisms are required for this threat vector.

**Adversarial Question 10 (Follow-up): Explicit Interface Configuration**
*   **Question:** Please confirm that we didn't miss anything earlier in the design about listening on a particular interface. Is there anything in the design for `AF_PACKET` sockets that assumes a small set of interfaces?
*   **Analysis:** Confirmed that `AF_PACKET` sockets must bind to a specific interface. The design does not inherently assume a small set of interfaces, but managing multiple ingress interfaces per core-pinned thread increases resource requirements and complexity. The `ForwardingRule` must explicitly include the `input_interface`.

**Design Decision Recorded:**
*   **D21 (Explicit Interface Configuration):** The `ForwardingRule` structure must be updated to include a mandatory `input_interface` field. The application will support configuring rules across multiple distinct input and output interfaces. The data plane architecture will be implemented such that each core-pinned thread can manage `AF_PACKET` sockets for multiple ingress interfaces simultaneously.

**Adversarial Question 11: Stateful Control Protocol**
*   **Question:** What are the recovery semantics if a control client disconnects mid-request? Can the JSON-RPC server get into a stuck state, and is the protocol designed to be idempotent?
*   **Initial Answer (Flawed):** Proposed client-generated UUIDs for rules and "UPSERT" semantics for `AddRule` (D22), which added significant complexity to the client.
*   **User Correction/Objection:** "this seems complex. Is there a simpler, correct way to do this?"
*   **Re-evaluation & Revised Answer (Server-Side Idempotency):**
    *   **Analysis of Previous Complexity:** Acknowledged that client-generated UUIDs and UPSERT semantics were overly complex for the client and the server.
    *   **Simpler Strategy: "Trust, but Verify" with Server-Generated IDs:**
        *   The server (supervisor) generates a unique ID for each new rule upon creation. This ID is returned in the `AddRule` success response.
        *   The `ListRules` command becomes the primary mechanism for a client to reconcile its state after a disconnect. By querying `ListRules`, the client can determine if its previous `AddRule` succeeded and learn the server-assigned ID.
        *   `AddRule` retains simple "create new rule" semantics; accidental duplicates are handled by the client observing the state via `ListRules`.
    *   **Outcome:** Significantly simpler client logic, server remains the single source of truth, and idempotency is achieved at the session level through client-side verification.

**Design Decision Recorded:**
*   **D22 (Revised - Server-Side Idempotency):** The control plane will ensure client recovery and idempotency through a server-side mechanism. The supervisor will generate a unique ID for each new rule upon creation, and this ID will be returned in the `AddRule` success response. The `ListRules` command will be the primary mechanism for a client to reconcile its state after a disconnect or timeout. The `AddRule` command will retain "create new rule" semantics.

**Adversarial Question 12: Core Affinity Strategy**
*   **Question:** How does the control plane decide which core to assign a new forwarding rule to? Is this decision static (e.g., based on a hash of the multicast group), and can an operator manually rebalance rules to mitigate the "hotspot" problem?
*   **Analysis:** The rule distribution strategy needs to be predictable and manageable.
    *   **Round-Robin:** Simple, but not workload-aware and not stable across restarts.
    *   **Consistent Hashing:** Stable and predictable (same rule always maps to same core), provides good average distribution, but still not truly workload-aware.
    *   **Manual Rebalancing:** Essential for operators to reactively mitigate hotspots identified via monitoring.
*   **Mitigation Strategy:** A hybrid approach combining consistent hashing for default assignment with manual rebalancing as an operator override.
    *   **Default:** Consistent hash of `(input_group, input_port)` for stable, predictable distribution.
    *   **Override:** `MoveRule` command allows operators to re-assign a rule to a specific core.
    *   **State:** Supervisor tracks the current core assignment, which may differ from the hash-based default.

**Design Decision Recorded:**
*   **D23 (Rule-to-Core Assignment Strategy):** The application will use a hybrid strategy for assigning forwarding rules to data plane cores. By default, the supervisor will assign rules to cores using a consistent hash of the rule's stable identifiers (e.g., `input_group`, `input_port`). The control plane will also support a `MoveRule` command, allowing an operator to manually re-assign a specific rule to a different core to reactively mitigate hotspots. The supervisor's master rule list will track the current core assignment for each rule.

**Adversarial Question 13: Privilege Escalation Surface**
*   **Question:** Using `AF_PACKET` requires `CAP_NET_RAW` privileges. How is the application designed to drop unnecessary privileges after binding to the socket to minimize its attack surface?
*   **Initial Answer (Flawed):** Proposed a "bind then drop" pattern within a single process.
*   **User Correction/Objection:** "that will not work. how will the supervisor be able to restart the other threads and make configuration changes?"
*   **Re-evaluation & Revised Answer (Privilege Separation):** Acknowledged that the supervisor's duties (restarting threads, handling new interfaces) require persistent privileges, making the "bind then drop" pattern unworkable. The correct solution is a multi-process architecture for privilege separation.
    *   **Privileged Supervisor Process:** Retains `CAP_NET_RAW`, manages worker lifecycles, and performs all privileged socket operations. Its attack surface is minimized by keeping its logic simple.
    *   **Unprivileged Control Plane Process:** Spun up by the supervisor, drops all privileges, and handles all complex/untrusted JSON parsing.
    *   **Unprivileged Data Plane Worker Processes:** Spun up by the supervisor, receive sockets via file descriptor passing, and run the entire data path without ever having privileges.
*   **Impact Analysis:** Confirmed that this architecture, while more complex, provides major benefits for Testability (enforced boundaries), Auditability (minimal privileged code), and Reliability (true OS-level fault isolation).
*   **User Acknowledgment:** "yes, though I dread the added complexity" - The significant increase in architectural complexity is explicitly acknowledged as a necessary trade-off for security and robustness.

**Design Decision Recorded:**
*   **D24 (Revised - Privilege Separation):** The application will be architected as a multi-process system to achieve privilege separation. A **Privileged Supervisor Process** will retain `CAP_NET_RAW` to manage the application's lifecycle and perform socket operations. It will spawn and manage separate, **Unprivileged Control Plane** and **Data Plane Worker Processes**. These worker processes will run with no elevated privileges, receiving necessary sockets from the supervisor via file descriptor passing.

**Adversarial Question 14: Protocol Evolution**
*   **Question:** The control plane uses JSON for simplicity. What is the strategy for versioning this API to allow for backward-compatible changes and graceful upgrades of clients and the server?
*   **Initial Answer (Flawed):** Proposed a multi-layered approach with connection-time handshake and "Tolerant Reader" principles (D25), which was overly complex for a co-located client/server.
*   **User Correction/Objection:** "keep this protocol evolution bit simple. The client and server live in the same package, same repository and run on the same machine. There is no real good reason to support a mismatched protocol version between client and server."
*   **Re-evaluation & Revised Answer (Strict Protocol Versioning):** Acknowledged that the co-located nature of client and server negates the need for complex backward compatibility. A strict, fail-fast approach is more appropriate.
    *   **Strategy: "Exact Match or Fail":** A single, shared `PROTOCOL_VERSION` constant will be defined and compiled into both client and server.
    *   **Version Check:** The first message on any new connection must be a `VersionCheck` from the client. The server will compare this to its own hardcoded version.
    *   **Strict Enforcement:** If versions do not match exactly, the server will respond with a `VersionMismatch` error and immediately close the connection.
    *   **Policy:** Any change to the JSON protocol, no matter how small, requires incrementing the shared `PROTOCOL_VERSION`.
*   **Outcome:** Simplicity, safety (prevents runtime errors from mismatches), and low overhead.

**Design Decision Recorded:**
*   **D25 (Revised - Strict Protocol Versioning):** The control plane protocol will use a strict, fail-fast versioning scheme. A single, shared `PROTOCOL_VERSION` constant will be defined and compiled into both the server and client. The first message on any new connection must be a `VersionCheck` from the client. The server will compare the client's version to its own; if they do not match exactly, the server will respond with a `VersionMismatch` error and close the connection. Any change to the JSON protocol requires incrementing the shared `PROTOCOL_VERSION` constant.

**Adversarial Question 15: Egress Error Handling**
*   **Question:** How are transient egress errors (e.g., ARP failure resulting in `EHOSTUNREACH`) propagated to the operator? Are packets that fail to send simply dropped, or are they queued for a short-lived retry?
*   **Analysis:** Retrying egress packets in a high-performance, low-latency UDP relay is detrimental due to:
    *   Increased complexity and state management.
    *   Risk of buffer exhaustion and head-of-line blocking.
    *   Introduction of unpredictable latency and jitter, which is unacceptable for real-time UDP traffic.
    *   Violation of UDP's unreliable delivery principle.
*   **Mitigation Strategy: "Drop and Count":**
    *   **Behavior:** Packets that fail to send due to transient errors (e.g., `EHOSTUNREACH`, `ENETUNREACH`) will be dropped immediately. No retry mechanism will be implemented. Buffers will be released promptly.
    *   **Observability:** A new, first-class metric, `egress_errors_total`, will be introduced. This metric will be tracked on a per-output-destination basis and reported via the `StatsAggregator` (D14). This ensures operators have immediate visibility into egress failures without impacting data plane performance.

**Design Decision Recorded:**
*   **D26 (Egress Error Handling):** The application will use a "Drop and Count" strategy for transient egress errors. Packets that fail to send due to transient errors will be dropped immediately, with no retry mechanism, to preserve low latency and prevent head-of-line blocking. A new metric, `egress_errors_total`, will be tracked on a per-output-destination basis and exposed via the control plane to provide immediate visibility into egress failures.