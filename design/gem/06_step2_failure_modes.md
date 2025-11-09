# Step 2: The "Failure Modes" Test (Resilience & Reliability)

This document is for analyzing how the GEM sketch behaves under common failure conditions to ensure the design is resilient and reliable.

---

## Question 2.1

**What happens if a signed SEK distribution message (now a Babel TLV) is lost due to packet drop? Do peers ever get the key?**

### Comprehensive Answer

Yes, peers will eventually get the key. The loss of a single SEK Announce TLV is a transient failure that is automatically handled by the Babel protocol's inherent resilience. We will explicitly avoid building any new, chatty return channel or acknowledgement mechanism.

The recovery process works as follows:

1.  **No Acknowledgements:** The source MCR that injects the SEK Announce TLV into Babel does not expect or wait for any acknowledgement. This aligns with our "fire-and-forget" design principle.

2.  **Babel's Resilience Mechanisms:** The Babel protocol is designed to operate over unreliable UDP and is built to handle packet loss. It ensures eventual consistency through two primary mechanisms:
    *   **Periodic Updates:** Babel nodes periodically exchange their full routing tables (or summaries thereof). If a peer misses the initial "triggered update" that announced a new SEK, it will receive the SEK information in the next scheduled periodic update from its neighbor.
    *   **State Comparison:** Babel messages like "I-Have" allow nodes to quickly determine if their neighbor has information that they are missing, and they can request it.

3.  **Recovery Timeframe:** The convergence time is tunable. By configuring Babel's timers (e.g., the "Update" interval) to a value in the range of 10-30 seconds, we can ensure that a lost SEK is recovered well within our target of "seconds or tens of seconds," not minutes.

4.  **Receiver Behavior:** The receiver's behavior, as defined in the "Happy Path" analysis (Q1.2), is designed to tolerate this brief delay. When an encrypted data packet arrives:
    *   It is first authorized by checking the GAK signature.
    *   If authorized but the corresponding SEK has not yet arrived, the packet is queued for a short period.
    *   This queue provides a buffer to absorb the latency of the Babel protocol's recovery, allowing the SEK to arrive before the data packet is discarded.

**Conclusion:** The problem of lost control messages is effectively solved by the choice of the Babel protocol. No additional mechanisms are needed.

---

## Question 2.2

**What happens if an MCR instance crashes and restarts? How does it rejoin the group and get the current keys?**

### Initial Thoughts (To Be Expanded)

*   This scenario seems to be fully and elegantly handled by the Babel-based design.
*   When the MCR instance restarts, its embedded Babel daemon will start.
*   It will go through the standard Babel neighbor discovery and route exchange process, protected by the Bootstrap Key (BK).
*   As part of the routing table convergence, it will automatically receive the full, current set of Public Key TLVs and SEK Announce TLVs from its neighbors.
*   There is no special "rejoin" logic needed. The process of joining for the first time and rejoining after a crash are identical from the protocol's perspective.

---

## Question 2.3

**What happens if the network partitions, separating the group into two halves (e.g., A & B on one side, C & D on the other)?**

### Initial Thoughts (To Be Expanded)

*   Babel is designed to handle network partitions.
*   **Within each partition:** The nodes (A+B and C+D) will maintain connectivity with each other. They will continue to exchange routes and keys. If A is a source, B will continue to receive its traffic.
*   **Between partitions:** Babel routes between the partitions will time out and be withdrawn. A and B will no longer see C and D as reachable, and vice-versa.
*   **Key Distribution:** If a source (e.g., A) generates a *new* SEK while the partition is active, that SEK Announce TLV will only propagate to B. It will not reach C and D.
*   **Data Plane:** Encrypted multicast traffic from A will likely not reach C and D due to the underlying network failure.
*   **Healing:** When the partition heals, Babel's protocol will automatically re-establish routes between the two halves. The routing tables will re-converge, and any SEK Announce TLVs that were created during the partition will be propagated to the other side.
*   This seems to be a robust and correct behavior.

---
