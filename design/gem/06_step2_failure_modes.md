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

### Comprehensive Answer

A restarting MCR instance recovers the complete network state quickly and efficiently by leveraging the **"Full Table Request" mechanism within the Babel protocol**. This avoids passive waiting and prevents network storms.

The process is as follows:

1.  **Restart and Neighbor Discovery:** The crashed instance (`MCR-C`) restarts. Its embedded Babel daemon, secured by the **Bootstrap Key (BK)**, comes online. It uses Babel's standard "Hello" messages to discover its immediate, reachable neighbors (e.g., `MCR-B`).

2.  **Active State Request:** Instead of passively waiting for periodic updates, `MCR-C` immediately sends a **Babel "Request" message** to its neighbor `MCR-B`. This is a standard protocol feature that asks the neighbor to send its entire routing table.

3.  **Full State Transfer:** Upon receiving the request, `MCR-B` responds with a series of update messages containing its **complete routing table**. This table includes all the custom GEM TLVs it knows about:
    *   The **Public Key TLV** for every known peer in the network.
    *   The active **SEK Announce TLV** for every currently active source stream.

4.  **Fast Convergence:** `MCR-C` processes these updates and instantly populates its own tables with the full set of identities and active keys for the entire group. This catch-up mechanism is localized between the new node and its neighbor; it does not trigger a network-wide re-advertisement ("strobing") of keys and does not require inefficient pair-wise communication with every other node.

**Conclusion:** The process for rejoining after a crash is identical to joining for the first time and is fully handled by the Babel protocol. By using an active "Request" for the full routing table, a restarting node can converge and begin participating (including decrypting traffic) in a matter of seconds, ensuring high availability and resilience.

---

## Question 2.3

**What happens if the network partitions, separating the group into two halves (e.g., A & B on one side, C & D on the other)?**

### Comprehensive Answer

The system handles network partitions gracefully, and the multi-source model is a core part of its resilience. The scenario where multiple sources exist for the same group is expected and normal.

The workflow is as follows:

1.  **Fundamental Design Principle:** It is a primary use case for multiple MCR instances (e.g., `MCR-A` and `MCR-C`) to be independent sources for the *same* multicast group (e.g., `239.1.1.1`). Each source generates and distributes its own unique **Source Encryption Key (SEK)**.

2.  **Receiver Operation:** A receiver (`MCR-B`) is designed to handle this. Its key cache maps keys based on a combination of the source's identity and the multicast group. For example:
    *   `(Source: MCR-A, Group: 239.1.1.1) -> SEK-A`
    *   `(Source: MCR-C, Group: 239.1.1.1) -> SEK-C`
    When `MCR-B` receives encrypted traffic for `239.1.1.1`, it uses the packet's source IP address to look up the correct SEK for decryption.

3.  **During a Partition:**
    *   The group splits into two independent, functional partitions (e.g., A+B and C+D).
    *   Within each partition, Babel maintains connectivity, and sources continue to distribute their SEKs to local peers. `MCR-B` will continue to process `MCR-A`'s stream, and `MCR-D` will continue to process `MCR-C`'s stream.
    *   Babel routes between the partitions will time out and be withdrawn.

4.  **When the Partition Heals:**
    *   The underlying network connectivity is restored.
    *   Babel's protocol automatically discovers the restored paths and the two partitions re-converge into a single routing domain.
    *   As part of this convergence, the SEK Announce TLVs from each partition are flooded to the other. `MCR-D` will learn about `SEK-A`, and `MCR-B` will learn about `SEK-C`.
    *   Shortly after convergence, `MCR-B` will start receiving encrypted data from `MCR-C`. Since it now has `SEK-C`, it will begin decrypting and forwarding this second stream. The same will happen for `MCR-D` with `MCR-A`'s stream.

**Conclusion:** The design requires no special logic to handle network partitions. The combination of the Babel routing protocol for state convergence and the multi-source-aware data plane design ensures that the system automatically and correctly recovers to the desired state after a partition heals.

---
