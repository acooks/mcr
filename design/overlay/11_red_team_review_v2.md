# Red Team Review of Overlay Sketch v2

This document contains adversarial questions and challenges for the `01a_overlay_sketch_v2.md` design, along with the Blue Team's responses and mitigations.

---

## Category 1: Control Plane Complexity & Contradictions

### 1. Control Plane Overload

*   **Challenge:** The Babel control plane is responsible for propagating many different types of information (Public Keys, SEKs, SAs, etc.). Is there a risk of this control plane becoming too complex or chatty?

*   **Response & Mitigation:**
    *   The challenge's premise is flawed. The various TLV types do not represent disparate, unrelated functions. They represent a single, coherent, and fundamentally linked set of **network state**:
        1.  Who is on the network (Public Keys).
        2.  What are they sending (Source Active TLVs).
        3.  How do I process what they are sending (SEK Announce TLVs).
    *   A routing protocol like Babel is the ideal and correct tool for synchronizing a shared view of network state across a distributed system. Using separate protocols would risk race conditions and state inconsistencies.
    *   The point regarding "Negotiating keys for Unicast ESP Tunnels" is a strawman. Data plane ESP tunnel keys would be negotiated by a dedicated IKE daemon (e.g., strongSwan). Babel's only role would be to advertise the public identity keys required for the IKE authentication, which is already covered by the Public Key TLV.
### 2. Contradictory Egress Models

*   **Challenge:** The sketch proposes two GEM egress modes: "Bridged Encrypted Multicast" and "Unicast ESP Tunnel". How does a receiver node know which type of traffic to expect? The sketch does not define the signaling for this.

*   **Response & Mitigation:**
    *   The challenge correctly identifies a missing piece of the design. The two egress modes are not contradictory, but represent dynamically chosen paths based on network conditions and reachability, rather than a static configuration.
    *   **New Architectural Component: The Forwarding Policy Engine.** This engine will reside on the source node and be responsible for making intelligent decisions about the egress path for each stream and each potential receiver.
    *   **Dynamic Path Selection:**
        1.  The Forwarding Policy Engine leverages **Babel's link quality metrics** (which are already part of the control plane) to assess the quality and type of path to each known peer.
        2.  **Policy Rule Example:**
            *   If the Babel metric to a peer is below a configured threshold (indicating a local, high-quality link), the engine will select the **Bridged Encrypted Multicast** egress path for that peer.
            *   If the metric is above the threshold (indicating a remote, WAN link), the engine will select the **Unicast ESP Tunnel** egress path for that peer.
        3.  A single source can simultaneously use both egress paths to reach different sets of receivers.
    *   **Receiver Behavior:** A receiver node does not need to know in advance which mode a source is using. It simply configures itself to listen for both types of traffic (i.e., it listens for bridged multicast on its local interfaces and also processes incoming traffic from its unicast ESP tunnels).
    *   **Conclusion:** The design is refined to include a dynamic Forwarding Policy Engine that intelligently selects the appropriate egress path based on Babel metrics. This resolves the ambiguity and adds a critical new architectural component. No architectural change is required for the egress modes themselves, but the signaling and decision-making logic are now defined.

### 3. Source Discovery vs. SEK Announcement

*   **Challenge:** Are the "Source Active (SA) TLV" and the "SEK Announce TLV" redundant? Announcing an SEK for a (Source, Group) seems to imply the source is active.

*   **Response & Mitigation:**
    *   The challenge correctly identified that the original sketch was missing a key component, which created the appearance of redundancy. The refined architecture now includes a third TLV, the `Subscription-TLV`, which clarifies the distinct and non-redundant roles of all three.
    *   The control plane follows a complete, three-part multicast workflow:
        1.  **Discovery (SA-TLV):** The `SA-TLV` acts as a "menu" or service announcement. It allows a source to declare that a stream is available *without* immediately sending the key. This is crucial for stream discovery and for supporting potential future features like plain-text streams.
        2.  **Subscription (Subscription-TLV):** This is the IGMP-like "join" message. A receiver, having seen the stream on the "menu," sends this TLV to explicitly request the traffic. This prevents the source from flooding traffic to all authorized group members and makes the system bandwidth-efficient.
        3.  **Enablement (SEK-TLV):** This is the "key" for the stream. The source sends this to provide the cryptographic material needed to decrypt the stream. This might be sent only to subscribed peers, or broadcast to the group, knowing that only subscribed peers will receive the actual data traffic.
    *   **Conclusion:** The three TLVs are not redundant. They map to the three necessary phases of a robust multicast protocol (Discovery, Subscription, Enablement) and are all required for an efficient and scalable system. No architectural change is required other than formally adopting this three-TLV model, which is detailed in `02_control_plane_signaling.md`.

## Category 2: Data Plane & Forwarding Logic

### 4. Unicast ESP Tunnel Keying

*   **Challenge:** The keying mechanism for the data plane Unicast ESP Tunnels is undefined.

*   **Response & Mitigation:**
    *   The keying mechanism will be based on a simple, robust, symmetric Pre-Shared Key (PSK) model, not a complex IKE/certificate model.
    *   **The Key:** The existing symmetric **Bootstrap Key (BK)** will be reused for this purpose. The same key that secures the control plane will also secure the data plane unicast tunnels, providing a consistent security architecture.
    *   **Mechanism:**
        1.  The need for a separate IKE daemon (e.g., strongSwan) is eliminated.
        2.  When the Forwarding Policy Engine on a source node decides to send unicast traffic to a remote peer, the `mcr-overlay` daemon itself will configure the necessary IPsec ESP tunnel in the Linux kernel (e.g., via `netlink` or `ip-xfrm`).
        3.  This tunnel will be configured to use the **Bootstrap Key (BK)** as the symmetric PSK for encryption and authentication.
    *   **Conclusion:** This is a simple and secure "full mesh" PSK model. Every node shares the same BK, allowing any node to establish a secure unicast tunnel with any other node without complex key negotiation. This design is cohesive and avoids unnecessary external dependencies.

### 5. The "Routing Step" Ambiguity

*   **Challenge:** The internal mechanism for passing a packet from the Normalizer function to the Gateway function is unclear. Is it a slow trip through the kernel stack or a fast in-memory handoff?

*   **Response & Mitigation:**
    *   **Architectural Decision:** The MCR Normalizer and the GEM Gateway will be developed as **two separate, composable daemons**. They are not two functions within a single monolithic application.
    *   **Handoff Mechanism:** The connection between the two daemons will be a standard Linux **`veth` pair**. The `mcr-normalizer` daemon will write its plain-text, normalized multicast output to one end of the pair, and the `gem-gateway` daemon will read that traffic from the other end.
    *   **Performance Trade-off:** This design choice means the handoff is a trip through the kernel's network stack, which incurs more overhead than a purely in-memory handoff. This is a **deliberate architectural trade-off**.
    *   **Justification:** The performance cost is accepted in order to gain immense and critical advantages in flexibility and composability. By exposing the normalized traffic on a standard kernel interface, users can insert other standard Linux networking functions (e.g., `nftables` firewall rules, QoS policies, `tcpdump` for debugging) between the two components. This makes the entire system more powerful, transparent, and easier to integrate into complex environments. It prioritizes robust, future-proof design over micro-optimization.

### 6. Performance of Chained Functions

*   **Challenge:** What is the performance impact of the multi-stage processing pipeline (normalize, encrypt, encapsulate)?


## Category 3: Security & Trust Model

---