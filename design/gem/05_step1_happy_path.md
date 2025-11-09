# Step 1: The "Happy Path" Test (Functional Correctness)

This document is for analyzing the GEM sketch under ideal conditions to ensure it is functionally correct.

---

## Question 1.1

**Does a source MCR instance (`MCR-A`) have all the information it needs to correctly encrypt and send a multicast data packet?**

### Comprehensive Answer

Yes, the source MCR (`MCR-A`) is self-sufficient. It operates on a "fire-and-forget" principle and does not require acknowledgements from peers.

The required information and workflow are as follows:

1.  **Pre-configured Secrets:** `MCR-A` must be configured with two shared secrets:
    *   The **Bootstrap Key (BK)**, for encrypting control messages.
    *   The **Group Authorization Key (GAK)** for the specific multicast group it intends to send to, for signing control messages.

2.  **Self-Generated Key:** `MCR-A` generates its own symmetric **Source Encryption Key (SEK)** for the data stream.

3.  **Control Plane Action (Encrypt and Sign):** Before sending data, `MCR-A` broadcasts its SEK in a control message.
    *   It constructs a message: `[My Identity] + [Target Group] + [SEK]`.
    *   It **signs** this message using the **GAK**.
    *   It then **encrypts** the `[Message + Signature]` blob using the **BK**.
    *   It sends this encrypted blob to the control-plane multicast address.
    *   It does not wait for any responses.

4.  **Data Plane Action (Immediate):** Immediately after broadcasting the control message, `MCR-A` can begin sending data packets.
    *   Receive a local multicast packet.
    *   Encrypt the payload with the **SEK**.
    *   Send the encrypted multicast packet to the destination group on the untrusted network.

**Conclusion:** The source `MCR-A` is not dependent on any state or response from its peers. Its ability to send traffic is entirely determined by its own configuration and actions. The dual-key system (BK for confidentiality, GAK for authentication) provides robust security for the control plane. This makes the source's logic simple and robust.

---

## Question 1.2

**Does a receiving MCR instance (`MCR-B`) have all the information it needs to correctly authorize, decrypt, and forward the packet?**

### Comprehensive Answer

Yes, the receiving MCR (`MCR-B`) can correctly process incoming traffic, and the refined model provides a robust way to handle out-of-order control and data plane packets.

The workflow for `MCR-B` is as follows:

1.  **Pre-configured Secrets:** `MCR-B` must be configured with:
    *   The **Bootstrap Key (BK)**, to decrypt control messages.
    *   The **Group Authorization Key (GAK)** for any group it is authorized to receive, to verify signatures on both control and data packets.

2.  **Control Plane Action (Receiving the SEK):**
    *   `MCR-B` receives an encrypted control message on the control-plane multicast address.
    *   It **decrypts** the message using the **BK**.
    *   It **verifies the signature** on the decrypted message using the **GAK**.
    *   If both steps succeed, it extracts the **SEK** and stores it in a local cache, associated with the source's identity and the multicast group.

3.  **Data Plane Action (Receiving Encrypted Data):**
    *   `MCR-B` receives an encrypted multicast data packet.
    *   **Step 3a: Authorization (Per-Packet Signature Check):** The data packet is structured as `[Encrypted Payload] + [Signature]`. `MCR-B` first **verifies the signature** using the **GAK**.
        *   If the signature is **invalid**, the packet is immediately dropped. This is a fast and efficient way to discard unauthorized traffic without attempting decryption.
    *   **Step 3b: Decryption:** If the signature is valid, `MCR-B` looks up the appropriate **SEK** in its cache (based on the packet's source and destination).
        *   If the **SEK is found**, it decrypts the payload and forwards the original multicast packet to its local network.
        *   If the **SEK is not yet in the cache** (i.e., the data packet arrived before the control message), `MCR-B` can optionally **queue the authorized packet** for a very short period, awaiting the arrival of the SEK. If the SEK does not arrive within a timeout, the queued packet is dropped.

**Conclusion:** This two-layer verification (GAK for authorization, SEK for decryption) is a robust and resilient model. It allows the receiver to immediately distinguish between unauthorized and legitimate traffic, and it provides a clear and secure mechanism for handling network race conditions where data packets arrive before their corresponding keys.

---

## Question 1.3

**What happens when a new peer (`MCR-C`) joins the group? Does it get everything it needs to participate?**

### Comprehensive Answer

Yes, the new peer `MCR-C` gets all the information it needs automatically and efficiently by leveraging the **Babel distance-vector routing protocol**. The previous ad-hoc discovery mechanism is replaced entirely by this more robust and proven approach.

The workflow for a new peer is as follows:

1.  **Bootstrap:** `MCR-C` starts with the pre-configured **Bootstrap Key (BK)**. This key is used to encrypt all Babel protocol traffic, creating a secure routing domain.

2.  **Babel Integration:** Each MCR instance runs an embedded Babel daemon. We will extend Babel to carry custom GEM information using a Type-Length-Value (TLV) mechanism.

3.  **Custom GEM TLVs:**
    *   **Public Key TLV:** Carries a node's IP address and its associated long-term Public Key.
    *   **SEK Announce TLV:** Carries the Source's IP, the target Multicast Group, the **Source Encryption Key (SEK)** for that stream, and a signature created with the **Group Authorization Key (GAK)**.

4.  **Convergence Process:**
    *   `MCR-C` starts its Babel process. It discovers its neighbors and begins the standard Babel route exchange, all protected by the **BK**.
    *   As part of the normal exchange of routing tables, `MCR-C` will receive all the **Public Key TLVs** and active **SEK Announce TLVs** that currently exist in the network.
    *   Babel's reliable flooding and state synchronization mechanism guarantees that `MCR-C` will converge to have the same set of public keys and SEKs as the existing peers.

**Conclusion:** This Babel-based approach elegantly solves the "new peer" problem. There is no need for a separate or special "catch-up" process. A new peer gets the complete, up-to-date control plane state (identities and keys) as a natural and inherent part of the routing protocol's convergence. This is a highly resilient and scalable solution.

---
