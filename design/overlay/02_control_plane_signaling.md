# Control Plane Signaling in the MCR/GEM Overlay

## 1. Summary: The Three-Part Multicast Workflow

The MCR/GEM overlay control plane uses a three-part signaling process to efficiently manage the distribution of multicast streams. This process is analogous to the roles of MSDP, IGMP, and key servers in a traditional multicast network. It ensures that traffic is only sent where it is explicitly requested by authorized receivers.

The three phases are:

1.  **Discovery (The "Menu"):** A source announces that a multicast stream is available.
2.  **Subscription (The "Order"):** An authorized receiver explicitly requests to receive that stream.
3.  **Enablement (The "Key"):** The source provides the cryptographic key needed to decrypt the stream to the subscribed receiver.

These three phases are implemented using three distinct, custom Type-Length-Value (TLV) structures that are propagated via the Babel-over-IPsec control plane.

---

## 2. Detailed TLV Descriptions

### 2.1. The Source Active (SA) TLV

*   **Purpose:** **Discovery.** Announces that a multicast stream is available on the network.
*   **Analogy:** MSDP Source-Active message.
*   **Content:**
    *   `Source IP`: The routable virtual IP of the `mcr-overlay` daemon originating the stream.
    *   `Group IP`: The destination multicast group address.
    *   `Flags`: (e.g., indicating if the stream is encrypted or plain-text).
*   **Security:** The SA-TLV **must be signed**. The signature is created using the **Group Authorization Key (GAK)** for the specified `Group IP`. This proves the announcer is an authorized member of the group and prevents unauthorized nodes from advertising fake streams.
*   **Function:** Provides a "menu" of available streams that potential subscribers can see.

### 2.2. The Subscription TLV

*   **Purpose:** **Subscription.** Allows a node to explicitly request a stream on behalf of its local network listeners.
*   **Analogy:** IGMP Join / PIM Join message.
*   **Content:**
    *   `Source IP`: The IP of the stream the node wishes to subscribe to.
    *   `Group IP`: The group of the stream the node wishes to subscribe to.
    *   `Receiver Identity`: The public key or identifier of the subscribing node.
*   **Security:** The Subscription TLV **must be signed** by the subscribing node's **Node Private Key**. This proves the authenticity of the request and prevents a malicious node from forging subscriptions on behalf of others.
*   **Function:** Provides the "order" from the menu. It signals to the source's Forwarding Policy Engine that a specific peer wants to receive a specific stream.

### 2.3. The SEK Announce TLV

*   **Purpose:** **Enablement.** Securely distributes the decryption key for an encrypted stream.
*   **Analogy:** Key server distribution message.
*   **Content:**
    *   `Source IP`: The IP of the stream's source.
    *   `Group IP`: The group of the stream.
    *   `Source Encryption Key (SEK)`: The symmetric key used to encrypt the data plane payload.
*   **Security (Crucial):** The SEK Announce TLV **must be signed**. The signature is created using the **Group Authorization Key (GAK)** for the specified `Group IP`.
*   **Function:** Provides the "key" to unlock the content.

---

## 3. Clarification: The GAK and SEK-Announce-TLV Relationship

The integrity and authenticity of the `SEK-Announce-TLV` are entirely dependent on the **Group Authorization Key (GAK)**.

*   When a source creates an `SEK-Announce-TLV` for a stream destined for group `239.1.1.1`, it calculates an HMAC signature over the TLV's content using the `GAK-for-239.1.1.1`.
*   When a receiver gets this TLV, it looks at the `Group IP` field (`239.1.1.1`), retrieves the corresponding `GAK-for-239.1.1.1` from its local secure storage, and uses it to verify the HMAC.

This ensures that:
1.  Only an authorized member of a group (a node possessing the GAK) can create a valid key announcement for that group.
2.  A receiver will only accept a key announcement if it comes from a legitimate, authorized source.

This GAK-based signing mechanism is the core of the security model for key distribution.
