# Step 3: The "Bad Actor" Test (Security)

This document is for analyzing the security of the GEM sketch by assuming a malicious actor is on the untrusted network.

---

## Question 3.1

**Can a bad actor without the Bootstrap Key (BK) disrupt the public key exchange or join the Babel routing domain?**

### Comprehensive Answer

No, an attacker without the Bootstrap Key cannot join the routing domain or meaningfully disrupt the control plane. The design will use a robust, standards-based IPsec approach for control plane security, which provides a strong perimeter.

The security model is as follows:

1.  **IPsec for Control Plane:** The entire Babel routing domain (the control plane) will be carried over IPsec ESP tunnels. The application will not "roll its own" crypto for this layer.

2.  **Bootstrap Key as PSK:** The **Bootstrap Key (BK)** will serve as the Pre-Shared Key (PSK) for these IPsec tunnels.

3.  **Link-Local Tunnels:** When MCR instances discover each other on a network segment, they will use their IPv6 link-local addresses to establish point-to-point IPsec ESP tunnels between themselves. The Babel protocol will be configured to run exclusively over these secure tunnels.

This design effectively mitigates several threats from an attacker who does not possess the BK:

*   **Joining the Domain (Prevented):** To participate in the Babel routing exchange, an attacker must first establish an IPsec tunnel with a legitimate peer. Without the correct PSK, the IKE (Internet Key Exchange) handshake will fail, and no tunnel will be formed. The attacker is therefore completely locked out of the control plane.

*   **Eavesdropping (Prevented):** All Babel traffic, including the propagation of Public Key and SEK TLVs, is encrypted within the ESP tunnel. An attacker cannot read the control plane messages.

*   **Injection/Modification (Prevented):** IPsec's ESP provides strong integrity and anti-replay protection. Any attempt by an attacker to inject a fake packet or modify an existing one will cause the integrity check to fail at the receiving kernel, and the packet will be dropped before it ever reaches the Babel daemon.

*   **Denial of Service (Mitigated):** The only remaining vector is a flood-based Denial of Service attack, where the attacker sends a high volume of garbage traffic to the MCR host's link-local address. This is a general network-layer attack, not a protocol-specific one. It can be mitigated by standard host-based firewalling (`ip6tables`), which can be configured to drop traffic that does not originate from the link-local addresses of known, legitimate peers.

**Conclusion:** By using a standard IPsec ESP tunnel model, the control plane is robustly secured. The security is handled by the host OS kernel, which is more secure and performant than any application-layer encryption scheme. An attacker without the BK cannot compromise the control plane.

---

## Question 3.2

**Can a bad actor who has compromised a legitimate node's Bootstrap Key (BK), but not its Group Authorization Key (GAK), inject false SEK distribution messages?**

### Comprehensive Answer

No, this attack is prevented by a clear separation between transport-layer keys (BK) and application-layer authorization keys (GAK), using a correct symmetric key model for group authorization.

The corrected key hierarchy is as follows:

1.  **Root of Trust:** A Hardware Security Module (HSM) or other secure storage on each node is the ideal container for all key material.

2.  **Bootstrap Key (BK):** A symmetric pre-shared key used as the PSK for the IPsec tunnels that carry the Babel control plane traffic. It provides **transport security**.

3.  **Group Authorization Key (GAK):** The GAK is a **symmetric key** (e.g., 256-bit secret).
    *   This key is securely and manually provisioned (out-of-band) to only those MCR instances that are authorized members of a specific multicast group.
    *   Its sole purpose is to create **signatures (specifically, HMACs)** for control messages related to that group, providing **application-layer authorization**.

This creates a robust and correct separation of concerns.

The attack scenario now plays out as follows:

1.  **Compromise:** An attacker compromises a node that has the **BK** but is **not** authorized for the target "Broadcast Video" group (i.e., it does not possess the symmetric GAK for that group).

2.  **Join Control Plane:** The attacker uses the compromised BK to successfully establish an IPsec tunnel and join the Babel routing domain.

3.  **Attempt Malicious Injection:** The attacker crafts a malicious "SEK Announce TLV" for the "Broadcast Video" group.

4.  **HMAC Failure:** To be accepted by peers, this TLV must be accompanied by a valid HMAC signature. This HMAC must be calculated using the symmetric **GAK** for the "Broadcast Video" group. The attacker does not possess this key and therefore cannot generate the correct HMAC.

5.  **Peer Rejection:** Legitimate members of the "Broadcast Video" group receive the malicious TLV. They use their shared copy of the symmetric **GAK** to compute the HMAC of the message and compare it to the HMAC received from the attacker. The comparison fails.

**Conclusion:** The malicious TLV is discarded. The layered security model, with a clear distinction between the transport key (BK) and the symmetric authorization key (GAK), successfully prevents an attacker who has only breached the transport layer from injecting malicious application-layer commands. The design correctly uses symmetric key operations (HMAC) for group authentication.

---

## Question 3.3

**Can a bad actor capture and replay a valid SEK distribution message (a Babel TLV) to cause confusion or denial of service? (A replay attack)**

### Comprehensive Answer

No, this attack is prevented at the transport layer by the **anti-replay mechanism inherent in the IPsec ESP protocol**. We do not need to add a separate sequence number or timestamp within our application-level TLV.

The protection mechanism works as follows:

1.  **IPsec as the Foundation:** As established in Q3.1, all Babel control plane traffic runs exclusively over IPsec ESP tunnels established between peers.

2.  **Built-in Anti-Replay:** The IPsec ESP protocol includes a mandatory and robust anti-replay service.
    *   **Sequence Numbers:** The sending node embeds a strictly increasing sequence number into every encrypted ESP packet.
    *   **Anti-Replay Window:** The receiving node's kernel maintains an "anti-replay window," which is a record of the sequence numbers of recently received, valid packets.

3.  **Attack Scenario and Mitigation:**
    *   An attacker captures a valid, encrypted Babel packet that contains a legitimate SEK Announce TLV. This packet has a specific IPsec sequence number (e.g., #123).
    *   Later, the attacker replays this packet on the network.
    *   The receiving MCR instance's kernel receives the replayed packet. It examines the IPsec header and sees sequence number #123 again.
    *   Because #123 is already recorded in its anti-replay window, the kernel identifies the packet as a duplicate and **discards it immediately**.

**Conclusion:** The replayed packet never reaches the Babel daemon or the MCR application logic. The attack is defeated at the kernel level. By leveraging a standard and secure transport (IPsec), we inherit its security features, including robust protection against replay attacks. This is a more secure and efficient solution than implementing our own application-level anti-replay logic.

---
