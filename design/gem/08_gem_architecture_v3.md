# GEM Architecture v3 (Hardened)

## 1. Overview

This document describes the v3 architecture for Group Encrypted Multicast (GEM). This design is the result of a formal Red Team analysis of the v2 architecture and incorporates specific mitigations for identified vulnerabilities. It serves as the definitive blueprint for implementation.

The core innovation of GEM remains: to transport encrypted multicast traffic **natively as multicast**, preserving network efficiency and multicast semantics over untrusted networks.

## 2. The Two-Plane Architecture

GEM is composed of a secure Control Plane for identity and key distribution, and a Data Plane for secure packet transport.

### 2.1. The Control Plane: Babel over IPsec

The control plane's function is to create a secure, resilient, and decentralized routing domain for MCR instances to exchange identity and keying information.

*   **Transport Security (IPsec):**
    *   The entire control plane is secured at the transport layer using **IPsec ESP tunnels**.
    *   A symmetric **Bootstrap Key (BK)**, ideally stored in a Hardware Security Module (HSM), is used as the Pre-Shared Key (PSK) for these tunnels.
    *   Tunnels are established between the **IPv6 link-local addresses** of neighboring MCR instances.
    *   The IPsec layer provides confidentiality, integrity, and **built-in anti-replay protection** for all Babel traffic, mitigating the replay attack vector identified in the Red Team review.

*   **Routing & Information Propagation (Babel):**
    *   The **Babel distance-vector routing protocol** runs exclusively over the secure IPsec tunnels.
    *   Babel is responsible for peer discovery, route propagation, and ensuring the eventual consistency of the control plane state. Its use provides inherent resilience against packet loss, node restarts (via "Full Table Request"), and network partitions.

*   **Custom Information Exchange (Babel TLVs):**
    *   Custom TLVs are carried by Babel to propagate GEM-specific information:
        1.  **Public Key TLV:** Associates a node's IP address with its long-term **Node Public Key**. This establishes a network-wide trusted identity map.
        2.  **SEK Announce TLV:** Used by a source to announce the key for a specific stream.

### 2.2. The Data Plane: Source-Encrypted Multicast

The data plane is responsible for the high-performance encryption and forwarding of user multicast traffic.

*   **Traffic Format:** The data traffic remains as standards-compliant multicast. Only the payload is encrypted.
*   **Encryption (Confidentiality):** Each source MCR instance generates a unique, symmetric **Source Encryption Key (SEK)** for each multicast stream it originates.
*   **Per-Packet Authorization (Integrity):** Each encrypted data packet is appended with a **signature (HMAC)** created with the symmetric **Group Authorization Key (GAK)**. This allows receivers to quickly verify that a packet is from an authorized group member before attempting decryption, mitigating garbage flood attacks.

## 3. Key Hierarchy and Lifecycle Management

The security of the system is rooted in a multi-layered key hierarchy, designed to separate concerns and mitigate the impact of a single key compromise.

1.  **Node Private/Public Key (Asymmetric Identity):** The permanent, unique identity of an MCR instance, with the private key ideally stored in an HSM.
2.  **Bootstrap Key (BK) (Symmetric Transport):** The PSK for the IPsec control plane. A compromised BK allows an attacker to join the control plane but not to authorize or decrypt data. BK rotation is a manual, out-of-band process.
3.  **Group Authorization Key (GAK) (Symmetric Authorization):** A pre-shared key for a specific multicast group. Provisioned only to authorized nodes. A compromised GAK allows an attacker to sign/verify traffic for one group, but not to decrypt it or access the control plane.
4.  **Source Encryption Key (SEK) (Symmetric Confidentiality):** A temporary key for a single stream. A compromised SEK only exposes a single stream from a single source.
5.  **KMG Private/Public Key (Asymmetric Administration):** The root of administrative authority, used for GAK rotation. The private key is kept highly secure and offline. The public key is distributed to all nodes.

### 3.1. Key Revocation and Rotation (GAK)

Rotation of a compromised GAK is handled by a decentralized, in-band mechanism using a Key Management Group (KMG).

*   **KMG Multicast Group:** A dedicated, well-known multicast address is used for administrative messages.
*   **Workflow:**
    1.  An administrator creates a "distribution package" containing the new `GAK-2`, encrypted for each legitimate group member's **Node Public Key**.
    2.  The administrator **signs this package** with the **KMG Private Key**.
    3.  The signed package is broadcast to the KMG multicast group.
    4.  All nodes receive this broadcast. They first verify the package's signature with the **KMG Public Key**.
    5.  Each legitimate node then finds and decrypts its specific portion of the package with its **Node Private Key** to retrieve `GAK-2`.
    6.  The compromised node is not included in the package and never learns the new key, implicitly revoking its access.

## 4. Detailed Workflow Summary

1.  **Initialization:** Nodes use the BK to establish IPsec tunnels and start the Babel protocol. They exchange Public Key TLVs to build a trusted identity map.
2.  **Source Stream Start:** `MCR-A` generates an SEK for its stream. It creates an SEK Announce TLV, signs it with the GAK, and injects it into Babel. Babel propagates it to all peers.
3.  **Data Transmission:** `MCR-A` encrypts data packets with the SEK and appends a GAK-based HMAC to each packet before sending as multicast.
4.  **Data Reception:** `MCR-B` receives a packet. It first verifies the per-packet HMAC with the GAK. If valid, it looks up the correct SEK (based on the source IP) and decrypts the payload.
5.  **GAK Revocation:** An administrator broadcasts a KMG-signed distribution package to the KMG multicast group, allowing all legitimate nodes to securely receive and switch to a new GAK.

---
