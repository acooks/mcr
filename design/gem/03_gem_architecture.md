# Architecture: Group Encrypted Multicast (GEM)

## 1. Introduction

This document details the architectural design for integrating Group Encrypted Multicast (GEM) functionality into MCR. GEM enables secure, scalable transport of multicast traffic over untrusted unicast networks. It builds upon the existing MCR architecture (refer to `ARCHITECTURE.md`).

## 2. Core Architectural Principles

*   **Minimal Impact on Fast Data Path:** GEM processing (encryption/decryption) should be integrated with minimal overhead to the existing high-performance data plane.
*   **Centralized Key Management:** A dedicated MCR instance will act as a Key Server (KS) to manage and distribute group keys, simplifying operational complexity.
*   **Leverage Existing IPC:** Utilize MCR's existing Unix domain socket IPC for secure communication between Supervisor and Workers, and for KS-GM communication.
*   **Extensibility:** Design for future expansion (e.g., different encryption algorithms, more complex policies).

## 3. Data Plane Modifications

GEM introduces two new types of packet processing within the data plane:

### 3.1. Encrypting Group Member (EGM) - Sending Side

When an MCR instance is configured to send multicast traffic via a GEM tunnel:

1.  **Ingress (Existing):** The Ingress Loop (`src/worker/ingress.rs`) receives a raw Ethernet frame, parses it, filters it, and extracts the UDP payload, as per existing architecture.
2.  **Encryption & Encapsulation (New):** Instead of sending the raw UDP payload to the Egress Loop for standard multicast forwarding, the Ingress Loop will:
    *   Retrieve the current symmetric encryption key for the GEM group from its local, secure cache.
    *   Encrypt the UDP payload using AES-256-GCM (or similar).
    *   Encapsulate the encrypted payload into a new unicast UDP packet. The outer header will have the destination IP/port of the peer Decrypting Group Member (DGM).
3.  **Egress (Existing):** The newly formed unicast UDP packet (containing the encrypted multicast payload) is then sent to the Egress Loop (`src/worker/egress.rs`). The Egress Loop treats this as a standard unicast UDP packet destined for the peer DGM.

### 3.2. Decrypting Group Member (DGM) - Receiving Side

When an MCR instance is configured to receive multicast traffic via a GEM tunnel:

1.  **Ingress (New Socket Type):** A new type of input socket will be introduced in the Ingress Loop: a standard `AF_INET` UDP socket bound to a specific unicast port (defined by `ForwardingRule.tunnel_from_port`). This socket will listen for incoming encrypted GEM unicast packets.
2.  **Decapsulation & Decryption (New):** When a packet arrives on this `tunnel_from_port` socket, the Ingress Loop will:
    *   Retrieve the current symmetric decryption key for the GEM group from its local, secure cache.
    *   Decrypt the encapsulated payload.
    *   Verify the integrity of the decrypted payload (using GCM's authentication tag).
    *   Recover the original multicast UDP payload.
3.  **Re-injection (New):** The recovered original multicast UDP payload is then treated as if it were a locally received multicast packet. It is passed to the Egress Loop for re-injection into the local multicast network, using the original multicast group and port from the `ForwardingRule`.

## 4. Control Plane Modifications

### 4.1. New `RelayCommand`s

New `RelayCommand` variants will be introduced to manage GEM-specific rules and key server interactions:

*   `AddGemRule(ForwardingRule)`: A `ForwardingRule` can now specify `tunnel_to` and `preshared_key` in its `OutputDestination`s for EGM, or `tunnel_from_port` for DGM.
*   `ConfigureKeyServer(KeyServerConfig)`: Configures an MCR instance to act as a GEM Key Server.
*   `RegisterGroupMember(GroupMemberConfig)`: Configures an MCR instance to register with a Key Server.

### 4.2. Key Server (KS) Architecture

*   **Role:** A designated MCR Supervisor instance will run as the GEM Key Server.
*   **Key Generation:** The KS will generate symmetric AES-256-GCM keys for each GEM group.
*   **Key Distribution:** GMs will establish a secure channel (e.g., TLS-protected Unix socket or DTLS over UDP) with the KS to request and receive keys. The KS will push key updates (rekeying) to active GMs.
*   **Key Storage:** The KS will securely store active and previous keys (for rekeying transitions).

### 4.3. Group Member (GM) Key Management

*   **Registration:** GMs will initiate a registration process with the configured KS, providing their identity.
*   **Key Cache:** Each GM (worker process) will maintain a secure, in-memory cache of the current symmetric keys for the GEM groups it is a member of.
*   **Rekeying:** GMs will receive new keys from the KS and manage the transition to the new key without interrupting traffic.

## 5. Security Considerations

*   **Key Protection:** Keys must never be stored in plain text on disk. In-memory storage must be protected where possible.
*   **Authentication:** GMs must authenticate with the KS, and the KS must authenticate GMs, to prevent unauthorized key distribution.
*   **Integrity & Confidentiality:** AES-256-GCM provides both confidentiality and integrity for the encapsulated multicast traffic.
*   **Replay Protection:** GCM includes a nonce, which helps prevent replay attacks. Additional mechanisms may be considered.

## 6. Phased Implementation (Architectural View)

1.  **Phase 1: Manual Encrypted Tunnel:** Implement the data plane encryption/decryption and encapsulation/decapsulation using a pre-shared key. This will bypass the KS for initial validation.
2.  **Phase 2: Basic Key Server:** Implement the KS role and GM registration/key distribution over a secure channel.
3.  **Phase 3: Rekeying & Policy:** Add automatic key rotation and more granular policy enforcement.

---
