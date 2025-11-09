# Sketch v3: MCR/GEM Overlay Network

## 1. High-Level Vision

To create a unified software service (`mcr-overlay`) that provides a comprehensive toolkit for multicast networking, including normalization, source discovery, and secure transport over diverse underlying networks.

## 2. Core Daemon Functions

The `mcr-overlay` daemon is a modular system that can be configured to perform several distinct functions.

### 2.1. Function A: MCR Normalizer (RPF Solver)

*   **Problem Solved:** Makes multicast streams from legacy, unroutable sources compatible with standard, routed multicast networks.
*   **Mechanism:**
    1.  Creates a virtual loopback interface with a routable IP address.
    2.  Captures the unroutable multicast stream.
    3.  Re-sources the stream by replacing the original source IP with its own routable virtual IP, solving the RPF-check problem for downstream routers.

### 2.2. Function B: Source Discovery Announcer (MSDP Replacement)

*   **Problem Solved:** Provides a decentralized, near-real-time mechanism for all nodes to learn about active multicast sources across the network.
*   **Mechanism:**
    1.  Leverages the **Babel-over-IPsec control plane**.
    2.  When a source becomes active (either via the MCR Normalizer or a native routed source), the local daemon injects a custom **Source Active (SA) TLV** into Babel.
    3.  This `SA-TLV(Source, Group)` is reliably propagated to all other daemons, creating a shared, eventually consistent view of the multicast network state.

### 2.4. Function D: Forwarding Policy Engine (New Component)

*   **Problem Solved:** Dynamically selects the optimal egress path for encrypted multicast traffic based on network conditions and peer reachability.
*   **Mechanism:**
    1.  Resides on the source `mcr-overlay` daemon.
    2.  Leverages **Babel's link quality metrics** to assess the path quality to each known peer.
    3.  Applies configurable policy rules (e.g., metric thresholds) to decide whether to use the Unicast ESP Tunnel egress (for high-latency/unicast-only paths) or the Bridged Encrypted Multicast egress (for low-latency/multicast-capable paths).
    4.  A single source can simultaneously use both egress paths to reach different sets of receivers.

### 2.3. Function C: GEM Gateway (Secure Transport)

*   **Problem Solved:** Secures multicast traffic for transport over untrusted or multicast-incapable networks.
*   **Mechanism:**
    1.  **Ingress:** Subscribes to a routable multicast stream on its local network.
    2.  **Processing:** Encrypts the packet payload with a **Source Encryption Key (SEK)** and appends a signature (HMAC) created with the **Group Authorization Key (GAK)**.
    3.  **Egress (Dynamically Selected):** The **Forwarding Policy Engine** dynamically determines the appropriate egress mode for the encrypted traffic based on the destination peer's reachability and link quality.

#### 2.3.1. GEM Egress Mode 1: Unicast ESP Tunnel

*   **Use Case:** Transporting multicast over the public internet or other unicast-only WANs.
*   **Mechanism:**
    1.  The encrypted GEM packet is encapsulated within a **point-to-point unicast IPsec ESP tunnel**.
    2.  This tunnel is established between the public, routable IP addresses of the source and destination GEM Gateways. Keys for this tunnel can be negotiated via the Babel control plane.
    3.  The daemon writes the resulting ESP packet to a virtual tunnel interface (e.g., `ipsec0`) for the OS to route.

#### 2.3.2. GEM Egress Mode 2: Bridged Encrypted Multicast

*   **Use Case:** Securing multicast traffic across a private network that already has multicast routing enabled.
*   **Mechanism:**
    1.  The encrypted GEM packet (with its multicast destination IP preserved) is **not** put in a unicast tunnel.
    2.  Instead, it is written to a **`veth` pair interface**.
    3.  The user can then bridge this `veth` interface to the appropriate physical interface, directing the encrypted multicast traffic onto the desired underlay network.

## 3. A Complete End-to-End Workflow (Internet Transport)

1.  **Studio A (Daemon 1 - MCR Normalizer):**
    *   Captures unroutable stream `10.1.1.50 -> 239.1.1.1`.
    *   Re-sources it as `192.168.100.1 -> 239.1.1.1`.
    *   Injects an `SA-TLV(192.168.100.1, 239.1.1.1)` into Babel.

2.  **Studio A (Daemon 2 - GEM Gateway, Unicast Mode):**
    *   Subscribes to the normalized stream `192.168.100.1 -> 239.1.1.1`.
    *   Encrypts/signs the packets.
    *   Encapsulates the resulting GEM packets into a unicast ESP tunnel destined for Studio B's public IP.

3.  **Studio B (Daemon 3 - GEM Gateway, Unicast Mode):**
    *   Receives the ESP traffic, decapsulates it.
    *   Verifies the GAK signature and decrypts with the SEK.
    *   Outputs the plain-text, normalized stream `192.168.100.1 -> 239.1.1.1` onto the local Studio B network.

4.  **Studio B (Local PIM Router):**
    *   Receives the stream. The RPF check for source `192.168.100.1` passes (because its route was learned via standard unicast routing protocols from the `mcr-overlay` network). The stream is forwarded to local receivers.

---
