# Sketch v3: MCR/GEM Overlay Network (Decoupled Architecture)

## 1. High-Level Vision

To create a toolkit of two complementary, composable daemons that solve key problems in multicast networking. This decoupled architecture prioritizes flexibility and integration with standard Linux networking tools.

1.  **`mcr-normalizer`:** A daemon that makes multicast streams from legacy, unroutable sources compatible with modern, routed networks.
2.  **`gem-gateway`:** A daemon that provides a secure overlay network for transporting multicast and unicast traffic over complex underlay networks (like the Internet).

## 2. The Common Control Plane

Both daemons are peers in a common control plane, which allows them to discover each other and share necessary state.

*   **Foundation:** The control plane is built on **IPsec ESP tunnels** using a shared **Bootstrap Key (BK)**.
*   **Routing & State:** The **Babel routing protocol** runs over these tunnels to reliably synchronize network state via custom TLVs (Public Keys, SA, Subscription, SEK).

## 3. The Daemons

### 3.1. Daemon 1: `mcr-normalizer`

*   **Purpose:** To solve the RPF-check problem for unroutable multicast sources.
*   **Mechanism:**
    1.  Creates a virtual loopback interface with a routable IP address.
    2.  Captures an unroutable multicast stream from a physical interface.
    3.  Re-sources the stream by replacing the source IP with its own routable virtual IP.
    4.  Outputs the now-routable, plain-text multicast stream onto a user-specified `veth` interface.
    5.  Announces the availability of this new, routable stream to the control plane using a **Source Active (SA) TLV**.

### 3.2. Daemon 2: `gem-gateway`

*   **Purpose:** To provide a secure transport fabric for multicast and unicast traffic.
*   **Mechanism:**
    1.  **Ingress:** Can be configured to read plain-text traffic from a `veth` interface (for chaining with `mcr-normalizer`) or a physical interface.
    2.  **Subscription:** For multicast, it sends **Subscription TLVs** to request streams announced by other nodes.
    3.  **Processing:** Encrypts payloads with the appropriate **SEK** and signs packets with the **GAK**.
    4.  **Egress (Flexible):** The **Forwarding Policy Engine** dynamically selects the egress mode based on Babel metrics:
        *   **Unicast ESP Tunnel:** For transport over WANs. The daemon configures kernel ESP tunnels using the shared **BK** as a PSK.
        *   **Bridged Encrypted Multicast:** For transport over private, multicast-enabled networks, outputting via a `veth` interface.

## 4. A Complete End-to-End Workflow

This workflow shows how the two daemons are composed to solve the full problem.

1.  **Setup:** An administrator creates a `veth` pair: `veth-norm-out` <-> `veth-gem-in`.

2.  **`mcr-normalizer` Daemon (Studio A):**
    *   Configured to read from `eth0` and write its normalized output to `veth-norm-out`.
    *   It captures `10.1.1.50 -> 239.1.1.1`, re-sources it as `192.168.100.1 -> 239.1.1.1`, and sends it into `veth-norm-out`.
    *   It also sends an `SA-TLV(192.168.100.1, 239.1.1.1)` to the control plane.

3.  **`gem-gateway` Daemon (Studio A):**
    *   Configured to read from `veth-gem-in`.
    *   It sees the packet from the normalizer, encrypts/signs it, and (based on its Forwarding Policy Engine) encapsulates it in a Unicast ESP tunnel to Studio B.

4.  **`gem-gateway` Daemon (Studio B):**
    *   Receives the ESP traffic, decrypts it, and outputs the plain-text, normalized stream (`192.168.100.1 -> 239.1.1.1`) onto its local network.

5.  **Result:** The stream is delivered securely and is now compatible with the local PIM routers in Studio B. The `veth` pair allows an administrator to insert `tcpdump` or `nftables` rules between the two stages for debugging and policy enforcement.

---
