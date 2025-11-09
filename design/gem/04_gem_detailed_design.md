# Detailed Design: Group Encrypted Multicast (GEM)

## 1. Introduction

This document provides a detailed design for implementing Group Encrypted Multicast (GEM) in MCR, focusing on the initial **Phase 1: Manual Encrypted Tunnel (Point-to-Point)**. It outlines specific code changes, new modules, and external dependencies, building upon the GEM Architecture (`design/gem/03_gem_architecture.md`) and the existing MCR architecture (`ARCHITECTURE.md`).

## 2. External Dependencies

*   `aes-gcm`: For AES-256-GCM encryption and decryption. Provides authenticated encryption.
*   `rand_core`: For secure random number generation (for nonces).

## 3. New Modules

### 3.1. `src/worker/crypto.rs`

This module will encapsulate all cryptographic operations for GEM.

*   **Functions:**
    *   `encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>`: Takes a 32-byte AES key and plaintext, returns ciphertext (including nonce and authentication tag).
    *   `decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>`: Takes a 32-byte AES key and ciphertext, returns plaintext if authentication succeeds.
*   **Key Derivation (Future):** For Phase 1, the `preshared_key` will be used directly. In later phases, this module might include key derivation functions.

## 4. Changes to Existing Modules

### 4.1. `src/lib.rs` (Already Updated)

*   `OutputDestination`:
    *   `pub tunnel_to: Option<std::net::SocketAddrV4>`: The unicast IP and port of the peer MCR instance for the tunnel.
    *   `pub preshared_key: Option<String>`: The base64-encoded AES-256 key for Phase 1. (Will be replaced by dynamic keys in Phase 2).
*   `ForwardingRule`:
    *   `pub tunnel_from_port: Option<u16>`: The UDP port on which this MCR instance should listen for incoming GEM tunnel traffic.

### 4.2. `src/worker/ingress.rs`

This module will be significantly modified to handle both sending and receiving GEM traffic.

#### 4.2.1. Receiving GEM Traffic (DGM Role)

*   **New UDP Socket:** If a `ForwardingRule` has `tunnel_from_port` set, the Ingress Loop will create and bind a new `tokio_uring::net::UdpSocket` to `0.0.0.0:tunnel_from_port`.
*   **Packet Processing:**
    *   When a unicast UDP packet arrives on this socket:
        1.  Extract the payload (encrypted multicast traffic).
        2.  Retrieve the `preshared_key` associated with the `ForwardingRule`.
        3.  Call `crypto::decrypt` with the key and payload.
        4.  If decryption is successful, the result is the original multicast UDP payload.
        5.  Construct a new `EgressPacket` with the original multicast `input_group` and `input_port` (from the `ForwardingRule`) and the decrypted payload.
        6.  Send this `EgressPacket` to the Egress Loop via the existing channel.
*   **Error Handling:** Decryption failures (e.g., invalid key, corrupted data) will be logged and the packet dropped. A new metric `gem_decryption_errors_total` will be introduced.

#### 4.2.2. Sending GEM Traffic (EGM Role)

*   **Modification to Existing Forwarding Logic:** In the `process_packet` function (or equivalent), when a packet matches a `ForwardingRule` and an `OutputDestination` has `tunnel_to` and `preshared_key` set:
    1.  Extract the original multicast UDP payload.
    2.  Retrieve the `preshared_key` from the `OutputDestination`.
    3.  Call `crypto::encrypt` with the key and payload.
    4.  Construct a new `EgressPacket`:
        *   `interface_name`: The interface to send the unicast tunnel traffic out of (from `OutputDestination.interface`).
        *   `dest_addr`: The `OutputDestination.tunnel_to` address.
        *   `payload`: The encrypted payload.
    5.  Send this `EgressPacket` to the Egress Loop via the existing channel.
*   **Error Handling:** Encryption failures will be logged and the packet dropped. A new metric `gem_encryption_errors_total` will be introduced.

### 4.3. `src/worker/egress.rs`

*   **No Major Changes:** The Egress Loop already handles sending unicast UDP packets. It will simply receive the `EgressPacket` (which now contains an encrypted payload and a unicast destination) and forward it as usual.
*   **Socket Management:** Ensure that `UdpSocket`s are correctly managed for unicast destinations (i.e., not attempting to join multicast groups for tunnel endpoints).

### 4.4. `src/supervisor.rs`

*   **Rule Management:** The Supervisor will need to correctly parse and store `ForwardingRule`s that include GEM-specific fields. When assigning rules to workers, it must pass these new fields correctly.
*   **Worker Spawning:** If a worker is configured with a `ForwardingRule` that has `tunnel_from_port`, the Supervisor must ensure the worker has the necessary network capabilities to bind to that port (though `CAP_NET_RAW` is already handled for `AF_PACKET` sockets, a standard UDP socket bind might not require it).

### 4.5. `src/control_client.rs`

*   **New Command Parameters:** The `AddRule` command in the CLI client will need new options to specify `tunnel_to`, `preshared_key`, and `tunnel_from_port` when creating GEM rules.

## 5. Phase 1 Implementation Steps (Manual Encrypted Tunnel)

1.  **Add `aes-gcm` and `rand_core` to `Cargo.toml`**.
2.  **Create `src/worker/crypto.rs`** with `encrypt` and `decrypt` functions.
3.  **Modify `src/worker/ingress.rs`:**
    *   Implement the new UDP socket for `tunnel_from_port` listening.
    *   Integrate decryption/decapsulation logic for incoming tunnel packets.
    *   Integrate encryption/encapsulation logic for outgoing tunnel packets.
    *   Add `gem_decryption_errors_total` and `gem_encryption_errors_total` metrics.
4.  **Modify `src/worker/egress.rs`:** Verify existing unicast forwarding handles encrypted payloads correctly.
5.  **Modify `src/supervisor.rs`:** Ensure `ForwardingRule`s with GEM fields are correctly handled and passed to workers.
6.  **Modify `src/control_client.rs`:** Add CLI options for GEM rule creation.
7.  **Write Unit/Integration Tests:** Create tests for `crypto.rs` and for the end-to-end GEM tunnel functionality between two MCR instances.

---
