# Multicast Relay - Architecture

This document describes the architecture of the `multicast_relay` application. It is the definitive guide to the system's design, components, and core technical decisions.

## 1. Overview

The `multicast_relay` is a high-performance userspace application designed to solve the "unroutable source" problem for multicast traffic. It receives multicast UDP packets, which may originate from unroutable sources, and re-transmits them from a routable local interface.

The architecture is designed around three core principles:
1.  **Peak Performance:** To handle millions of packets per second by minimizing system calls, memory copies, and cross-core cache misses.
2.  **Dynamic Reconfiguration:** To allow for adding, removing, and monitoring forwarding flows at runtime without service interruption.
3.  **Testability:** To structure the code in a way that is modular and verifiable.

## 2. High-Level Design

The system is architected as a multi-process application to ensure robust privilege separation. It is composed of:
1.  **A single, privileged Supervisor Process.**
2.  **A single, unprivileged Control Plane Process.**
3.  **Multiple, unprivileged Data Plane Worker Processes** (one per CPU core).

## 3. The Data Plane: A Core-Pinned, `io_uring` Architecture

The data plane is the performance-critical heart of the application.

*   **(D2) Core Affinity:** The application is multi-threaded, but not in a traditional sense. It creates a dedicated OS thread for each CPU core it intends to use and pins each thread to its specific core. Each of these threads runs an independent, single-threaded `tokio` runtime. This ensures that a packet is processed on the same core that received it, maximizing CPU cache locality.

*   **(D7, D1) Ingress Path (`io_uring` + `AF_PACKET`):**
    *   Packet reception is handled using `AF_PACKET` sockets to bypass the kernel's IP/UDP stack and RPF checks.
    *   The I/O is driven by the `tokio-uring` runtime, which uses the `io_uring` Linux API. This minimizes system call overhead by submitting and completing I/O operations in batches.

*   **(D3, D4, D6) Filtering and Demultiplexing:**
    *   **Hardware Filtering:** The primary filtering is done by the NIC hardware. For each multicast group we need to receive, a standard `AF_INET` "helper" socket is created solely to trigger the kernel to send an IGMP Join and program the NIC's MAC address filter.
    *   **Userspace Demultiplexing:** A single `AF_PACKET` socket per core receives all relevant multicast frames. A userspace task inspects the headers of each packet to identify its destination group/port and looks up the corresponding `ForwardingRule` in a core-local hash map.

*   **(D5, D8) Egress Path (`io_uring` + `AF_INET`):**
    *   **(D5 Revised - Memory Copy Egress):** To change the source IP, a new packet is constructed in userspace. The original UDP payload is **copied** from the `AF_PACKET` receive buffer into a new, core-local buffer. This immediately frees the `AF_PACKET` receive buffer for reuse, decoupling the ingress and egress paths. The new IP/UDP headers are then prepended to this copied payload. This design, while involving a memory copy, is chosen to simplify buffer lifecycle management, reduce overall system complexity, and enable a clean, robust implementation of QoS priority queuing.
    *   The new packet is sent using standard `AF_INET` (`UdpSocket`) file descriptors. This allows the kernel to handle routing, ARP, and Ethernet framing.
    *   The `sendto` operations on these sockets are also submitted to `io_uring` in batches to maintain minimal system call overhead.

*   **(D26) Egress Error Handling:** The application will use a "Drop and Count" strategy for transient egress errors. Packets that fail to send due to transient errors will be dropped immediately, with no retry mechanism, to preserve low latency and prevent head-of-line blocking. A new metric, `egress_errors_total`, will be tracked on a per-output-destination basis and exposed via the control plane to provide immediate visibility into egress failures.

### Interface Management

*   **(D21) Explicit Interface Configuration:** The `ForwardingRule` structure includes a mandatory `input_interface` field. The application supports configuring rules across multiple distinct input and output interfaces. Each core-pinned data plane thread is designed to manage `AF_PACKET` sockets for multiple ingress interfaces simultaneously, if required.

## 4. The Control Plane

The control plane provides the mechanism for runtime configuration and monitoring.

*   **(D9) Centralized RPC Server:** A single, centralized `control_plane_task` runs within the application.
*   **(D9) Communication:** It listens on a single Unix Domain Socket for local, secure communication.
*   **(D9) Protocol:** It uses a **JSON**-based protocol for commands and responses. This was chosen for ease of debugging, testing, and future interoperability over the negligible performance gains of a binary format for this interface.
*   **(D22) Server-Side Idempotency:** The control plane ensures client recovery and idempotency through a server-side mechanism. The supervisor generates a unique ID for each new rule upon creation, and this ID is returned in the `AddRule` success response. The `ListRules` command is the primary mechanism for a client to reconcile its state after a disconnect or timeout. The `AddRule` command retains "create new rule" semantics.

### Rule Assignment

*   **(D23) Rule-to-Core Assignment Strategy:** The application uses a hybrid strategy for assigning forwarding rules to data plane cores. By default, the supervisor assigns rules to cores using a consistent hash of the rule's stable identifiers (e.g., `input_group`, `input_port`). The control plane also supports a `MoveRule` command, allowing an operator to manually re-assign a specific rule to a different core to reactively mitigate hotspots. The supervisor's master rule list tracks the current core assignment for each rule.

*   **(D14) Decoupled Statistics Aggregation:** To prevent statistical queries from blocking the control plane, a dedicated `StatsAggregator` task is used. Each core-pinned data plane thread proactively pushes its complete state and metrics to the aggregator on a regular interval. The `ControlPlane` task serves `GetStats` and `ListRules` requests by querying this aggregator for the latest cached, system-wide state, ensuring the control plane remains highly responsive.

*   **(D25) Strict Protocol Versioning:** The control plane protocol will use a strict, fail-fast versioning scheme. A single, shared `PROTOCOL_VERSION` constant will be defined and compiled into both the server and client. The first message on any new connection must be a `VersionCheck` from the client. The server will compare the client's version to its own; if they do not match exactly, the server will respond with a `VersionMismatch` error and close the connection. Any change to the JSON protocol requires incrementing the shared `PROTOCOL_VERSION` constant.

## 5. Monitoring and Hotspot Management

*   **(D10) Hotspot Management (Observe, Don't Act):** The initial design will not implement an automatic hotspot mitigation strategy. Instead, it will rely on a robust, **core-aware monitoring system** to make any potential single-core saturation observable to the operator. The statistics reporting will be enhanced to include per-core packet rates and CPU utilization metrics. This provides the necessary visibility to manage the known architectural limitation.

## 6. Memory Management

*   **(D15) Core-Local Buffer Pools:** To avoid the performance penalty of dynamic memory allocation, the application uses a core-local buffer pool strategy. Each core-pinned data plane thread pre-allocates and manages its own independent set of fixed-size memory buffers. These buffers are organized into multiple pools based on common packet sizes (e.g., Small, Standard, Jumbo). Runtime "allocations" are fast, lock-free operations that acquire a buffer from the appropriate pool.

*   **(D16) Buffer Pool Observability:** The system is designed to handle buffer pool exhaustion by dropping packets rather than falling back to slow, dynamic allocation. To make this manageable, the monitoring system exposes detailed, per-core, per-pool metrics, including the total size of each pool, the current number of buffers in use, and a counter for exhaustion events.

## 7. Reliability and Resilience

*   **(D18) Supervisor Pattern for Resilience:** The application will implement a supervisor pattern. The main application thread will act as the supervisor, responsible for the lifecycle of the data plane threads. The supervisor will maintain the canonical, master list of all forwarding rules. It will monitor its child threads for panics. Upon detecting a failure, it will automatically restart the failed thread and re-provision it with the correct set of forwarding rules from its master list.

*   **(D19) Idempotent Network State Reconciliation:** The supervisor will maintain the master rule list with states like "active" and "unresolved." It will use a Netlink socket to listen for all network state changes (`UP`, `DOWN`, `DELIF`, `NEWIF`). When an interface appears, the supervisor will automatically scan its "unresolved" rules and activate any that can now be satisfied. Rules will be gracefully paused and resumed as their underlying interfaces lose and regain carrier. Rules dependent on a deleted interface will be moved to the "unresolved" state, to be automatically re-activated if the interface reappears later.

## 8. Security and Privilege Model

*   **(D24) Privilege Separation:** The application uses a multi-process architecture to minimize the attack surface.
    *   The **Supervisor Process** is the only component that runs with elevated privileges (`CAP_NET_RAW`). Its sole responsibilities are managing the lifecycle of the unprivileged worker processes and performing privileged operations (e.g., creating `AF_PACKET` sockets).
    *   The **Control Plane Process** runs as an unprivileged user. It handles all parsing of potentially untrusted user input from the JSON-RPC interface.
    *   The **Data Plane Worker Processes** run as an unprivileged user. They handle all high-volume packet processing. They receive the necessary sockets from the Supervisor via file descriptor passing and never require privileges themselves.
*   **(D20) DDoS Amplification Risk (Trusted Network & QoS Mitigation):** The risk of DDoS amplification from external, malicious actors is considered mitigated by the operational requirement that the relay's ingress interfaces are connected only to physically secured, trusted network segments. The risk of accidental overload of a unicast destination due to misconfiguration is fully mitigated by the existing advanced QoS design (D13), which allows for the classification and rate-limiting/prioritized dropping of high-bandwidth flows. No additional security-specific mechanisms are required for this threat vector.