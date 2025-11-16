# Multicast Relay - Architecture

This document describes the architecture of the `multicast_relay` application. It is the definitive, up-to-date guide to the system's design, components, and core technical decisions. As the project evolves, this document must be updated to reflect the current state of the implementation.

## 1. Overview

The `multicast_relay` is a high-performance userspace application designed to solve the "unroutable source" problem for multicast traffic. It receives multicast UDP packets, which may originate from unroutable sources, and re-transmits them from a routable local interface.

The architecture is designed around three core principles:

1.  **Peak Performance:** To handle millions of packets per second by minimizing system calls, memory copies, and cross-core cache misses.
2.  **Dynamic Reconfiguration:** To allow for adding, removing, and monitoring forwarding flows at runtime without service interruption.
3.  **Testability:** To structure the code in a way that is modular and verifiable.

## 1A. Architectural Principles

The current architecture is the result of a significant refactor guided by the following principles:

### 1. Simplicity Through Unification
Use a single, consistent mechanism for asynchronous I/O to reduce complexity and eliminate entire classes of synchronization bugs. The project has standardized on `io_uring` for all performance-critical I/O, and `tokio` for the less-critical supervisor tasks.

### 2. Kernel-Managed State
Let the kernel manage as much state and synchronization as possible. The kernel's event notification mechanisms (e.g., pipes, sockets) are well-tested and highly optimized. This is preferred over custom, error-prone userspace synchronization primitives.

### 3. Zero-Copy Where Possible
Minimize data copying in the fast path. The architecture prefers passing metadata and buffer references between threads and processes over copying entire packets, especially at high packet rates.

### 4. Fail-Fast Error Handling
Worker threads are designed as isolated, restartable processes. They prefer to panic on unrecoverable errors rather than continuing in a potentially corrupt state. The Supervisor process is responsible for monitoring workers and restarting them if they fail.

## 2. High-Level Design

The system is architected as a multi-process application to ensure robust privilege separation. It is composed of:

1.  **A single, privileged Supervisor Process.**
2.  **A single, unprivileged Control Plane Process.**
3.  **Multiple, unprivileged Data Plane Worker Processes** (one per CPU core).

## 3. The Data Plane: A Core-Pinned, `io_uring` Architecture

The data plane is the performance-critical heart of the application.

- **Core Affinity:** The application is multi-threaded, but not in a traditional sense. It creates a dedicated OS thread for each CPU core it intends to use and pins each thread to its specific core. Each of these threads runs an independent, single-threaded `tokio` runtime. This ensures that a packet is processed on the same core that received it, maximizing CPU cache locality.

- **Ingress Path (`io_uring` + `AF_PACKET`):**
  - **Problem:** For MCR's role as an RPF-bypassing relay, relying on the kernel's standard IP/UDP stack for ingress processing is problematic. Features like Reverse Path Forwarding (RPF) checks, while crucial for security, can prevent valid multicast traffic from unroutable sources from ever reaching userspace.
  - **Solution:** Packet reception is handled using `AF_PACKET` sockets to bypass the kernel's IP/UDP stack and RPF checks. Crucially, `AF_PACKET` enables MCR to receive raw frames even on network interfaces that **do not have an IP address assigned**, providing flexibility for highly isolated network segments.
  - The I/O is driven by the `tokio-uring` runtime, which uses the `io_uring` Linux API. This minimizes system call overhead by submitting and completing I/O operations in batches. `AF_PACKET` provides MCR with raw, unfiltered access to Ethernet frames, enabling granular control and custom Layer 2/3/4 processing independent of the kernel's higher-level network policies. This low-level approach necessitates MCR to perform its own packet parsing and re-transmission with newly constructed IP/UDP headers, ensuring clean and compliant egress traffic.

- **Filtering and Demultiplexing:**
  - **Hardware Filtering:** The primary filtering is done by the NIC hardware. For each multicast group we need to receive, a standard `AF_INET` "helper" socket is created solely to trigger the kernel to send an IGMP Join and program the NIC's MAC address filter.
  - **Userspace Demultiplexing:** A single `AF_PACKET` socket per core receives all relevant multicast frames. A userspace task inspects the headers of each packet to identify its destination group/port and looks up the corresponding `ForwardingRule` in a core-local hash map.

- **Egress Path (`io_uring` + `AF_INET`):**
  - **Memory Copy Egress:** To change the source IP, the original UDP payload is **copied** from the `AF_PACKET` receive buffer into a new, core-local buffer. This immediately frees the `AF_PACKET` receive buffer for reuse, decoupling the ingress and egress paths. This payload is then sent via `io_uring` `sendto` operations on a standard `AF_INET` `UdpSocket` that has been **bound to the desired source IP address**. The kernel will then construct the new IP/UDP headers, handle routing, ARP, and Ethernet framing.
  - The `sendto` operations on these sockets are also submitted to `io_uring` in batches to maintain minimal system call overhead.

- **Egress Error Handling:** The application will use a "Drop and Count" strategy for transient egress errors. Packets that fail to send due to transient errors will be dropped immediately, with no retry mechanism, to preserve low latency and prevent head-of-line blocking. A new metric, `egress_errors_total`, will be tracked on a per-output-destination basis and exposed via the control plane to provide immediate visibility into egress failures.

- **No IP Reassembly:** The application will not support IP fragmentation. The data plane will inspect the IP header of every incoming packet to identify fragments. Any packet identified as a fragment (either the first, middle, or last) will be immediately dropped. A new metric, `ip_fragments_dropped_total`, will be tracked on a per-core basis and exposed via the control plane to make the presence of fragmented traffic visible to the operator.

- **Egress Fragmentation by Kernel:** The application will not implement userspace IP fragmentation. It will always present the complete, reconstructed datagram (UDP payload) to the egress `AF_INET` socket, regardless of size. The application will rely entirely on the Linux kernel's IP stack to perform any necessary fragmentation on the egress path if a packet's size exceeds the egress interface's MTU. The operational documentation will strongly recommend that operators maintain consistent MTU sizes across the data path to avoid performance degradation from fragmentation, and will instruct them to use tools like `netstat` to monitor for kernel-level fragmentation.

### Egress Path Clarification

- **Egress Path Types:** The application has three distinct egress paths. The concerns of MTU handling, fragmentation, and NIC offloading apply only to the Fast Data Path.
  1.  **Control Plane:** Uses `AF_UNIX` sockets for local IPC. MTU is not applicable.
  2.  **IGMP Signaling:** Uses `AF_INET` sockets managed by the Supervisor. MTU is not a practical concern.
  3.  **Fast Data Path:** Uses `AF_INET` sockets managed by the data plane workers. This is the exclusive subject of all high-performance design decisions.

### Interface Management

- **Explicit Interface Configuration:** The `ForwardingRule` structure includes a mandatory `input_interface` field. The application supports configuring rules across multiple distinct input and output interfaces. Each core-pinned data plane thread is designed to manage `AF_PACKET` sockets for multiple ingress interfaces simultaneously, if required.

- **Nuanced NIC Offloading:** For the application to function correctly, NIC offloading features that coalesce packets must be disabled on all ingress interfaces. Generic Receive Offload (GRO) and Large Receive Offload (LRO) **must be disabled** on all `input_interface`s. These features are fundamentally incompatible with the application's `AF_PACKET` processing model and can cause artificial jumbo frames, leading to unnecessary egress fragmentation. For egress offloads (GSO/TSO), the recommendation depends on the operator's goal: for handling MTU mismatches, it is **recommended to enable** GSO/TSO on the egress interface; for maximum predictability or performance testing, it is **recommended to disable** GSO/TSO. These explicit, nuanced recommendations will be a critical part of the operational documentation.

## 4. The Control Plane

The control plane provides the mechanism for runtime configuration and monitoring.

- **Centralized RPC Server:** A single, centralized `control_plane_task` runs within the application.
- **Communication:** It listens on a single Unix Domain Socket for local, secure communication.
- **Protocol:** It uses a **JSON**-based protocol for commands and responses. This was chosen for ease of debugging, testing, and future interoperability over the negligible performance gains of a binary format for this interface.
- **Server-Side Idempotency:** The control plane ensures client recovery and idempotency through a server-side mechanism. The supervisor generates a unique ID for each new rule upon creation, and this ID is returned in the `AddRule` success response. The `ListRules` command is the primary mechanism for a client to reconcile its state after a disconnect or timeout. The `AddRule` command retains "create new rule" semantics.

### Rule Assignment

- **Rule-to-Core Assignment Strategy:** The application uses a hybrid strategy for assigning forwarding rules to data plane cores. By default, the supervisor assigns rules to cores using a consistent hash of the rule's stable identifiers (e.g., `input_group`, `input_port`). The control plane also supports a `MoveRule` command, allowing an operator to manually re-assign a specific rule to a different core to reactively mitigate hotspots. The supervisor's master rule list tracks the current core assignment for each rule.

- **Decoupled Statistics Aggregation:** To prevent statistical queries from blocking the control plane, a dedicated `StatsAggregator` task is used. Each core-pinned data plane thread proactively pushes its complete state and metrics to the aggregator on a regular interval. **This push includes a high-resolution timestamp captured only once per interval by each worker, ensuring minimal system call overhead.** The `StatsAggregator` maintains a cached, up-to-date, system-wide view of the application's state. The `ControlPlane` task serves `GetStats` and `ListRules` requests by querying this aggregator for the latest cached, system-wide state, ensuring the control plane remains highly responsive. The `GetStats` response will include these per-core timestamps, making any temporal skew transparent to the operator.

- **Strict Protocol Versioning:** The control plane protocol will use a strict, fail-fast versioning scheme. A single, shared `PROTOCOL_VERSION` constant will be defined and compiled into both the server and client. The first message on any new connection must be a `VersionCheck` from the client. The server will compare the client's version to its own; if they do not match exactly, the server will respond with a `VersionMismatch` error and close the connection. Any change to the JSON protocol requires incrementing the shared `PROTOCOL_VERSION` constant.

- **Command Dispatch via Unix Sockets:** Communication from the Supervisor to the data plane worker processes uses a dedicated `UnixStream` socket pair for each worker.
  - The Supervisor serializes commands (e.g., `AddRule`) into a length-prefixed JSON payload and writes them to its end of the socket using its `tokio` runtime.
  - The worker's `io_uring` runtime polls its end of the socket. When data arrives, a command reader parses the length-prefixed JSON back into a command struct for processing.
  - This mechanism acts as a bridge between the supervisor's `tokio`-based control plane and the worker's `io_uring`-based data plane.

## 5. Monitoring and Hotspot Management

- **Hotspot Management (Observe, Don't Act):** The initial design will not implement an automatic hotspot mitigation strategy. Instead, it will rely on a robust, **core-aware monitoring system** to make any potential single-core saturation observable to the operator. The statistics reporting will be enhanced to include per-core packet rates and CPU utilization metrics. This provides the necessary visibility to manage the known architectural limitation.

- **Custom Observability via Control Plane:** The application will provide comprehensive observability through its control plane, compensating for the lack of visibility from standard networking tools like `netstat`. A `ListRules` command will expose the forwarding table, and a `GetStats` command will expose a detailed set of metrics with per-core, per-rule, per-buffer-pool, and per-destination granularity.

- **On-Demand Packet Tracing:** The application will implement a low-impact, on-demand packet tracing capability. Tracing will be configurable on a per-rule basis via control plane commands (`EnableTrace`, `DisableTrace`, `GetTrace`) and disabled by default. Each data plane worker will maintain a pre-allocated, in-memory ring buffer to store key diagnostic events for packets matching an enabled rule. The `GetTrace` command will retrieve these events, providing a detailed, chronological log of a packet's lifecycle or the reason for its drop.

## 5A. Logging Architecture

Worker processes do not log directly to the console or to files. Instead, a simple and robust pipe-based mechanism is used to centralize logging in the supervisor.

- **Pipe Redirection:** When the Supervisor process spawns a new worker, it creates a standard Unix pipe. The worker process's standard error (`stderr`) stream is redirected to the "write end" of this pipe.
- **Log Aggregation:** The Supervisor holds the "read end" of the pipe for each worker. It uses its main event loop to asynchronously monitor all pipes for data.
- **Log Flow:** When a worker writes a log message (e.g., via `eprintln!`), the operating system sends that data through the pipe. The Supervisor reads the data, prepends it with worker-specific context (e.g., `[Worker-1]`), and prints the final message to its own standard output.

This design decouples the high-performance workers from the slower I/O of logging. Workers can emit logs as a fast "fire-and-forget" operation, while the supervisor handles the slower aggregation and output tasks.

## 6. Memory Management

- **Core-Local Buffer Pools:** To avoid the performance penalty of dynamic memory allocation, the application uses a core-local buffer pool strategy. Each core-pinned data plane thread pre-allocates and manages its own independent set of fixed-size memory buffers. These buffers are organized into multiple pools based on common packet sizes (e.g., Small, Standard, Jumbo). Runtime "allocations" are fast, lock-free operations that acquire a buffer from the appropriate pool.

- **Buffer Pool Observability:** The system is designed to handle buffer pool exhaustion by dropping packets rather than falling back to slow, dynamic allocation. To make this manageable, the monitoring system exposes detailed, per-core, per-pool metrics, including the total size of each pool, the current number of buffers in use, and a counter for exhaustion events.

## 7. Reliability and Resilience

- **Supervisor Pattern for Resilience:** The application will implement a supervisor pattern. The main application thread will act as the supervisor, responsible for the lifecycle of the data plane threads. The supervisor will maintain the canonical, master list of all forwarding rules. It will monitor its child threads for panics. Upon detecting a failure, it will automatically restart the failed thread and re-provision it with the correct set of forwarding rules from its master list.

- **Idempotent Network State Reconciliation:** The supervisor will maintain the master rule list with states like "active" and "unresolved." It will use a Netlink socket to listen for all network state changes (`UP`, `DOWN`, `DELIF`, `NEWIF`). When an interface appears, the supervisor will automatically scan its "unresolved" rules and activate any that can now be satisfied. Rules will be gracefully paused and resumed as their underlying interfaces lose and regain carrier. Rules dependent on a deleted interface will be moved to the "unresolved" state, to be automatically re-activated if the interface reappears later.

## 8. Security and Privilege Model

- **Privilege Separation (Target Architecture):** The application is designed to use a multi-process architecture to minimize attack surface and operate with least-privilege.
  - The **Supervisor Process** is intended to be the only component that runs with elevated privileges (`CAP_NET_RAW`). Its sole responsibilities are managing the lifecycle of the unprivileged worker processes and performing privileged operations (e.g., creating `AF_PACKET` sockets).
  - The **Control Plane Process** runs as an unprivileged user. It handles all parsing of potentially untrusted user input from the JSON-RPC interface.
  - The **Data Plane Worker Processes** should run as a completely unprivileged user. They are intended to handle all high-volume packet processing after receiving the necessary sockets from the Supervisor via file descriptor passing.
  - **Current Implementation Status:** The Control Plane correctly drops privileges. However, the Data Plane workers currently create their own `AF_PACKET` sockets and therefore must retain `CAP_NET_RAW`, deviating from the target architecture. Migrating socket creation to the Supervisor and using file descriptor passing to achieve a fully unprivileged data plane is a high-priority roadmap item.
- **DDoS Amplification Risk (Trusted Network & QoS Mitigation):** The risk of DDoS amplification from external, malicious actors is considered mitigated by the operational requirement that the relay's ingress interfaces are connected only to physically secured, trusted network segments. The risk of accidental overload of a unicast destination due to misconfiguration is fully mitigated by the existing advanced QoS design, which allows for the classification and rate-limiting/prioritized dropping of high-bandwidth flows. No additional security-specific mechanisms are required for this threat vector.
