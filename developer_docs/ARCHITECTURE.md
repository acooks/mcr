# Multicast Relay - Architecture

**Status:** ✅ CURRENT
**Last Updated:** 2025-11-18

---

This document describes the architecture of the `multicast_relay` application. It is the definitive, up-to-date guide to the system's design, components, and core technical decisions. As the project evolves, this document is updated to reflect the current state of the implementation.

## 1. System Overview

The `multicast_relay` is a high-performance userspace application designed to address the "unroutable source" problem for multicast traffic. It receives multicast UDP packets, which may originate from unroutable sources, and re-transmits them from a routable local interface.

The architecture is designed around three core principles:

1. **Peak Performance:** To handle millions of packets per second by minimizing system calls, memory copies, and cross-core cache misses.
2. **Dynamic Reconfiguration:** To allow for adding, removing, and monitoring forwarding flows at runtime without service interruption.
3. **Testability:** To structure the code in a way that is modular and verifiable.

## 2. Architectural Principles

The current architecture is the result of a significant refactor guided by the following principles:

### 1. Simplicity Through Unification

Use a single, consistent mechanism for asynchronous I/O to reduce complexity and eliminate entire classes of synchronization bugs. The project has standardized on `io_uring` for all performance-critical I/O, and `tokio` for the less-critical supervisor tasks.

### 2. Kernel-Managed State

Let the kernel manage as much state and synchronization as possible. The kernel's event notification mechanisms (e.g., pipes, sockets) are well-tested and highly optimized. This is preferred over custom, error-prone userspace synchronization primitives.

### 3. Zero-Copy Where Possible

Minimize data copying in the fast path. The architecture prefers passing metadata and buffer references between threads and processes over copying entire packets, especially at high packet rates.

### 4. Fail-Fast Error Handling

Worker threads are designed as isolated, restartable processes. They prefer to panic on unrecoverable errors rather than continuing in a potentially corrupt state. The Supervisor process is responsible for monitoring workers and restarting them if they fail.

## 3. High-Level Design

The system is architected as a multi-process application to ensure robust privilege separation and scalability. It is composed of a single supervisor process that manages multiple data plane worker processes.

```mermaid
graph TD
    subgraph User Space
        A["User/Operator"] --> B{"control_client"};
    end

    subgraph MCR Application
        B -- JSON over Unix Socket --> C["Supervisor Process"];

        subgraph "Data Plane (Privileged)"
            C -- Command Dispatch --> D1["Worker 1<br/>Core 0"];
            C -- Command Dispatch --> D2["Worker 2<br/>Core 1"];
            C -- Command Dispatch --> DN["Worker N<br/>Core N-1"];
        end
    end

    subgraph Kernel Space / Network
        NetIn["Inbound Multicast Traffic"] --> D1;
        NetIn --> D2;
        NetIn --> DN;

        D1 --> NetOut["Outbound Multicast Traffic"];
        D2 --> NetOut;
        DN --> NetOut;
    end

    style C fill:#f9f,stroke:#333,stroke-width:2px
    style D1 fill:#bbf,stroke:#333,stroke-width:2px
    style D2 fill:#bbf,stroke:#333,stroke-width:2px
    style DN fill:#bbf,stroke:#333,stroke-width:2px
```

- **User/Operator:** Interacts with the system via the `control_client`.
- **`control_client`:** A command-line tool that sends JSON commands to the supervisor over a Unix socket.
- **Supervisor Process:** The main process that manages workers, handles configuration commands, and centralizes logging and statistics. It runs with privileges but does not handle high-speed packet forwarding.
- **Worker Processes:** High-performance data plane processes, each pinned to a specific CPU core. They receive, process, and re-transmit all multicast traffic.

## 4. The Data Plane: A Unified, Single-Threaded Architecture

### Current Default: Single-Threaded Unified Event Loop

The MCR data plane uses a **single-threaded, unified event loop model** as the default architecture. This eliminates the complexity and performance issues of inter-thread communication. All data plane logic for a given CPU core runs within a single OS thread.

**Implementation:** `run_unified_data_plane()` in `src/worker/data_plane_integrated.rs`

- **Core Affinity:** The supervisor spawns one data plane worker process per designated CPU core, and this worker process is pinned to that core.

- **Unified `io_uring` Instance:** Each worker process uses a **single `io_uring` instance** to manage all asynchronous I/O operations for both ingress and egress. This provides a unified, highly efficient event queue.

### Legacy Architecture: Two-Thread Model (Available but Not Default)

The codebase also contains a legacy two-thread implementation that uses:

- One ingress thread with AF_PACKET socket
- One egress thread with UDP sockets
- Cross-thread communication via `SegQueue`

This model is still present in the codebase but is **not the default**. The single-threaded unified model is selected at compile time (see `src/worker/mod.rs:29`).

**Implementation:** `run_data_plane()` in `src/worker/data_plane_integrated.rs`

**Why Keep Both?** The legacy model is maintained for performance comparison and as a fallback during the transition period. It may be removed in a future release once the unified model is fully validated across all production scenarios.

- **Event Loop Architecture:**
  1. **Ingress (`AF_PACKET`):** The worker submits multiple `Recv` operations to the `io_uring` for its `AF_PACKET` socket.
  2. **Egress (`AF_INET`):** When a received packet is processed and ready to be forwarded, the worker submits one or more `Send` operations to the _same_ `io_uring` instance for the appropriate `AF_INET` egress sockets.
  3. **Unified Completion:** The worker makes a single blocking call (`submit_and_wait()`) that waits for _any_ type of event to complete—a packet being received, a packet having been sent, or a command arriving from the supervisor.
  4. **Processing:** When the loop wakes, it processes all available completion events, frees buffers from sent packets, forwards newly received packets, and then submits new I/O operations to the ring.

### Data Plane Packet Flow

```mermaid
flowchart LR
    subgraph "Worker Thread (Unified `io_uring`)"
        NIC[NIC Hardware Filter] --> AF[AF_PACKET Socket];
        AF --> RECV[Recv Batch];
        RECV --> PARSE[Parse Headers];
        PARSE --> LOOKUP{Rule Lookup};
        LOOKUP -- Match --> SEND[Send Batch];
        LOOKUP -- No Match --> DROP([Drop]);
        SEND --> INET[AF_INET Socket];
        INET --> OUT[Output Interface];
    end

    subgraph "Buffer Pool"
        BP[Core-Local Buffer Pool]
    end

    BP -- Allocate --> RECV;
    SEND -- Free --> BP;
```

- **Benefits of this Model:**
  - **No Inter-Thread Communication:** This architecture completely eliminates the need for complex, performance-sapping cross-thread communication mechanisms.
  - **Simplified Buffer Management:** The buffer pool is owned and accessed by a single thread, removing the need for `Arc<Mutex>` or other synchronization primitives.
  - **Natural Batching:** The single event loop naturally batches both receive and send operations, maximizing `io_uring`'s efficiency.

- **Filtering and Demultiplexing:**
  - **Hardware Filtering:** The primary filtering is done by the NIC hardware. For each multicast group we need to receive, a standard `AF_INET` "helper" socket is created solely to trigger the kernel to send an IGMP Join and program the NIC's MAC address filter.
  - **Userspace Demultiplexing:** The `AF_PACKET` socket receives all relevant multicast frames. The unified event loop inspects the headers of each packet to identify its destination group/port and looks up the corresponding `ForwardingRule` in a hash map.

- **Egress Path and Zero-Copy Fan-Out:** MCR now supports high-performance, multi-output "fan-out." When a packet needs to be forwarded to multiple destinations, the payload of the single received packet is wrapped in a reference-counted pointer (`Arc<[u8]>`). This allows the same memory to be queued for sending on multiple egress sockets without any memory copying, which is critical for scalable performance. This also applies to single-output forwarding, eliminating the previous `memcpy` overhead.

  The application utilizes three distinct egress paths:
  1. **Control Plane:** Uses `AF_UNIX` sockets for local IPC. MTU is not applicable.
  2. **IGMP Signaling:** Uses `AF_INET` sockets managed by the Supervisor. MTU is not a practical concern.
  3. **Fast Data Path:** Uses `AF_INET` sockets managed by the data plane workers. This is the exclusive subject of all high-performance design decisions concerning MTU handling, fragmentation, and NIC offloading.

- **Egress Error Handling:** The application will use a "Drop and Count" strategy for transient egress errors. Packets that fail to send due to transient errors will be dropped immediately, with no retry mechanism, to preserve low latency and prevent head-of-line blocking. A new metric, `egress_errors_total`, will be tracked on a per-output-destination basis and exposed via the control plane to provide immediate visibility into egress failures.

- **No IP Reassembly:** The application will not support IP fragmentation. The data plane will inspect the IP header of every incoming packet to identify fragments. Any packet identified as a fragment (either the first, middle, or last) will be immediately dropped. A new metric, `ip_fragments_dropped_total`, will be tracked on a per-core basis and exposed via the control plane to make the presence of fragmented traffic visible to the operator.

- **Egress Fragmentation by Kernel:** The application will not implement userspace IP fragmentation. It will always present the complete, reconstructed datagram (UDP payload) to the egress `AF_INET` socket, regardless of size. The application will rely entirely on the Linux kernel's IP stack to perform any necessary fragmentation on the egress path if a packet's size exceeds the egress interface's MTU. The operational documentation will strongly recommend that operators maintain consistent MTU sizes across the data path to avoid performance degradation from fragmentation, and will instruct them to use tools like `netstat` to monitor for kernel-level fragmentation.

### Interface Management

- **Explicit Interface Configuration:** The `ForwardingRule` structure includes a mandatory `input_interface` field. The application supports configuring rules across multiple distinct input and output interfaces. Each core-pinned data plane thread is designed to manage `AF_PACKET` sockets for multiple ingress interfaces simultaneously, if required.

- **Nuanced NIC Offloading:** For the application to function correctly, NIC offloading features that coalesce packets must be disabled on all ingress interfaces. Generic Receive Offload (GRO) and Large Receive Offload (LRO) **must be disabled** on all `input_interface`s. These features are fundamentally incompatible with the application's `AF_PACKET` processing model and can cause artificial jumbo frames, leading to unnecessary egress fragmentation. For egress offloads (GSO/TSO), the recommendation depends on the operator's goal: for handling MTU mismatches, it is **recommended to enable** GSO/TSO on the egress interface; for maximum predictability or performance testing, it is **recommended to disable** GSO/TSO. These explicit, nuanced recommendations will be a critical part of the operational documentation.

## 5. The Control Plane

The control plane provides the mechanism for runtime configuration and monitoring.

- **Centralized RPC Server:** A single, centralized `control_plane_task` runs within the application.
- **Communication:** It listens on a single Unix Domain Socket for local, secure communication.
- **Protocol:** It uses a **JSON**-based protocol for commands and responses. This was chosen for ease of debugging, testing, and future interoperability over the negligible performance gains of a binary format for this interface.
- **Server-Side Idempotency:** The control plane ensures client recovery and idempotency through a server-side mechanism. The supervisor generates a unique ID for each new rule upon creation, and this ID is returned in the `AddRule` success response. The `ListRules` command is the primary mechanism for a client to reconcile its state after a disconnect or timeout. The `AddRule` command retains "create new rule" semantics.

### Rule Assignment

- **Rule-to-Core Assignment Strategy:** The application uses a hybrid strategy for assigning forwarding rules to data plane cores. By default, the supervisor assigns rules to cores using a consistent hash of the rule's stable identifiers (e.g., `input_group`, `input_port`). The control plane also supports a `MoveRule` command, allowing an operator to manually re-assign a specific rule to a different core to reactively mitigate hotspots. The supervisor's master rule list tracks the current core assignment for each rule.

- **Decoupled Statistics Aggregation:** To prevent statistical queries from blocking the control plane, a dedicated `StatsAggregator` task is used. Each core-pinned data plane thread proactively pushes its complete state and metrics to the aggregator on a regular interval. **This push includes a high-resolution timestamp captured only once per interval by each worker, ensuring minimal system call overhead.** The `StatsAggregator` maintains a cached, up-to-date, system-wide view of the application's state. The `ControlPlane` task serves `GetStats` and `ListRules` requests by querying this aggregator for the latest cached, system-wide state, ensuring the control plane remains highly responsive. The `GetStats` response will include these per-core timestamps, making any temporal skew transparent to the operator.

- **Strict Protocol Versioning (NOT IMPLEMENTED):** _Future work:_ The control plane protocol will use a strict, fail-fast versioning scheme. A single, shared `PROTOCOL_VERSION` constant will be defined and compiled into both the server and client. The first message on any new connection must be a `VersionCheck` from the client. The server will compare the client's version to its own; if they do not match exactly, the server will respond with a `VersionMismatch` error and close the connection. Any change to the JSON protocol requires incrementing the shared `PROTOCOL_VERSION` constant.

- **Command Dispatch via Unix Sockets:** Communication from the Supervisor to the data plane worker processes uses a dedicated `UnixStream` socket pair for each worker.
  - The Supervisor serializes commands (e.g., `AddRule`) into a length-prefixed JSON payload and writes them to its end of the socket using its `tokio` runtime.
  - The worker's `io_uring` runtime polls its end of the socket. When data arrives, a command reader parses the length-prefixed JSON back into a command struct for processing.
  - This mechanism acts as a bridge between the supervisor's `tokio`-based control plane and the worker's `io_uring`-based data plane.

## 6. Monitoring and Hotspot Strategy

- **Hotspot Management (Observe, Don't Act):** The initial design will not implement an automatic hotspot mitigation strategy. Instead, it will rely on a robust, **core-aware monitoring system** to make any potential single-core saturation observable to the operator. The statistics reporting will be enhanced to include per-core packet rates and CPU utilization metrics. This provides the necessary visibility to manage the known architectural limitation.

- **Custom Observability via Control Plane:** The application provides comprehensive observability through its control plane, compensating for the lack of visibility from standard networking tools like `netstat`. A `ListRules` command exposes the forwarding table, and a `GetStats` command exposes metrics with per-rule granularity. _Note:_ Per-destination granularity (for fan-out scenarios) is not currently implemented; stats are aggregated at the rule level.

- **On-Demand Packet Tracing (NOT IMPLEMENTED):** _Future work:_ The application will implement a low-impact, on-demand packet tracing capability. Tracing will be configurable on a per-rule basis via control plane commands (`EnableTrace`, `DisableTrace`, `GetTrace`) and disabled by default. Each data plane worker will maintain a pre-allocated, in-memory ring buffer to store key diagnostic events for packets matching an enabled rule. The `GetTrace` command will retrieve these events, providing a detailed, chronological log of a packet's lifecycle or the reason for its drop.

## 7. Logging Architecture

Worker processes do not log directly to files. Instead, a simple and robust pipe-based mechanism decouples the high-performance workers from slower I/O by centralizing logging in the supervisor. Workers emit logs as a fast "fire-and-forget" operation into a pipe, and the supervisor asynchronously reads from these pipes, aggregates the messages, and prints them to its standard output.

For a comprehensive guide to the logging system, including the high-performance cross-process design for the data plane, API usage, and monitoring techniques, see the detailed **[Logging Design Document](../design/LOGGING_DESIGN.md)**.

## 8. Memory Management

- **Core-Local Buffer Pools:** To avoid the performance penalty of dynamic memory allocation, the application uses a core-local buffer pool strategy. Each core-pinned data plane thread pre-allocates and manages its own independent set of fixed-size memory buffers. These buffers are organized into multiple pools based on common packet sizes (e.g., Small, Standard, Jumbo). Runtime "allocations" are fast, lock-free operations that acquire a buffer from the appropriate pool.

- **Buffer Pool Observability:** The system is designed to handle buffer pool exhaustion by dropping packets rather than falling back to slow, dynamic allocation. To make this manageable, the monitoring system exposes detailed, per-core, per-pool metrics, including the total size of each pool, the current number of buffers in use, and a counter for exhaustion events.

## 9. Reliability and Resilience

- **Supervisor Pattern for Resilience:** The application implements a supervisor pattern. The main supervisor process is responsible for the lifecycle of the data plane worker processes. It monitors its child worker processes for crashes and will automatically restart a failed worker process using an exponential backoff strategy.

- **Network State Reconciliation (Future Work):** A high-priority item on the roadmap is to implement idempotent network state reconciliation. The target design is for the supervisor to use a Netlink socket to listen for network state changes (e.g., interfaces going up or down). This would allow it to automatically pause, resume, or re-resolve forwarding rules as network conditions change. **This feature is not yet implemented.**

### Supervisor Lifecycle Management

```mermaid
stateDiagram-v2
    [*] --> Initializing
    Initializing --> Running: All workers spawned

    state Running {
        [*] --> MonitoringWorkers
        MonitoringWorkers --> WorkerCrashed: Worker panic/exit
        WorkerCrashed --> BackoffDelay: failure_count++
        BackoffDelay --> RespawningWorker: After delay
        RespawningWorker --> ResyncingRules: Worker restarted
        ResyncingRules --> MonitoringWorkers: Rules sent
    }

    Running --> ShuttingDown: SIGTERM/SIGINT
    ShuttingDown --> [*]: All workers stopped
```

## 10. Security and Privilege Model

### Current Implementation vs. Target Architecture

**Current Multi-Process Architecture:**

The application uses a **multi-process architecture** where components run as separate OS processes:

- **Supervisor Process**: Main tokio-based async process that spawns and monitors workers
- **Control Plane Worker**: Separate process spawned by supervisor
- **Data Plane Workers**: Separate processes, one per CPU core

Each worker is spawned as a separate OS process with its own PID using `tokio::process::Command`.

**Privilege Separation Status:**

✅ **Control Plane Worker**: Successfully drops privileges to unprivileged user (`nobody:nobody` or configured user) immediately after startup. This worker handles runtime configuration and management without requiring elevated privileges.

⚠️ **Data Plane Workers**: Currently **do NOT drop privileges** and run as root. This is a known limitation documented in the code (see `src/worker/mod.rs:283-307`). Data plane workers require `CAP_NET_RAW` to create `AF_PACKET` sockets, and the ambient capabilities workaround doesn't survive `setuid()`.

**Target Architecture (Future Work):**

The goal is to implement file descriptor passing so the Supervisor creates `AF_PACKET` sockets and passes them to data plane workers via `SCM_RIGHTS`. This would allow data plane workers to drop ALL privileges completely while still being able to use the pre-created sockets. This is a **high-priority future work item**.

- **DDoS Amplification Risk (Trusted Network & QoS Mitigation):** The risk of DDoS amplification from external, malicious actors is considered mitigated by the operational requirement that the relay's ingress interfaces are connected only to physically secured, trusted network segments. The risk of accidental overload of a unicast destination due to misconfiguration is fully mitigated by the existing advanced QoS design, which allows for the classification and rate-limiting/prioritized dropping of high-bandwidth flows. No additional security-specific mechanisms are required for this threat vector.
