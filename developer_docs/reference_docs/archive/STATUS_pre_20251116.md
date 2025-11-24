# Project Status

**Last Updated:** 2025-11-16
**Note:** This is a living document, intended to be the single source of truth for the project's current state and roadmap. It should be updated upon the completion of any major task.

---

## Current State: Post-Scaling Fixes / Pre-Architectural Refactor

The MCR data plane is functionally complete and has demonstrated performance that exceeds its initial targets. Recent work has focused on resolving critical scaling limitations, and the project is now positioned for a final architectural simplification phase to improve robustness and maintainability.

### Key Achievements

*   **Performance Targets Exceeded:** The data plane has been validated in a realistic 3-hop pipeline test, achieving **490k pps ingress** and **307k pps egress**, surpassing the 312.5k pps target.
*   **Multi-Stream & Multi-Worker Scaling Fixed:** A major investigation resolved two critical bugs that previously blocked scaling beyond a single stream or worker. The system now scales correctly with multiple concurrent streams and properly load-balances across multiple workers using `PACKET_FANOUT`. A full report on this effort is available in [`developer_docs/reports/MULTI_STREAM_SCALING_REPORT.md`](./developer_docs/reports/MULTI_STREAM_SCALING_REPORT.md).

---

## Outstanding Work (Prioritized Roadmap)

The next phase of work focuses on simplifying the architecture to eliminate technical debt and improve security, followed by hardening the test suite and addressing medium-priority features.

### 🔴 HIGH PRIORITY

#### 1. Architectural Refactor: Pipe-Based Logging
*   **Goal:** Replace the entire custom shared memory logging subsystem (`ringbuffer.rs`) with a standard, robust pipe-based mechanism.
*   **Problem:** The current shared memory logging is complex (~2000 lines), fragile, and can leak resources on crashes.
*   **Action:** Modify the supervisor to create a `pipe()` for each worker, redirect worker `stderr` to the pipe, and consume the logs from the supervisor's main event loop. This will significantly simplify the codebase and eliminate a major source of bugs.

#### 2. Architectural Refactor: IPC and Configuration
*   **Goal:** Unify inter-process communication on a single `io_uring`-based mechanism, eliminating the current "Three-Primitive Bridge" (`UnixStream` -> `tokio` -> `mpsc` -> `eventfd`).
*   **Problem:** The current IPC is overly complex, introduces latency, and was the source of startup deadlocks. Configuration via command-line arguments also prevents dynamic socket creation.
*   **Action:** Pass command sockets directly to workers and handle them in the main `io_uring` loop. Send an `Initialize` command over IPC for configuration instead of using CLI arguments.

#### 3. Security: Privilege Separation via FD Passing
*   **Goal:** Achieve a true least-privilege model where data plane workers run with zero privileges.
*   **Problem:** Workers currently run as root, which is a significant security vulnerability.
*   **Action:** The privileged supervisor will create the necessary `AF_PACKET` sockets and pass the file descriptors (FDs) to the unprivileged worker processes. The workers can then drop all capabilities and run as a non-privileged user (e.g., `nobody`).

#### 4. Scaling: Lazy AF_PACKET Socket Creation
*   **Goal:** Allow MCR to scale to many cores without eagerly allocating resources.
*   **Problem:** All workers currently create sockets on startup, which exhausts kernel resources and prevents multi-core scaling. This violates the core architecture.
*   **Action:** Modify workers to start without sockets. Sockets for a given input interface will be created lazily, on-demand, when the first forwarding rule for that interface is received.

### 🟡 MEDIUM PRIORITY

#### 1. Stats Aggregation from Workers
*   **Problem:** The `GetStats` command currently returns configured rules but does not include live packet/byte counters from the data plane workers.
*   **Action:** Design and implement an IPC mechanism for the supervisor to query workers for live statistics, likely on a per-rule basis.

#### 2. Consolidate and Harden Test Suite
*   **Goal:** Make the test suite the single source of truth for application correctness.
*   **Action:** Create a definitive performance benchmark script based on the proven 3-hop chain topology. Deprecate and remove redundant legacy test scripts, porting any unique scenarios to new, focused Rust integration tests.

### 🟢 LOW PRIORITY

#### 1. Performance Optimization (Egress Path)
*   **Finding:** A 37% performance gap exists between the AF_PACKET ingress (490k pps) and the UDP socket egress (307k pps).
*   **Action:** Defer optimization. The current egress performance still exceeds project targets. Future work could involve profiling the egress path and exploring `SEND_ZC` (zero-copy send).
