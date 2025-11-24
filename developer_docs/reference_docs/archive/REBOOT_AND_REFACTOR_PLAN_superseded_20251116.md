# MCR Reboot & Refactoring Plan

**Objective:** To produce a robust, performant, and maintainable multicast relay application by systematically addressing the architectural flaws and bugs uncovered during recent testing.

**Current State (High-Level Summary):**
-   The core `io_uring`-based data plane is implemented but has known bugs related to multi-worker and multi-stream scaling.
-   The supervisor and `WorkerManager` provide a solid foundation for process management.
-   The test suite has successfully identified critical flaws but is a mix of legacy scripts and modern Rust tests that needs consolidation.
-   **Key Insight:** The primary sources of complexity and fragility have been the "impedance mismatches" between different parts of the system (e.g., `tokio` vs. `std::thread`, userspace queues vs. kernel event loops).

---

## **Phase 1: Stabilize the Core Architecture (The "Big Fix")**

**Goal:** Create a single, simple, and robust architecture for IPC and logging that eliminates the major bug classes we've discovered. This phase implements the "Pragmatic Refactoring" plan.

**Task 1.1: Implement Pipe-Based Logging.**
-   **Action:** Replace the entire shared memory logging subsystem.
-   **Mechanism:**
    1.  The supervisor creates a `pipe()` for each worker.
    2.  The worker `dup2()`s the write-end of the pipe to its `stderr`.
    3.  The worker's logging framework is configured to write structured JSON to `stderr`.
    4.  The supervisor reads from the pipes in its main `tokio` event loop.
-   **Outcome:** The `ringbuffer.rs` and `integration.rs` files are **deleted**. All shared memory complexity and fragility are gone.

**Task 1.2: Implement Direct `io_uring`-based Command IPC.**
-   **Action:** Eliminate the "Three-Primitive Bridge" (`UnixStream` -> `tokio` -> `mpsc` -> `eventfd`).
-   **Mechanism:**
    1.  The supervisor passes the `UnixStream` file descriptors for commands directly to the workers.
    2.  The `IngressLoop` and `EgressLoop` `run()` methods are modified to add these FDs to their `io_uring` instances.
    3.  Commands are now received as `io_uring` completion events, unifying them with the main I/O loop.
-   **Outcome:** The `mpsc` channels, command `eventfd`s, and the `tokio` bridge task in the worker are **deleted**. The startup deadlock is structurally eliminated.

**Task 1.3: Implement "Configuration-over-IPC".**
-   **Action:** Stop passing configuration via command-line arguments.
-   **Mechanism:**
    1.  The supervisor spawns a "dumb" worker.
    2.  The first message sent over the new, direct command channel is an `Initialize` command containing the `core_id`, `input_interface`, etc.
    3.  The worker waits for this message before completing its initialization.
-   **Outcome:** The worker's `clap` argument parser is massively simplified. Configuration is centralized in the supervisor.

---

### **Phase 2: Fix Critical Data Plane Bugs**

**Goal:** Address the two major functional bugs identified by the test suite.

**Task 2.1: Fix the Multi-Worker Packet Duplication Bug.**
-   **Action:** Implement `PACKET_FANOUT` for the `AF_PACKET` sockets.
-   **Mechanism:**
    1.  The supervisor generates a single "fanout group ID" (e.g., its PID).
    2.  This ID is passed to each data plane worker as part of the `Initialize` command from Phase 1.
    3.  The `IngressLoop::new()` function uses `setsockopt` to add its `AF_PACKET` socket to this fanout group.
-   **Outcome:** The kernel will now load-balance packets across the workers instead of duplicating them. MCR's multi-core scaling will now function as designed.

**Task 2.2: Fix the Multi-Stream Forwarding Failure.**
-   **Action:** Debug and resolve the 100% packet loss issue when more than one forwarding rule is active.
-   **Mechanism:**
    1.  Use the `multi_stream_scaling.sh` test as the reproducible test case.
    2.  Add extensive `TRACE`-level logging to `IngressLoop::add_rule` and `IngressLoop::process_packet`.
    3.  Use `tcpdump` to verify that IGMP "join" messages are being sent for *all* multicast groups.
    4.  Investigate the `rules` `HashMap` lookup in `process_packet` to ensure it's correctly matching packets for all streams, not just the first one.
-   **Outcome:** MCR can correctly handle a high density of concurrent multicast streams.

---

### **Phase 3: Consolidate and Harden the Test Suite**

**Goal:** Make the test suite robust, reliable, and the single source of truth for application correctness.

**Task 3.1: Create the Definitive Performance Benchmark.**
-   **Action:** Create a single, final `tests/performance/benchmark.sh` script.
-   **Mechanism:** This script will be based on the proven `compare_socat_chain.sh`. It will use the simple, reliable **chain topology**. It will be the official tool for comparing MCR vs. `socat` and for tracking performance regressions.

**Task 3.2: Deprecate and Remove Redundant Scripts.**
-   **Action:** Delete all other experimental and legacy test scripts in `docs/experiments/` and `tests/topologies/`.
-   **Mechanism:** Their findings and valuable topologies (like the dual-bridge) will be documented in the `MCR_vs_socat.md` file or ported to new, focused Rust integration tests if they test a unique behavior.
-   **Outcome:** The `tests/` directory becomes clean and easy to navigate. There is one clear performance test and a focused set of Rust integration tests.
