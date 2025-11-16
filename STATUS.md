# Project Status

**Last Updated:** 2025-11-16
**Note:** This is a living document, intended to be the single source of truth for the project's current state and roadmap. It should be updated upon the completion of any major task.

---

## Current State: Active Development - Architectural Refactor In Progress

The MCR data plane has achieved functional completeness for its core purpose and demonstrated strong performance, with critical scaling limitations resolved. The project is currently in an active development phase, focusing on key architectural refinements.

### Key Achievements

*   **Performance Targets Exceeded:** The data plane has been validated in a realistic 3-hop pipeline test, achieving **490k pps ingress** and **307k pps egress**.
*   **Multi-Stream & Multi-Worker Scaling Fixed:** The system now demonstrates correct scaling behavior with multiple concurrent streams and workers. See the full report in [`developer_docs/reports/MULTI_STREAM_SCALING_REPORT.md`](./developer_docs/reports/MULTI_STREAM_SCALING_REPORT.md).
*   **Pipe-Based Logging Implemented:** The complex shared memory logging system has been replaced with a standard, robust pipe-based mechanism.
*   **Technical Investigation Complete:** A `codebase_investigator` analysis of all high-priority refactoring tasks has been completed, providing a solid technical foundation as the project moves into its next implementation phase.

---

## Outstanding Work (Prioritized Roadmap)

The next phase of work focuses on executing the now well-defined architectural refactoring tasks to unify the IPC mechanism and harden the security model.

### 🔴 HIGH PRIORITY

#### 1. Architectural Refactor: IPC and Configuration
*   **Goal:** Unify inter-process communication on a single `io_uring`-based mechanism.
*   **Current State:** The supervisor (Tokio) and workers (`io_uring`) communicate via a `UnixStream` socket pair. The supervisor passes all configuration to workers as command-line arguments.
*   **Action:** Refactor the IPC to pass an `Initialize` command containing the worker's configuration over the existing `UnixStream`, removing the dependency on command-line arguments. This centralizes configuration and simplifies the worker's entry point.

#### 2. Security: Privilege Separation via FD Passing
*   **Goal:** Achieve a true least-privilege model where data plane workers run with zero privileges.
*   **Current State:** The data plane worker creates its own privileged `AF_PACKET` socket in `src/worker/ingress.rs` and therefore cannot drop root privileges. The necessary FD-passing mechanism (`SCM_RIGHTS`) is already used for control sockets.
*   **Action:** Move the `AF_PACKET` socket creation from the worker to the supervisor. Pass the resulting file descriptor (FD) to the worker using the existing FD-passing mechanism. The worker can then call `drop_privileges` and run as a non-privileged user.

#### 3. Scaling: Lazy AF_PACKET Socket Creation
*   **Goal:** Allow MCR to scale to many cores without eagerly allocating resources.
*   **Current State:** The supervisor passes a global `--interface` argument to each worker, which eagerly creates a single `AF_PACKET` socket on startup in `IngressLoop::new`.
*   **Action:** Remove the global `--interface` parameter. Modify the `IngressLoop::add_rule` function in `src/worker/ingress.rs` to check the rule's `input_interface`. If a socket for that interface does not already exist, create it on-demand and add it to the `io_uring` instance.

### 🟡 MEDIUM PRIORITY

#### 1. Stats Aggregation from Workers
*   **Problem:** The `GetStats` command does not include live packet/byte counters from workers.
*   **Action:** Design and implement an IPC mechanism for the supervisor to query workers for live statistics.

#### 2. Consolidate and Harden Test Suite
*   **Goal:** Make the test suite the single source of truth for application correctness.
*   **Action:** Create a definitive performance benchmark script. Deprecate and remove redundant legacy test scripts.

### 🟢 LOW PRIORITY

#### 1. Performance Optimization (Egress Path)
*   **Finding:** A 37% performance gap exists between ingress (490k pps) and egress (307k pps).
*   **Action:** Defer optimization. Current performance exceeds targets.
