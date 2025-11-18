# Project Status

**Last Updated:** 2025-11-16
**Note:** This is a living document, intended to be the single source of truth for the project's current state and roadmap. It should be updated upon the completion of any major task.

---

## Current State: Core Functionality Complete, Test Coverage & Hardening In Progress

The core data plane of MCR is functional and its basic performance has been validated. The project is currently in a phase of active development focused on two key areas:
1.  **Expanding Test Coverage:** Systematically increasing unit and integration test coverage to harden the existing codebase and prevent regressions.
2.  **Architectural Hardening:** Executing a series of planned refactoring tasks to improve security, scalability, and maintainability.

While the basics are working, the project is still "rough around the edges" and is not yet considered production-ready.

### Recent Milestones

*   **Architectural Pivot to Unified Data Plane:** The data plane was refactored from a complex, two-thread (ingress/egress) model to a simpler and more performant **single-threaded, unified event loop**. This architectural change completely eliminates the need for inter-thread communication (channels, eventfds, wakeup strategies), resolving a major source of complexity and bugs.
*   **Performance Regression Addressed:** A severe performance regression was identified and **fixed**. The egress path has been reverted to a synchronous submit-and-reap model, restoring performance to historical levels.
*   **Scaling Bugs Addressed:** Critical bugs preventing scaling beyond a single stream or worker have been fixed. See the full report in [`developer_docs/reports/MULTI_STREAM_SCALING_REPORT.md`](./developer_docs/reports/MULTI_STREAM_SCALING_REPORT.md).
*   **Logging System Refactored:** The original, complex shared memory logging system has been replaced with a simpler, more robust pipe-based mechanism.
*   **Technical Investigation Completed:** A detailed investigation of the remaining high-priority architectural refactoring tasks is complete.

---

## Outstanding Work (Prioritized Roadmap)

The next phase of work focuses on executing the now well-defined architectural refactoring tasks to unify the IPC mechanism and harden the security model.

### 🔴 HIGH PRIORITY

#### 1. Architectural Refactor: Supervisor-to-Worker IPC & Configuration
*   **Goal:** Simplify worker startup and centralize configuration by passing it over IPC instead of command-line arguments.
*   **Action:** Refactor the supervisor-to-worker communication to send an initial `Initialize` command containing the worker's full configuration (core ID, interfaces, etc.) over the existing `UnixStream`. This will eliminate the need for most command-line argument parsing in the worker, making it a more generic "dumb" process.

#### 3. Security: Privilege Separation via FD Passing
*   **Goal:** Achieve a true least-privilege model where data plane workers run with zero privileges.
*   **Action:** Move `AF_PACKET` socket creation from the worker to the supervisor and pass the file descriptor to the worker using the existing FD-passing mechanism.

#### 4. Scaling: Lazy AF_PACKET Socket Creation
*   **Goal:** Allow MCR to scale to many cores without eagerly allocating resources.
*   **Action:** Modify the `IngressLoop::add_rule` function to create `AF_PACKET` sockets on-demand based on the rule's `input_interface`.

### 🟡 MEDIUM PRIORITY

#### 1. Stats Aggregation from Workers
*   **Problem:** The `GetStats` command does not include live packet/byte counters from workers.
*   **Action:** Design and implement an IPC mechanism for the supervisor to query workers for live statistics.

#### 2. Consolidate and Harden Test Suite
*   **Goal:** Make the test suite the single source of truth for application correctness.
*   **Action:** Create a definitive performance benchmark script. Deprecate and remove redundant legacy test scripts.

### 🟢 LOW PRIORITY
(No low priority items at this time)
