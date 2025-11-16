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

*   **Performance Regression and Recovery:**
    *   **Historical Performance:** Initial data plane development achieved high throughput (**~307k pps egress**).
    *   **Regression Identified:** A severe performance regression (down to **~83k pps egress**) was introduced by commits that added unconditional logging calls into the per-packet "hot path".
    *   **Ingress Performance Restored:** The problematic logging calls have been removed, restoring *ingress* performance to high levels (**~689k pps**).
    *   **Egress Bottleneck Exposed:** With the logging bottleneck gone, a pre-existing lack of tuning in the egress path is now the primary performance limiter. See the roadmap below for the fix.
*   **Scaling Bugs Addressed:** Critical bugs preventing scaling beyond a single stream or worker have been fixed. See the full report in [`developer_docs/reports/MULTI_STREAM_SCALING_REPORT.md`](./developer_docs/reports/MULTI_STREAM_SCALING_REPORT.md).
*   **Logging System Refactored:** The original shared memory logging system has been replaced with a simpler, pipe-based mechanism.
*   **Technical Investigation Completed:** A detailed investigation of the remaining high-priority architectural refactoring tasks is complete.

---

## Outstanding Work (Prioritized Roadmap)

The next phase of work focuses on executing the now well-defined architectural refactoring tasks to unify the IPC mechanism, harden the security model, and restore egress performance.

### 🔴 HIGH PRIORITY

#### 1. Performance: Restore Egress Throughput
*   **Goal:** Restore egress performance to historical levels (~300k pps).
*   **Problem:** A severe performance regression (down to ~97k pps) was caused by an architectural change to the egress worker's event loop. The `send_batch()` function was refactored from a synchronous submit-and-reap model to an asynchronous, deferred-submission model.
*   **Impact:** This broke the critical feedback loop for the buffer pool, causing ingress to starve for buffers and leading to massive packet drops (86% buffer exhaustion).
*   **Action:**
    1.  **Primary Fix:** Revert the `send_batch()` function in `src/worker/egress.rs` to its original, synchronous model where it submits its batch and immediately reaps the completions.
    2.  **Secondary Optimizations:** Concurrently, apply performance tuning by setting a large `SO_SNDBUF` size on egress sockets and parameterizing the `EgressConfig` to use a much larger `io_uring` queue depth (e.g., 1024).

#### 2. Architectural Refactor: IPC and Configuration
*   **Goal:** Unify inter-process communication on a single `io_uring`-based mechanism.
*   **Action:** Refactor the IPC to pass an `Initialize` command containing the worker's configuration over the existing `UnixStream`, removing the dependency on command-line arguments.

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
