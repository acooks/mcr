# Testing Philosophy

**Note:** All testing workflows are orchestrated using the `just` command runner. This document outlines the philosophy and strategy for the `multicast-relay` application. It is a core project document, equal in importance to `ARCHITECTURE.md` and `CONTRIBUTING.md`. Adherence to this strategy is mandatory for all contributions.

## The Challenge: Why Testing This Application is Hard

Testing a high-performance, low-level networking application like this is non-trivial. We face several technical and cultural hurdles:

1.  **Privilege Requirements:** The application's core functionality (`AF_PACKET`, `io_uring`) requires elevated privileges (`CAP_NET_RAW`), which are not available in a standard, unprivileged unit test environment.
2.  **Kernel & Environment Dependency:** The code is deeply coupled to the Linux kernel's networking stack. Tests cannot assume the existence or configuration of specific network interfaces (e.g., `eth0`).
3.  **Asynchronous & Multi-Process Complexity:** The system is composed of multiple, independently scheduled processes communicating asynchronously. This can lead to complex race conditions and flaky tests if not handled carefully.
4.  **The "It's Just Plumbing" Fallacy:** A common cultural trap is to assume that if the code compiles, it must work. This ignores the vast number of edge cases in configuration, error handling, and resource management that can only be caught with rigorous, automated testing.

A failure to address these challenges leads to code that builds but doesn't work, is difficult to debug, and is impossible to refactor safely. We explicitly reject this outcome.

## The Solution: A Tiered Testing Strategy

To overcome these challenges, we adopt a formal, tiered testing strategy. This approach allows us to test every aspect of the application—from pure business logic to high-performance data flow—in an appropriate, isolated, and reliable manner.

### Tier 1: Unit Tests

**Purpose:** To test pure, internal business logic that does not require privileges or a specific kernel environment.

- **Scope:**
  - Serialization/deserialization of control plane commands.
  - State management logic within the Supervisor.
  - Statistics aggregation logic.
  - Buffer pool allocation and exhaustion logic.
  - Packet header parsing and manipulation.
- **Methodology:** We use Rust's trait system for dependency injection and mocking. Components are written to operate against abstract interfaces (traits). In production, we provide the real implementation; in tests, we provide a mock implementation that allows us to simulate behavior and assert outcomes without touching the network.
- **Goal:** Achieve and maintain at least 90% line coverage for all logic in the `lib.rs` crate and other modules where this technique is applicable.

### Tier 2: Rust Integration Tests

**Purpose:** To test the interaction between the application's Rust components, either unprivileged or in isolated network namespaces.

- **Scope:**
  - Supervisor's ability to spawn, monitor, and restart worker processes.
  - End-to-end control plane functionality (`control_client` -> `multicast_relay`).
  - Correct command dispatch from Supervisor to data plane workers.
  - Resilience to network interface changes (e.g., link up/down).
- **Methodology:** Unprivileged tests run directly with `cargo test`. Privileged tests use Linux network namespaces (`ip netns`) and are typically marked `#[ignore]` in Rust, orchestrated via `just` commands that execute them with `sudo`.
- **Goal:** Verify that the distinct Rust processes of the application work together as a cohesive system according to the architectural design.

### Tier 3: E2E Bash Tests

**Purpose:** To validate the **fully compiled release binaries** (`multicast_relay`, `control_client`, `traffic_generator`) under realistic conditions in complex, multi-hop network topologies.

- **Scope:**
  - Verifying that packets are correctly relayed from a given input to a given output across multiple MCR instances.
  - Performance benchmarking against tools like `socat`.
  - Load testing to ensure the application meets its performance targets.
- **Methodology:** These tests are shell scripts (`.sh` files) located in `tests/` and `tests/topologies/`. They typically use `unshare --net` for network namespace isolation and leverage the `just` framework to orchestrate the compiled MCR binaries, traffic generators, and validation tools.
- **Goal:** Prove that the application, as a whole, meets its functional and non-functional requirements in deployment-like scenarios.

## The Official Workflow

The `justfile` is the single source of truth for running tests. The following commands provide the primary entry points.

```bash
# Build all test and application binaries (as regular user)
just build-test

# Run all tests that do NOT require root privileges (fastest)
just test-quick

# Run the complete test suite, including all privileged tests.
# This is the command to run before submitting a PR.
just test-all
```

### Prototyping: Risk Reduction, Demonstration, and Teaching

For particularly complex or high-risk features (e.g., initial `io_uring` and `AF_PACKET` integration), we first build small, standalone prototypes in the `experiments/` directory. These prototypes serve multiple critical purposes:

- **Risk Reduction:** They allow us to isolate and de-risk core technical challenges and prove concepts work before integrating them into the main, more complex application codebase.
- **Demonstration:** They act as concrete, runnable examples of how a specific complex mechanism works, making it easier to understand and validate the approach.
- **Teaching Aid:** They are invaluable for onboarding new contributors, providing clear, focused examples of tricky concepts or API usage without the cognitive overhead of the full application. They are not detritus to be discarded, but rather treasured artifacts that ensure the continuity of knowledge and understanding within the project.

## Supporting Documents

These documents provide deeper dives into specific aspects of the MCR testing strategy and framework.

*   **[Test Coverage Analysis](./test_coverage_analysis.md):** A detailed analysis of current Rust code coverage, identifying critical gaps and areas for improvement.
*   **[Test Coverage Improvement Plan](./improvement_plan.md):** A pragmatic, prioritized action plan for systematically increasing test coverage over time.
*   **[Test Framework Proposal](./test_framework_proposal.md):** The strategic proposal for a `just`-based workflow that separates build and test phases, ensuring consistent and reliable test execution.
*   **[Network Namespace Test Framework](./netns_test_framework.md):** The technical plan for implementing the `netns` wrapper script and helpers for Rust integration tests.

