# Implementation Plan

This document is the strategic roadmap for building the `multicast-relay` application. It breaks the work into sequential, test-driven phases. Each phase includes specific testing requirements as primary deliverables, not afterthoughts. This plan is the primary reference for tracking progress and ensuring a high-quality, verifiable implementation.

**Core Principle:** We will build this application incrementally, maintaining a high level of automated test coverage (aiming for 90%+) from the start. No feature is complete until it is tested.

## Phase 1: Testable Foundation & Core Types

**Goal:** Create a compilable, verifiable foundation with all core data structures fully unit-tested.

1.  **Define Core Types (`lib.rs`):** Define all shared data structures, including `ForwardingRule`, `Command`, `Response`, and all statistics structs.
2.  **Unit Test Core Types:** Write comprehensive unit tests for all defined types. This must include tests for serialization/deserialization, validation logic, and any other business logic contained within these types.
3.  **Establish a Testable Baseline:** Refactor all existing placeholder code in `main.rs`, `control_client.rs`, etc., to use the new, tested types. Ensure `cargo build` and `cargo test` complete successfully.
4.  **Setup CI & Code Coverage:** Implement the CI pipeline as defined in `CONTRIBUTING.md`. Configure it to run `cargo test` and track code coverage, failing the build if coverage for the `lib` crate drops below 90%.

**Exit Criteria:** The project compiles without warnings, the CI pipeline is green, and the `lib` crate has at least 90% unit test coverage.

## Phase 2: Supervisor & Process Lifecycle (Integration Tested)

**Goal:** Implement the multi-process architecture and prove, through integration testing, that the Supervisor can robustly manage worker lifecycles.

1.  **Implement Supervisor (`supervisor.rs`):** Implement the logic to spawn, monitor, and automatically restart the unprivileged Data Plane and Control Plane processes (D18).
2.  **Implement Basic Workers:** Create skeleton `data_plane.rs` and `control_plane.rs` modules that can be spawned and monitored.
3.  **Implement Basic IPC:** Establish the MPSC channels for Supervisor-to-worker communication.
4.  **Write Lifecycle Integration Test:** Create a new integration test in the `tests/` directory. This test will:
    - Start the `multicast_relay` binary as a child process.
    - Verify that the Supervisor and its worker processes are running.
    - Send a `SIGKILL` signal to one of the worker processes.
    - Verify that the Supervisor detects the failure and successfully restarts the worker.

**Exit Criteria:** The Supervisor can spawn and monitor worker processes. The lifecycle integration test passes, proving the self-healing mechanism works.

## Phase 3: Control Plane (End-to-End Tested)

**Goal:** Build a functional control plane, verified by end-to-end tests using the `control_client`.

1.  **Implement Control Plane Server (`control_plane.rs`):** Implement the Unix Domain Socket listener and JSON-RPC handling.
2.  **Implement Supervisor Rule Management:** Implement the logic in the Supervisor to maintain the master rule list and dispatch commands to workers (D23).
3.  **Write Control Plane Integration Test:** Create a new integration test that uses the `control_client` binary to communicate with a live `multicast_relay` process. The test must:
    - Add a new forwarding rule and verify the command succeeds.
    - List the current rules and verify the newly added rule is present and correct.
    - Remove the forwarding rule and verify the command succeeds.
    - List the rules again and verify the rule has been removed.

**Exit Criteria:** The `control_client` can successfully add, list, and remove rules on a running `multicast_relay` instance, as verified by a passing integration test.

## Phase 4: Data Plane (Test-Driven Implementation)

**Goal:** Implement the core packet processing logic in a testable, piecemeal fashion, culminating in a full end-to-end data flow test.

1.  **Unit Test Data Plane Components:** Before building the `io_uring` loop, create and unit-test the core components in isolation:
    - **Buffer Pool:** Implement the core-local buffer pool (D15) and write unit tests to verify its allocation, deallocation, and exhaustion logic.
    - **Packet Parsing:** Implement any necessary packet header parsing logic and write unit tests using static, pre-captured packet data.
    - **Rule Lookup:** Write unit tests for the hash map lookup logic (D11).
2.  **Implement Data Plane I/O Loop:** Assemble the tested components into the main `tokio-uring` processing loop in `data_plane.rs`.
3.  **Write End-to-End Data Flow Test:** Create a comprehensive test script (`test_high_load.sh` or similar) that:
    - Starts the `multicast_relay` application.
    - Starts a separate UDP listener to receive the relayed traffic.
    - Uses the `control_client` to add a valid forwarding rule.
    - Uses the `traffic_generator` to send a known quantity of multicast packets to the input address.
    - Verifies that the UDP listener receives the correct number of packets at the correct output address.
    - Uses the `control_client` to remove the rule and verifies that traffic stops.

**Exit Criteria:** All data plane components are unit-tested. The end-to-end data flow test passes, proving the relay can successfully forward traffic according to a dynamically configured rule.

## Phase 5: Advanced Features (Test-Driven)

**Goal:** Layer in the remaining features, ensuring each is accompanied by its own set of verifying tests.

1.  **Implement & Test Statistics:**
    - Implement the statistics collection and aggregation logic (D14).
    - Write unit tests for the `StatsAggregator` logic.
    - Extend the end-to-end data flow test to query the `control_client stats` endpoint and verify that the reported packet/byte counts are accurate.
2.  **Implement & Test Resilience:**
    - Implement the Netlink listener in the Supervisor (D19).
    - Create a test script that uses `ip` commands to bring an interface down and then up, while using the `control_client` to verify that the corresponding forwarding rules are correctly paused and resumed.
3.  **Implement & Test Advanced Observability:**
    - Implement on-demand packet tracing (D28).
    - Extend an integration test to enable tracing on a rule, send a single packet, fetch the trace via the `control_client`, and verify its contents.

**Exit Criteria:** All architectural decisions are implemented and verified by a comprehensive suite of unit, integration, and end-to-end tests.
