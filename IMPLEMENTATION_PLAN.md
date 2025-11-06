# Implementation Plan

This document outlines the development roadmap for the `multicast-relay` application, breaking the work into sequential phases.

## Phase 1: Stabilize the Baseline & Core Types

**Goal:** Create a compilable, testable foundation with all core data structures defined.

1.  **Define Core Types:** In `lib.rs`, define all the shared data structures as decided in the architecture. This includes:
    -   `ForwardingRule`
    -   `OutputDestination`
    -   `Command` and `Response` enums for the control plane.
    -   Internal command types for Supervisor-to-worker communication.
    -   All statistics-related structs.
2.  **Fix Existing Code:** Refactor the existing placeholder code in `main.rs`, `control_client.rs`, etc., to use these new types.
3.  **Achieve Compilation:** The primary goal is to get the entire project to a state where `cargo build` and `cargo test` complete successfully, even if the tests do nothing yet.
4.  **Setup CI:** Implement the CI pipeline (as defined in `CONTRIBUTING.md`) to run `cargo fmt --check`, `cargo clippy`, and `cargo test` on every commit.

**Exit Criteria:** The project compiles without errors or warnings, and the CI pipeline is green.

## Phase 2: The Supervisor and Process Management

**Goal:** Implement the multi-process architecture and prove that the Supervisor can manage worker lifecycles.

1.  **Implement Supervisor (`supervisor.rs`):**
    -   Create the main loop for the Supervisor.
    -   Implement the logic to spawn unprivileged Data Plane and Control Plane processes.
    -   Implement the panic-detection and automatic restart logic for worker processes (D18).
2.  **Implement Basic Workers:** Create skeleton `data_plane.rs` and `control_plane.rs` modules that can be spawned by the Supervisor. Initially, they will just start, print a message, and loop indefinitely.
3.  **Implement IPC:**
    -   Establish the MPSC channels for Supervisor-to-worker communication.
    -   Prove that the Supervisor can send a simple command (e.g., `Ping`) and a worker can receive it.

**Exit Criteria:** The main application starts a Supervisor, which in turn spawns and monitors at least one data plane and one control plane process. Basic IPC is functional.

## Phase 3: The Control Plane

**Goal:** Build a functional control plane that can manage rules, but without a working data plane yet.

1.  **Implement Control Plane Server (`control_plane.rs`):**
    -   Implement the Unix Domain Socket listener.
    -   Implement the JSON-RPC command parsing and response serialization.
    -   Implement the logic to forward commands to the Supervisor (e.g., `AddRule`, `RemoveRule`).
2.  **Implement Supervisor Rule Management:**
    -   In the Supervisor, implement the logic to maintain the master rule list.
    -   Implement the rule-to-core assignment logic (D23).
    -   Prove that an `AddRule` command from the control client results in the Supervisor sending the correct `AddRuleInternal` command to the correct (mocked) data plane worker.
3.  **Update Control Client:** Make the `control_client.rs` binary a fully functional tool for sending all supported commands.

**Exit Criteria:** The `control_client` can add, list, and remove rules. The Supervisor's internal state correctly reflects these changes.

## Phase 4: The Data Plane (Ingress & Egress)

**Goal:** Implement the core packet processing loop. This is the most complex phase.

1.  **Implement Privileged Socket Creation:** In the Supervisor, implement the logic to create `AF_PACKET` "helper" (D6) and main sockets, and pass their file descriptors to the data plane workers upon startup.
2.  **Implement Data Plane Worker (`data_plane.rs`):**
    -   Initialize the `tokio-uring` runtime.
    -   Receive the socket file descriptors from the Supervisor.
    -   Implement the core-local buffer pool (D15).
    -   Implement the main `io_uring` loop for receiving from the `AF_PACKET` socket.
    -   Implement the userspace hash map for rule lookup (D11).
    -   Implement the egress path using `AF_INET` sockets, including the payload copy (D5).
3.  **End-to-End Test:** Perform the first end-to-end test: send a multicast packet to an input group and verify it is relayed correctly to an output destination.

**Exit Criteria:** A single forwarding rule can be added, and it will successfully relay traffic.

## Phase 5: Features & Resilience

**Goal:** Layer in the remaining features and resilience mechanisms.

1.  **Implement Statistics:** Implement the full statistics collection in the data plane and the `StatsAggregator` logic (D14).
2.  **Implement QoS:** Implement the DSCP-based classification and priority queuing logic (D13).
3.  **Implement Tracing:** Implement the on-demand packet tracing feature (D28).
4.  **Implement Netlink Listener:** In the Supervisor, implement the Netlink socket listener to handle network interface changes (D19).
5.  **Integration Testing:** Create a comprehensive suite of integration tests in the `tests/` directory to validate all functionality under various conditions.

**Exit Criteria:** All architectural decisions are implemented and tested. The application is feature-complete.
