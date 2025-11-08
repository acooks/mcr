# Testing Implementation Plan

This document provides the concrete implementation plan for the testing philosophy outlined in `TESTING.md`. It defines the test suite's structure, the tools we will use, and a phased approach to restructuring existing tests and expanding coverage.

## 1. Proposed Test Directory Structure

To bring clarity and align with Rust best practices, the `tests/` directory will be restructured as follows. Unit tests (Tier 1) will continue to reside within their respective modules in `src/` under a `#[cfg(test)]` block.

```
mcr/
├── src/
│   └── supervisor.rs
│       └── #[cfg(test)] mod tests { /* Unit tests here */ }
├── tests/
│   ├── lib.rs                  # Common test helpers and utilities
│   ├── benchmarks/             # Tier 3: Performance benchmarks (Criterion.rs)
│   │   └── forwarding_rate.rs
│   ├── e2e/                    # Tier 3: End-to-end shell script tests (Existing)
│   │   ├── 01_happy_path.t
│   │   └── ...
│   ├── integration/            # Tier 2: Rust-based integration tests
│   │   ├── cli.rs              # Tests for the main binary's CLI parsing and execution
│   │   ├── ipc.rs              # Tests for Supervisor <-> Worker communication
│   │   └── supervisor.rs       # Tests for supervisor lifecycle, resilience, etc.
│   └── proptests/              # Tier 1: Property-based tests
│       └── packet_parser.rs
└── Cargo.toml
```

### Why this structure?

-   **`tests/lib.rs`**: A standard Rust pattern for sharing code between different integration test files.
-   **`tests/integration/`**: Houses all Tier 2 tests, which verify the interaction between different parts of the application. Sub-modules provide clear organization.
-   **`tests/e2e/`**: Unchanged. Continues to house the Tier 3 shell-based tests that run the final binaries.
-   **`tests/benchmarks/`**: Formalizes performance testing as a first-class citizen.
-   **`tests/proptests/`**: Creates a dedicated space for property-based tests, which are fundamentally different from example-based integration tests.

## 2. Phased Implementation Plan

### Phase 1: Foundational Tooling

1.  **Integrate Code Coverage:** Add `cargo-tarpaulin` to the project. Update the `justfile` with a `just coverage` command and integrate it into the CI pipeline to enforce the >90% coverage goal from `TESTING.md`.
2.  **Introduce Property Testing:** Add the `proptest` crate as a development dependency to enable property-based testing.

### Phase 2: Restructure & Document Existing Tests (Immediate Action)

1.  **Create New Directory Structure:** Implement the directory layout proposed above.
2.  **Relocate Existing Tests:** Move the existing test files to their new, logical locations.
3.  **Refactor Unit Tests:** Move the logic from `tests/supervisor_logic.rs` and `tests/worker_logic.rs` into `#[cfg(test)]` modules within `src/supervisor.rs` and `src/worker/mod.rs` respectively, as is idiomatic for Rust unit tests.
4.  **Document Each Test:** Add doc comments (`///`) to each test function (`#[test]`) explaining its **Purpose**, **Method**, and **Tier** in the testing strategy.

### Phase 3: Expand Test Coverage

1.  **Implement Tier 2 Integration Tests:**
    -   **DONE:** Create a full integration test for the Supervisor-Worker IPC, using the `nix` crate to programmatically create Unix socket pairs and verify command/response serialization.
    -   Build a namespace-based test in `tests/integration/supervisor.rs` to verify that the supervisor can correctly restart workers after a failure.
    -   Un-ignore the existing tests in `supervisor_logic.rs` and fix them within their new home as unit tests.
2.  **Implement Property-Based Tests:**
    -   **DONE:** Create a property-based test suite in `tests/proptests/packet_parser.rs` that generates arbitrary byte streams and asserts that the `packet_parser` either correctly parses them or returns a `ParseError`, but never panics.

### Phase 4: Formalize E2E & Performance Testing

1.  **Refactor E2E Scripts:** Add comments and clear function definitions to the scripts in `tests/e2e/` to improve readability and maintainability.
2.  **Create Benchmark Suite:** Implement a formal benchmark test in `tests/benchmarks/` using `criterion` to measure the maximum sustainable packet forwarding rate and end-to-end latency.

### Phase 5: CI Integration

1.  **Update CI Workflow:** Modify the `.github/workflows/rust.yml` file to run all test types (unit, integration, proptests, e2e) on every pull request.
2.  **Enforce Quality Gates:** Configure the CI to fail if code coverage drops below the established threshold.
