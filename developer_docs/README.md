# Developer Documentation

This directory contains all documentation relevant to contributors and developers working on the Multicast Relay (MCR) project.

## Core Documents

*   **[ARCHITECTURE.md](./ARCHITECTURE.md):** The definitive, up-to-date guide to the system's design, components, and core technical decisions.
*   **[DESIGN.md](./DESIGN.md):** The rationale and thought process behind the current architecture, explaining *why* key decisions were made.
*   **[CONTRIBUTING.md](./CONTRIBUTING.md):** The guide for new contributors, covering development standards, testing requirements, and workflow.
*   **[DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md):** A comprehensive guide to setting up your development environment and understanding the core development workflow.

## Thematic Guides

*   **[Design Documents](./design/README.md):** Detailed design specifications for various MCR subsystems.
    *   **[Architecture Diagrams](./design/ARCHITECTURE_DIAGRAMS.md):** Visual representations of the MCR architecture.
    *   **[Logging Design](./design/LOGGING.md):** Details on MCR's logging subsystem.

*   **[Policies](./policies/README.md):** Important policy documents governing development.
    *   **[Unsafe Code Policy](./policies/UNSAFE_CODE_POLICY.md):** Guidelines and rationale for using `unsafe` Rust code in MCR.

*   **[Reports](./reports/README.md):** Comprehensive reports on major investigations and resolutions.
    *   **[Multi-Stream Scaling Report](./reports/MULTI_STREAM_SCALING_REPORT.md):** Full report on the investigation and fix for multi-stream and multi-worker scaling issues.
*   **[Devnull Egress Sink Proposal](./reports/DEVNULL_EGRESS_SINK_PROPOSAL.md):** A proposal for implementing a /dev/null egress sink to aid performance testing and debugging.
*   **[Test Framework Validation Results](./reports/TEST_FRAMEWORK_VALIDATION_RESULTS.md):** Report on the implementation and validation of the network namespace test framework, including test failure analysis.
*   **[Session Summary: Test Framework Implementation](./reports/SESSION_SUMMARY_TEST_FRAMEWORK_IMPLEMENTATION.md):** Recap of a development session focused on test framework implementation and test failure analysis.

*   **[Testing Strategy](./testing/README.md):** The high-level philosophy and tiered strategy guiding how we test MCR.
    *   **[Developer Testing Strategy](./testing/DEVELOPER_TESTING_STRATEGY.md):** In-depth guide for developers on writing and maintaining tests.
    *   **[Practical Testing Guide](./testing/PRACTICAL_TESTING_GUIDE.md):** The hands-on 'how-to' guide for running the test suites.

*   **[Comparisons](./comparisons/README.md):** Analysis and comparison of MCR with other networking tools.
    *   **[MCR vs. socat](./comparisons/MCR_vs_socat.md):** A detailed comparison of MCR's architecture and performance against `socat`.

## Reference Docs (Archived & Historical)

For more specific deep-dives into older plans, experiments, or completed phase reports, see the `reference_docs/` directory.
