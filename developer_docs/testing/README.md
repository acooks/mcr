# Testing

This directory contains all documentation related to testing the Multicast Relay (MCR) application.

## Core Documents

*   **[Developer Testing Strategy](./DEVELOPER_TESTING_STRATEGY.md):** The high-level "why." This document outlines the philosophy, goals, and tiered strategy (Unit, Integration, E2E) for testing MCR. Start here to understand the team's approach to quality.

*   **[Practical Testing Guide](./PRACTICAL_TESTING_GUIDE.md):** The hands-on "how-to." This guide provides the specific `just` commands, workflows, and debugging tips needed to actually run the test suites. Use this as a day-to-day reference.

## Supporting Documents

These documents provide deeper dives into specific aspects of the MCR testing strategy and framework.

*   **[Test Coverage Analysis](./test_coverage_analysis.md):** A detailed analysis of current Rust code coverage, identifying critical gaps and areas for improvement.
*   **[Test Coverage Improvement Plan](./improvement_plan.md):** A pragmatic, prioritized action plan for systematically increasing test coverage over time.
*   **[Test Framework Proposal](./test_framework_proposal.md):** The strategic proposal for a `just`-based workflow that separates build and test phases, ensuring consistent and reliable test execution.
*   **[Network Namespace Test Framework](./netns_test_framework.md):** The technical plan for implementing the `netns` wrapper script and helpers for Rust integration tests.
