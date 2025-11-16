# Testing Strategy

This directory contains documentation outlining the high-level testing philosophy and the tiered strategy employed for the Multicast Relay (MCR) project. It guides developers on how to approach, write, and maintain tests across different levels of the application.

*   **[Developer Testing Strategy](./DEVELOPER_TESTING_STRATEGY.md):** An in-depth guide for developers, detailing the unit, integration, and end-to-end testing approaches, along with best practices for contributing tests.

## Test Coverage & Improvement

*   **[Test Coverage Analysis](./test_coverage_analysis.md):** A detailed analysis of current test coverage, identifying critical gaps and areas for improvement across various modules.
*   **[Test Coverage Improvement Plan](./improvement_plan.md):** A pragmatic, prioritized strategy and action plan for systematically increasing test coverage over time.

## Test Framework

*   **[Test Framework Proposal](./test_framework_proposal.md):** A strategic proposal for a `just`-based workflow that separates build and test phases, ensuring consistent and reliable test execution.
*   **[Network Namespace Test Framework](./netns_test_framework.md):** A detailed technical plan for running Rust-based integration tests in isolated network namespaces.