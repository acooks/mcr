# Developer Documentation

This directory contains all documentation relevant to contributors and developers working on the Multicast Relay (MCR) project.

## Core Documents

*   **[ARCHITECTURE.md](./ARCHITECTURE.md):** The definitive, up-to-date guide to the system's design, including the unified `io_uring` data plane and supervisor-worker model. This is the source of truth for the current architecture.
*   **[DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md):** A comprehensive guide to setting up your development environment and understanding the core development workflow.
*   **[CONTRIBUTING.md](./CONTRIBUTING.md):** The guide for new contributors, covering development standards, testing requirements, and the pull request process.

## Build & Testing

*   **[BUILD_CONSISTency.md](./BUILD_CONSISTENCY.md):** Explains how to achieve consistent builds and avoid common recompilation issues.
*   **[Testing Strategy](./testing/README.md):** The high-level philosophy and tiered strategy guiding how we test MCR.
*   **[Practical Testing Guide](./testing/PRACTICAL_TESTING_GUIDE.md):** A hands-on 'how-to' guide for running the various test suites.

## Design & Reports

*   **[Design Documents](./design/README.md):** Detailed design specifications for various MCR subsystems.
*   **[Reports](./reports/README.md):** A collection of summary reports for major investigations and architectural decisions.
    *   **[Performance Regression & Fix Summary (Nov 2025)](./reports/PERFORMANCE_REGRESSION_FIX_SUMMARY_Nov2025.md):** A summary of the successful investigation and resolution of a critical performance regression.
    *   **[Multi-Stream Scaling Report](./reports/MULTI_STREAM_SCALING_REPORT.md):** Report on scaling issues with the previous data plane model.

## Policies & Comparisons

*   **[Policies](./policies/README.md):** Important policy documents governing development, such as our **[Unsafe Code Policy](./policies/UNSAFE_CODE_POLICY.md)**.
*   **[Comparisons](./comparisons/README.md):** Analysis and comparison of MCR with other networking tools, like **[MCR vs. socat](./comparisons/MCR_vs_socat.md)**.

## Archive (Historical Documents)

For detailed historical reports, outdated plans, and previous architectural documents, please see the **[Archive](./archive/)**. This includes the original day-by-day reports from the November 2025 performance investigation.