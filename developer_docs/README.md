# Developer Documentation

This directory contains all documentation relevant to contributors and developers working on the Multicast Relay (MCR) project.

## 1. Getting Started

If you are a new contributor, start here.

- **[DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md):** How to set up your development environment and the core workflow.
- **[CONTRIBUTING.md](./CONTRIBUTING.md):** The standards, procedures, and quality gates for all contributions.

## 2. Core Architecture

Understand how MCR is designed.

- **[ARCHITECTURE.md](./ARCHITECTURE.md):** The definitive guide to the system's design, components, and data flow.
- **[design/](../design/):** Active design specifications for MCR subsystems.
- **[design/archive/](../design/archive/):** Historical design research and analysis (e.g., ringbuffer implementation research).

## 3. Development & Testing

Guides for the day-to-day development process.

- **[BUILD_CONSISTENCY.md](./BUILD_CONSISTENCY.md):** How to achieve consistent builds and avoid recompilation issues.
- **[JUSTFILE_QUICK_REFERENCE.md](./JUSTFILE_QUICK_REFERENCE.md):** A quick reference for all `just` commands.
- **[testing/README.md](./testing/README.md):** The high-level testing strategy and philosophy.
- **[testing/PRACTICAL_TESTING_GUIDE.md](./testing/PRACTICAL_TESTING_GUIDE.md):** A hands-on guide for running the various test suites.

## 4. Reference & Reports

Deeper dives into specific topics, policies, and historical analysis.

- **[policies/README.md](./policies/README.md):** Important policy documents, like our **[Unsafe Code Policy](./policies/UNSAFE_CODE_POLICY.md)**.
- **[reports/README.md](./reports/README.md):** Summary reports from major investigations and decisions.
- **[comparisons/README.md](./comparisons/README.md):** Analysis and comparison of MCR with other networking tools.
- **[reference_docs/](./reference_docs/):** Detailed investigation archives and completed implementation plans (see [completed/](./reference_docs/completed/) and [experiments/](./reference_docs/experiments/))
- **[plans/](./plans/):** Implementation plans for upcoming features and improvements.
