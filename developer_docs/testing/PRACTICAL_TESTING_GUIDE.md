# A Practical Guide to Testing MCR

**Status:** ✅ CURRENT
**Last Updated:** 2025-11-18

---

This is the comprehensive guide to testing the Multicast Relay (MCR) application. It covers our testing philosophy, the different types of tests, and the practical commands you'll use every day.

## 1. Our Testing Philosophy

Testing a high-performance, low-level networking application is challenging. Our code requires elevated privileges, depends on the Linux kernel, and involves multiple asynchronous processes. To manage this complexity, we adhere to a strict, tiered testing strategy that is mandatory for all contributions.

Our goal is to ensure that every part of the application—from pure business logic to high-performance data flow—is tested in an appropriate, isolated, and reliable manner.

## 2. The Tiered Testing Strategy

We use a three-tiered strategy to test different aspects of the application. All tests are orchestrated via the `just` command runner.

### Tier 1: Unit Tests

- **Purpose:** To test pure, internal business logic in isolation, without requiring privileges or a specific kernel environment.
- **Scope:** Protocol serialization, state management, statistics logic, buffer pool management, and packet header parsing.
- **Command:** `just test-unit`

### Tier 2: Rust Integration Tests

- **Purpose:** To test the interaction between MCR's Rust components. These are divided into unprivileged and privileged tests.
- **Scope:**
- Control interface functionality (`control_client` -> `supervisor`).
- Supervisor/worker process lifecycle.
- Behavior in isolated network namespaces (privileged only).
- **Commands:**
- `just test-integration-light` (for unprivileged tests)
- `sudo -E just test-integration-privileged` (for privileged tests)

### Tier 3: E2E (End-to-End) Bash Tests

- **Purpose:** To validate the final, compiled **release binaries** under realistic network conditions.
- **Scope:** Packet forwarding correctness, performance benchmarks, and complex multi-hop topologies.
- **Commands:**
- `sudo just test-e2e-bash`
- `sudo just test-performance`

## 3. The "Build Once, Test Many" Workflow

Our testing framework is built on a core principle: **build as a regular user, test as root**. We separate the build and test phases to ensure consistency and avoid toolchain conflicts that can arise when building with `sudo`.

The `justfile` orchestrates this workflow.

### Core Commands

- **`just build-release` / `just build-test`**: Builds the release or test binaries as your current user.
- **`just test-fast`**: The most common command for daily development. It runs all fast, unprivileged tests (unit and integration-light).
- **`just check`**: The primary quality gate. It formats, lints, builds, and runs `test-fast`.
- **`sudo -E just test-privileged`**: Runs the full suite of privileged tests, including Rust integration tests and E2E bash scripts. The `-E` flag is critical to preserve the user's environment variables.

For a complete list of commands, see the **[Justfile Quick Reference](../JUSTFILE_QUICK_REFERENCE.md)**.

## 4. How Privileged Tests Work: Network Namespaces

To run tests that require root privileges without interfering with the host system's network, we use **isolated Linux network namespaces**.

### The Wrapper Script

A key component of our framework is the `scripts/run-tests-in-netns.sh` script. This script automates the process:

1. **Creates a unique network namespace.**
2. Sets up the loopback interface within the namespace.
3. Executes the pre-compiled Rust test binary inside the namespace with `sudo -E ip netns exec ...`.
4. **Automatically cleans up** the namespace when the test completes, even if it fails.

### Running Privileged Tests

The `just test-integration-privileged` command handles this for you. It finds the compiled test binary and executes it using the network namespace wrapper script.

This ensures that privileged tests are:

- **Isolated:** They cannot interfere with your local network.
- **Repeatable:** They run in a clean, consistent environment every time.
- **CI-Friendly:** This approach works reliably in automated CI/CD pipelines.

### Debugging E2E Tests

To debug a specific E2E test, you can run the script directly. This is useful for inspecting logs or testing changes.

```bash
# Run a specific test with sudo
sudo ./tests/debug_10_packets.sh
```

When writing or debugging these scripts, pay close attention to the patterns for waiting for MCR to start and ensuring a graceful shutdown, as detailed in the original `PRACTICAL_TESTING_GUIDE.md`.

---

## 5. Known Gaps and Future Improvements

Our test suite is continuously evolving. Based on `TODO` comments in the source code, here are some known areas where coverage could be improved:

- **Performance Benchmarks:** The benchmark tests in `tests/benchmarks/` are currently stubs and need to be fully implemented to provide meaningful performance metrics for forwarding rate, latency, and control interface operations.
- **Rule Removal E2E Test:** The E2E test suite is missing a test case to validate the removal of forwarding rules via the `control_client`.
- **Supervisor Resilience:** While some resilience is tested, more complex failure scenarios (e.g., worker crash loops) could be added to the integration test suite.
