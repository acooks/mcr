# Contributing to Multicast Relay

First off, thank you for considering contributing. This document is the rulebook for all contributions, outlining the standards, procedures, and quality gates that all code changes must adhere to. This project is a high-performance, security-sensitive application, and as such, we adhere to a strict set of coding standards to ensure the code is as correct, readable, and maintainable as possible.

This document outlines the code style, structure, and methods we use to promote good practices.

## Core Development Principles

Beyond the mechanical checks for formatting and linting, this project adheres to a set of core principles to ensure the final application is readable, maintainable, and robust.

1. **Simplicity and Linearity in the Fast Path:** The data plane code that processes packets must be as simple and linear as possible. It must be non-blocking, avoid dynamic memory allocation, and handle all transient errors with a "Drop and Count" strategy (D26).

2. **Strict Separation of Concerns:** The roles of the Supervisor and Data Plane workers are distinct and must not be blurred. The Supervisor manages lifecycles, privileged operations, and user interaction via the control socket. The Data Plane only processes packets.

3. **State is Centralized and Explicit:** The Supervisor is the single source of truth for configuration (D18). Data plane workers operate on replicated state and never modify their own configuration based on the data they process.

4. **Observability is a First-Class Feature:** Every significant event, especially packet drops, must be counted and exposed as a metric (D27). The state of all critical resources (e.g., buffer pools) must be observable.

5. **Panic is Not an Error Handling Strategy:** The data plane must be panic-free. All functions must be total, handling every possible input and error condition gracefully (typically via "Drop and Count").

6. **Comments Explain "Why," Not "What":** The code should be self-evident in what it does. Comments must provide the context and reasoning that the code cannot, such as performance trade-offs or links to specific design decisions.

## Code Style and Structure

We adhere to standard, idiomatic Rust conventions. The primary goal is to write code that is clear, concise, and easy for other developers to understand.

### Module Structure

The project's module structure directly mirrors the multi-process architecture to ensure a clear separation of concerns.

- **`main.rs` (Binary Entry Point):** Responsible only for parsing arguments, initializing the environment, and launching the Supervisor Process.
- **`supervisor.rs`:** Contains all logic for the privileged Supervisor Process, including lifecycle management of worker processes, privileged operations, control socket handling, and network interface changes.
- **`worker/`:** Contains all logic for the unprivileged Data Plane Worker Processes. This is the performance-critical "hot path" for packet processing.
- **`lib.rs` (Shared Library Crate):** Defines all shared data structures, types, and constants used across the different processes (e.g., `ForwardingRule`, `Command`, `Response`).

This layout makes the codebase easier to navigate and reinforces the architectural separation of concerns.

### Formatting

All Rust code in this repository is formatted using `rustfmt`. Before committing any changes, please ensure your code is formatted by running:

```bash
cargo fmt
```

A formatting check is run in our CI pipeline, and any pull request with formatting errors will be rejected.

### Linting and Static Analysis

We use `clippy` to catch common mistakes and improve the quality of our code. We enforce a high standard by treating all warnings as errors. Before committing, please ensure `clippy` runs without any warnings:

```bash
cargo clippy --all-targets -- -D warnings
```

This command will run `clippy` on all targets (the library, binaries, tests, etc.) and deny (`-D`) any warnings, effectively treating them as build errors.

### Naming Conventions

We follow the official [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/naming.html) for all naming conventions. In summary:

- **Modules, crates, and variables:** `snake_case`
- **Types (structs, enums, traits):** `PascalCase`
- **Constants:** `UPPER_SNAKE_CASE`

### Error Handling

For general-purpose error handling where a variety of errors may occur (e.g., in `main.rs` or across I/O boundaries), we use the `anyhow` crate. Use `anyhow::Result<T>` and the `?` operator for concise and effective error propagation.

For specific, well-defined errors within a library component, defining a custom error enum is preferred.

### Dependencies

All dependencies are managed through `Cargo.toml`. When adding a new dependency, please choose it carefully, considering its performance, security implications, and maintenance status.

## Developer Environment and Compatibility

This project does not prescribe specific developer environment setups or pin exact package versions beyond what is strictly necessary for `Cargo.toml`. Developers are free to configure their environments as they see fit. Compatibility issues that arise due to environment differences or dependency versions will be addressed on a case-by-case basis, either by fixing bugs or explicitly identifying compatibility requirements.

## Local Development Workflow

This project uses `just` as its command runner. The workflow is simple:

### Quick Feedback (No Root)

```bash
just dev
```

Runs format check, linter, build, and unit tests. Use this for fast iteration.

### Full Test Suite (Before Commit)

```bash
just test
```

Runs **all** tests with coverage:

- Unit tests
- Integration tests (network namespaces)
- Topology tests (payload integrity, scaling, etc.)
- Generates coverage report at `target/coverage/html/index.html`

This command handles `sudo` internally - you don't need to think about privileges.

For the full command reference, see [`JUSTFILE_QUICK_REFERENCE.md`](JUSTFILE_QUICK_REFERENCE.md).

## Enforcement

All code must pass automated checks before merging:

1. **CI Pipeline:** GitHub Actions runs `just test` on every pull request. This includes all tests and coverage. Pull requests that fail cannot be merged.
2. **Pre-commit Hook:** Install with `just setup-hooks`. This runs format check, linter, and unit tests before each commit, providing fast local feedback.

By following these guidelines, we can build a robust, secure, and maintainable application.
