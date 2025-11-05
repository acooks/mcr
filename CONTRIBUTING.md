# Contributing to Multicast Relay

First off, thank you for considering contributing. This project is a high-performance, security-sensitive application, and as such, we adhere to a strict set of coding standards to ensure the code is as correct, readable, and maintainable as possible.

This document outlines the code style, structure, and methods we use to promote good practices.

## Code Style and Structure

We adhere to standard, idiomatic Rust conventions. The primary goal is to write code that is clear, concise, and easy for other developers to understand.

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

-   **Modules, crates, and variables:** `snake_case`
-   **Types (structs, enums, traits):** `PascalCase`
-   **Constants:** `UPPER_SNAKE_CASE`

### Error Handling

For general-purpose error handling where a variety of errors may occur (e.g., in `main.rs` or across I/O boundaries), we use the `anyhow` crate. Use `anyhow::Result<T>` and the `?` operator for concise and effective error propagation.

For specific, well-defined errors within a library component, defining a custom error enum is preferred.

### Dependencies

All dependencies are managed through `Cargo.toml`. When adding a new dependency, please choose it carefully, considering its performance, security implications, and maintenance status.

## Testing

All new features and bug fixes must be accompanied by tests.

-   **Unit Tests:** Should be placed in the same file as the code they are testing, within a `#[cfg(test)]` module.
-   **Integration Tests:** Should be placed in the `tests/` directory.

You can run all tests using:

```bash
cargo test
```

## Enforcement

To ensure all code adheres to these standards, we will implement automated checks:

1.  **CI Pipeline:** A Continuous Integration pipeline will automatically run `cargo fmt --check`, `cargo clippy`, and `cargo test` on every pull request. Pull requests that fail these checks cannot be merged.
2.  **Pre-commit Hooks (Recommended):** It is highly recommended that developers use a pre-commit hook to run these checks locally before they even commit. This provides faster feedback and helps keep the repository history clean.

By following these guidelines, we can build a robust, secure, and maintainable application.
