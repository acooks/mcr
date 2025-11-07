# justfile for multicast_relay development

# Default recipe, runs when you just type 'just'
default: check

# Run all quality gates, mirroring the CI pipeline
check: fmt clippy build test audit outdated
    @echo "\n✅ All checks passed!"

# Format check
fmt:
    @echo "--- Running Formatting Check (cargo fmt) ---"
    cargo fmt --all -- --check

# Linter check
clippy:
    @echo "--- Running Linter (cargo clippy) ---"
    cargo clippy --all-targets --features integration_test -- -D warnings

# Build the project
build:
    @echo "--- Building Project ---"
    cargo build --all-targets --features integration_test

# Run all tests
test:
    @echo "--- Running Tests (cargo test) ---"
    cargo test --all-targets --features integration_test -- --nocapture

# Security audit
audit:
    @echo "--- Running Security Audit (cargo audit) ---"
    @command -v cargo-audit >/dev/null || cargo install cargo-audit
    cargo audit

# Check for outdated dependencies
outdated:
    @echo "--- Checking for Outdated Dependencies (cargo outdated) ---"
    @command -v cargo-outdated >/dev/null || cargo install cargo-outdated
    cargo outdated --exit-code 1

# Clean the project
clean:
    @echo "--- Cleaning Project ---"
    cargo clean
