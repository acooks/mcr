# justfile for multicast_relay development

# Default recipe, runs when you just type 'just'
default: check

# Run all quality gates, mirroring the CI pipeline
check: fmt clippy build test audit outdated coverage
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
    @echo "--- Running Unit and Integration Tests (cargo test) ---"
    cargo test --all-targets --features integration_test -- --nocapture

# End-to-End Test
test-e2e: build
    @echo "--- Running End-to-End Test ---"
    @# Define socket paths
    @export CONTROL_SOCKET_PATH="/tmp/multicast_relay_control_e2e.sock"
    @export RELAY_COMMAND_SOCKET_PATH="/tmp/mcr_relay_commands_e2e.sock"

    @# Clean up old sockets
    @rm -f $CONTROL_SOCKET_PATH $RELAY_COMMAND_SOCKET_PATH

    @# Start supervisor in the background
    @echo "Starting supervisor..."
    @./target/debug/multicast_relay supervisor --relay-command-socket-path $RELAY_COMMAND_SOCKET_PATH &
    @SUPERVISOR_PID=$!
    @sleep 1 # Give it time to start

    @# Run test sequence
    @echo "Running test sequence..."
    @set -e
    @# Add a rule
    @./target/debug/control_client --socket-path $CONTROL_SOCKET_PATH add --rule-id "e2e-test-rule" --input-interface "lo" --input-group "224.0.0.1" --input-port 5000 --outputs "224.0.0.2:5001:127.0.0.1"
    @# List rules and verify
    @./target/debug/control_client --socket-path $CONTROL_SOCKET_PATH list | grep "e2e-test-rule"
    @# Remove the rule
    @./target/debug/control_client --socket-path $CONTROL_SOCKET_PATH remove --rule-id "e2e-test-rule"
    @# List again and verify removal
    @! ./target/debug/control_client --socket-path $CONTROL_SOCKET_PATH list | grep "e2e-test-rule"
    @set +e

    @# Cleanup
    @echo "Cleaning up supervisor process..."
    @kill $SUPERVISOR_PID
    @wait $SUPERVISOR_PID || true
    @echo "✅ E2E Test Passed!"


# Security audit
audit:
    @echo "--- Running Security Audit (cargo audit) ---"
    @command -v cargo-audit >/dev/null || cargo install cargo-audit
    cargo audit

# Check for outdated dependencies
outdated:
    @echo "--- Checking for Outdated Dependencies (cargo outdated) ---"
    @cargo outdated

# Generate test coverage report
coverage:
    @echo "--- Generating Test Coverage Report (cargo tarpaulin) ---"
    @command -v cargo-tarpaulin >/dev/null || cargo install cargo-tarpaulin --version 0.27.0 --locked
    cargo tarpaulin --out html --output-dir target/tarpaulin --features integration_test --exclude-files src/main.rs "experiments/*"


# Clean the project
clean:
    @echo "--- Cleaning Project ---"
    cargo clean
