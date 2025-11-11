# justfile for multicast_relay development

# Default recipe, runs when you just type 'just'
default: check

# Run all quality gates, mirroring the CI pipeline
check: fmt clippy build test audit outdated coverage unsafe-check
    @echo "\n✅ All checks passed!"

# Format check
fmt:
    @echo "--- Running Formatting Check (cargo fmt) ---"
    cargo fmt --all -- --check

# Linter check
clippy:
    @echo "--- Running Linter (cargo clippy) ---"
    cargo clippy --all-targets --features integration_test,testing -- -D warnings

# Build the project
build:
    @echo "--- Building Project ---"
    cargo build --all-targets --features integration_test

# Run all tests
# Note: Tests run sequentially (--test-threads=1) due to supervisor test socket contention
test:
    @echo "--- Running Unit and Integration Tests (cargo test) ---"
    cargo test --all-targets --features integration_test -- --test-threads=1 --nocapture

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

# Run topology tests (requires root for network namespace isolation)
test-topologies:
    @echo "--- Running Topology Integration Tests ---"
    @if [ "$EUID" -ne 0 ]; then echo "ERROR: Requires root (sudo just test-topologies)"; exit 1; fi
    @for test in tests/topologies/*.sh; do \
        [ "$$test" = "tests/topologies/common.sh" ] && continue; \
        echo "\n=== Running $$(basename $$test) ==="; \
        "$$test" || exit 1; \
    done
    @echo "\n✅ All topology tests passed!"

# Run specific topology test (requires root)
test-topology TEST:
    @echo "--- Running {{TEST}} Topology Test ---"
    @if [ "$EUID" -ne 0 ]; then echo "ERROR: Requires root (sudo just test-topology {{TEST}})"; exit 1; fi
    @sudo tests/topologies/{{TEST}}.sh

# Generate test coverage report
# Note: Tests run sequentially (--test-threads=1) due to supervisor test socket contention
coverage:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo tarpaulin --out html --output-dir target/tarpaulin --features integration_test --exclude-files src/main.rs "experiments/*" -- --test-threads=1


# Check unsafe code usage
unsafe-check:
    @echo "--- Checking Unsafe Code Usage ---"
    @./scripts/check_unsafe.sh

# Generate detailed unsafe code report (runs cargo-geiger)
unsafe-report:
    @echo "--- Generating Unsafe Code Report (cargo-geiger) ---"
    @command -v cargo-geiger >/dev/null || cargo install cargo-geiger
    @cargo geiger --all-features 2>&1 | tee target/geiger-report.txt || true
    @echo "Report saved to target/geiger-report.txt"

# Clean the project
clean:
    @echo "--- Cleaning Project ---"
    cargo clean
