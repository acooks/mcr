# justfile for multicast_relay development

# Default recipe, runs when you just type 'just'
# Fast development loop: format, lint, build release, run fast tests
default: dev

# Quick development loop (recommended for regular use)
dev: fmt clippy build-release test-fast
    @echo "\n✅ Development cycle complete!"
    @echo ""
    @echo "Next steps:"
    @echo "  sudo -E just test-privileged     # Run privileged tests"
    @echo "  sudo just test-performance       # Run performance tests"

# Run code quality checks (fast, no coverage)
check: fmt clippy lint-docs check-links build-release test-fast
    @echo "\n✅ Code quality checks passed!"
    @echo ""
    @echo "Additional test suites:"
    @echo "  just test-all                    # All unprivileged tests"
    @echo "  sudo -E just test-privileged     # Privileged Rust tests"
    @echo "  sudo just test-performance       # Performance validation"
    @echo ""
    @echo "For full CI pipeline: just check-full"

# Run ALL quality gates (slow, includes coverage)
check-full: fmt clippy lint-docs check-links build test audit outdated coverage unsafe-check
    @echo "\n✅ All checks passed (full CI pipeline)!"

# Format check
fmt:
    @echo "--- Running Formatting Check (cargo fmt) ---"
    cargo fmt --all -- --check

# Linter check
clippy:
    @echo "--- Running Linter (cargo clippy) ---"
    cargo clippy --all-targets --features integration_test,testing -- -D warnings

# Lint documentation files
lint-docs:
    @echo "--- Running Documentation Linter (markdownlint) ---"
    @if ! command -v npm &> /dev/null; then \
        echo "Error: npm is not installed."; \
        echo "Please install Node.js and npm to run markdown linting."; \
        exit 1; \
    fi
    npx markdownlint --config .markdownlint.json "**/*.md"

# Auto-fix documentation formatting issues
fix-docs:
    @echo "--- Auto-fixing Documentation Issues ---"
    @if ! command -v npm &> /dev/null; then \
        echo "Error: npm is not installed."; \
        echo "Please install Node.js and npm to run markdown fixing."; \
        exit 1; \
    fi
    npx markdownlint --fix --config .markdownlint.json "**/*.md"
    @echo "✅ Documentation auto-fixed! Review changes with 'git diff'"

# Check for broken links in markdown files
check-links:
    @echo "--- Checking Markdown Links ---"
    @if ! command -v npm &> /dev/null; then \
        echo "Error: npm is not installed."; \
        echo "Please install Node.js and npm to run link checking."; \
        exit 1; \
    fi
    @echo "Checking internal links in documentation..."
    @find . -name "*.md" -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/target/*" | \
        xargs -I {} npx markdown-link-check --config .markdown-link-check.json --quiet {}

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

# --- New Test Framework Targets ---

# Tier 0: Build all application and test binaries (as regular user).
# This is the first step in the testing workflow, separating build from execution.
build-test:
    @echo "--- Building Test Binaries ---"
    cargo test --no-run --all-targets --features integration_test
    cargo build --release --bins

# Tier 1: Run fast, unprivileged unit tests (as regular user).
test-unit:
    @echo "--- Running Unit Tests ---"
    cargo test --lib --features integration_test

# Tier 2 (Part A): Run unprivileged Rust integration tests (as regular user).
test-integration-light:
    @echo "--- Running Integration Tests (non-privileged) ---"
    cargo nextest run --profile default --test integration

# Tier 2 (Part B): Run privileged Rust integration tests (requires root).
# Note: This builds as the current user first, then runs with elevated privileges.
test-integration-privileged:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running Privileged Integration Tests (requires root) ---"
    echo "Building release binaries and test binaries as current user..."
    cargo build --release --bins
    cargo test --test integration --no-run

    # Find the integration test binary
    TEST_BINARY=$(find target/debug/deps -name 'integration-*' -type f -executable ! -name '*.d' | head -1)
    if [ -z "$TEST_BINARY" ]; then
        echo "ERROR: Integration test binary not found"
        exit 1
    fi

    echo "Running privileged tests with sudo..."
    sudo -E "$TEST_BINARY" privileged:: --test-threads=1 --nocapture

# Tier 3: Run a representative E2E Bash script test (requires root).
test-e2e-bash:
    @echo "--- Running Bash E2E Tests (requires root) ---"
    @if [ "$$EUID" -ne 0 ]; then echo "ERROR: Requires root (sudo just test-e2e-bash)"; exit 1; fi
    bash tests/data_plane_e2e.sh

# Meta-Target: Run the complete test suite.
# This is the primary command for contributors to validate changes before a PR.
test-all: build-test test-unit test-integration-light
    @echo "\n✅ Unprivileged test suite complete."
    @echo "To run privileged tests, execute: sudo -E just test-integration-privileged"

# Meta-Target: Run all fast, unprivileged tests.
# This is useful for a quick feedback loop during development.
test-quick: test-unit test-integration-light

# --- Performance Testing (New) ---

# Build release binaries using build script
build-release:
    @echo "--- Building Release Binaries ---"
    @bash scripts/build_all.sh

# Setup kernel tuning for performance testing
setup-kernel:
    @echo "--- Setting Up Kernel Tuning ---"
    @sudo bash scripts/setup_kernel_tuning.sh

# Run performance tests (requires root and release binaries)
test-performance: build-release setup-kernel
    @echo "--- Running Performance Tests ---"
    @sudo bash tests/data_plane_pipeline_veth.sh

# Quick performance check (10 packets, for debugging)
test-perf-quick: build-release
    @echo "--- Running Quick Performance Check ---"
    @sudo bash tests/debug_10_packets.sh

# --- Fast Development Workflow (New) ---

# Fast tests (unit + unprivileged integration)
test-fast: test-unit test-integration-light
    @echo "\n✅ Fast tests passed!"
