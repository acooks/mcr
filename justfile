# justfile for multicast_relay development

# Default recipe, runs when you just type 'just'
# Fast development loop: format, lint, build release, run fast tests
default: dev

# Quick development loop (recommended for regular use)
dev: fmt clippy build-release test-fast
    @echo "\n✅ Development cycle complete!"
    @echo ""
    @echo "Next steps:"
    @echo "  sudo -E just test-integration    # Run integration tests"
    @echo "  sudo just test-performance       # Run performance tests"

# Run code quality checks (fast, no coverage)
check: fmt clippy lint-docs check-links validate-mermaid build-release test-fast
    @echo "\n✅ Code quality checks passed!"
    @echo ""
    @echo "Additional test suites:"
    @echo "  just test-all                    # All unprivileged tests"
    @echo "  sudo -E just test-integration    # Integration tests (requires root)"
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

# Format documentation with prettier (handles tables better)
prettier-docs:
    @echo "--- Formatting Documentation with Prettier ---"
    @if ! command -v prettier &> /dev/null; then \
        echo "Error: prettier is not installed."; \
        echo "Install with: npm install -g prettier"; \
        exit 1; \
    fi
    prettier --write "**/*.md"
    @echo "✅ Documentation formatted with prettier!"

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

# Validate Mermaid diagrams in markdown files
validate-mermaid:
    @node scripts/validate_mermaid.js

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

# Generate test coverage report (all unprivileged tests)
# Uses cargo-llvm-cov for accurate LLVM-based coverage measurement
coverage:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo llvm-cov --all-targets --html --output-dir target/coverage
    echo "Coverage report: target/coverage/html/index.html"

# Generate full coverage report (unit + integration + topology tests, requires root)
# This provides the most accurate coverage by including all test types
coverage-full:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== Full Coverage Report (unit + integration + topology tests) ==="
    echo ""

    # Fix any permission issues from previous runs
    sudo chown -R "$(whoami):$(whoami)" target/ 2>/dev/null || true

    # Set up instrumentation environment
    # shellcheck disable=SC1090
    source <(cargo llvm-cov show-env --export-prefix)
    cargo llvm-cov clean --workspace 2>/dev/null || true

    # Use /tmp for profile files so privilege-dropped workers can write them
    # This fixes "Permission denied" errors from workers running as nobody
    export LLVM_PROFILE_FILE="/tmp/mcr-cov-%p-%m.profraw"
    rm -f /tmp/mcr-cov-*.profraw 2>/dev/null || true

    echo "LLVM_PROFILE_FILE=$LLVM_PROFILE_FILE"
    echo ""

    echo "Step 1: Building instrumented binaries..."
    cargo build --release --all-targets

    echo ""
    echo "Step 2: Running all unprivileged tests..."
    cargo test --release

    echo ""
    echo "Step 3: Running integration tests (requires sudo)..."
    TEST_BINARY=$(find target/release/deps -name 'integration-*' -type f -executable ! -name '*.d' | head -1)
    if [ -z "$TEST_BINARY" ]; then
        echo "ERROR: Integration test binary not found"
        exit 1
    fi
    sudo -E LLVM_PROFILE_FILE="$LLVM_PROFILE_FILE" "$TEST_BINARY" --test-threads=1

    echo ""
    echo "Step 4: Running topology tests (requires sudo)..."
    # Run a subset of topology tests to get coverage of the actual relay binary
    for test in tests/topologies/baseline_test.sh tests/topologies/edge_cases.sh tests/topologies/dynamic_rules.sh; do
        if [ -f "$test" ]; then
            echo "  Running $(basename "$test")..."
            sudo -E LLVM_PROFILE_FILE="$LLVM_PROFILE_FILE" bash "$test" || echo "  Warning: $test had failures"
        fi
    done

    # Copy profile files from /tmp to target/ for cargo llvm-cov to find them
    echo ""
    echo "Step 5: Collecting profile data..."
    cp /tmp/mcr-cov-*.profraw target/ 2>/dev/null || true
    PROFILE_COUNT=$(ls -1 target/mcr-cov-*.profraw 2>/dev/null | wc -l)
    echo "  Collected $PROFILE_COUNT profile files"
    rm -f /tmp/mcr-cov-*.profraw 2>/dev/null || true

    echo ""
    echo "Step 6: Generating coverage report..."
    cargo llvm-cov report --release --html --output-dir target/coverage-full

    echo ""
    echo "=== Coverage Summary ==="
    cargo llvm-cov report --release

    echo ""
    echo "Full coverage report: target/coverage-full/html/index.html"

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

# Tier 2: Run integration tests (requires root for network namespace isolation).
# Note: This builds as the current user first, then runs with elevated privileges.
# Integration tests create network namespaces and veth pairs, requiring CAP_NET_ADMIN.
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running Integration Tests (requires root) ---"
    echo "Building release binaries and test binaries as current user..."
    cargo build --release --bins
    cargo test --test integration --no-run --release

    # Find the integration test binary
    TEST_BINARY=$(find target/release/deps -name 'integration-*' -type f -executable ! -name '*.d' | head -1)
    if [ -z "$TEST_BINARY" ]; then
        echo "ERROR: Integration test binary not found"
        exit 1
    fi

    echo "Running integration tests with sudo (network namespaces require root)..."
    sudo -E "$TEST_BINARY" --test-threads=1 --nocapture

# Alias for backward compatibility
test-integration-privileged: test-integration

# Note: test-integration-light removed - all integration tests require root for network namespaces

# Tier 3: Run a representative E2E Bash script test (requires root).
test-e2e-bash:
    @echo "--- Running Bash E2E Tests (requires root) ---"
    @if [ "$$EUID" -ne 0 ]; then echo "ERROR: Requires root (sudo just test-e2e-bash)"; exit 1; fi
    bash tests/data_plane_e2e.sh

# Meta-Target: Run the complete unprivileged test suite.
# This is the primary command for contributors to validate changes before a PR.
test-all: build-test test-unit
    @echo "\n✅ Unprivileged test suite complete."
    @echo "To run integration tests (requires root), execute: sudo -E just test-integration"

# Meta-Target: Run all fast, unprivileged tests.
# This is useful for a quick feedback loop during development.
test-quick: test-unit

# --- Performance Testing (New) ---

# Build release binaries using build script
build-release:
    @echo "--- Building Release Binaries ---"
    @bash scripts/build_all.sh

# Install git hooks for development
setup-hooks:
    @echo "--- Installing Git Hooks ---"
    @cp scripts/pre-commit .git/hooks/pre-commit
    @chmod +x .git/hooks/pre-commit
    @echo "Pre-commit hook installed!"

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

# Fast tests (unit tests only - integration tests require root)
test-fast: test-unit
    @echo "\n✅ Fast tests passed!"
    @echo "To run integration tests (requires root), execute: sudo -E just test-integration"
