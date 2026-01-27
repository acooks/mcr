# justfile for multicast_relay development
#
# Most useful tests require root for network namespaces. This justfile handles
# sudo internally where needed, so you can just run `just <target>`.
#
# Quick reference:
#   just dev  - Fast dev loop (format, lint, build, unit tests) - no root needed
#   just test - All tests with coverage report (calls sudo internally)

# Default recipe
default: dev

# =============================================================================
# DEVELOPMENT WORKFLOW
# =============================================================================

# Quick development loop - format, lint, build, unit tests (no root needed)
dev: fmt clippy build-release test-unit
    @echo ""
    @echo "✅ Development cycle complete!"
    @echo ""
    @echo "Run 'just test' for full test suite (integration tests)"

# Full test suite - all tests with coverage (calls sudo internally)
test: coverage
    @echo ""
    @echo "✅ All tests passed with coverage!"

# =============================================================================
# CODE QUALITY
# =============================================================================

# Check formatting
fmt:
    @echo "--- Checking formatting ---"
    cargo fmt --all -- --check

# Run clippy linter
clippy:
    @echo "--- Running clippy ---"
    cargo clippy --all-targets --features integration_test,testing -- -D warnings

# Lint markdown documentation
lint-docs:
    @echo "--- Linting documentation ---"
    @if ! command -v npm &> /dev/null; then \
        echo "Error: npm not installed"; exit 1; \
    fi
    npx markdownlint --config .markdownlint.json "**/*.md"

# Check markdown links (can be flaky with external URLs)
check-links:
    @echo "--- Checking markdown links ---"
    @if ! command -v npm &> /dev/null; then \
        echo "Error: npm not installed"; exit 1; \
    fi
    @find . -name "*.md" -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/target/*" | \
        xargs -I {} npx markdown-link-check --config .markdown-link-check.json --quiet {}

# Validate Mermaid diagrams
validate-mermaid:
    @node scripts/validate_mermaid.js

# Auto-fix documentation formatting
fix-docs:
    @echo "--- Auto-fixing documentation ---"
    npx markdownlint --fix --config .markdownlint.json "**/*.md"
    @echo "✅ Done. Review changes with 'git diff'"

# Full code quality check (slow)
check: fmt clippy lint-docs check-links validate-mermaid build-release test-unit
    @echo ""
    @echo "✅ Code quality checks passed!"

# =============================================================================
# BUILDING
# =============================================================================

# Build debug binaries
build:
    @echo "--- Building (debug) ---"
    cargo build --all-targets --features integration_test

# Build release binaries
build-release:
    @echo "--- Building (release) ---"
    @bash scripts/build_all.sh

# =============================================================================
# TESTING
# =============================================================================

# Run unit tests only (no root needed)
test-unit:
    @echo "--- Running unit tests (lib + bins) ---"
    cargo test --lib --bins --features integration_test

# Run integration tests (calls sudo internally)
test-integration: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running integration tests ---"

    # Use short stats interval for faster test execution
    export MCR_STATS_INTERVAL_MS=100

    cargo test --test integration --no-run --release 2>/dev/null

    TEST_BINARY=$(find target/release/deps -name 'integration-*' -type f -executable ! -name '*.d' | head -1)
    if [ -z "$TEST_BINARY" ]; then
        echo "ERROR: Integration test binary not found"
        exit 1
    fi

    sudo -E "$TEST_BINARY" --test-threads=1 --nocapture

# Run topology shell script tests (calls sudo internally)
test-topologies: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running topology tests ---"

    # Use short stats interval for faster test execution
    export MCR_STATS_INTERVAL_MS=100

    for test in tests/topologies/*.sh; do
        [ "$(basename "$test")" = "common.sh" ] && continue
        echo ""
        echo "=== Running $(basename "$test") ==="
        sudo -E "$test" || exit 1
    done
    echo ""
    echo "✅ All topology tests passed!"

# Run a specific topology test
test-topology NAME: build-release
    @echo "--- Running {{NAME}} topology test ---"
    @MCR_STATS_INTERVAL_MS=100 sudo -E tests/topologies/{{NAME}}.sh

# Run PIM protocol tests
test-topology-pim: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running PIM protocol tests ---"
    export MCR_STATS_INTERVAL_MS=100
    for test in pim_neighbor pim_join; do
        echo ""
        echo "=== Running $test.sh ==="
        sudo -E tests/topologies/$test.sh || exit 1
    done
    echo ""
    echo "All PIM tests passed!"

# Run MSDP protocol tests
test-topology-msdp: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running MSDP protocol tests ---"
    export MCR_STATS_INTERVAL_MS=100
    for test in msdp_peer msdp_sa; do
        echo ""
        echo "=== Running $test.sh ==="
        sudo -E tests/topologies/$test.sh || exit 1
    done
    echo ""
    echo "All MSDP tests passed!"

# Run all protocol integration tests (PIM + MSDP)
test-topology-protocol: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running protocol integration tests ---"
    export MCR_STATS_INTERVAL_MS=100
    for test in pim_neighbor msdp_peer pim_join msdp_sa protocol_e2e; do
        echo ""
        echo "=== Running $test.sh ==="
        sudo -E tests/topologies/$test.sh || exit 1
    done
    echo ""
    echo "All protocol integration tests passed!"

# Run performance tests (calls sudo internally)
test-performance: build-release
    @echo "--- Running performance tests ---"
    @sudo bash scripts/setup_kernel_tuning.sh
    @sudo bash tests/data_plane_pipeline_veth.sh

# =============================================================================
# COVERAGE
# =============================================================================

# Run all tests with coverage (unit + integration + topology, calls sudo internally)
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== Generating Coverage Report ==="
    echo ""

    # Use short stats interval for faster test execution
    # (default 10s is too slow for tests that validate stats reporting)
    export MCR_STATS_INTERVAL_MS=100

    # Fix permission issues from previous runs
    sudo chown -R "$(whoami):$(whoami)" target/ 2>/dev/null || true

    # Set up instrumentation
    source <(cargo llvm-cov show-env --export-prefix)
    cargo llvm-cov clean --workspace 2>/dev/null || true

    # Use /tmp so privilege-dropped workers can write profile data
    # IMPORTANT: Use the same filename pattern as cargo llvm-cov (mcr-%p-%m.profraw)
    # The pattern must match what 'cargo llvm-cov show-env' outputs, otherwise
    # cargo llvm-cov report won't find the worker profraw files!
    export LLVM_PROFILE_FILE="/tmp/mcr-%p-%m.profraw"
    # Clean up profraw files from previous runs (need sudo for root/nobody-owned files)
    sudo rm -f /tmp/mcr-*.profraw 2>/dev/null || true
    sudo rm -f target/mcr-*.profraw 2>/dev/null || true

    echo "Building instrumented binaries..."
    cargo build --release --all-targets

    echo ""
    echo "Running unit tests (lib + bins)..."
    cargo test --release --lib --bins

    echo ""
    echo "Running integration tests..."
    TEST_BINARY=$(find target/release/deps -name 'integration-*' -type f -executable ! -name '*.d' | head -1)
    if [ -n "$TEST_BINARY" ]; then
        sudo -E LLVM_PROFILE_FILE="$LLVM_PROFILE_FILE" "$TEST_BINARY" --test-threads=1
    fi

    echo ""
    echo "Running topology tests..."
    for test in tests/topologies/*.sh; do
        [ "$(basename "$test")" = "common.sh" ] && continue
        testname="$(basename "$test")"
        echo "  $testname..."
        sudo -E LLVM_PROFILE_FILE="$LLVM_PROFILE_FILE" bash "$test" || exit 1
    done

    # Collect profile data from /tmp (where workers wrote them)
    # Need sudo because files are owned by root (supervisor) and nobody (workers)
    echo ""
    echo "Collecting profile data..."
    sudo cp /tmp/mcr-*.profraw target/ 2>/dev/null || true
    sudo chown "$(whoami):$(whoami)" target/mcr-*.profraw 2>/dev/null || true
    sudo rm -f /tmp/mcr-*.profraw 2>/dev/null || true

    # Remove corrupt profile files (from killed processes that didn't flush)
    # Find llvm-profdata from rustup toolchain or system PATH
    LLVM_PROFDATA=$(find ~/.rustup/toolchains -name llvm-profdata -type f 2>/dev/null | head -1)
    [ -z "$LLVM_PROFDATA" ] && LLVM_PROFDATA=$(command -v llvm-profdata 2>/dev/null || true)

    if [ -n "$LLVM_PROFDATA" ]; then
        echo "Validating profile data..."
        for prof in target/mcr-*.profraw; do
            [ -f "$prof" ] || continue
            if ! "$LLVM_PROFDATA" show "$prof" >/dev/null 2>&1; then
                echo "  Removing corrupt profile: $(basename "$prof")"
                rm -f "$prof"
            fi
        done
    else
        echo "Warning: llvm-profdata not found, skipping profile validation"
    fi

    echo ""
    echo "Generating report..."
    # Exclude experiments/ directory from coverage (not part of the test suite)
    cargo llvm-cov report --release --html --output-dir target/coverage --ignore-filename-regex 'experiments/'

    echo ""
    echo "=== Coverage Summary ==="
    cargo llvm-cov report --release --ignore-filename-regex 'experiments/'

    echo ""
    echo "Report: target/coverage/html/index.html"

# Quick coverage (unit tests only, no root needed)
coverage-quick:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo llvm-cov --lib --html --output-dir target/coverage --ignore-filename-regex 'experiments/'
    echo "Report: target/coverage/html/index.html"

# =============================================================================
# SECURITY & MAINTENANCE
# =============================================================================

# Security audit
audit:
    @echo "--- Security audit ---"
    @command -v cargo-audit >/dev/null || cargo install cargo-audit
    cargo audit

# Check for outdated dependencies
outdated:
    @echo "--- Checking outdated dependencies ---"
    cargo outdated

# Check unsafe code usage
unsafe-check:
    @echo "--- Checking unsafe code ---"
    @./scripts/check_unsafe.sh

# Generate unsafe code report
unsafe-report:
    @echo "--- Generating unsafe code report ---"
    @command -v cargo-geiger >/dev/null || cargo install cargo-geiger
    @cargo geiger --all-features 2>&1 | tee target/geiger-report.txt || true
    @echo "Report: target/geiger-report.txt"

# Clean build artifacts
clean:
    @echo "--- Cleaning ---"
    cargo clean

# =============================================================================
# SETUP
# =============================================================================

# Install git hooks
setup-hooks:
    @echo "--- Installing git hooks ---"
    @cp scripts/pre-commit .git/hooks/pre-commit
    @chmod +x .git/hooks/pre-commit
    @echo "✅ Pre-commit hook installed"

# Setup kernel tuning for performance testing
setup-kernel:
    @echo "--- Setting up kernel tuning ---"
    @sudo bash scripts/setup_kernel_tuning.sh

# =============================================================================
# CAPABILITIES (Run without root)
# =============================================================================

# Set capabilities on release binary (one-time setup)
set-caps: build-release
    @echo "--- Setting capabilities on mcrd ---"
    sudo setcap 'cap_net_raw,cap_setuid,cap_setgid=eip' ./target/release/mcrd
    @getcap ./target/release/mcrd

# Clear capabilities from binary
clear-caps:
    @echo "--- Clearing capabilities ---"
    @sudo setcap -r ./target/release/mcrd 2>/dev/null || true
    @getcap ./target/release/mcrd || echo "(no capabilities set)"

# Build and set capabilities
build-with-caps: build-release set-caps
    @echo "✅ Binary ready to run without sudo"

# Run supervisor with capabilities (no sudo needed after set-caps)
run-caps *ARGS:
    ./target/release/mcrd supervisor {{ARGS}}

# Test that capabilities work (run after set-caps, no sudo needed)
test-caps:
    @./tests/capabilities_test.sh
