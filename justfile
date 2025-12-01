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
    @echo "--- Running unit tests ---"
    cargo test --lib --features integration_test

# Run integration tests (calls sudo internally)
test-integration: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running integration tests ---"
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
    @sudo -E tests/topologies/{{NAME}}.sh

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

    # Fix permission issues from previous runs
    sudo chown -R "$(whoami):$(whoami)" target/ 2>/dev/null || true

    # Set up instrumentation
    source <(cargo llvm-cov show-env --export-prefix)
    cargo llvm-cov clean --workspace 2>/dev/null || true

    # Use /tmp so privilege-dropped workers can write profile data
    export LLVM_PROFILE_FILE="/tmp/mcr-cov-%p-%m.profraw"
    rm -f /tmp/mcr-cov-*.profraw 2>/dev/null || true

    echo "Building instrumented binaries..."
    cargo build --release --all-targets

    echo ""
    echo "Running unit tests..."
    cargo test --release --lib

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
        echo "  $(basename "$test")..."
        sudo -E LLVM_PROFILE_FILE="$LLVM_PROFILE_FILE" bash "$test" || exit 1
    done

    # Collect profile data
    echo ""
    echo "Collecting profile data..."
    cp /tmp/mcr-cov-*.profraw target/ 2>/dev/null || true
    rm -f /tmp/mcr-cov-*.profraw 2>/dev/null || true

    echo ""
    echo "Generating report..."
    cargo llvm-cov report --release --html --output-dir target/coverage

    echo ""
    echo "=== Coverage Summary ==="
    cargo llvm-cov report --release

    echo ""
    echo "Report: target/coverage/html/index.html"

# Quick coverage (unit tests only, no root needed)
coverage-quick:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo llvm-cov --lib --html --output-dir target/coverage
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
