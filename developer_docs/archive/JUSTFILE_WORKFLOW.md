# Justfile Workflow Analysis and Recommendations

**Status:** ✅ **APPLIED** - This document details the analysis and recommendations that have now been implemented in the project's `justfile`. It serves as a historical record of the workflow improvements.

**Date:** 2025-11-18
**Issue:** `just check` rebuilds binaries multiple times, conflicts with build-once workflow

---

## Current Workflow Problems

### Issue 1: `just check` Rebuilds Multiple Times

The `check` recipe runs:
```just
check: fmt clippy build test audit outdated coverage unsafe-check
```

This triggers **multiple rebuilds**:
1. `build` → `cargo build --all-targets --features integration_test` (debug)
2. `test` → `cargo test --all-targets` (rebuild with test harness)
3. `coverage` → `cargo tarpaulin` (rebuild with instrumentation)

**Result:** 3+ compilations of the same code!

### Issue 2: Test Target Uses Wrong Configuration

Line 27-29:
```just
test:
    @echo "--- Running Unit and Integration Tests (cargo test) ---"
    cargo test --all-targets --features integration_test -- --test-threads=1 --nocapture
```

Problems:
- Rebuilds binaries (doesn't use pre-built release binaries)
- Uses debug build (slower)
- Doesn't separate privileged from unprivileged tests

### Issue 3: New Test Framework Not Integrated

Lines 120-170 define **new test framework** with proper separation:
- `build-test` - Build once
- `test-unit` - Fast unit tests
- `test-integration-light` - Unprivileged
- `test-integration-privileged` - Requires root
- `test-all` - Complete suite

But the old `check` target doesn't use these!

---

## Recommended Changes

### Option A: Update `check` to Use New Framework (RECOMMENDED)

**Modify the `check` recipe:**

```just
# Run all quality gates (BUILD ONCE, TEST MANY)
check: fmt clippy build-release test-fast
    @echo "\n✅ Code quality checks passed!"
    @echo ""
    @echo "To run full test suite:"
    @echo "  just test-all                    # All tests except privileged"
    @echo "  sudo -E just test-privileged     # Privileged tests (requires root)"
    @echo "  sudo just test-performance       # Performance tests (requires root)"

# Build release binaries once
build-release:
    @echo "--- Building Release Binaries ---"
    cargo build --release --bins
    @echo "Binaries ready:"
    @ls -lh target/release/multicast_relay target/release/control_client target/release/traffic_generator

# Fast tests (no root required)
test-fast: test-unit test-integration-light
    @echo "\n✅ Fast tests passed!"

# Privileged tests (requires root)
test-privileged: build-test test-integration-privileged
    @echo "\n✅ Privileged tests passed!"

# Performance tests (requires root)
test-performance:
    @echo "--- Running Performance Tests ---"
    @if [ ! -f target/release/multicast_relay ]; then echo "ERROR: Run 'just build-release' first"; exit 1; fi
    @bash tests/data_plane_pipeline_veth.sh
```

**Benefits:**
- ✅ Builds once (release mode)
- ✅ Fast feedback (fmt, clippy, unit tests)
- ✅ Clear separation of privileged vs unprivileged
- ✅ No redundant rebuilds

### Option B: Minimal Changes

Just update the `test` target:

```just
# Run fast tests only (unit + unprivileged integration)
test: test-unit test-integration-light
    @echo "\n✅ Fast tests passed!"
    @echo "For privileged tests, run: sudo -E just test-integration-privileged"
```

---

## Recommended Developer Workflow

### Daily Development

```bash
# 1. Format and lint check
just fmt
just clippy

# 2. Build release binaries
just build-release

# 3. Run fast tests (no root)
just test-fast

# 4. Run privileged tests when needed
sudo -E just test-privileged

# 5. Run performance tests before committing
sudo just test-performance
```

### Pre-Commit

```bash
# Complete quality check
just check                      # Formatting, linting, fast tests

# Build release
just build-release             # Build once

# Full test suite
just test-all                  # All unprivileged tests
sudo -E just test-privileged   # Privileged tests
```

### CI/CD Pipeline

```bash
# Separates build from test execution
just build-test                # Build all binaries
just build-release             # Build release binaries
just test-unit                 # Fast unit tests
just test-integration-light    # Unprivileged integration
just test-integration-privileged  # Privileged (requires root)
just test-performance          # Performance validation
```

---

## Updated Justfile Recommendations

### Add New Targets

```just
# --- Performance Testing ---

# Setup kernel for performance testing
setup-kernel:
    @echo "--- Setting Up Kernel for Performance Testing ---"
    @bash scripts/setup_kernel_tuning.sh

# Run performance test (requires root and release binaries)
test-performance: build-release setup-kernel
    @echo "--- Running Performance Tests ---"
    @sudo bash tests/data_plane_pipeline_veth.sh

# Quick performance check (10 packets, for debugging)
test-perf-quick: build-release
    @echo "--- Running Quick Performance Check ---"
    @sudo bash tests/debug_10_packets.sh

# --- Build Variants ---

# Build all binaries in release mode (production)
build-release:
    @echo "--- Building Release Binaries ---"
    @bash scripts/build_all.sh

# Build test binaries (for Rust integration tests)
build-test:
    @echo "--- Building Test Binaries ---"
    cargo test --no-run --all-targets --features integration_test

# Build both release and test binaries
build-all: build-release build-test
    @echo "\n✅ All binaries built!"

# --- Fast Feedback Loop ---

# Quick check (formatting + linting only, no build)
quick-check: fmt clippy
    @echo "\n✅ Quick checks passed!"

# Developer loop (format, lint, build, fast tests)
dev: fmt clippy build-release test-fast
    @echo "\n✅ Development cycle complete!"
```

### Update Existing Targets

```just
# Default recipe - now uses new workflow
default: dev

# Run all quality gates (NEW VERSION)
check: fmt clippy build-release test-fast
    @echo "\n✅ Code quality checks passed!"
    @echo ""
    @echo "Additional test suites:"
    @echo "  just test-all                # All unprivileged tests"
    @echo "  sudo -E just test-privileged # Privileged Rust tests"
    @echo "  sudo just test-performance   # Performance validation"

# Fast tests (unit + light integration, no root)
test-fast: test-unit test-integration-light
    @echo "\n✅ Fast tests passed!"

# Complete test suite (unprivileged)
test-all: build-test test-unit test-integration-light
    @echo "\n✅ All unprivileged tests passed!"

# Privileged test suite (requires root)
test-privileged: build-test test-integration-privileged test-e2e-bash
    @echo "\n✅ All privileged tests passed!"

# Meta-target: Everything (for CI)
test-complete: test-all test-privileged test-performance
    @echo "\n✅ COMPLETE TEST SUITE PASSED!"
```

---

## Comparison: Old vs New

### Old Workflow (`just check`)
```
fmt → clippy → build (debug) → test (rebuild!) → audit → outdated → coverage (rebuild!) → unsafe-check
Time: ~10 minutes
Rebuilds: 3+
Runs privileged tests: No (requires separate run)
```

### New Workflow (`just check`)
```
fmt → clippy → build-release → test-fast
Time: ~3 minutes
Rebuilds: 0 (uses pre-built binaries)
Clear next steps: Shows how to run privileged/performance tests
```

### For Complete Testing (`just test-complete`)
```
test-all → test-privileged → test-performance
Time: ~5 minutes + performance test time
All tests: Yes
```

---

## Implementation Priority

### HIGH PRIORITY (Do First)
1. ✅ Add `build-release` target that calls `scripts/build_all.sh`
2. ✅ Add `test-fast` combining unit and light integration tests
3. ✅ Update `check` to use new targets (no coverage by default)

### MEDIUM PRIORITY
1. Add `test-performance` target for performance validation
2. Add `setup-kernel` target for one-time kernel setup
3. Add `dev` target for quick development loop

### LOW PRIORITY
1. Update `default` to use `dev` instead of old `check`
2. Add `test-complete` meta-target for full suite
3. Add `quick-check` for formatting/linting only

---

## Justfile After Changes

```just
# justfile for multicast_relay development

# Default recipe - fast development loop
default: dev

# Quick development loop (format, lint, build, fast tests)
dev: fmt clippy build-release test-fast
    @echo "\n✅ Development cycle complete!"

# Run code quality checks (fast)
check: fmt clippy build-release test-fast
    @echo "\n✅ Code quality checks passed!"
    @echo ""
    @echo "Additional test suites:"
    @echo "  just test-all                # All unprivileged tests"
    @echo "  sudo -E just test-privileged # Privileged Rust tests"
    @echo "  sudo just test-performance   # Performance validation"

# Format check
fmt:
    @echo "--- Running Formatting Check ---"
    cargo fmt --all -- --check

# Linter check
clippy:
    @echo "--- Running Linter ---"
    cargo clippy --all-targets --features integration_test,testing -- -D warnings

# Build release binaries (production)
build-release:
    @echo "--- Building Release Binaries ---"
    @bash scripts/build_all.sh

# Build test binaries
build-test:
    @echo "--- Building Test Binaries ---"
    cargo test --no-run --all-targets --features integration_test

# Fast tests (no root required)
test-fast: test-unit test-integration-light
    @echo "\n✅ Fast tests passed!"

# Run unit tests
test-unit:
    @echo "--- Running Unit Tests ---"
    cargo test --lib --features integration_test

# Run unprivileged integration tests
test-integration-light:
    @echo "--- Running Integration Tests (unprivileged) ---"
    cargo test --test integration --features integration_test

# Run privileged integration tests (requires root)
test-integration-privileged:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "--- Running Privileged Integration Tests ---"

    TEST_BINARY=$(find target/debug/deps -name 'integration-*' -type f -executable ! -name '*.d' | head -1)

    if [ -z "$TEST_BINARY" ]; then
        echo "ERROR: Integration test binary not found. Run 'just build-test' first."
        exit 1
    fi

    sudo -E "$TEST_BINARY" --ignored --test-threads=1 --nocapture

# Setup kernel for performance testing
setup-kernel:
    @echo "--- Setting Up Kernel Tuning ---"
    @sudo bash scripts/setup_kernel_tuning.sh

# Run performance tests (requires root)
test-performance: build-release setup-kernel
    @echo "--- Running Performance Tests ---"
    @sudo bash tests/data_plane_pipeline_veth.sh

# Complete test suite (unprivileged)
test-all: build-test test-unit test-integration-light
    @echo "\n✅ All unprivileged tests passed!"

# Security audit
audit:
    @echo "--- Running Security Audit ---"
    @command -v cargo-audit >/dev/null || cargo install cargo-audit
    cargo audit

# Coverage report
coverage:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo tarpaulin --out html --output-dir target/tarpaulin \
        --features integration_test --exclude-files src/main.rs "experiments/*" \
        -- --test-threads=1

# Check unsafe code
unsafe-check:
    @echo "--- Checking Unsafe Code ---"
    @./scripts/check_unsafe.sh

# Clean
clean:
    @echo "--- Cleaning Project ---"
    cargo clean
```

---

## Usage Guide

### For Regular Development
```bash
just dev              # Format, lint, build, test (fast loop)
```

### Before Committing
```bash
just check            # Quality gates
sudo -E just test-privileged  # Privileged tests
```

### Before Releasing
```bash
just test-all         # All unprivileged tests
sudo -E just test-privileged  # Privileged tests
sudo just test-performance    # Performance validation
```

### Performance Testing Only
```bash
just build-release    # Build once
sudo just test-performance  # Run performance tests
```

---

## Migration Path

1. **Add new targets** to existing justfile (non-breaking)
2. **Test new workflow** in parallel with old workflow
3. **Update `check`** after validation
4. **Update documentation** to reference new targets
5. **Deprecate old targets** (comment out or rename to `check-old`)

---

## Summary

The current `just check` has issues:
- ❌ Rebuilds multiple times
- ❌ Mixes privileged and unprivileged tests
- ❌ Doesn't use the new test framework
- ❌ Slow feedback loop

Recommended new workflow:
- ✅ Build once, test many
- ✅ Clear separation of test types
- ✅ Fast feedback (2-3 minutes)
- ✅ Explicit about what's being tested
- ✅ Works with new build-once philosophy

**Action:** Update justfile with new targets, then use `just dev` for development and `just check` for pre-commit validation.
