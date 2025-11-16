# Test Framework Proposal: Separating Build and Test Phases

## The Problem

**Current state**: Integration tests that require root privileges are bit-rotting because:
1. They're marked `#[ignore]` so they don't run in CI
2. Running them with `sudo cargo test` uses root's Rust toolchain (different from user's)
3. No consistent, repeatable process for running them
4. They don't get run regularly, so they break
5. Coverage tools can't measure them

## The Solution: Separate Build and Test Phases

### Design Principle
**Build as user, test as root** - Never mix privilege levels during build.

### Proposed Workflow

```bash
# Phase 1: Build (as regular user)
just build-test

# Phase 2: Test - Unit (as regular user)
just test-unit

# Phase 3: Test - Integration (as root)
just test-integration

# Phase 4: Test - E2E (as root)
just test-e2e

# All-in-one
just test-all
```

## Implementation

### 1. Add Justfile Targets

```justfile
# Build all test binaries without running them
build-test:
    cargo test --no-run --all-targets
    cargo build --release --bins

# Run unit tests only (no root required)
test-unit:
    cargo test --lib
    cargo test --bins

# Run integration tests that don't need root
test-integration-light:
    cargo test --test integration

# Run integration tests that need root (uses pre-built binaries)
test-integration-privileged:
    #!/usr/bin/env bash
    set -euo pipefail

    # Find the test binary that was already built
    TEST_BINARY=$(find target/debug/deps -name 'integration-*' -type f -executable | head -1)

    if [ -z "$TEST_BINARY" ]; then
        echo "Error: Test binary not found. Run 'just build-test' first."
        exit 1
    fi

    # Run only the ignored tests with sudo
    sudo -E "$TEST_BINARY" --ignored --test-threads=1

# Run E2E bash tests (requires root)
test-e2e:
    #!/usr/bin/env bash
    set -euo pipefail

    # Ensure binaries are built
    if [ ! -f target/release/multicast_relay ]; then
        echo "Error: Release binaries not found. Run 'just build-test' first."
        exit 1
    fi

    # Run E2E tests
    sudo bash tests/data_plane_e2e.sh

# Run all tests in sequence
test-all: build-test test-unit test-integration-light test-integration-privileged test-e2e

# Coverage (unit + light integration only)
coverage:
    cargo tarpaulin --out html --output-dir coverage

# Coverage with manual E2E validation
coverage-full: coverage test-integration-privileged test-e2e
```

### 2. Fix Integration Test Structure

Create `tests/integration/lib.rs`:
```rust
// Common test utilities
pub mod helpers;

// Test modules - these run without root
pub mod cli;
pub mod log_level_control;
pub mod rule_management;

// Privileged test modules - require root and network namespaces
#[cfg(test)]
mod privileged {
    // These tests are marked #[ignore] by default
    mod supervisor_lifecycle;
    mod multi_worker;
    mod network_namespace;
}
```

### 3. Mark Privileged Tests Consistently

```rust
#[test]
#[ignore = "requires root and network namespaces"]
fn test_supervisor_spawns_workers() {
    // Test supervisor process lifecycle
}

#[test]
#[ignore = "requires root and network namespaces"]
fn test_multi_worker_fanout() {
    // Test multiple data plane workers
}
```

### 4. CI/CD Integration

**GitHub Actions** (example):
```yaml
name: Test

on: [push, pull_request]

jobs:
  test-unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo test --lib
      - run: cargo test --bins

  test-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo test --test integration

  test-privileged:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo test --no-run --all-targets
      - run: |
          TEST_BINARY=$(find target/debug/deps -name 'integration-*' -type f -executable | head -1)
          sudo -E "$TEST_BINARY" --ignored --test-threads=1
```

### 5. Developer Workflow

**Daily development**:
```bash
# Fast feedback loop
just test-unit

# Before committing
just test-all
```

**Weekly/CI**:
```bash
# Full validation including privileged tests
just test-all
```

## Benefits

1. **Separation of concerns**: Build phase doesn't require root
2. **Consistent toolchain**: Same Rust installation for build and test
3. **Repeatable**: Clear commands that work the same every time
4. **CI-friendly**: Can run privileged tests in CI with proper setup
5. **No bit-rot**: Tests run regularly with clear failure messages
6. **Coverage**: Unit tests contribute to coverage, privileged tests validate E2E behavior

## Migration Path

### Week 1: Infrastructure
1. Add justfile targets
2. Verify `just build-test && sudo -E <test-binary> --ignored` works
3. Document in README

### Week 2: Fix Broken Tests
1. Run `just test-integration-privileged`
2. Fix any failures (likely API changes since tests were ignored)
3. Ensure all privileged tests pass

### Week 3: CI Integration
1. Add GitHub Actions workflow
2. Make privileged tests required for merge
3. Add status badge to README

### Week 4: Coverage Strategy
1. Measure unit test coverage: `just coverage` (current 34%)
2. Validate E2E behavior: `just test-integration-privileged`
3. Document that these are complementary, not competitive

## Alternative Considered: Docker

**Approach**: Run all tests in a privileged container
```bash
docker run --rm --privileged -v $(pwd):/work -w /work rust:latest \
  bash -c "cargo test --all"
```

**Pros**: Isolated, reproducible environment
**Cons**:
- Slower (rebuild in container)
- Hides the root/user separation problem
- Doesn't work well with tarpaulin
- Complexity

**Decision**: Use justfile approach for simplicity and speed

## Questions to Resolve

1. **Test parallelism**: Should privileged tests run with `--test-threads=1`? (Probably yes, network namespaces may conflict)
2. **Cleanup**: Who ensures namespace cleanup after test failures?
3. **CI runner**: Do we need self-hosted runners with CAP_NET_ADMIN?
4. **Coverage**: Should we attempt `sudo cargo tarpaulin --include-ignored` or accept separate coverage/validation?

## Recommendation

**Start with justfile approach**. It's simple, explicit, and solves the immediate problem of bit-rot. We can iterate on CI integration later.

**Next steps**:
1. Implement justfile targets
2. Run `just test-integration-privileged` and fix failures
3. Add to daily workflow
4. Document in improvement plan
