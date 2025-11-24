# Build Consistency Issues and Solutions

**Date:** 2025-11-18
**Status:** Active Issue

---

## Problem Statement

When running tests, Cargo rebuilds the project with different compile-time configurations, resulting in:
1. Multiple binaries with different feature flags
2. Stale binaries in different target directories
3. Confusion about which binary is actually being tested
4. Wasted time recompiling

---

## Root Causes Identified

### 1. Test vs Non-Test Builds

**Issue:** `cargo test` and `cargo build` create different compilation units:
- `cargo build --release` → `target/release/multicast_relay`
- `cargo test --release` → `target/release/deps/multicast_relay-<hash>` + test harness

Even though your integration tests use `binary_path()` to find release binaries, running `cargo test` triggers dependency recompilation.

### 2. Shell Scripts Triggering Rebuilds

Found in `tests/*.sh`:
```bash
# These all trigger rebuilds:
tests/data_plane_debug.sh:            cargo build --release
tests/data_plane_e2e.sh:              cargo build          # ← DEBUG BUILD!
tests/data_plane_performance.sh:      cargo build --release
tests/data_plane_pipeline.sh:         cargo build --release
tests/data_plane_pipeline_veth.sh:    cargo build --release
tests/debug_10_packets.sh:            cargo build --release --quiet
tests/scaling_test.sh:                cargo build --release --quiet
```

**Problem:** Each script independently rebuilds, and `data_plane_e2e.sh` builds in DEBUG mode!

### 3. Feature Flags

Your `Cargo.toml` has:
```toml
[features]
integration_test = []
testing = []
```

These features aren't currently being used inconsistently, but they could cause issues if test code conditionally compiles different logic.

### 4. Dev-Dependencies

Test compilation includes all `[dev-dependencies]`:
```toml
[dev-dependencies]
proptest = "1.9.0"
rusty-fork = "0.3.1"
tempfile = "3.23.0"
# ... etc
```

These dependencies can cause different feature resolution in the dependency tree.

---

## Current Workflow Problems

### Scenario 1: Run Integration Test
```bash
cargo test --release test_single_hop_1000_packets
# → Recompiles with test harness
# → Binary is in target/release/deps/
# → Test finds target/release/multicast_relay (may be stale!)
```

### Scenario 2: Run Shell Script Test
```bash
sudo tests/data_plane_pipeline_veth.sh
# → Runs "cargo build --release" internally
# → May recompile if cargo test was run before
# → Uses target/release/multicast_relay
```

### Scenario 3: Mixed Testing
```bash
cargo build --release --bins          # Build 1
cargo test --release                  # Build 2 (recompiles!)
sudo tests/data_plane_pipeline_veth.sh  # Build 3 (may recompile!)
```

Result: Three compilations, confusion about which binary is tested.

---

## Solutions

### Solution 1: Build Once, Test Many (RECOMMENDED)

Create a single "build everything" script:

**File:** `scripts/build_all.sh`
```bash
#!/bin/bash
set -e

echo "=== Building all binaries in release mode ==="
cargo build --release --bins

echo ""
echo "=== Build complete ==="
ls -lh target/release/multicast_relay
ls -lh target/release/control_client
ls -lh target/release/traffic_generator
echo ""
echo "Binaries ready in: target/release/"
echo "Run tests with: ./scripts/run_tests.sh"
```

**File:** `scripts/run_tests.sh`
```bash
#!/bin/bash
set -e

# Ensure binaries are built
if [ ! -f target/release/multicast_relay ]; then
    echo "ERROR: Binaries not found. Run: ./scripts/build_all.sh"
    exit 1
fi

echo "=== Running integration tests (with pre-built binaries) ==="
cargo test --release --no-fail-fast -- --test-threads=1 --ignored

echo ""
echo "=== Running shell script tests ==="
sudo tests/data_plane_pipeline_veth.sh
```

Then modify shell scripts to skip building:

**In each `tests/*.sh` file:**
```bash
# OLD:
# cargo build --release

# NEW:
if [ ! -f "$RELAY_BINARY" ]; then
    echo "ERROR: Binary not found at $RELAY_BINARY"
    echo "Run: cargo build --release --bins"
    exit 1
fi

echo "Using binary: $RELAY_BINARY ($(stat -c%s $RELAY_BINARY) bytes, built $(stat -c%y $RELAY_BINARY))"
```

### Solution 2: Consistent Build Commands

**Create `.cargo/config.toml`:**
```toml
[alias]
# Build all binaries in release mode
build-all = "build --release --bins"

# Run integration tests (assumes binaries are pre-built)
test-integration = "test --release --test integration -- --ignored --test-threads=1"

# Clean and rebuild everything
rebuild = "clean && build --release --bins"
```

**Usage:**
```bash
cargo build-all              # Build once
cargo test-integration       # Run Rust tests
sudo tests/*.sh              # Run shell tests (no rebuild)
```

### Solution 3: Makefile (Traditional Approach)

**File:** `Makefile`
```makefile
.PHONY: all build test clean

CARGO := cargo
RELEASE_DIR := target/release
BINARIES := multicast_relay control_client traffic_generator

all: build

build:
    $(CARGO) build --release --bins
    @echo ""
    @echo "=== Binaries built ==="
    @ls -lh $(RELEASE_DIR)/multicast_relay
    @ls -lh $(RELEASE_DIR)/control_client
    @ls -lh $(RELEASE_DIR)/traffic_generator

test: build
    @echo "=== Running integration tests ==="
    $(CARGO) test --release --no-fail-fast -- --test-threads=1 --ignored

test-shell: build
    @echo "=== Running shell tests ==="
    sudo tests/data_plane_pipeline_veth.sh

test-all: test test-shell

clean:
    $(CARGO) clean
    rm -f /tmp/mcr_*.sock /tmp/mcr_*.log

rebuild: clean build
```

**Usage:**
```bash
make build           # Build once
make test            # Rust integration tests
make test-shell      # Shell tests
make test-all        # All tests
```

### Solution 4: Just File (Modern Approach)

Create `justfile`:
```just
# Build all binaries
build:
    cargo build --release --bins
    @echo ""
    @echo "Binaries ready:"
    @ls -lh target/release/multicast_relay

# Run Rust integration tests
test-rust:
    cargo test --release --no-fail-fast -- --test-threads=1 --ignored

# Run shell tests
test-shell:
    #!/bin/bash
    set -e
    sudo tests/data_plane_pipeline_veth.sh

# Run all tests
test-all: build test-rust test-shell

# Clean and rebuild
rebuild:
    cargo clean
    just build

# Show binary info
info:
    @echo "=== Binary Information ==="
    @stat target/release/multicast_relay 2>/dev/null || echo "Not built"
    @echo ""
    @md5sum target/release/multicast_relay 2>/dev/null || true
```

**Usage:**
```bash
just build           # Build once
just test-rust       # Rust tests
just test-shell      # Shell tests
just test-all        # All tests
```

---

## Recommended Workflow

### For Development
```bash
# 1. Build once
cargo build --release --bins

# 2. Run specific test
cargo test --release test_single_hop_1000_packets -- --ignored --nocapture

# 3. Run performance test
sudo tests/data_plane_pipeline_veth.sh

# 4. If you change code, rebuild
cargo build --release --bins
```

### For CI/CD
```bash
# Single build step
cargo build --release --bins

# Run all tests with pre-built binaries
cargo test --release -- --ignored --test-threads=1
sudo tests/data_plane_pipeline_veth.sh
```

---

## Modifications Required

### 1. Update Shell Scripts

**Pattern to add at the top of each `tests/*.sh`:**
```bash
# Check for required binaries
check_binary() {
    local binary="$1"
    if [ ! -f "$binary" ]; then
        echo "ERROR: Binary not found: $binary"
        echo "Build with: cargo build --release --bins"
        exit 1
    fi
    echo "Using: $binary (built $(stat -c%y "$binary"))"
}

check_binary "$RELAY_BINARY"
check_binary "$CONTROL_CLIENT_BINARY"
check_binary "$TRAFFIC_GENERATOR_BINARY"

# Remove any "cargo build" lines
```

### 2. Update Integration Test Helper

**In `tests/integration/common/mod.rs`:**
```rust
/// Get the path to a compiled binary
pub fn binary_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("release");
    path.push(name);

    if !path.exists() {
        panic!(
            "Binary '{}' not found at {:?}.\n\
             Build with: cargo build --release --bins\n\
             DO NOT run 'cargo test' without building first!",
            name, path
        );
    }

    // Warn if binary is old
    if let Ok(metadata) = std::fs::metadata(&path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() > 3600 {  // 1 hour
                    eprintln!(
                        "WARNING: Binary '{}' is {} minutes old. Consider rebuilding.",
                        name,
                        elapsed.as_secs() / 60
                    );
                }
            }
        }
    }

    path
}
```

### 3. Document in README

Add to `README.md`:
```markdown
## Testing

### Build Once
```bash
cargo build --release --bins
```

### Run Tests
```bash
# Rust integration tests
cargo test --release -- --ignored --test-threads=1

# Shell script tests (requires root)
sudo tests/data_plane_pipeline_veth.sh
```

**Important:** Always build with `cargo build --release --bins` before running tests.
Do NOT rely on `cargo test` to build binaries - it creates test harness builds.

---

## Verification

After implementing Solution 1:

```bash
# Clean slate
cargo clean

# Build once
time cargo build --release --bins
# Should take ~2 minutes

# Run test 1 - should NOT rebuild
time cargo test --release test_single_hop_1000_packets -- --ignored
# Should be fast (seconds)

# Run test 2 - should NOT rebuild
time sudo tests/data_plane_pipeline_veth.sh
# Should use existing binary

# Verify no recompilation occurred
ls -lh target/release/multicast_relay
# Timestamp should be from first build
```

---

## Root Cause: Why Cargo Rebuilds

Cargo rebuilds when:
1. **Different profiles**: `--release` vs debug
2. **Different features**: `--features testing` changes compilation
3. **Test harness**: `cargo test` adds test runtime
4. **Dependency changes**: Even benign changes trigger rebuilds
5. **Timestamp changes**: Touching source files invalidates cache

**The only reliable solution:** Build binaries once with `cargo build --release --bins`, then use those binaries for all testing.

---

## Implementation Priority

**HIGH PRIORITY:**
1. Modify all shell scripts to check for binaries instead of building
2. Add warning in `binary_path()` for stale binaries
3. Document workflow in README

**MEDIUM PRIORITY:**
4. Create `scripts/build_all.sh` and `scripts/run_tests.sh`
5. Add Makefile or justfile

**LOW PRIORITY:**
6. Add CI checks to ensure consistent builds
7. Consider binary caching strategies
