# Testing Guide

## Quick Start

### 1. Build Once
```bash
./scripts/build_all.sh
# or manually:
cargo build --release --bins
```

### 2. Run Tests

**Rust Integration Tests:**
```bash
# All integration tests
cargo test --release -- --ignored --test-threads=1

# Specific test
cargo test --release test_single_hop_1000_packets -- --ignored --nocapture
```

**Shell Script Tests:**
```bash
# Performance test (requires root)
sudo tests/data_plane_pipeline_veth.sh

# End-to-end test (requires root)
sudo tests/data_plane_e2e.sh
```

---

## Important: Build Strategy

### ✅ DO THIS
```bash
# Build binaries ONCE
cargo build --release --bins

# Then run tests (they use the pre-built binaries)
cargo test --release -- --ignored
sudo tests/data_plane_pipeline_veth.sh
```

### ❌ DON'T DO THIS
```bash
# Don't rely on cargo test to build your binaries
cargo test --release  # ← This builds test harness, not production binaries!
```

---

## Why This Matters

**The Problem:**
- `cargo test` builds with test harness → different compilation
- `cargo build` builds production binaries
- Shell scripts were rebuilding on every run
- Result: Multiple compilations, stale binaries, confusion

**The Solution:**
- Build production binaries ONCE with `cargo build --release --bins`
- All tests use these pre-built binaries
- Tests check for binaries but don't rebuild them
- Faster iteration, consistent behavior

---

## Test Categories

### 1. Unit Tests
```bash
# Run unit tests (fast, no root required)
cargo test --lib
```

### 2. Integration Tests (Rust)
Located in `tests/integration/`:
- `test_basic.rs` - Basic packet forwarding (requires root)
- `rule_management.rs` - Rule add/remove/list
- `supervisor_resilience.rs` - Worker crash handling
- `test_scaling.rs` - Multi-worker scaling

```bash
# Run all integration tests
cargo test --release -- --ignored --test-threads=1

# Run specific test with output
cargo test --release test_single_hop_1000_packets -- --ignored --nocapture
```

**Requirements:**
- Root privileges (creates network namespaces)
- Pre-built release binaries
- Single-threaded execution (`--test-threads=1` prevents namespace conflicts)

### 3. Shell Script Tests
Located in `tests/`:
- `data_plane_pipeline_veth.sh` - 3-hop performance test (10M packets)
- `data_plane_e2e.sh` - End-to-end functional test
- `debug_10_packets.sh` - Minimal debugging test
- `scaling_test.sh` - Worker scaling test

```bash
# Build first
cargo build --release --bins

# Then run (requires root)
sudo tests/data_plane_pipeline_veth.sh
```

**Requirements:**
- Root privileges (creates veth interfaces)
- Pre-built release binaries

### 4. Property-Based Tests
```bash
# Packet parser property tests
cargo test --test proptests
```

---

## Debugging Failed Tests

### Check Binary Version
```bash
ls -lh target/release/multicast_relay
md5sum target/release/multicast_relay
```

### Check for Stale Binaries
```bash
# If tests fail with strange errors, rebuild
cargo clean
cargo build --release --bins
```

### View Test Logs
Integration tests write logs to `/tmp/`:
```bash
# Find recent test logs
ls -lt /tmp/test_mcr_*.log | head -5

# View log
tail -f /tmp/test_mcr_*.log
```

### Run with Maximum Debug Output
```bash
# Rust tests
cargo test --release test_name -- --ignored --nocapture

# Shell tests (add -x)
bash -x tests/data_plane_pipeline_veth.sh
```

---

## Performance Testing

### Baseline Performance Test
```bash
# Build in release mode (required for performance!)
cargo build --release --bins

# Run 3-hop pipeline test
sudo tests/data_plane_pipeline_veth.sh
```

**Expected Results (Option 4 unified loop):**
- Ingress: ~690k pps
- Egress: Target 307k pps (PHASE4 baseline)
- Buffer exhaustion: < 40%

### Quick Performance Check
```bash
# 10 packets only (for debugging)
sudo tests/debug_10_packets.sh
```

---

## Common Issues

### Issue: "Binary not found"
```
ERROR: Binary not found: target/release/multicast_relay
Build with: cargo build --release --bins
```

**Solution:**
```bash
cargo build --release --bins
```

### Issue: Test rebuilds on every run
**Cause:** Old script was calling `cargo build`

**Solution:** Scripts now check for binaries instead of building. Build manually:
```bash
./scripts/build_all.sh
```

### Issue: Permission denied
```
ERROR: This script requires root privileges.
```

**Solution:**
```bash
sudo tests/data_plane_pipeline_veth.sh
```

### Issue: Test hangs
**Cause:** Multiple tests running concurrently, network namespace conflicts

**Solution:** Run with `--test-threads=1`:
```bash
cargo test --release -- --ignored --test-threads=1
```

### Issue: Port/socket already in use
**Cause:** Previous test didn't clean up

**Solution:**
```bash
# Kill stray processes
sudo killall multicast_relay

# Remove stale sockets
rm -f /tmp/mcr_*.sock /tmp/test_*.sock
```

---

## CI/CD Integration

```bash
#!/bin/bash
set -e

# 1. Build once
cargo build --release --bins

# 2. Run Rust tests
cargo test --release -- --ignored --test-threads=1

# 3. Run shell tests
sudo tests/data_plane_pipeline_veth.sh
sudo tests/data_plane_e2e.sh

# 4. Run property tests
cargo test --test proptests

echo "✅ All tests passed"
```

---

## Development Workflow

### When writing new code
```bash
# 1. Make changes to src/

# 2. Rebuild
cargo build --release --bins

# 3. Run relevant test
cargo test --release test_name -- --ignored --nocapture

# 4. If performance-sensitive, benchmark
sudo tests/data_plane_pipeline_veth.sh
```

### Before committing
```bash
# Run all tests
./scripts/build_all.sh
cargo test --release -- --ignored --test-threads=1
sudo tests/data_plane_pipeline_veth.sh
```

---

## Related Documentation

- `developer_docs/BUILD_CONSISTENCY.md` - Detailed explanation of build issues
- `developer_docs/ARCHITECTURE.md` - System architecture
- `STATUS.md` - Current project status and known issues
