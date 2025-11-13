# Testing Guide

## Quick Start

```bash
# 1. Build everything as regular user
cargo build --release --bins

# 2. Run unit tests (no sudo needed)
cargo test --lib

# 3. Run shell integration tests (requires sudo)
sudo ./tests/test_all_scripts.sh
```

## Test Types

### Unit Tests (~122 tests)
- **Location:** `src/**/*.rs` with `#[cfg(test)]`
- **Requirements:** None (run as regular user)
- **Run:** `cargo test --lib`
- **What they test:** Individual functions, logic, protocol parsing
- **Status:** ✅ All passing

### Shell Integration Tests
- **Location:** `tests/*.sh` and `tests/topologies/*.sh`
- **Requirements:** Root privileges (AF_PACKET, network namespaces)
- **Run:** `sudo ./tests/test_all_scripts.sh` (runs all tests)
- **What they test:**
  - Basic forwarding validation (debug_10_packets.sh)
  - End-to-end packet delivery (data_plane_e2e.sh)
  - Performance and scaling (scaling_test.sh, data_plane_performance.sh)
  - Multi-hop topologies (topologies/baseline_50k.sh, chain_3hop.sh, tree_fanout.sh)
- **Documentation:** See [tests/README.md](tests/README.md)

## Why Build Before Running Tests?

**Always build as regular user first:**
```bash
cargo build --release --bins
```

**Then run tests with sudo:**
```bash
sudo ./tests/test_all_scripts.sh
```

This prevents:
- Root-owned files in `target/` directory
- Permission errors in cargo cache
- Toolchain confusion

## Test Standards

Shell integration tests follow standardized patterns:
- Network namespace isolation (no host pollution)
- Graceful shutdown with final stats logging
- Consistent pass/fail reporting (✅/❌)
- Individual test logs in `/tmp/`

See [tests/TEST_STANDARDS.md](tests/TEST_STANDARDS.md) for detailed patterns and templates.

## Debugging Failed Tests

Each test writes detailed logs:
```bash
# Run a test
sudo ./tests/debug_10_packets.sh

# Check logs
cat /tmp/test_mcr.log        # MCR process log
cat /tmp/test_debug_10_packets.log  # Test output
```

## Testing Philosophy

For the formal testing strategy and 3-tier architecture, see [docs/reference/TESTING.md](docs/reference/TESTING.md).

## CI/Automation

For CI environments:
```bash
# Build step (as regular user)
cargo build --release --bins

# Unit test step (no root needed)
cargo test --lib

# Integration test step (requires root)
if [ "$EUID" -eq 0 ]; then
    ./tests/test_all_scripts.sh
else
    echo "Skipping integration tests (no root)"
fi
```
