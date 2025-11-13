# Testing Guide

## Quick Start

```bash
# 1. Build everything as regular user
cargo build --release --bins
cargo test --no-run

# 2. Run unit tests (no sudo needed)
cargo test --lib

# 3. Run integration tests (requires sudo)
sudo -E cargo test --test integration test_basic -- --ignored --test-threads=1
```

## Test Types

### Unit Tests (122 tests)
- **Location:** `src/**/*.rs` with `#[cfg(test)]`
- **Requirements:** None (run as regular user)
- **Run:** `cargo test --lib`
- **What they test:** Individual functions, logic, protocol parsing

### Integration Tests (Existing)
- **Location:** `tests/integration/{cli,log_level_control,rule_management}.rs`
- **Requirements:** None (run as regular user)
- **Run:** `cargo test --test integration` (without --ignored)
- **What they test:** CLI, IPC, rule propagation

### Network Integration Tests (New!)
- **Location:** `tests/integration/test_*.rs` (test_basic, test_scaling, test_topologies)
- **Requirements:** Root privileges for network namespaces
- **Run:** `sudo -E cargo test --test integration <test_name> -- --ignored --test-threads=1`
- **What they test:**
  - `test_basic`: Basic 10 and 1000 packet forwarding (replaces debug_10_packets.sh)
  - `test_scaling`: Scaling at 1k, 10k, and 1M packets (replaces scaling_test.sh)
  - `test_topologies`: Multi-hop chains and fanout patterns (replaces baseline_50k.sh, chain_3hop.sh, tree_fanout.sh)

## Why Build Before Running Tests?

**Always build as regular user first:**
```bash
cargo build --release --bins
cargo test --no-run
```

**Then run tests with sudo:**
```bash
sudo -E cargo test --test integration test_basic -- --ignored --test-threads=1
```

This prevents:
- Root-owned files in `target/` directory
- Permission errors in cargo cache
- Toolchain confusion

## Detailed Documentation

See [tests/integration/README.md](tests/integration/README.md) for:
- Test utilities (McrInstance, NetworkNamespace, VethPair)
- Writing new tests
- Debugging failures
- Known issues

## CI/Automation

For CI environments, use:
```bash
# Build step (as regular user)
cargo build --release --bins
cargo test --no-run

# Test step (unit tests)
cargo test --lib

# Test step (integration tests - if root available)
if [ "$EUID" -eq 0 ]; then
    cargo test --test integration test_basic -- --ignored --test-threads=1
    cargo test --test integration test_scaling -- --ignored --test-threads=1
    cargo test --test integration test_topologies -- --ignored --test-threads=1
else
    echo "Skipping network integration tests (no root)"
fi
```
