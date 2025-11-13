# Shell Script to Rust Test Migration

This document maps the old shell script tests to their new Rust equivalents.

## Converted Tests

### ✅ Basic Forwarding Tests

| Old Shell Script | New Rust Test | Location |
|-----------------|---------------|----------|
| `tests/debug_10_packets.sh` | `test_minimal_10_packets()` | `tests/integration/test_basic.rs` |
| (implicit in basic tests) | `test_single_hop_1000_packets()` | `tests/integration/test_basic.rs` |

**What changed:**
- Uses Rust test framework with `#[requires_root]` macro
- Better error handling and validation
- Perfect 1:1 forwarding validation (no more "2x bug" confusion)
- Comprehensive stats checking (all fields validated)

### ✅ Scaling Tests

| Old Shell Script | New Rust Test | Location |
|-----------------|---------------|----------|
| `tests/scaling_test.sh` (10 packets) | `test_minimal_10_packets()` | `tests/integration/test_basic.rs` |
| `tests/scaling_test.sh` (1k packets) | `test_scale_1000_packets()` | `tests/integration/test_scaling.rs` |
| `tests/scaling_test.sh` (10k packets) | `test_scale_10000_packets()` | `tests/integration/test_scaling.rs` |
| `tests/scaling_test.sh` (1M packets) | `test_scale_1m_packets()` | `tests/integration/test_scaling.rs` |

**What changed:**
- Each packet count is a separate test for easier debugging
- Consistent validation across all scales
- Better timeout handling
- More reliable stats extraction (prefers FINAL stats)

### ✅ Topology Tests

| Old Shell Script | New Rust Test | Location |
|-----------------|---------------|----------|
| `tests/topologies/baseline_50k.sh` | `test_baseline_2hop_100k_packets()` | `tests/integration/test_topologies.rs` |
| `tests/topologies/chain_3hop.sh` | `test_chain_3hop()` | `tests/integration/test_topologies.rs` |
| `tests/topologies/tree_fanout.sh` | `test_tree_fanout_1_to_3()` | `tests/integration/test_topologies.rs` |

**What changed:**
- Cleaner multi-instance management
- Per-instance stats validation
- Better understanding of veth behavior (no more misleading expectations)
- Validates 1:1 forwarding at each hop
- For fanout: validates 3x amplification

## Legacy Tests (Not Converted)

The following tests were **not converted** because they overlap with the new Rust tests or test things better covered by unit tests:

### Data Plane Tests
- `tests/data_plane_e2e.sh` - **Covered by:** `test_basic.rs` (same coverage, better isolation)
- `tests/data_plane_debug.sh` - **Covered by:** Debug output in any test with `--nocapture`
- `tests/data_plane_performance.sh` - **Covered by:** `test_scaling.rs` (scaling tests measure performance)
- `tests/data_plane_pipeline.sh` - **Covered by:** Unit tests in `src/worker/` modules
- `tests/data_plane_pipeline_veth.sh` - **Covered by:** All new tests use veth pairs

### Other Legacy Tests
- `tests/e2e/` - Old E2E framework, superseded by new integration tests
- `tests/topologies/common.sh` - Helper functions, replaced by `tests/integration/common/` modules

## How to Run

### Old Way (Shell Scripts)
```bash
# Required root, polluted host network, complex setup
sudo tests/debug_10_packets.sh
sudo tests/scaling_test.sh
sudo tests/topologies/baseline_50k.sh
```

### New Way (Rust Tests)
```bash
# Build once as regular user
cargo build --release --bins
cargo test --no-run

# Run tests with sudo (isolated namespaces, no host pollution)
sudo -E cargo test --test integration test_basic -- --ignored --test-threads=1
sudo -E cargo test --test integration test_scaling -- --ignored --test-threads=1
sudo -E cargo test --test integration test_topologies -- --ignored --test-threads=1
```

## Migration Benefits

### Reliability
- ✅ Consistent test framework (no bash quirks)
- ✅ Better error messages
- ✅ Type safety
- ✅ Comprehensive stats validation

### Maintainability
- ✅ One language (Rust) instead of two (Rust + Bash)
- ✅ Shared test utilities (DRY principle)
- ✅ IDE support (autocomplete, refactoring)
- ✅ Compile-time checks

### Isolation
- ✅ Network namespaces (no host pollution)
- ✅ Automatic cleanup via RAII (Drop trait)
- ✅ Process management built-in
- ✅ Clear test boundaries

### Performance
- ✅ Faster startup (no shell overhead)
- ✅ Parallel compilation
- ✅ Better resource tracking

## Test Coverage Summary

| Test Category | Old (Shell) | New (Rust) | Status |
|--------------|-------------|------------|--------|
| Basic forwarding | 1 script | 2 tests | ✅ Converted |
| Scaling | 1 script | 3 tests | ✅ Converted |
| Topologies | 3 scripts | 3 tests | ✅ Converted |
| **Total** | **5 scripts** | **8 tests** | **✅ Complete** |

## Deprecation Plan

The following shell scripts can be safely removed after verifying Rust tests pass:

1. `tests/debug_10_packets.sh`
2. `tests/scaling_test.sh`
3. `tests/topologies/baseline_50k.sh`
4. `tests/topologies/chain_3hop.sh`
5. `tests/topologies/tree_fanout.sh`
6. `tests/topologies/common.sh`
7. `tests/data_plane_*.sh` (all variants)
8. `tests/e2e/` (entire directory)

**Before removal:** Run Rust tests to ensure all functionality is preserved.
