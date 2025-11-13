# MCR Test Suite

This directory contains shell script integration tests for the multicast relay.

## Quick Start

```bash
# Build first (as regular user)
cargo build --release --bins

# Run individual test (requires sudo)
sudo ./tests/debug_10_packets.sh

# Run all shell tests
sudo ./tests/test_all_scripts.sh

# Run topology tests
cd tests/topologies
sudo ./baseline_50k.sh
```

## Test Categories

### Debug Tests
Small packet counts for debugging and validation:

- **debug_10_packets.sh** - Minimal 10-packet test, validates 1:1 forwarding
- **data_plane_debug.sh** - Debug test with 3 packets per size

### End-to-End Tests
Complete system validation:

- **data_plane_e2e.sh** - Basic E2E with namespace, packet verification (100 packets)
- **data_plane_pipeline.sh** - Pipeline validation using loopback
- **data_plane_pipeline_veth.sh** - Pipeline with veth pairs

### Performance Tests
- **data_plane_performance.sh** - Performance benchmarks (1.3KB-32KB packets)
- **scaling_test.sh** - Scaling validation (10, 1k, 10k, 1M packets)

### Topology Tests (topologies/)
Multi-instance, multi-hop forwarding:

- **baseline_50k.sh** - 2-hop baseline topology (50k packets)
- **chain_3hop.sh** - 3-hop chain topology
- **tree_fanout.sh** - Tree with 1-to-3 fanout

### Shared Infrastructure
- **topologies/common.sh** - Shared functions for all tests
- **test_all_scripts.sh** - Automated test runner

## Test Standards

All tests follow standardized patterns documented in TEST_STANDARDS.md:

- Network namespace isolation
- Graceful shutdown with final stats
- STATS:Ingress FINAL format for accurate counts
- Proper cleanup via trap handlers
- Consistent pass/fail reporting (✅/❌)

## Requirements

- Root privileges (for AF_PACKET sockets, network namespaces)
- Binaries: `multicast_relay`, `control_client`, `traffic_generator`
- Network utilities: `ip`, `unshare`, `taskset`

## Debugging Failed Tests

Each test writes logs to `/tmp/test_*.log`. Check these for details:

```bash
# Example: Debug a failed test
sudo ./tests/debug_10_packets.sh
cat /tmp/test_mcr.log  # Check MCR logs
```

## Known Issues

- **Egress stats timing**: Some tests may show egress stats not appearing due to shutdown race condition (infrastructure is present, timing issue being investigated)
- **Interactive tests**: `data_plane_debug.sh` had interactive prompts, now fixed

## Test Philosophy

See [docs/reference/TESTING.md](../docs/reference/TESTING.md) for the formal testing strategy and philosophy.

See [TESTING.md](../TESTING.md) for quick start guide including Rust unit and integration tests.
