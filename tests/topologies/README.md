# Network Topology Tests

This directory contains end-to-end integration tests that validate the multicast relay application using different network topologies. Each test runs in an **isolated network namespace** to ensure zero host pollution and automatic cleanup.

## Architecture

### Network Namespace Isolation

All tests use `unshare --net` to create an isolated network namespace that is automatically destroyed when the test exits. This provides:

- ✅ **Zero host pollution** - veth interfaces exist only in test namespace
- ✅ **Automatic cleanup** - namespace destroyed even on crash/SIGTERM
- ✅ **Safe parallelism** - multiple tests can run concurrently
- ✅ **No manual cleanup** - no leaked interfaces or namespaces

### Test Structure

Each topology test follows this pattern:

```bash
#!/bin/bash
# 1. Build binaries (in host namespace)
cargo build --release

# 2. Run test in isolated namespace
unshare --net --mount-proc --map-root-user bash -c '
    # Source common functions
    source tests/topologies/common.sh

    # Set up network topology (veth pairs)
    setup_veth_pair veth0 veth1 10.0.0.1/24 10.0.0.2/24

    # Start MCR instances
    start_mcr mcr1 veth0 /tmp/mcr1.sock

    # Configure forwarding rules
    add_rule /tmp/mcr1.sock veth0 239.1.1.1 5001 "239.2.2.2:5002:veth1"

    # Run traffic
    run_traffic 10.0.0.1 239.1.1.1 5001 1000000 1400 500000

    # Validate results
    validate_stat /tmp/mcr1.log "STATS:Ingress" "matched" 800000 "Packets matched"
'
# Namespace auto-destroyed here
```

## Available Topologies

### 1. Chain (3-hop) - `chain_3hop.sh`

**Status:** ✅ Implemented

**Topology:**

```text
Traffic Gen → MCR-1 → MCR-2 → MCR-3
```

**Tests:**

- Serial forwarding through multiple hops
- Buffer management across hops
- Stats accuracy at each hop
- No packet corruption

**Usage:**

```bash
sudo tests/topologies/chain_3hop.sh
```

**Expected Outcome:**

- MCR-1: Receives ~1M packets, forwards most
- MCR-2: Receives packets from MCR-1, forwards most
- MCR-3: Receives packets from MCR-2 (terminus)
- Packet loss expected due to buffer backpressure (by design)

### 2. Tree (1:N Fanout) - `tree_fanout.sh`

**Status:** ✅ Implemented

**Topology:**

```text
                    ┌→ MCR-2
Traffic Gen → MCR-1 ┼→ MCR-3
                    └→ MCR-4
```

**Tests:**

- Head-end replication (1 input → N outputs)
- Buffer pool under amplification (3x traffic)
- Per-output stats tracking
- Egress queue fairness

**Usage:**

```bash
sudo tests/topologies/tree_fanout.sh
```

### 3. High Fanout (1:50) - `high_fanout_50.sh`

**Status:** ✅ Implemented

**Topology:**

```text
Traffic Gen → MCR → 50 outputs (loopback)
```

**Tests:**

- High fanout ratio (1 input → 50 outputs)
- VecDeque-based send queue performance under amplification
- Buffer pool performance with 50x traffic multiplication
- Egress queue management with many destinations

**Usage:**

```bash
sudo tests/topologies/high_fanout_50.sh
```

**Expected Outcome:**

- Matched packets ≈ 10,000 (input)
- TX packets ≈ 500,000 (50x amplification)
- Zero buffer exhaustion at 10k pps input rate

### 4. Tree (N:1 Convergence) - `tree_converge.sh`

**Status:** ✅ Implemented

**Topology:**

```text
Traffic Gen 1 (239.1.1.1) ─┐
Traffic Gen 2 (239.1.1.2) ─┼→ MCR ─→ Sink
Traffic Gen 3 (239.1.1.3) ─┘
```

**Tests:**

- Multiple independent rules on same interface
- Per-rule packet counting (isolation)
- Fair handling of concurrent streams
- No cross-talk between rules

**Usage:**

```bash
sudo tests/topologies/tree_converge.sh
```

### 5. Diamond (Multipath) - `diamond.sh`

**Status:** 🔜 Planned

**Topology:**

```text
               ┌→ MCR-2 ┐
Traffic Gen → MCR-1      → MCR-4
               └→ MCR-3 ┘
```

**Tests:**

- Multiple paths converge at destination
- No duplicate packets
- Timing/ordering consistency
- Independent path failures

### 6. Full Mesh - `mesh.sh`

**Status:** 🔜 Planned

**Topology:**

```text
Every MCR instance forwards to every other MCR instance
```

**Tests:**

- Scalability (N² connections)
- Cross-talk isolation
- Rule management complexity
- Resource utilization

### 7. Multi-Worker Mode - `multi_worker.sh`

**Status:** ✅ Implemented

**Topology:**

```text
Traffic Generator → MCR (2 workers with PACKET_FANOUT) → Sink
```

**Tests:**

- PACKET_FANOUT kernel packet distribution
- Multiple workers processing traffic concurrently
- Combined stats validation
- No packet duplication

**Usage:**

```bash
sudo tests/topologies/multi_worker.sh
```

### 8. Fault Tolerance - `fault_tolerance.sh`

**Status:** ✅ Implemented

**Tests:**

- Graceful shutdown during active traffic
- SIGTERM signal handling
- Multiple SIGTERM resilience
- Final stats persistence on shutdown
- No zombie processes or resource leaks

**Usage:**

```bash
sudo tests/topologies/fault_tolerance.sh
```

### 9. Edge Cases - `edge_cases.sh`

**Status:** ✅ Implemented

**Tests:**

- Minimum packet size (64 bytes)
- Maximum MTU packet size (1472 bytes)
- Buffer pool under high load stress
- Minimum valid UDP packet handling

**Usage:**

```bash
sudo tests/topologies/edge_cases.sh
```

### 10. Dynamic Rule Changes - `dynamic_rules.sh`

**Status:** ✅ Implemented

**Tests:**

- Traffic before rule exists (not_matched counter)
- Adding rules during active traffic
- Multiple concurrent rules
- Rule listing and visibility

**Usage:**

```bash
sudo tests/topologies/dynamic_rules.sh
```

## Baseline Performance Tests

These tests validate forwarding efficiency at specific packet rates. All baseline
tests use a unified parameterized script (`baseline_test.sh`).

### baseline_test.sh (Unified Script)

**Status:** ✅ Implemented

Parameterized baseline test supporting any rate/packet count combination.

```bash
# Quick test at 100k pps (default)
sudo tests/topologies/baseline_test.sh

# Custom parameters
sudo tests/topologies/baseline_test.sh --rate 150000 --packets 1000000

# With profiling (requires perf)
sudo tests/topologies/baseline_test.sh --rate 100000 --packets 6000000 --profiling
```

### baseline_100k.sh

**Status:** ✅ Implemented

Validates 100% packet forwarding at 100k pps (100k packets, ~1 second).

```bash
sudo tests/topologies/baseline_100k.sh
```

### baseline_150k_60s.sh

**Status:** ✅ Implemented

60-second sustained performance test at 150k pps (9M packets). Validates that
performance is sustainable under load. Runs in CI nightly.

```bash
sudo tests/topologies/baseline_150k_60s.sh
```

## Common Functions Library

The `common.sh` library provides reusable functions for all topology tests:

### Network Setup

- `enable_loopback()` - Enable lo interface in namespace
- `setup_veth_pair <n1> <n2> <ip1> <ip2>` - Create and configure veth pair

### MCR Management

- `start_mcr <name> <iface> <socket> [logfile] [core_id]` - Start MCR instance
- `wait_for_sockets <sock1> [sock2] ...` - Wait for control sockets
- `add_rule <socket> <in_if> <in_grp> <in_port> <out_spec>` - Configure rule

### Traffic & Validation

- `run_traffic <ip> <group> <port> <count> <size> <rate>` - Generate traffic
- `get_stats <logfile>` - Extract final stats
- `validate_stat <log> <type> <field> <min> <desc>` - Assert stat value

### Monitoring & Cleanup

- `start_log_monitor <name> <logfile>` - Monitor logs in background
- `graceful_cleanup_unshare <pid_var1> [pid_var2] ...` - Gracefully terminate MCR instances

## Running Tests

### Single Test

```bash
# Run specific topology test
sudo tests/topologies/chain_3hop.sh
```

### All Tests

```bash
# Run all topology tests sequentially
for test in tests/topologies/*.sh; do
    [ "$test" = "tests/topologies/common.sh" ] && continue
    echo "=== Running $(basename $test) ==="
    sudo "$test" || exit 1
done
```

### With Coverage

```bash
# Run tests with coverage measurement (future)
sudo tests/topologies/run_with_coverage.sh
```

## Requirements

- **Root privileges** - Required for `unshare --net` and `AF_PACKET` sockets
- **Linux kernel** - Network namespaces (any modern kernel)
- **ip command** - From `iproute2` package

## Debugging

### View Logs

Logs persist after test completion in `/tmp/`:

```bash
tail -f /tmp/mcr1.log
tail -50 /tmp/mcr1.log | grep STATS
```

### Run Test Manually

To debug interactively, extract the inner bash script and run it:

```bash
# Enter isolated namespace
sudo unshare --net --mount-proc --map-root-user bash

# Inside namespace, set up topology manually
ip link set lo up
ip link add veth0 type veth peer name veth1
# ... etc
```

### Common Issues

#### "Operation not permitted" creating veth

- Ensure running with `sudo`
- Check that `unshare` supports `--map-root-user`

#### "Timeout waiting for socket"

- Check `/tmp/mcrN.log` for startup errors
- Verify binaries are built: `ls -la target/release/mcrd`
- Ensure loopback is enabled: `ip link set lo up`

#### "No stats found"

- Check MCR instance is running: `ps aux | grep mcrd`
- Verify traffic generator completed: check its exit code
- Look for errors in logs: `grep ERROR /tmp/mcr1.log`

## Coverage Contribution

These topology tests provide end-to-end coverage for:

- ✅ **Ingress path** - AF_PACKET receive, parsing, rule lookup
- ✅ **Egress path** - io_uring send, buffer management
- ✅ **Buffer pools** - Allocation, exhaustion, reuse
- ✅ **Stats reporting** - Counters, rates, aggregation
- ✅ **Multi-instance coordination** - Process isolation
- ✅ **Head-end replication** - 1:N amplification
- ✅ **High fanout scenarios** - 1:50 replication (VecDeque send queue)
- ✅ **Multi-worker mode** - PACKET_FANOUT kernel distribution
- ✅ **N:1 convergence** - Multiple sources to single destination
- ✅ **Fault tolerance** - Graceful shutdown, signal handling
- ✅ **Edge cases** - Min/max packet sizes, buffer stress
- ✅ **Dynamic rules** - Runtime rule addition and concurrent rules

**Not covered** (blocked by architectural debt):

- ⚠️ Privilege separation (workers run as root - D24)
- ⚠️ Lazy socket creation (eager creation - D23)
- ⚠️ Multi-interface per worker (--interface parameter - D21)

## Future Enhancements

- [ ] Coverage measurement integration
- [x] Performance benchmarking mode (baseline_*_60s.sh tests)
- [ ] Fault injection (link down, process kill)
- [x] Long-duration stress tests (60-second profiling tests)
- [x] CI/CD integration (GitHub Actions workflows added)
- [ ] Rust-based test harness (as alternative to bash)
