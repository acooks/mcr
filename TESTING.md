# How to Run Tests

This guide provides everything you need to know to run the tests for the Multicast Relay (MCR). For the high-level testing *philosophy* and tiered strategy guiding developers, see [`docs/DEVELOPER_TESTING_STRATEGY.md`](docs/DEVELOPER_TESTING_STRATEGY.md).

## Quick Start

Follow these steps to run the most common test suites.

**Step 1: Build the Binaries (as a regular user)**

It is critical to build first as a non-privileged user to prevent file permission issues in your `target/` directory and Cargo cache.

```bash
cargo build --release --bins
```

**Step 2: Run Unit Tests (no sudo needed)**

These are Rust-based tests that verify core logic without requiring special permissions.

```bash
cargo test --lib
```

**Step 3: Run All E2E Shell Script Tests (requires sudo)**

These scripts test the complete, compiled application in realistic scenarios involving network namespaces and raw sockets.

```bash
sudo ./tests/test_all_scripts.sh
```

## Running Specific Tests

### Running a Single E2E Test

For debugging, you can run any test script individually.

```bash
sudo ./tests/debug_10_packets.sh
```

### Running a Topology Test

The multi-hop topology tests are located in a subdirectory.

```bash
cd tests/topologies
sudo ./baseline_50k.sh
```

## E2E Test Catalog

The E2E tests are shell scripts located in `tests/` and organized by purpose.

*   **Debug Tests (`debug_*.sh`):** Small packet counts for basic validation and easy debugging.
*   **End-to-End Tests (`data_plane_e2e.sh`, etc.):** Complete system validation in isolated environments.
*   **Performance & Scaling Tests (`data_plane_performance.sh`, `scaling_test.sh`):** Benchmarks and high-load validation.
*   **Topology Tests (`tests/topologies/`):** Multi-instance, multi-hop forwarding scenarios (e.g., chains, fan-out trees).

## Debugging Failed Tests

Each E2E test script writes detailed logs to the `/tmp/` directory.

```bash
# Example: Run a test that is failing
sudo ./tests/debug_10_packets.sh

# Check the MCR process log for errors, statistics, and panics
cat /tmp/test_mcr.log

# Check the test script's own output log for validation failures
cat /tmp/test_debug_10_packets.log
```

## Important Patterns for E2E Tests (Fragile Commands)

The shell scripts rely on specific, fragile command patterns to function correctly. When debugging or writing new tests, these are critical to understand.

### Waiting for MCR to Start

A loop-and-wait pattern must be used to ensure the MCR control socket exists before sending commands. A fixed `sleep` is also required to allow full initialization.

```bash
# Start MCR in the background
taskset -c 0 "$RELAY_BIN" supervisor ... &
MCR_PID=$!

# Wait for control socket (up to 5 seconds)
for i in {1..50}; do
    if [ -S /tmp/test_mcr.sock ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S /tmp/test_mcr.sock ]; then
    echo "ERROR: Control socket not found after 5 seconds"
    exit 1
fi

# Allow time for full initialization before sending commands
sleep 2
```

### Graceful Shutdown and Pipeline Drain

To ensure all in-flight packets are processed and final statistics are logged, tests must wait for traffic to finish and then perform a graceful shutdown.

```bash
# Send traffic with the traffic generator
"$TRAFFIC_BIN" --count $COUNT --rate $RATE ...

# Wait for the pipeline to drain. Calculation is based on packet count and rate.
DRAIN_TIME=$(echo "scale=0; ($COUNT / $RATE) + 5" | bc)
sleep $DRAIN_TIME

# Graceful shutdown (SIGTERM) triggers final stats logging
kill $MCR_PID 2>/dev/null || true
wait $MCR_PID 2>/dev/null || true
sync  # Ensure logs are flushed to disk before parsing
```

### Accurate Statistics Parsing

Packet counts for validation **must** be parsed from specific log lines to be accurate.

*   **Ingress stats** are definitive and should be read from `STATS:Ingress FINAL` lines.
*   **Egress stats** do not have a `FINAL` line due to shutdown timing, so the last periodic `STATS:Egress` line must be used.

```bash
# ✅ CORRECT: Use FINAL stats for Ingress
INGRESS_MATCHED=$(grep 'STATS:Ingress FINAL' $LOG | grep -oP 'matched=\K[0-9]+' || echo 0)
INGRESS_EGR_SENT=$(grep 'STATS:Ingress FINAL' $LOG | grep -oP 'egr_sent=\K[0-9]+' || echo 0)

# ✅ CORRECT: Use last periodic stat for Egress
EGRESS_SENT=$(grep 'STATS:Egress' $LOG | tail -1 | grep -oP 'sent=\K[0-9]+' || echo 0)
EGRESS_CH_RECV=$(grep 'STATS:Egress' $LOG | tail -1 | grep -oP 'ch_recv=\K[0-9]+' || echo 0)
```

## CI/Automation

For CI environments, use the following pattern to run tests safely.

```bash
# Build step (as regular user)
cargo build --release --bins

# Unit test step (no root needed)
cargo test --lib

# Integration test step (requires root)
if [ "$EUID" -eq 0 ]; then
    ./tests/test_all_scripts.sh
else
    echo "Skipping E2E tests (no root privileges)"
fi
```