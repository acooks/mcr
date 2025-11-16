# How to Run Tests

This guide provides everything you need to know to run the tests for the Multicast Relay (MCR). For the high-level testing *philosophy* and tiered strategy guiding developers, see [`docs/DEVELOPER_TESTING_STRATEGY.md`](docs/DEVELOPER_TESTING_STRATEGY.md).

## Test Types

MCR employs a three-tiered testing strategy. All testing is orchestrated via `just` commands. For a detailed explanation of the philosophy and methodology behind these tiers, see the [Developer Testing Strategy](developer_docs/testing/DEVELOPER_TESTING_STRATEGY.md).

### Tier 1: Unit Tests

*   **Purpose:** To test pure, internal business logic in isolation.
*   **Scope:** Individual functions, logic, protocol parsing.
*   **Command:** `just test-unit`

### Tier 2: Rust Integration Tests

*   **Purpose:** To test the interaction between the application's Rust components, either unprivileged or in isolated network namespaces.
*   **Scope:** Control plane functionality, supervisor/worker lifecycle, multi-worker scenarios.
*   **Commands:**
    *   `just test-integration-light` (unprivileged tests)
    *   `just test-integration-privileged` (privileged tests requiring `sudo`)

### Tier 3: E2E Bash Tests

*   **Purpose:** To validate the final, compiled release binaries in realistic, multi-hop network topologies.
*   **Scope:** Packet forwarding correctness, performance benchmarking, complex network scenarios.
*   **Commands:**
    *   `just test-e2e-bash` (runs a single, representative E2E script)
    *   `just test-topologies` (runs the full suite of multi-hop topology tests, requires `sudo`)

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