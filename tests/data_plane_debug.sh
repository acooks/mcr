#!/bin/bash

# Data Plane Debug Test
#
# Small test with 3 packets per size for debugging

set -e
set -u
set -o pipefail

# --- Configuration ---
RELAY_BINARY="target/release/multicast_relay"
CONTROL_CLIENT_BINARY="target/release/control_client"
TRAFFIC_GENERATOR_BINARY="target/release/traffic_generator"

SUPERVISOR_SOCKET="/tmp/mcr_perf_test.sock"
INPUT_INTERFACE="lo"
INPUT_GROUP="239.1.1.1"
INPUT_PORT="5001"
OUTPUT_INTERFACE="lo"
OUTPUT_GROUP="239.10.10.10"
OUTPUT_PORT="6001"

# Test parameters - SMALL for debugging
PACKET_COUNTS=(3 3 3 3 3)  # Just 3 packets per size
PACKET_SIZES=(1300 1500 1800 9000 32768)
PACKET_DESCRIPTIONS=("1300B video" "1500B standard MTU" "1800B jumbo" "9000B jumbo" "32kB max")
SEND_RATE=10  # Slow rate for debugging (10 pps)

# --- Cleanup ---
cleanup() {
    echo "--- Cleaning up ---"
    sudo killall -q multicast_relay || true
    sudo killall -q traffic_generator || true
    killall -q nc || true
    sudo rm -f "$SUPERVISOR_SOCKET" || true
    echo "Cleanup complete."
}
trap cleanup EXIT

# --- Build ---
echo "=== Building Release Binaries ==="
cargo build --release
echo ""

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script requires root privileges for data plane operations."
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Start Supervisor ---
echo "=== Starting Supervisor (Release Mode) ==="
cleanup  # Ensure clean state

"$RELAY_BINARY" supervisor \
    --control-socket-path "$SUPERVISOR_SOCKET" \
    --num-workers 1 \
    --user "$SUDO_USER" \
    --group "$SUDO_USER" &
SUPERVISOR_PID=$!

echo "Waiting for supervisor socket..."
WAIT_START_TIME=$(date +%s)
while ! [ -S "$SUPERVISOR_SOCKET" ]; do
    if [ "$(($(date +%s) - WAIT_START_TIME))" -gt 10 ]; then
        echo "ERROR: Timed out waiting for supervisor socket"
        exit 1
    fi
    sleep 0.1
done

# Make socket accessible to non-root user
chmod 666 "$SUPERVISOR_SOCKET"
echo "Supervisor started (PID: $SUPERVISOR_PID)"
sleep 2
echo ""

# --- Add Forwarding Rule ---
echo "=== Adding Forwarding Rule ==="
sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" add \
    --input-interface "$INPUT_INTERFACE" \
    --input-group "$INPUT_GROUP" \
    --input-port "$INPUT_PORT" \
    --outputs "$OUTPUT_GROUP:$OUTPUT_PORT:$OUTPUT_INTERFACE"
echo "Rule added successfully"
echo ""

# --- Run Debug Tests ---
echo "=== Running Debug Tests (3 packets per size) ==="
echo ""

for i in "${!PACKET_SIZES[@]}"; do
    SIZE=${PACKET_SIZES[$i]}
    COUNT=${PACKET_COUNTS[$i]}
    DESC=${PACKET_DESCRIPTIONS[$i]}

    echo "--- Test $((i+1))/${#PACKET_SIZES[@]}: $DESC ($SIZE bytes, $COUNT packets) ---"

    # Get initial stats
    echo "Getting initial stats..."
    STATS_BEFORE=$(sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" stats 2>&1)
    echo "Stats before: $STATS_BEFORE"

    # Run traffic generator
    echo "Sending $COUNT packets at $SIZE bytes (rate: $SEND_RATE pps)..."
    echo "Traffic generator output:"
    sudo -u "$SUDO_USER" "$TRAFFIC_GENERATOR_BINARY" \
        --interface "127.0.0.1" \
        --group "$INPUT_GROUP" \
        --port "$INPUT_PORT" \
        --rate "$SEND_RATE" \
        --size "$SIZE" \
        --count "$COUNT"

    # Wait for processing
    echo "Waiting for processing..."
    sleep 2

    # Get final stats
    echo "Getting final stats..."
    STATS_AFTER=$(sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" stats 2>&1)
    echo "Stats after: $STATS_AFTER"

    echo "Test $((i+1)) complete"
    echo ""
done

echo "=== Debug Test Complete ==="

exit 0
