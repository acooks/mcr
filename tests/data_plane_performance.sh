#!/bin/bash

# Data Plane Performance Test
#
# This script measures actual end-to-end throughput of the multicast relay
# data plane with real packet traffic at various packet sizes.
#
# Requirements:
# - Root privileges (for raw socket operations)
# - Release build (for accurate performance measurements)
#
# Measurements:
# - Packet rate (pps) and throughput (Gbps) for various packet sizes
# - Statistics from supervisor (packets relayed, bytes relayed)
# - Comparison between sent vs relayed packets

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

# Test parameters
PACKET_COUNTS=(100000 100000 100000 50000 10000)  # Packets to send for each size
PACKET_SIZES=(1300 1500 1800 9000 32768)  # Packet sizes to test (bytes)
PACKET_DESCRIPTIONS=("1300B video" "1500B standard MTU" "1800B jumbo" "9000B jumbo" "32kB max")
SEND_RATE=1000000  # Target send rate (pps) - will be limited by system

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

# Results file
RESULTS_FILE=$(mktemp)
echo "Results will be saved to: $RESULTS_FILE"
echo ""

# --- Run Performance Tests ---
echo "=== Running Performance Tests ==="
echo ""

for i in "${!PACKET_SIZES[@]}"; do
    SIZE=${PACKET_SIZES[$i]}
    COUNT=${PACKET_COUNTS[$i]}
    DESC=${PACKET_DESCRIPTIONS[$i]}

    echo "--- Test $((i+1))/${#PACKET_SIZES[@]}: $DESC ($SIZE bytes, $COUNT packets) ---"

    # Get initial stats
    STATS_BEFORE=$(sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" stats)
    echo "Stats before: $STATS_BEFORE"

    # Run traffic generator
    echo "Sending $COUNT packets at $SIZE bytes..."
    sudo -u "$SUDO_USER" "$TRAFFIC_GENERATOR_BINARY" \
        --interface "127.0.0.1" \
        --group "$INPUT_GROUP" \
        --port "$INPUT_PORT" \
        --rate "$SEND_RATE" \
        --size "$SIZE" \
        --count "$COUNT" \
        > /tmp/traffic_gen_output.txt 2>&1

    # Display traffic generator summary
    echo ""
    grep -A 10 "=== Traffic Generator Summary ===" /tmp/traffic_gen_output.txt || true
    echo ""

    # Wait for processing
    sleep 2

    # Get final stats
    STATS_AFTER=$(sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" stats)
    echo "Stats after: $STATS_AFTER"

    # Save results
    echo "=== Test: $DESC ($SIZE bytes) ===" >> "$RESULTS_FILE"
    echo "Packets sent: $COUNT" >> "$RESULTS_FILE"
    grep "Actual packet rate:" /tmp/traffic_gen_output.txt >> "$RESULTS_FILE" || true
    grep "Actual throughput:" /tmp/traffic_gen_output.txt >> "$RESULTS_FILE" || true
    echo "Stats before: $STATS_BEFORE" >> "$RESULTS_FILE"
    echo "Stats after: $STATS_AFTER" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"

    echo "Test $((i+1)) complete"
    echo ""
    sleep 1
done

# --- Final Results ---
echo "=== Performance Test Summary ==="
echo ""
cat "$RESULTS_FILE"
echo ""
echo "Detailed results saved to: $RESULTS_FILE"
echo ""
echo "=== Performance Test Complete ==="

exit 0
