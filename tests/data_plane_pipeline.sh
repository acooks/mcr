#!/bin/bash

# Data Plane Pipeline Test
#
# Tests a 3-hop MCR pipeline to validate end-to-end performance:
# Traffic Generator → MCR-1 → MCR-2 → MCR-3
#
# Each MCR reports ingress/egress stats every second, allowing us to:
# - Verify packet flow through the pipeline
# - Measure performance at each hop
# - Validate that egress of hop N matches ingress of hop N+1

set -e
set -u
set -o pipefail

# --- Configuration ---
RELAY_BINARY="target/release/multicast_relay"
CONTROL_CLIENT_BINARY="target/release/control_client"
TRAFFIC_GENERATOR_BINARY="target/release/traffic_generator"

# Socket paths for each MCR instance
MCR1_SOCKET="/tmp/mcr_pipeline_1.sock"
MCR2_SOCKET="/tmp/mcr_pipeline_2.sock"
MCR3_SOCKET="/tmp/mcr_pipeline_3.sock"

# Pipeline configuration
# Traffic Gen → MCR-1 (239.1.1.1:5001) → MCR-2 (239.2.2.2:5002) → MCR-3 (239.3.3.3:5003)
INPUT_INTERFACE="lo"

# Test parameters
PACKET_SIZE=1500  # Standard MTU
PACKET_COUNT=100000  # 100k packets
SEND_RATE=100000  # Target 100k pps (adjust based on system)

# --- Cleanup ---
cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    sudo killall -q multicast_relay || true
    sudo killall -q traffic_generator || true
    rm -f "$MCR1_SOCKET" "$MCR2_SOCKET" "$MCR3_SOCKET"
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

# --- Start MCR Instances ---
echo "=== Starting 3-Hop MCR Pipeline ==="
cleanup  # Ensure clean state
echo ""

# Start MCR-1
echo "Starting MCR-1..."
"$RELAY_BINARY" supervisor \
    --control-socket-path "$MCR1_SOCKET" \
    --num-workers 1 > /tmp/mcr1.log 2>&1 &
MCR1_PID=$!

# Start MCR-2
echo "Starting MCR-2..."
"$RELAY_BINARY" supervisor \
    --control-socket-path "$MCR2_SOCKET" \
    --num-workers 1 > /tmp/mcr2.log 2>&1 &
MCR2_PID=$!

# Start MCR-3
echo "Starting MCR-3..."
"$RELAY_BINARY" supervisor \
    --control-socket-path "$MCR3_SOCKET" \
    --num-workers 1 > /tmp/mcr3.log 2>&1 &
MCR3_PID=$!

# Wait for all sockets
echo "Waiting for MCR instances to start..."
WAIT_START=$(date +%s)
for socket in "$MCR1_SOCKET" "$MCR2_SOCKET" "$MCR3_SOCKET"; do
    while ! [ -S "$socket" ]; do
        if [ "$(($(date +%s) - WAIT_START))" -gt 15 ]; then
            echo "ERROR: Timeout waiting for $socket"
            exit 1
        fi
        sleep 0.1
    done
    chmod 666 "$socket"
done

echo "All MCR instances started (PIDs: $MCR1_PID, $MCR2_PID, $MCR3_PID)"
sleep 2
echo ""

# --- Configure Pipeline Rules ---
echo "=== Configuring Pipeline Rules ==="

# MCR-1: Receive from traffic gen (239.1.1.1:5001) → Forward to MCR-2 (239.2.2.2:5002)
echo "MCR-1: 239.1.1.1:5001 → 239.2.2.2:5002"
sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$MCR1_SOCKET" add \
    --input-interface "$INPUT_INTERFACE" \
    --input-group "239.1.1.1" \
    --input-port 5001 \
    --outputs "239.2.2.2:5002:$INPUT_INTERFACE" > /dev/null

# MCR-2: Receive from MCR-1 (239.2.2.2:5002) → Forward to MCR-3 (239.3.3.3:5003)
echo "MCR-2: 239.2.2.2:5002 → 239.3.3.3:5003"
sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$MCR2_SOCKET" add \
    --input-interface "$INPUT_INTERFACE" \
    --input-group "239.2.2.2" \
    --input-port 5002 \
    --outputs "239.3.3.3:5003:$INPUT_INTERFACE" > /dev/null

# MCR-3: Receive from MCR-2 (239.3.3.3:5003) → No output (terminus)
# Note: We don't add a rule for MCR-3 since it has no outputs.
# MCR-3 will still receive packets and report them in ingress stats (as "no_rule_match")
echo "MCR-3: 239.3.3.3:5003 → (terminus - no rule needed, measuring ingress only)"

echo "Pipeline configured successfully"
sleep 1
echo ""

# --- Start Log Monitoring ---
echo "=== Starting Log Monitoring ==="
echo "Logs will show stats from all 3 MCR instances..."
echo ""

# Monitor logs in background
tail -f /tmp/mcr1.log | sed 's/^/[MCR-1] /' &
TAIL1_PID=$!
tail -f /tmp/mcr2.log | sed 's/^/[MCR-2] /' &
TAIL2_PID=$!
tail -f /tmp/mcr3.log | sed 's/^/[MCR-3] /' &
TAIL3_PID=$!

sleep 2

# --- Run Traffic Generator ---
echo "=== Running Traffic Generator ==="
echo "Sending $PACKET_COUNT packets @ $PACKET_SIZE bytes (target: $SEND_RATE pps)"
echo ""

sudo -u "$SUDO_USER" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "127.0.0.1" \
    --group "239.1.1.1" \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKET_COUNT" &

TRAFFIC_PID=$!

# Wait for traffic generator to finish
wait $TRAFFIC_PID

echo ""
echo "=== Traffic Generator Complete ==="

# Give MCR instances time to process remaining packets
echo "Waiting for pipeline to flush..."
sleep 5

# Kill log monitors
kill $TAIL1_PID $TAIL2_PID $TAIL3_PID 2>/dev/null || true

echo ""
echo "=== Final Stats Summary ==="
echo ""
echo "MCR-1 Final Stats:"
tail -20 /tmp/mcr1.log | grep -E "\[Ingress Stats\]|\[Egress Stats\]" | tail -2 || echo "No stats found"
echo ""
echo "MCR-2 Final Stats:"
tail -20 /tmp/mcr2.log | grep -E "\[Ingress Stats\]|\[Egress Stats\]" | tail -2 || echo "No stats found"
echo ""
echo "MCR-3 Final Stats:"
tail -20 /tmp/mcr3.log | grep -E "\[Ingress Stats\]|\[Egress Stats\]" | tail -2 || echo "No stats found"

echo ""
echo "=== Pipeline Test Complete ==="
echo "Full logs available at:"
echo "  MCR-1: /tmp/mcr1.log"
echo "  MCR-2: /tmp/mcr2.log"
echo "  MCR-3: /tmp/mcr3.log"
echo ""

# Cleanup will happen via trap
exit 0
