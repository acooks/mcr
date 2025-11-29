#!/bin/bash

# End-to-End Data Plane Test with Network Namespace
#
# This script verifies the complete data flow of the multicast relay:
# 1. Creates an isolated network namespace with veth pair
# 2. Starts the relay supervisor in the namespace
# 3. Starts a UDP listener (socat) in the namespace to capture relayed traffic
# 4. Adds a forwarding rule via the control client
# 5. Sends a burst of test packets using the traffic generator
# 6. Verifies that the listener received the correct number of packets
#
# TODO: Add test for rule removal once control_client returns rule IDs

set -e
set -u
set -o pipefail

# --- Configuration ---
RELAY_BINARY="target/release/multicast_relay"
CONTROL_CLIENT_BINARY="target/release/control_client"
TRAFFIC_GENERATOR_BINARY="target/release/traffic_generator"

# Use unique paths to avoid conflicts between concurrent test runs
TEST_ID="$$"
NS_NAME="mcr_e2e_${TEST_ID}"
# Create TWO veth pairs to avoid same-interface restriction
VETH_IN_HOST="vhin${TEST_ID}"   # Host-side of ingress veth
VETH_IN_NS="vnin${TEST_ID}"     # Namespace-side of ingress veth (MCR receives here)
VETH_OUT_HOST="vhout${TEST_ID}" # Host-side of egress veth
VETH_OUT_NS="vnout${TEST_ID}"   # Namespace-side of egress veth (MCR sends here)
SUPERVISOR_SOCKET=$(mktemp -u --tmpdir mcr_supervisor_XXXXXX.sock)
LISTENER_OUTPUT_FILE="/tmp/mcr_e2e_listener_${TEST_ID}.txt"

# Network configuration
IP_IN_HOST="192.168.100.1/24"
IP_IN_NS="192.168.100.2/24"
IP_IN_NS_ADDR="192.168.100.2"  # Without CIDR for traffic generator
IP_OUT_HOST="192.168.101.1/24"
IP_OUT_NS="192.168.101.2/24"

# Test parameters
INPUT_INTERFACE="$VETH_IN_NS"
INPUT_GROUP="239.1.1.1"
INPUT_PORT="5001"
OUTPUT_INTERFACE="$VETH_OUT_NS"
OUTPUT_GROUP="239.10.10.10"
OUTPUT_PORT="6001"
PACKET_COUNT=100
PAYLOAD="E2E_TEST_PACKET"

# --- Cleanup ---
cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    sudo killall -q multicast_relay socat || true
    sudo ip netns pids "$NS_NAME" 2>/dev/null | xargs -r sudo kill 2>/dev/null || true
    sudo ip netns del "$NS_NAME" 2>/dev/null || true
    sudo rm -f "$SUPERVISOR_SOCKET" || true
    rm -f "$LISTENER_OUTPUT_FILE" || true
    echo "Cleanup complete."
}
trap cleanup EXIT

# --- Cleanup any stale shared memory files ---
echo "--- Cleaning up stale shared memory files ---"
sudo rm -f /dev/shm/mcr_*
echo ""

# --- Check Dependencies ---
echo "--- Checking dependencies ---"
if ! command -v socat &> /dev/null; then
    echo "ERROR: socat is required but not installed."
    echo "Install with: sudo apt-get install socat"
    exit 1
fi
echo "✓ Found: socat"
echo ""

# --- Check Binaries ---
echo "--- Checking release binaries ---"
for binary in "$RELAY_BINARY" "$CONTROL_CLIENT_BINARY" "$TRAFFIC_GENERATOR_BINARY"; do
    if [ ! -f "$binary" ]; then
        echo "ERROR: Binary not found: $binary"
        echo "Build with: cargo build --release --bins"
        exit 1
    fi
    echo "✓ Found: $binary"
done
echo ""

# --- Setup Network Namespace ---
echo "--- Setting up network namespace ($NS_NAME) ---"
sudo ip netns add "$NS_NAME"

# Create ingress veth pair (for receiving traffic from generator)
sudo ip link add "$VETH_IN_HOST" type veth peer name "$VETH_IN_NS"
sudo ip link set "$VETH_IN_NS" netns "$NS_NAME"
sudo ip addr add "$IP_IN_HOST" dev "$VETH_IN_HOST"
sudo ip link set "$VETH_IN_HOST" up

sudo ip netns exec "$NS_NAME" ip addr add "$IP_IN_NS" dev "$VETH_IN_NS"
sudo ip netns exec "$NS_NAME" ip link set "$VETH_IN_NS" up

# Create egress veth pair (for sending relayed traffic to listener)
sudo ip link add "$VETH_OUT_HOST" type veth peer name "$VETH_OUT_NS"
sudo ip link set "$VETH_OUT_NS" netns "$NS_NAME"
sudo ip addr add "$IP_OUT_HOST" dev "$VETH_OUT_HOST"
sudo ip link set "$VETH_OUT_HOST" up

sudo ip netns exec "$NS_NAME" ip addr add "$IP_OUT_NS" dev "$VETH_OUT_NS"
sudo ip netns exec "$NS_NAME" ip link set "$VETH_OUT_NS" up

# Enable loopback
sudo ip netns exec "$NS_NAME" ip link set lo up

# Add multicast routes for the traffic generator and listener
# The traffic generator and listener use UDP sockets which require kernel routing
# The relay itself works at Layer 2 and doesn't need routes
sudo ip netns exec "$NS_NAME" ip route add 224.0.0.0/4 dev "$VETH_IN_NS"

echo "Network namespace created successfully with dual veth pairs"
echo "  Ingress:  $VETH_IN_NS ($IP_IN_NS)"
echo "  Egress:   $VETH_OUT_NS ($IP_OUT_NS)"
echo ""

# --- Start Supervisor ---
echo "--- Starting Supervisor in namespace ---"
sudo ip netns exec "$NS_NAME" "$RELAY_BINARY" supervisor \
    --control-socket-path "$SUPERVISOR_SOCKET" \
    --num-workers 1 \
    --interface "$INPUT_INTERFACE" &
SUPERVISOR_PID=$!

echo "--- Waiting for supervisor socket to be created ---"
WAIT_START_TIME=$(date +%s)
while ! sudo ip netns exec "$NS_NAME" test -S "$SUPERVISOR_SOCKET" 2>/dev/null; do
    if [ "$(($(date +%s) - WAIT_START_TIME))" -gt 10 ]; then
        echo "❌ FAILURE: Timed out waiting for supervisor socket."
        exit 1
    fi
    sleep 0.1
done
sudo ip netns exec "$NS_NAME" chmod 666 "$SUPERVISOR_SOCKET"
echo "Supervisor socket found."

# Wait for supervisor to be ready to accept commands (poll list-rules)
echo "--- Waiting for supervisor to be ready ---"
WAIT_START_TIME=$(date +%s)
while true; do
    if sudo ip netns exec "$NS_NAME" "$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" list-rules >/dev/null 2>&1; then
        echo "Supervisor is ready."
        break
    fi
    if [ "$(($(date +%s) - WAIT_START_TIME))" -gt 10 ]; then
        echo "❌ FAILURE: Timed out waiting for supervisor to be ready."
        exit 1
    fi
    sleep 0.1
done
echo ""

# --- Start UDP Listener ---
echo "--- Starting UDP listener (socat) in namespace ---"
# Redirect socat's stdout to file (avoids permission issues with OPEN)
# Listener binds to OUTPUT interface to receive relayed traffic
sudo ip netns exec "$NS_NAME" \
    socat -u UDP4-RECV:${OUTPUT_PORT},ip-add-membership="${OUTPUT_GROUP}:${OUTPUT_INTERFACE}" \
    STDOUT > "$LISTENER_OUTPUT_FILE" &
LISTENER_PID=$!
sleep 1 # Give the listener time to bind
echo ""

# --- Add Forwarding Rule ---
echo "--- Adding Forwarding Rule ---"
sudo ip netns exec "$NS_NAME" "$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" add \
    --input-interface "$INPUT_INTERFACE" \
    --input-group "$INPUT_GROUP" \
    --input-port "$INPUT_PORT" \
    --outputs "$OUTPUT_GROUP:$OUTPUT_PORT:$OUTPUT_INTERFACE"
echo ""

# --- Send Initial Burst ---
echo "--- Sending packets to be relayed ---"
sudo ip netns exec "$NS_NAME" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "$IP_IN_NS_ADDR" \
    --group "$INPUT_GROUP" \
    --port "$INPUT_PORT" \
    --count "$PACKET_COUNT" \
    --payload "$PAYLOAD"

# Brief wait for packets to be processed and received
sleep 0.5

# Kill the listener to force it to flush and close the output file
sudo kill $LISTENER_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true
echo ""

# --- Verify Packets ---
echo "--- Verifying packets were relayed ---"
RECEIVED_COUNT=$(grep -c "$PAYLOAD" "$LISTENER_OUTPUT_FILE" || echo "0")
if [ "$RECEIVED_COUNT" -eq "$PACKET_COUNT" ]; then
    echo "✅ SUCCESS: Received all $PACKET_COUNT packets."
    echo ""
    echo "--- End-to-End Test Passed ---"
    exit 0
else
    echo "❌ FAILURE: Expected $PACKET_COUNT packets, but received $RECEIVED_COUNT."
    echo ""
    exit 1
fi
