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
RELAY_BINARY="target/debug/multicast_relay"
CONTROL_CLIENT_BINARY="target/debug/control_client"
TRAFFIC_GENERATOR_BINARY="target/debug/traffic_generator"

# Use unique paths to avoid conflicts between concurrent test runs
TEST_ID="$$"
NS_NAME="mcr_e2e_${TEST_ID}"
VETH_HOST="vh${TEST_ID}"
VETH_NS="vn${TEST_ID}"
SUPERVISOR_SOCKET=$(mktemp -u --tmpdir mcr_supervisor_XXXXXX.sock)
LISTENER_OUTPUT_FILE="/tmp/mcr_e2e_listener_${TEST_ID}.txt"

# Network configuration
IP_HOST="192.168.100.1/24"
IP_NS="192.168.100.2/24"
IP_NS_ADDR="192.168.100.2"  # Without CIDR for traffic generator

# Test parameters
INPUT_INTERFACE="$VETH_NS"
INPUT_GROUP="239.1.1.1"
INPUT_PORT="5001"
OUTPUT_INTERFACE="$VETH_NS"
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

# --- Build ---
echo "--- Building binaries ---"
cargo build
echo ""

# --- Setup Network Namespace ---
echo "--- Setting up network namespace ($NS_NAME) ---"
sudo ip netns add "$NS_NAME"
sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
sudo ip link set "$VETH_NS" netns "$NS_NAME"

sudo ip addr add "$IP_HOST" dev "$VETH_HOST"
sudo ip link set "$VETH_HOST" up

sudo ip netns exec "$NS_NAME" ip addr add "$IP_NS" dev "$VETH_NS"
sudo ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
sudo ip netns exec "$NS_NAME" ip link set lo up

# Add multicast route for the traffic generator
# The traffic generator uses UDP sockets which require kernel routing
# The relay itself works at Layer 2 and doesn't need routes
sudo ip netns exec "$NS_NAME" ip route add 224.0.0.0/4 dev "$VETH_NS"

echo "Network namespace created successfully"
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
sudo ip netns exec "$NS_NAME" \
    socat -u UDP4-RECV:${OUTPUT_PORT},ip-add-membership="${OUTPUT_GROUP}:${INPUT_INTERFACE}" \
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
    --interface "$IP_NS_ADDR" \
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
