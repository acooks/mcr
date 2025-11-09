#!/bin/bash

# End-to-End Data Plane Test
#
# This script verifies the complete data flow of the multicast relay:
# 1. Starts the relay supervisor.
# 2. Starts a UDP listener to capture relayed traffic.
# 3. Adds a forwarding rule via the control client.
# 4. Sends a burst of test packets using the traffic generator.
# 5. Verifies that the listener received the correct number of packets.
# 6. Removes the forwarding rule.
# 7. Sends another burst of packets.
# 8. Verifies that no more packets are received.

set -e
set -u
set -o pipefail

# --- Configuration ---
RELAY_BINARY="target/debug/multicast_relay"
CONTROL_CLIENT_BINARY="target/debug/control_client"
TRAFFIC_GENERATOR_BINARY="target/debug/traffic_generator"

SUPERVISOR_SOCKET="/tmp/mcr_supervisor.sock"
INPUT_INTERFACE="lo"
INPUT_GROUP="239.1.1.1"
INPUT_PORT="5001"
OUTPUT_INTERFACE="lo"
OUTPUT_GROUP="239.10.10.10"
OUTPUT_PORT="6001"
PACKET_COUNT=100
PAYLOAD="E2E_TEST_PACKET"

# --- Cleanup ---
cleanup() {
    echo "--- Cleaning up ---"
    killall -q multicast_relay || true
    killall -q nc || true
    rm -f "$SUPERVISOR_SOCKET"
    echo "Cleanup complete."
}
trap cleanup EXIT

# --- Build ---
echo "--- Building binaries ---"
cargo build

# --- Test ---
echo "--- Starting Supervisor ---"
# Use 1 worker for simple loopback test
sudo -E "$RELAY_BINARY" supervisor --control-socket-path "$SUPERVISOR_SOCKET" --num-workers 1 &
SUPERVISOR_PID=$!

echo "--- Waiting for supervisor socket to be created ---"
WAIT_START_TIME=$(date +%s)
while ! [ -S "$SUPERVISOR_SOCKET" ]; do
    if [ "$(($(date +%s) - WAIT_START_TIME))" -gt 10 ]; then
        echo "❌ FAILURE: Timed out waiting for supervisor socket."
        exit 1
    fi
    sleep 0.1
done
sudo chown "$USER":"$USER" "$SUPERVISOR_SOCKET"
echo "Supervisor socket found."
sleep 2 # Give the supervisor time to start

echo "--- Starting UDP Listener ---"
LISTENER_OUTPUT_FILE=$(mktemp)
nc -ul -w 5 "$OUTPUT_GROUP" "$OUTPUT_PORT" > "$LISTENER_OUTPUT_FILE" &
LISTENER_PID=$!
sleep 1 # Give the listener time to bind

echo "--- Adding Forwarding Rule ---"
"$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" add \
    --input-interface "$INPUT_INTERFACE" \
    --input-group "$INPUT_GROUP" \
    --input-port "$INPUT_PORT" \
    --outputs "$OUTPUT_GROUP:$OUTPUT_PORT:$OUTPUT_INTERFACE"

echo "--- Sending initial burst of packets (should be relayed) ---"
"$TRAFFIC_GENERATOR_BINARY" \
    --interface "127.0.0.1" \
    --group "$INPUT_GROUP" \
    --port "$INPUT_PORT" \
    --count "$PACKET_COUNT" \
    --payload "$PAYLOAD"

sleep 2 # Allow time for packets to be processed and received

echo "--- Verifying initial burst ---"
RECEIVED_COUNT=$(grep -c "$PAYLOAD" "$LISTENER_OUTPUT_FILE")
if [ "$RECEIVED_COUNT" -eq "$PACKET_COUNT" ]; then
    echo "✅ SUCCESS: Received all $PACKET_COUNT packets."
else
    echo "❌ FAILURE: Expected $PACKET_COUNT packets, but received $RECEIVED_COUNT."
    exit 1
fi

echo "--- Removing Forwarding Rule ---"
# First, get the rule ID
RULE_ID=$("$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" list-rules | grep -o -E '[0-9a-f-]{36}')
"$CONTROL_CLIENT_BINARY" --socket-path "$SUPERVISOR_SOCKET" remove --rule-id "$RULE_ID"

# Clear the listener output file for the next check
> "$LISTENER_OUTPUT_FILE"

echo "--- Sending second burst of packets (should NOT be relayed) ---"
"$TRAFFIC_GENERATOR_BINARY" \
    --interface "127.0.0.1" \
    --group "$INPUT_GROUP" \
    --port "$INPUT_PORT" \
    --count "$PACKET_COUNT" \
    --payload "$PAYLOAD"

sleep 2

echo "--- Verifying second burst ---"
RECEIVED_COUNT_AFTER_REMOVE=$(grep -c "$PAYLOAD" "$LISTENER_OUTPUT_FILE")
if [ "$RECEIVED_COUNT_AFTER_REMOVE" -eq 0 ]; then
    echo "✅ SUCCESS: Received 0 packets after rule removal."
else
    echo "❌ FAILURE: Expected 0 packets after rule removal, but received $RECEIVED_COUNT_AFTER_REMOVE."
    exit 1
fi

echo "--- End-to-End Test Passed ---"
exit 0