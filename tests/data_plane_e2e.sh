#!/bin/bash

# End-to-End Test for Data Plane Forwarding Correctness
#
# This test verifies that the multicast_relay can successfully receive, forward,
# and retransmit a multicast stream according to a dynamically configured rule.
#
# It uses network namespaces to create an isolated environment, ensuring the
# test does not interfere with the host system's network configuration and can
# be run without requiring root privileges for the main logic.

set -e
set -o pipefail

# --- Configuration ---
NS_NAME="mcr_e2e_test"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
IP_HOST="192.168.200.1/24"
IP_NS="192.168.200.2/24"

INPUT_GROUP="224.10.10.1"
INPUT_PORT="5001"
OUTPUT_GROUP="225.10.10.1"
OUTPUT_PORT="6001"
PACKET_COUNT=10
PACKET_PAYLOAD="E2E-TEST-PACKET"

RELAY_COMMAND_SOCKET="/tmp/mcr_relay_e2e.sock"
OUTPUT_FILE="/tmp/mcr_e2e_output.txt"

# --- Helper Functions ---
cleanup() {
    echo "--- Cleaning up ---"
    # Kill all background processes that were started by this script
    # The '|| true' prevents the script from exiting if a process is already gone
    pkill -P $$ || true
    wait || true

    # Remove the network namespace
    sudo ip netns del "$NS_NAME" 2>/dev/null || true

    # Clean up temporary files
    rm -f "$RELAY_COMMAND_SOCKET" "$OUTPUT_FILE"
}

# --- Main Test Logic ---

# Ensure cleanup runs on script exit
trap cleanup EXIT

echo "--- Setting up isolated network namespace ---"
sudo ip netns add "$NS_NAME"
sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
sudo ip link set "$VETH_NS" netns "$NS_NAME"

sudo ip addr add "$IP_HOST" dev "$VETH_HOST"
sudo ip link set "$VETH_HOST" up

sudo ip netns exec "$NS_NAME" ip addr add "$IP_NS" dev "$VETH_NS"
sudo ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
sudo ip netns exec "$NS_NAME" ip link set lo up

# Add routes for multicast traffic
sudo ip route add 224.0.0.0/4 dev "$VETH_HOST"
sudo ip netns exec "$NS_NAME" ip route add 224.0.0.0/4 dev "$VETH_NS"

echo "Network namespace '$NS_NAME' created."

echo "--- Building project ---"
cargo build

echo "--- Starting UDP listener (socat) in background ---"
# Run socat inside the namespace to listen for the relayed packets
# It will write the received payload to the output file
sudo ip netns exec "$NS_NAME" \
    socat -u UDP4-RECV:$OUTPUT_PORT,ip-add-membership=$OUTPUT_GROUP:$VETH_NS \
    "OPEN:$OUTPUT_FILE,creat,append" &
LISTENER_PID=$!
echo "Listener started with PID $LISTENER_PID."
sleep 1 # Give socat time to start up

echo "--- Starting multicast_relay in background ---"
# Run the relay inside the namespace
# Note: The relay needs to be run with sudo to have CAP_NET_RAW for AF_PACKET
    sudo ip netns exec "$NS_NAME" \
        ./target/debug/multicast_relay supervisor \
        --relay-command-socket-path "$RELAY_COMMAND_SOCKET" \
        --user root \
        --group root &
RELAY_PID=$!
echo "Relay started with PID $RELAY_PID."
sleep 5 # Give the relay time to initialize and for ports to clear

echo "--- Adding forwarding rule ---"# The control client runs in the host namespace but communicates via the shared socket
./target/debug/control_client --socket-path "$RELAY_COMMAND_SOCKET" add \
    --rule-id "e2e-data-test" \
    --input-interface "$VETH_NS" \
    --input-group "$INPUT_GROUP" \
    --input-port "$INPUT_PORT" \
    --outputs "$OUTPUT_GROUP:$OUTPUT_PORT:$VETH_NS"

echo "Rule added."

echo "--- Sending $PACKET_COUNT test packets ---"
# The traffic generator also runs inside the namespace to send on the correct interface
sudo ip netns exec "$NS_NAME" \
    ./target/debug/traffic_generator \
    --group "$INPUT_GROUP" \
    --port "$INPUT_PORT" \
    --interface "$VETH_NS" \
    --count "$PACKET_COUNT" \
    --payload "$PACKET_PAYLOAD"

echo "Packets sent. Waiting for relay..."
sleep 2 # Allow time for packets to be relayed

echo "--- Verifying results ---"
RECEIVED_COUNT=$(grep -c "$PACKET_PAYLOAD" "$OUTPUT_FILE" || true)

if [ "$RECEIVED_COUNT" -eq "$PACKET_COUNT" ]; then
    echo "✅ SUCCESS: Received exactly $PACKET_COUNT packets."
    exit 0
else
    echo "❌ FAILURE: Expected $PACKET_COUNT packets, but received $RECEIVED_COUNT."
    echo "--- Listener Output ---"
    cat "$OUTPUT_FILE"
    echo "-----------------------"
    exit 1
fi
