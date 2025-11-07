#!/bin/bash

# Common functions for End-to-End tests

# --- Configuration ---
NS_NAME="mcr_e2e_test_$$" # Unique namespace name per script run
VETH_HOST="vh-$$"
VETH_NS="vn-$$"
IP_HOST="192.168.200.1/24"
IP_NS="192.168.200.2/24"

RELAY_COMMAND_SOCKET="/tmp/mcr_relay_e2e_$$.sock"
OUTPUT_FILE="/tmp/mcr_e2e_output_$$.txt"

# --- Helper Functions ---

# Function to clean up all resources created by the test
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

# Function to set up an isolated network namespace
setup_namespace() {
    echo "--- Setting up isolated network namespace ($NS_NAME) ---"
    sudo ip netns add "$NS_NAME"
    sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    sudo ip link set "$VETH_NS" netns "$NS_NAME"

    sudo ip addr add "$IP_HOST" dev "$VETH_HOST"
    sudo ip link set "$VETH_HOST" up

    sudo ip netns exec "$NS_NAME" ip addr add "$IP_NS" dev "$VETH_NS"
    sudo ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
    sudo ip netns exec "$NS_NAME" ip link set lo up

    # Add routes for multicast traffic
    sudo ip route add 224.0.0.0/4 dev "$VETH_HOST" src "${IP_HOST%/*}"
    sudo ip netns exec "$NS_NAME" ip route add 224.0.0.0/4 dev "$VETH_NS" src "${IP_NS%/*}"

    echo "Network namespace '$NS_NAME' created."
}

# Function to start the UDP listener (socat) in the namespace
start_listener() {
    local output_group="$1"
    local output_port="$2"
    echo "--- Starting UDP listener (socat) in background ---"
    sudo ip netns exec "$NS_NAME" \
        socat -u UDP4-RECV:$output_port,ip-add-membership="$output_group:$VETH_NS" \
        "OPEN:$OUTPUT_FILE,creat,append" &
    LISTENER_PID=$!
    echo "Listener started with PID $LISTENER_PID."
    sleep 1 # Give socat time to start up
}

# Function to start the multicast_relay supervisor in the namespace
start_relay() {
    echo "--- Starting multicast_relay in background ---"
    # Note: The relay needs to be run with sudo to have CAP_NET_RAW for AF_PACKET
    # The supervisor and workers will run with privileges dropped to the configured user/group
    # (or root if not configured, which is fine for tests).
    sudo ip netns exec "$NS_NAME" \
        ./target/debug/multicast_relay supervisor \
        --relay-command-socket-path "$RELAY_COMMAND_SOCKET" &
    RELAY_PID=$!
    echo "Relay started with PID $RELAY_PID."

    # The socket is created by a root process, so we need to change its ownership
    # to allow the non-root control_client to connect.
    # We need to wait a moment for the socket to be created.
    sleep 1
    sudo chown "$(id -u):$(id -g)" "$RELAY_COMMAND_SOCKET"

    sleep 1 # Give the relay time to fully initialize
}

# Function to send packets using traffic_generator
send_packets() {
    local input_group="$1"
    local input_port="$2"
    local packet_count="$3"
    local packet_payload="$4"
    echo "--- Sending $packet_count test packets ---"
    sudo ip netns exec "$NS_NAME" \
        ./target/debug/traffic_generator \
        --group "$input_group" \
        --port "$input_port" \
        --interface "$VETH_NS" \
        --count "$packet_count" \
        --payload "$packet_payload"
    echo "Packets sent. Waiting for relay..."
    sleep 2 # Allow time for packets to be relayed
}

# Function to add a forwarding rule
add_rule() {
    local rule_id="$1"
    local input_interface="$2"
    local input_group="$3"
    local input_port="$4"
    local output_group="$5"
    local output_port="$6"
    local output_interface="$7"
    echo "--- Adding forwarding rule ($rule_id) ---"
    ./target/debug/control_client --socket-path "$RELAY_COMMAND_SOCKET" add \
        --rule-id "$rule_id" \
        --input-interface "$input_interface" \
        --input-group "$input_group" \
        --input-port "$input_port" \
        --outputs "$output_group:$output_port:$output_interface"
    echo "Rule added."
}

# Function to remove a forwarding rule
remove_rule() {
    local rule_id="$1"
    echo "--- Removing forwarding rule ($rule_id) ---"
    ./target/debug/control_client --socket-path "$RELAY_COMMAND_SOCKET" remove \
        --rule-id "$rule_id"
    echo "Rule removed."
}

# Function to list forwarding rules
list_rules() {
    echo "--- Listing forwarding rules ---"
    ./target/debug/control_client --socket-path "$RELAY_COMMAND_SOCKET" list
}

# Function to get flow statistics
get_stats() {
    echo "--- Getting flow statistics ---"
    ./target/debug/control_client --socket-path "$RELAY_COMMAND_SOCKET" stats
}

# Function to assert the number of packets received
assert_packet_count() {
    local expected_count="$1"
    echo "--- Verifying results ---"
    RECEIVED_COUNT=$(grep -c "E2E-TEST-PACKET" "$OUTPUT_FILE" || true)

    if [ "$RECEIVED_COUNT" -eq "$expected_count" ]; then
        echo "✅ SUCCESS: Received exactly $expected_count packets."
        return 0
    else
        echo "❌ FAILURE: Expected $expected_count packets, but received $RECEIVED_COUNT."
        echo "--- Listener Output ---"
        cat "$OUTPUT_FILE"
        echo "-----------------------"
        return 1
    fi
}

# Function to find PID of a worker process
find_worker_pid() {
    local worker_type="$1" # e.g., "Data Plane", "Control Plane"
    # Find the PID of the worker process within the namespace
    # This assumes the worker process prints "Worker process started." and then its type
    sudo ip netns exec "$NS_NAME" pgrep -f "multicast_relay worker.*$worker_type" | head -n 1
}

# Ensure cleanup runs on script exit
trap cleanup EXIT

# Build the project once for all tests
# This should ideally be done by run_all.sh or a CI system, but for now, keep it here
# to ensure individual test scripts can be run directly during development.
# echo "--- Building project ---"
# cargo build
