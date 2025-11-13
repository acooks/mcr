#!/bin/bash

# Data Plane Pipeline Test with Virtual Ethernet Interfaces
#
# Creates a clean 3-hop pipeline using veth pairs to avoid loopback feedback:
# Traffic Generator → veth0 → MCR-1 → veth1 → MCR-2 → veth2 → MCR-3
#
# Each veth pair connects two MCR instances, eliminating the feedback loop
# problem that occurs with loopback interfaces.

set -e
set -u
set -o pipefail

# --- Configuration ---
RELAY_BINARY="target/release/multicast_relay"
CONTROL_CLIENT_BINARY="target/release/control_client"
TRAFFIC_GENERATOR_BINARY="target/release/traffic_generator"

# Socket paths for each MCR instance
MCR1_SOCKET="/tmp/mcr_veth_1.sock"
MCR2_SOCKET="/tmp/mcr_veth_2.sock"
MCR3_SOCKET="/tmp/mcr_veth_3.sock"

# Relay command socket paths (for supervisor-worker communication)
MCR1_RELAY_SOCKET="/tmp/mcr_veth_1_relay.sock"
MCR2_RELAY_SOCKET="/tmp/mcr_veth_2_relay.sock"
MCR3_RELAY_SOCKET="/tmp/mcr_veth_3_relay.sock"

# Virtual interface names
VETH0="veth0"       # Traffic generator endpoint
VETH0_PEER="veth0p" # MCR-1 ingress
VETH1A="veth1a"     # MCR-1 egress
VETH1B="veth1b"     # MCR-2 ingress
VETH2A="veth2a"     # MCR-2 egress
VETH2B="veth2b"     # MCR-3 ingress

# Test parameters
# Packet size: 1400 bytes leaves room for UDP (8) + IP (20) + Ethernet (14) = 42 bytes of headers
# Total on-wire: 1442 bytes, well under MTU 1500, so no fragmentation
PACKET_SIZE=1400
PACKET_COUNT=10000000  # 10M packets
SEND_RATE=1000000      # Target 1M pps (will achieve ~667k pps for 15 sec = 10M packets)

# --- Cleanup ---
cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    sudo killall -q multicast_relay || true
    sudo killall -q traffic_generator || true
    rm -f "$MCR1_SOCKET" "$MCR2_SOCKET" "$MCR3_SOCKET"
    rm -f "$MCR1_RELAY_SOCKET" "$MCR2_RELAY_SOCKET" "$MCR3_RELAY_SOCKET"

    # Remove veth interfaces
    sudo ip link del "$VETH0" 2>/dev/null || true
    sudo ip link del "$VETH1A" 2>/dev/null || true
    sudo ip link del "$VETH2A" 2>/dev/null || true

    echo "Cleanup complete."
}
trap cleanup EXIT

# --- Build ---
echo "=== Building Release Binaries ==="
cargo build --release
echo ""

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script requires root privileges."
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Setup Virtual Interfaces ---
echo "=== Setting Up Virtual Ethernet Interfaces ==="
cleanup  # Ensure clean state

# Create veth pair for traffic generator → MCR-1
echo "Creating $VETH0 ←→ $VETH0_PEER (Traffic Gen → MCR-1)"
ip link add "$VETH0" type veth peer name "$VETH0_PEER"
ip addr add 10.0.0.1/24 dev "$VETH0"
ip addr add 10.0.0.2/24 dev "$VETH0_PEER"
ip link set "$VETH0" up
ip link set "$VETH0_PEER" up

# Create veth pair for MCR-1 → MCR-2
echo "Creating $VETH1A ←→ $VETH1B (MCR-1 → MCR-2)"
ip link add "$VETH1A" type veth peer name "$VETH1B"
ip addr add 10.0.1.1/24 dev "$VETH1A"
ip addr add 10.0.1.2/24 dev "$VETH1B"
ip link set "$VETH1A" up
ip link set "$VETH1B" up

# Create veth pair for MCR-2 → MCR-3
echo "Creating $VETH2A ←→ $VETH2B (MCR-2 → MCR-3)"
ip link add "$VETH2A" type veth peer name "$VETH2B"
ip addr add 10.0.2.1/24 dev "$VETH2A"
ip addr add 10.0.2.2/24 dev "$VETH2B"
ip link set "$VETH2A" up
ip link set "$VETH2B" up

echo "Virtual interfaces created successfully"
ip link show | grep veth
echo ""

# --- Start MCR Instances ---
echo "=== Starting 3-Hop MCR Pipeline ==="

# Start MCR-1 (ingress: veth0p, egress: veth1a)
echo "Starting MCR-1 (ingress: $VETH0_PEER, egress: $VETH1A)..."
"$RELAY_BINARY" supervisor \
    --relay-command-socket-path "$MCR1_RELAY_SOCKET" \
    --control-socket-path "$MCR1_SOCKET" \
    --interface "$VETH0_PEER" \
    --num-workers 1 \
    --user "$SUDO_USER" \
    --group "$SUDO_USER" > /tmp/mcr1_veth.log 2>&1 &
MCR1_PID=$!

# Start MCR-2 (ingress: veth1b, egress: veth2a)
echo "Starting MCR-2 (ingress: $VETH1B, egress: $VETH2A)..."
"$RELAY_BINARY" supervisor \
    --relay-command-socket-path "$MCR2_RELAY_SOCKET" \
    --control-socket-path "$MCR2_SOCKET" \
    --interface "$VETH1B" \
    --num-workers 1 \
    --user "$SUDO_USER" \
    --group "$SUDO_USER" > /tmp/mcr2_veth.log 2>&1 &
MCR2_PID=$!

# Start MCR-3 (ingress: veth2b)
echo "Starting MCR-3 (ingress: $VETH2B)..."
"$RELAY_BINARY" supervisor \
    --relay-command-socket-path "$MCR3_RELAY_SOCKET" \
    --control-socket-path "$MCR3_SOCKET" \
    --interface "$VETH2B" \
    --num-workers 1 \
    --user "$SUDO_USER" \
    --group "$SUDO_USER" > /tmp/mcr3_veth.log 2>&1 &
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

# MCR-1: Receive on veth0p (239.1.1.1:5001) → Forward to veth1a (239.2.2.2:5002)
echo "MCR-1: $VETH0_PEER (239.1.1.1:5001) → $VETH1A (239.2.2.2:5002)"
sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$MCR1_SOCKET" add \
    --input-interface "$VETH0_PEER" \
    --input-group "239.1.1.1" \
    --input-port 5001 \
    --outputs "239.2.2.2:5002:$VETH1A" > /dev/null

# MCR-2: Receive on veth1b (239.2.2.2:5002) → Forward to veth2a (239.3.3.3:5003)
echo "MCR-2: $VETH1B (239.2.2.2:5002) → $VETH2A (239.3.3.3:5003)"
sudo -u "$SUDO_USER" "$CONTROL_CLIENT_BINARY" --socket-path "$MCR2_SOCKET" add \
    --input-interface "$VETH1B" \
    --input-group "239.2.2.2" \
    --input-port 5002 \
    --outputs "239.3.3.3:5003:$VETH2A" > /dev/null

# MCR-3: Receive on veth2b (239.3.3.3:5003) → No output (terminus)
echo "MCR-3: $VETH2B (239.3.3.3:5003) → (terminus - measuring ingress only)"

echo "Pipeline configured successfully"
sleep 1
echo ""

# --- Start Log Monitoring ---
echo "=== Starting Log Monitoring ==="
echo "Stats from all 3 MCR instances will appear below..."
echo ""

# Monitor logs in background
tail -f /tmp/mcr1_veth.log | sed 's/^/[MCR-1] /' &
TAIL1_PID=$!
tail -f /tmp/mcr2_veth.log | sed 's/^/[MCR-2] /' &
TAIL2_PID=$!
tail -f /tmp/mcr3_veth.log | sed 's/^/[MCR-3] /' &
TAIL3_PID=$!

sleep 2

# --- Run Traffic Generator ---
echo "=== Running Traffic Generator ==="
echo "Sending $PACKET_COUNT packets @ $PACKET_SIZE bytes to $VETH0 (target: $SEND_RATE pps)"
echo ""

# Get the IP address of veth0 for the traffic generator
VETH0_IP=$(ip addr show "$VETH0" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

sudo -u "$SUDO_USER" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "$VETH0_IP" \
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
tail -30 /tmp/mcr1_veth.log | grep -E "\[STATS:Ingress\]|\[STATS:Egress\]" | tail -2 || echo "No stats found"
echo ""
echo "MCR-2 Final Stats:"
tail -30 /tmp/mcr2_veth.log | grep -E "\[STATS:Ingress\]|\[STATS:Egress\]" | tail -2 || echo "No stats found"
echo ""
echo "MCR-3 Final Stats:"
tail -30 /tmp/mcr3_veth.log | grep -E "\[STATS:Ingress\]|\[STATS:Egress\]" | tail -2 || echo "No stats found"

echo ""
echo "=== Pipeline Test Complete ==="
echo "Full logs available at:"
echo "  MCR-1: /tmp/mcr1_veth.log"
echo "  MCR-2: /tmp/mcr2_veth.log"
echo "  MCR-3: /tmp/mcr3_veth.log"
echo ""
echo "Virtual interfaces will be cleaned up on exit"

# Cleanup will happen via trap
exit 0
