#!/bin/bash
#
# Test harness for Helper Socket Pattern experiment
#
# This script creates an isolated network environment using network namespaces
# and veth pairs, then runs the experiment to validate the helper socket pattern.
#
# Requires: sudo privileges for namespace and interface manipulation

set -e

# Configuration
NS_RELAY="ns-relay"
NS_SENDER="ns-sender"
VETH_RELAY="veth-relay"
VETH_SENDER="veth-sender"
IP_RELAY="192.168.100.1"
IP_SENDER="192.168.100.2"
MULTICAST_GROUP="239.255.1.1"
MULTICAST_PORT="9999"
PACKET_COUNT=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

echo "=== Helper Socket Pattern Test Harness ==="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."

    # Kill any running processes
    pkill -f "poc_helper_socket_igmp" 2>/dev/null || true
    pkill -f "nc -u" 2>/dev/null || true

    # Delete namespaces (this also removes veth pairs)
    ip netns del "$NS_RELAY" 2>/dev/null || true
    ip netns del "$NS_SENDER" 2>/dev/null || true

    echo "Cleanup complete"
}

# Register cleanup on exit
trap cleanup EXIT INT TERM

# Step 1: Build the experiment
echo "[Step 1] Building experiment..."
cd "$(dirname "$0")"
cargo build --release 2>&1 | grep -E "(Compiling|Finished)" || true
echo -e "${GREEN}✓${NC} Build complete"
echo ""

# Step 2: Create network namespaces
echo "[Step 2] Creating network namespaces..."
ip netns add "$NS_RELAY" 2>/dev/null || true
ip netns add "$NS_SENDER" 2>/dev/null || true
echo -e "${GREEN}✓${NC} Namespaces created: $NS_RELAY, $NS_SENDER"
echo ""

# Step 3: Create veth pair
echo "[Step 3] Creating veth pair..."
ip link add "$VETH_RELAY" type veth peer name "$VETH_SENDER" 2>/dev/null || true
echo -e "${GREEN}✓${NC} Veth pair created: $VETH_RELAY <-> $VETH_SENDER"
echo ""

# Step 4: Move interfaces to namespaces
echo "[Step 4] Assigning interfaces to namespaces..."
ip link set "$VETH_RELAY" netns "$NS_RELAY"
ip link set "$VETH_SENDER" netns "$NS_SENDER"
echo -e "${GREEN}✓${NC} Interfaces assigned"
echo ""

# Step 5: Configure IP addresses
echo "[Step 5] Configuring IP addresses..."
ip netns exec "$NS_RELAY" ip addr add "$IP_RELAY/24" dev "$VETH_RELAY"
ip netns exec "$NS_SENDER" ip addr add "$IP_SENDER/24" dev "$VETH_SENDER"
echo -e "${GREEN}✓${NC} IP addresses configured"
echo ""

# Step 6: Bring up interfaces
echo "[Step 6] Bringing up interfaces..."
ip netns exec "$NS_RELAY" ip link set lo up
ip netns exec "$NS_RELAY" ip link set "$VETH_RELAY" up
ip netns exec "$NS_SENDER" ip link set lo up
ip netns exec "$NS_SENDER" ip link set "$VETH_SENDER" up
echo -e "${GREEN}✓${NC} Interfaces up"
echo ""

# Step 7: Add multicast route in relay namespace
echo "[Step 7] Configuring multicast routing..."
ip netns exec "$NS_RELAY" ip route add 224.0.0.0/4 dev "$VETH_RELAY" 2>/dev/null || true
echo -e "${GREEN}✓${NC} Multicast routes configured"
echo ""

# Step 8: Start receiver in background
echo "[Step 8] Starting receiver in $NS_RELAY namespace..."
echo ""
ip netns exec "$NS_RELAY" ./target/release/poc_helper_socket_igmp "$VETH_RELAY" &
RECEIVER_PID=$!

# Give receiver time to start and join multicast group
sleep 2

# Step 9: Send multicast packets
echo ""
echo "[Step 9] Sending multicast packets from $NS_SENDER namespace..."
echo ""

for i in $(seq 1 $PACKET_COUNT); do
    echo "Sending packet $i/$PACKET_COUNT to $MULTICAST_GROUP:$MULTICAST_PORT"
    ip netns exec "$NS_SENDER" bash -c "echo 'Test packet $i' | nc -u -w1 $MULTICAST_GROUP $MULTICAST_PORT" 2>/dev/null || true
    sleep 0.2
done

# Wait for receiver to finish
echo ""
echo "Waiting for receiver to finish processing..."
sleep 2

# Check if receiver is still running
if kill -0 $RECEIVER_PID 2>/dev/null; then
    echo -e "${YELLOW}Receiver still running, waiting...${NC}"
    wait $RECEIVER_PID || true
fi

echo ""
echo "=== Test Complete ==="
echo ""

# Results will be printed by the receiver process
# Exit code will indicate success/failure
