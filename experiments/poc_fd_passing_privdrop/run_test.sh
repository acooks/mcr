#!/bin/bash
#
# Test harness for File Descriptor Passing with Privilege Drop experiment
#
# This script creates an isolated network environment and runs the experiment
# to validate that AF_PACKET sockets can be passed to unprivileged processes.
#
# Requires: sudo privileges

set -e

# Configuration
NS_RELAY="ns-fdpass"
NS_SENDER="ns-sender"
VETH_RELAY="veth-fdp-r"
VETH_SENDER="veth-fdp-s"
IP_RELAY="192.168.101.1"
IP_SENDER="192.168.101.2"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== FD Passing with Privilege Drop Test Harness ==="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    sudo pkill -f "poc_fd_passing_privdrop" 2>/dev/null || true

    # Delete veth interfaces (need to do this before deleting namespaces)
    sudo ip link del "$VETH_RELAY" 2>/dev/null || true
    sudo ip link del "$VETH_SENDER" 2>/dev/null || true

    # Delete namespaces
    sudo ip netns del "$NS_RELAY" 2>/dev/null || true
    sudo ip netns del "$NS_SENDER" 2>/dev/null || true
    echo "Cleanup complete"
}

trap cleanup EXIT INT TERM

# Build first (as normal user, before becoming root)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check if we're running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Error: Please run this script as a normal user with sudo privileges.${NC}"
    echo "The build step needs to run as your normal user, then the script will use sudo for network setup."
    echo ""
    echo "Usage: ./run_test.sh (it will prompt for sudo when needed)"
    exit 1
fi

echo "[Step 1] Building experiment..."
cd "$SCRIPT_DIR"

# Build and properly check result
set +e  # Temporarily disable exit on error
BUILD_OUTPUT=$(cargo build --release 2>&1)
BUILD_EXIT=$?
set -e  # Re-enable exit on error

# Show compilation progress
echo "$BUILD_OUTPUT" | grep -E "(Compiling|Finished)"

# Check if build actually succeeded
if [ $BUILD_EXIT -ne 0 ]; then
    echo -e "${RED}✗${NC} Build failed"
    echo "$BUILD_OUTPUT" | grep -E "error"
    exit 1
fi

# Verify binary exists
if [ ! -f "$SCRIPT_DIR/target/release/poc_fd_passing_privdrop" ]; then
    echo -e "${RED}✗${NC} Binary not found after build"
    exit 1
fi

echo -e "${GREEN}✓${NC} Build complete"
echo ""

# Now perform privileged operations
echo "Setting up network environment (requires sudo)..."
echo ""

# Clean up any leftover resources from previous runs
echo "Pre-flight cleanup..."
sudo ip link del "$VETH_RELAY" 2>/dev/null || true
sudo ip link del "$VETH_SENDER" 2>/dev/null || true
sudo ip netns del "$NS_RELAY" 2>/dev/null || true
sudo ip netns del "$NS_SENDER" 2>/dev/null || true
echo ""

# Create namespaces
echo "[Step 2] Creating network namespaces..."
sudo ip netns add "$NS_RELAY"
sudo ip netns add "$NS_SENDER"
echo -e "${GREEN}✓${NC} Namespaces created"
echo ""

# Create veth pair
echo "[Step 3] Creating veth pair..."
sudo ip link add "$VETH_RELAY" type veth peer name "$VETH_SENDER"
echo -e "${GREEN}✓${NC} Veth pair created"
echo ""

# Assign to namespaces
echo "[Step 4] Assigning interfaces to namespaces..."
sudo ip link set "$VETH_RELAY" netns "$NS_RELAY"
sudo ip link set "$VETH_SENDER" netns "$NS_SENDER"
echo -e "${GREEN}✓${NC} Interfaces assigned"
echo ""

# Configure IPs
echo "[Step 5] Configuring IP addresses..."
sudo ip netns exec "$NS_RELAY" ip addr add "$IP_RELAY/24" dev "$VETH_RELAY"
sudo ip netns exec "$NS_SENDER" ip addr add "$IP_SENDER/24" dev "$VETH_SENDER"
echo -e "${GREEN}✓${NC} IP addresses configured"
echo ""

# Bring up interfaces
echo "[Step 6] Bringing up interfaces..."
sudo ip netns exec "$NS_RELAY" ip link set lo up
sudo ip netns exec "$NS_RELAY" ip link set "$VETH_RELAY" up
sudo ip netns exec "$NS_SENDER" ip link set lo up
sudo ip netns exec "$NS_SENDER" ip link set "$VETH_SENDER" up
echo -e "${GREEN}✓${NC} Interfaces up"
echo ""

# Run experiment
echo "[Step 7] Running experiment in $NS_RELAY namespace..."
echo ""
sudo ip netns exec "$NS_RELAY" "$SCRIPT_DIR/target/release/poc_fd_passing_privdrop" "$VETH_RELAY"
RESULT=$?

echo ""
echo "=== Test Complete ==="
echo ""

exit $RESULT
