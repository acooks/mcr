#!/bin/bash
# Simple wrapper to test individual requirements

TEST_NAME="$1"

case "$TEST_NAME" in
  "no-ip-forward")
    # Comment out IP forwarding
    sed -i 's/^sudo ip netns exec relay-ns sysctl/# DISABLED: &/' test_socat_single_bridge.sh
    ;;
  "no-relay-route")
    # Comment out relay multicast route
    sed -i 's/^sudo ip netns exec relay-ns ip route add 239/# DISABLED: &/' test_socat_single_bridge.sh
    ;;
  "no-src-route")
    # Comment out source multicast route
    sed -i 's/^sudo ip netns exec src-ns ip route add 239/# DISABLED: &/' test_socat_single_bridge.sh
    ;;
  "same-address")
    # Use same multicast address
    sed -i 's/^MCAST_ADDR_OUT="239.255.0.2"/MCAST_ADDR_OUT="239.255.0.1" # MODIFIED/' test_socat_single_bridge.sh
    ;;
  "restore")
    # Restore from git
    git checkout test_socat_single_bridge.sh 2>/dev/null || echo "Could not restore from git"
    # Reapply our working changes
    sed -i '7,9s/.*/MCAST_ADDR_IN="239.255.0.1"\nMCAST_ADDR_OUT="239.255.0.2"\nMCAST_PORT="5001"/' test_socat_single_bridge.sh
    ;;
  *)
    echo "Usage: $0 {no-ip-forward|no-relay-route|no-src-route|same-address|restore}"
    exit 1
    ;;
esac

echo "Modified test for: $TEST_NAME"
echo "Running test..."
sudo ./test_socat_single_bridge.sh 2>&1 | grep -E "(TEST|Result|SUCCESS|FAILURE|received)"
