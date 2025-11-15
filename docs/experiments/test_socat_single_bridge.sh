#!/bin/bash
# Test socat's ability to forward multicast across a single bridge
# This validates whether socat can act as a multicast relay in the simplest case

set -e

MCAST_ADDR_IN="239.255.0.1"
MCAST_ADDR_OUT="239.255.0.2"
MCAST_PORT="5001"

echo "=== Single Bridge Multicast Forwarding Test ==="
echo "Testing if socat can forward multicast packets across a bridge"
echo ""

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    sudo ip netns del src-ns 2>/dev/null || true
    sudo ip netns del relay-ns 2>/dev/null || true
    sudo ip netns del sink-ns 2>/dev/null || true
    sudo pkill -f "socat.*UDP4-RECV" 2>/dev/null || true
    sudo pkill -f "nc -u -l" 2>/dev/null || true
}

trap cleanup EXIT

# Create namespaces
echo "Creating network namespaces..."
sudo ip netns add src-ns
sudo ip netns add relay-ns
sudo ip netns add sink-ns

# Create veth pairs: src <-> relay <-> sink
echo "Creating veth pairs..."
sudo ip link add veth-src0 type veth peer name veth-relay0
sudo ip link add veth-relay1 type veth peer name veth-sink0

# Move interfaces to namespaces
sudo ip link set veth-src0 netns src-ns
sudo ip link set veth-relay0 netns relay-ns
sudo ip link set veth-relay1 netns relay-ns
sudo ip link set veth-sink0 netns sink-ns

# Configure src namespace
echo "Configuring source namespace..."
sudo ip netns exec src-ns ip addr add 10.0.1.1/24 dev veth-src0
sudo ip netns exec src-ns ip link set veth-src0 up
sudo ip netns exec src-ns ip link set lo up

# Configure relay namespace
echo "Configuring relay namespace..."
sudo ip netns exec relay-ns ip addr add 10.0.1.2/24 dev veth-relay0
sudo ip netns exec relay-ns ip addr add 10.0.2.1/24 dev veth-relay1
sudo ip netns exec relay-ns ip link set veth-relay0 up
sudo ip netns exec relay-ns ip link set veth-relay1 up
sudo ip netns exec relay-ns ip link set lo up

# Configure sink namespace
echo "Configuring sink namespace..."
sudo ip netns exec sink-ns ip addr add 10.0.2.2/24 dev veth-sink0
sudo ip netns exec sink-ns ip link set veth-sink0 up
sudo ip netns exec sink-ns ip link set lo up

# Add routes
sudo ip netns exec src-ns ip route add 10.0.2.0/24 via 10.0.1.2
sudo ip netns exec sink-ns ip route add 10.0.1.0/24 via 10.0.2.1

# Enable IP forwarding in relay namespace (needed for Layer 3 routing)
sudo ip netns exec relay-ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Add multicast routes in relay namespace
sudo ip netns exec relay-ns ip route add 239.255.0.0/24 dev veth-relay1
sudo ip netns exec src-ns ip route add 239.255.0.0/24 dev veth-src0

echo ""
echo "=== Starting Receiver in sink namespace ==="
# Start receiver that will log received packets (listening for OUTPUT multicast address)
sudo ip netns exec sink-ns socat -u \
    UDP4-RECV:${MCAST_PORT},ip-add-membership=${MCAST_ADDR_OUT}:veth-sink0,reuseaddr \
    OPEN:/tmp/sink_received.txt,creat,append &
RECEIVER_PID=$!
sleep 1

echo ""
echo "=== Starting socat bridge in relay namespace ==="
# Start socat to bridge multicast between the two interfaces
# Using UDP4-RECV → UDP4-SEND pattern (same as compare_socat_bridge.sh)
# Relay from MCAST_ADDR_IN to MCAST_ADDR_OUT (different multicast groups)
sudo ip netns exec relay-ns socat -u -v \
    UDP4-RECV:${MCAST_PORT},ip-add-membership=${MCAST_ADDR_IN}:veth-relay0,reuseaddr \
    UDP4-SEND:${MCAST_ADDR_OUT}:${MCAST_PORT},ip-multicast-if=10.0.2.1,reuseaddr \
    2>/tmp/socat_debug.log &
SOCAT_PID=$!
sleep 1

echo ""
echo "=== Sending multicast packets from source ==="
# Send test packets - need to bind to source interface
for i in {1..5}; do
    echo "Packet $i from source" | sudo ip netns exec src-ns socat STDIN UDP4-SENDTO:${MCAST_ADDR_IN}:${MCAST_PORT},bind=10.0.1.1
    sleep 0.5
done

echo ""
echo "=== Waiting for receiver to finish ==="
wait $RECEIVER_PID 2>/dev/null || true
sleep 1

echo ""
echo "=== Results ==="
echo "Packets received at sink:"
if [ -f /tmp/sink_received.txt ]; then
    RECEIVED=$(wc -l < /tmp/sink_received.txt)
    echo "  Received: $RECEIVED packets"
    if [ $RECEIVED -gt 0 ]; then
        echo "  Content:"
        cat /tmp/sink_received.txt | sed 's/^/    /'
        echo ""
        echo "✓ SUCCESS: socat successfully forwarded multicast packets!"
    else
        echo ""
        echo "✗ FAILURE: No packets received at sink"
        echo "  This means socat did NOT forward multicast packets across the bridge"
    fi
else
    echo "  No output file created"
    echo "✗ FAILURE: Receiver did not capture any data"
fi

# Cleanup temp file
rm -f /tmp/sink_received.txt

echo ""
echo "=== Test Complete ==="
