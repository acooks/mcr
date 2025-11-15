#!/bin/bash
#
# Debug version: Single Bridge Test with packet capture
#
set -euo pipefail

NETNS="test_single_bridge_dbg"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TRAFFIC_GEN="$PROJECT_ROOT/target/release/traffic_generator"

cleanup() {
    echo "[Cleanup]"
    pkill -f "tcpdump.*$NETNS" 2>/dev/null || true
    ip netns pids "$NETNS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$NETNS" 2>/dev/null || true
    rm -f /tmp/single_bridge_sink.bin
}
trap cleanup EXIT

echo "=== Single Bridge Test (Debug Mode) ==="
echo ""

# Create namespace
ip netns add "$NETNS"
ip netns exec "$NETNS" ip link set lo up

# Create single bridge
ip netns exec "$NETNS" ip link add br0 type bridge
ip netns exec "$NETNS" ip link set br0 up type bridge mcast_snooping 0 stp_state 0

# Create three veth pairs
ip netns exec "$NETNS" ip link add veth-gen type veth peer name veth-gen-p
ip netns exec "$NETNS" ip addr add 10.0.0.10/24 dev veth-gen
ip netns exec "$NETNS" ip link set veth-gen up
ip netns exec "$NETNS" ip link set veth-gen-p up master br0

ip netns exec "$NETNS" ip link add veth-relay type veth peer name veth-relay-p
ip netns exec "$NETNS" ip addr add 10.0.0.20/24 dev veth-relay
ip netns exec "$NETNS" ip link set veth-relay up
ip netns exec "$NETNS" ip link set veth-relay-p up master br0

ip netns exec "$NETNS" ip link add veth-sink type veth peer name veth-sink-p
ip netns exec "$NETNS" ip addr add 10.0.0.30/24 dev veth-sink
ip netns exec "$NETNS" ip link set veth-sink up
ip netns exec "$NETNS" ip link set veth-sink-p up master br0

echo "[OK] Topology created"
echo ""

# Start packet captures BEFORE starting socat
echo "[Debug] Starting packet captures..."
ip netns exec "$NETNS" tcpdump -i veth-relay -n 'udp port 5001' -c 3 -l 2>&1 | sed 's/^/[RELAY-RX] /' &
DUMP1=$!

ip netns exec "$NETNS" tcpdump -i veth-relay -n 'udp port 5099' -c 3 -l 2>&1 | sed 's/^/[RELAY-TX] /' &
DUMP2=$!

ip netns exec "$NETNS" tcpdump -i veth-sink -n 'udp port 5099' -c 3 -l 2>&1 | sed 's/^/[SINK-RX]  /' &
DUMP3=$!

sleep 2

# Start sink
echo "[Test] Starting socat sink (listening for 239.9.9.9:5099)..."
ip netns exec "$NETNS" socat -d -d -u \
    UDP4-RECV:5099,ip-add-membership=239.9.9.9:veth-sink,reuseaddr \
    CREATE:/tmp/single_bridge_sink.bin 2>&1 | sed 's/^/[SINK]   /' &
SINK_PID=$!
sleep 1

# Start relay
echo "[Test] Starting socat relay (239.1.1.1:5001 -> 239.9.9.9:5099)..."
ip netns exec "$NETNS" socat -d -d -u \
    UDP4-RECV:5001,ip-add-membership=239.1.1.1:veth-relay,reuseaddr \
    UDP4-SEND:239.9.9.9:5099,bind=10.0.0.20 2>&1 | sed 's/^/[RELAY]  /' &
RELAY_PID=$!
sleep 2

# Send test packets
echo "[Test] Sending 3 test packets..."
for i in {1..3}; do
    echo "  Packet $i..."
    ip netns exec "$NETNS" "$TRAFFIC_GEN" \
        --interface 10.0.0.10 \
        --group 239.1.1.1 \
        --port 5001 \
        --rate 10 \
        --size 1024 \
        --count 1 2>/dev/null || true
    sleep 0.5
done

echo "[Test] Waiting for captures..."
sleep 3

# Stop processes
kill $RELAY_PID $SINK_PID 2>/dev/null || true
wait $DUMP1 $DUMP2 $DUMP3 2>/dev/null || true

# Check results
echo ""
echo "=== RESULTS ==="
if [ -f /tmp/single_bridge_sink.bin ]; then
    SIZE=$(stat -c%s /tmp/single_bridge_sink.bin)
    PACKETS=$((SIZE / 1024))
    echo "Packets received: $PACKETS/3"
else
    echo "Packets received: 0/3"
fi
