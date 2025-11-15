#!/bin/bash
#
# Test: socat multicast in dual-bridge topology
# Tests two solutions: ip-multicast-if vs multicast route
#
set -euo pipefail

NETNS="test_mcast_solutions"

cleanup() {
    echo "[Cleanup]"
    ip netns pids "$NETNS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$NETNS" 2>/dev/null || true
    rm -f /tmp/sink_test1.bin /tmp/sink_test2.bin
}
trap cleanup EXIT

# Setup topology
echo "=== Setting up dual-bridge topology ==="
ip netns add "$NETNS"
ip netns exec "$NETNS" ip link set lo up

# Bridge 0 (ingress)
ip netns exec "$NETNS" ip link add br0 type bridge
ip netns exec "$NETNS" ip link set br0 up type bridge mcast_snooping 0 stp_state 0

# Bridge 1 (egress)
ip netns exec "$NETNS" ip link add br1 type bridge
ip netns exec "$NETNS" ip link set br1 up type bridge mcast_snooping 0 stp_state 0

# Generator on br0
ip netns exec "$NETNS" ip link add veth-gen type veth peer name veth-gen-p
ip netns exec "$NETNS" ip addr add 10.0.0.10/24 dev veth-gen
ip netns exec "$NETNS" ip link set veth-gen up
ip netns exec "$NETNS" ip link set veth-gen-p up master br0

# Relay ingress on br0
ip netns exec "$NETNS" ip link add veth-mcr0 type veth peer name veth-mcr0-p
ip netns exec "$NETNS" ip addr add 10.0.0.20/24 dev veth-mcr0
ip netns exec "$NETNS" ip link set veth-mcr0 up
ip netns exec "$NETNS" ip link set veth-mcr0-p up master br0

# Relay egress on br1
ip netns exec "$NETNS" ip link add veth-mcr1 type veth peer name veth-mcr1-p
ip netns exec "$NETNS" ip addr add 10.0.1.20/24 dev veth-mcr1
ip netns exec "$NETNS" ip link set veth-mcr1 up
ip netns exec "$NETNS" ip link set veth-mcr1-p up master br1

# Sink on br1
ip netns exec "$NETNS" ip link add veth-sink type veth peer name veth-sink-p
ip netns exec "$NETNS" ip addr add 10.0.1.30/24 dev veth-sink
ip netns exec "$NETNS" ip link set veth-sink up
ip netns exec "$NETNS" ip link set veth-sink-p up master br1

echo "[OK] Topology created"
echo ""

# ==============================================================================
# TEST 1: Using ip-multicast-if socket option
# ==============================================================================
echo "=== TEST 1: Using ip-multicast-if ==="
echo ""

# Start sink
ip netns exec "$NETNS" socat -u \
    UDP4-RECV:5099,ip-add-membership=239.9.9.9:veth-sink,reuseaddr \
    CREATE:/tmp/sink_test1.bin &
SINK1=$!
sleep 1

# Start relay with ip-multicast-if
echo "Starting relay with: ip-multicast-if=10.0.1.20"
ip netns exec "$NETNS" socat -u \
    UDP4-RECV:5001,ip-add-membership=239.1.1.1:veth-mcr0,reuseaddr \
    UDP4-SEND:239.9.9.9:5099,bind=10.0.1.20,ip-multicast-if=10.0.1.20 &
RELAY1=$!
sleep 1

# Send 5 test packets
echo "Sending 5 test packets..."
for i in {1..5}; do
    ip netns exec "$NETNS" /home/acooks/mcr/target/release/traffic_generator \
        --interface 10.0.0.10 --group 239.1.1.1 --port 5001 \
        --rate 10 --size 1024 --count 1 2>/dev/null || true
    sleep 0.1
done

sleep 2
kill $RELAY1 $SINK1 2>/dev/null || true
wait $RELAY1 $SINK1 2>/dev/null || true

# Check results
if [ -f /tmp/sink_test1.bin ]; then
    SIZE1=$(stat -c%s /tmp/sink_test1.bin)
    PKTS1=$((SIZE1 / 1024))
    echo "Result: Received $PKTS1/5 packets ($SIZE1 bytes)"
else
    PKTS1=0
    echo "Result: Received 0/5 packets"
fi
echo ""

# ==============================================================================
# TEST 2: Using multicast route
# ==============================================================================
echo "=== TEST 2: Using multicast route ==="
echo ""

# Add multicast route
echo "Adding: ip route add 224.0.0.0/4 dev veth-mcr1"
ip netns exec "$NETNS" ip route add 224.0.0.0/4 dev veth-mcr1
ip netns exec "$NETNS" ip route show | grep 224.0.0.0
echo ""

# Start sink
ip netns exec "$NETNS" socat -u \
    UDP4-RECV:5099,ip-add-membership=239.9.9.9:veth-sink,reuseaddr \
    CREATE:/tmp/sink_test2.bin &
SINK2=$!
sleep 1

# Start relay WITHOUT ip-multicast-if (relying on route)
echo "Starting relay with: bind=10.0.1.20 (no ip-multicast-if)"
ip netns exec "$NETNS" socat -u \
    UDP4-RECV:5001,ip-add-membership=239.1.1.1:veth-mcr0,reuseaddr \
    UDP4-SEND:239.9.9.9:5099,bind=10.0.1.20 &
RELAY2=$!
sleep 1

# Send 5 test packets
echo "Sending 5 test packets..."
for i in {1..5}; do
    ip netns exec "$NETNS" /home/acooks/mcr/target/release/traffic_generator \
        --interface 10.0.0.10 --group 239.1.1.1 --port 5001 \
        --rate 10 --size 1024 --count 1 2>/dev/null || true
    sleep 0.1
done

sleep 2
kill $RELAY2 $SINK2 2>/dev/null || true
wait $RELAY2 $SINK2 2>/dev/null || true

# Check results
if [ -f /tmp/sink_test2.bin ]; then
    SIZE2=$(stat -c%s /tmp/sink_test2.bin)
    PKTS2=$((SIZE2 / 1024))
    echo "Result: Received $PKTS2/5 packets ($SIZE2 bytes)"
else
    PKTS2=0
    echo "Result: Received 0/5 packets"
fi
echo ""

# ==============================================================================
# SUMMARY
# ==============================================================================
echo "=========================================="
echo "           TEST SUMMARY"
echo "=========================================="
echo ""
echo "TEST 1 (ip-multicast-if): $PKTS1/5 packets"
echo "TEST 2 (multicast route): $PKTS2/5 packets"
echo ""

if [ $PKTS1 -ge 4 ] && [ $PKTS2 -ge 4 ]; then
    echo "✅ BOTH solutions work!"
    echo "   - ip-multicast-if is more explicit and portable"
    echo "   - multicast route is system-wide and affects all processes"
elif [ $PKTS1 -ge 4 ]; then
    echo "✅ ip-multicast-if works!"
    echo "⚠️  multicast route does NOT work"
elif [ $PKTS2 -ge 4 ]; then
    echo "✅ multicast route works!"
    echo "⚠️  ip-multicast-if does NOT work"
else
    echo "❌ BOTH solutions FAILED"
    echo "   Additional investigation needed"
fi
echo ""

exit 0
