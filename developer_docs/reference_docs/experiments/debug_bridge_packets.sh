#!/bin/bash
#
# Debug: Where are packets getting lost in bridge topology?
#
set -euo pipefail

NETNS="debug_bridge"

cleanup() {
    pkill -f "tcpdump.*$NETNS" 2>/dev/null || true
    ip netns pids "$NETNS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$NETNS" 2>/dev/null || true
}
trap cleanup EXIT

# Setup
ip netns add "$NETNS"
ip netns exec "$NETNS" ip link set lo up

# Bridge 0
ip netns exec "$NETNS" ip link add br0 type bridge
ip netns exec "$NETNS" ip link set br0 up type bridge mcast_snooping 0 stp_state 0

# Bridge 1
ip netns exec "$NETNS" ip link add br1 type bridge
ip netns exec "$NETNS" ip link set br1 up type bridge mcast_snooping 0 stp_state 0

# Generator
ip netns exec "$NETNS" ip link add veth-gen type veth peer name veth-gen-p
ip netns exec "$NETNS" ip addr add 10.0.0.10/24 dev veth-gen
ip netns exec "$NETNS" ip link set veth-gen up
ip netns exec "$NETNS" ip link set veth-gen-p up master br0

# Relay ingress
ip netns exec "$NETNS" ip link add veth-mcr0 type veth peer name veth-mcr0-p
ip netns exec "$NETNS" ip addr add 10.0.0.20/24 dev veth-mcr0
ip netns exec "$NETNS" ip link set veth-mcr0 up
ip netns exec "$NETNS" ip link set veth-mcr0-p up master br0

# Relay egress
ip netns exec "$NETNS" ip link add veth-mcr1 type veth peer name veth-mcr1-p
ip netns exec "$NETNS" ip addr add 10.0.1.20/24 dev veth-mcr1
ip netns exec "$NETNS" ip link set veth-mcr1 up
ip netns exec "$NETNS" ip link set veth-mcr1-p up master br1

# Sink
ip netns exec "$NETNS" ip link add veth-sink type veth peer name veth-sink-p
ip netns exec "$NETNS" ip addr add 10.0.1.30/24 dev veth-sink
ip netns exec "$NETNS" ip link set veth-sink up
ip netns exec "$NETNS" ip link set veth-sink-p up master br1

echo "=== Topology ready ==="
echo ""

# Add multicast route
echo "Adding multicast route..."
ip netns exec "$NETNS" ip route add 224.0.0.0/4 dev veth-mcr1
echo ""

# Start tcpdump on all key interfaces
echo "=== Starting packet captures ==="
ip netns exec "$NETNS" tcpdump -i veth-mcr0 -n 'udp port 5001' -c 3 -l 2>&1 | sed 's/^/[veth-mcr0 INGRESS] /' &
DUMP1=$!

ip netns exec "$NETNS" tcpdump -i veth-mcr1 -n 'udp port 5099' -c 3 -l 2>&1 | sed 's/^/[veth-mcr1 EGRESS]  /' &
DUMP2=$!

ip netns exec "$NETNS" tcpdump -i veth-sink -n 'udp port 5099' -c 3 -l 2>&1 | sed 's/^/[veth-sink FINAL]   /' &
DUMP3=$!

sleep 2

# Start socat processes
echo "=== Starting socat sink and relay ==="
ip netns exec "$NETNS" socat -u \
    UDP4-RECV:5099,ip-add-membership=239.9.9.9:veth-sink,reuseaddr \
    OPEN:/tmp/debug_sink.bin,creat,append 2>&1 | sed 's/^/[socat sink]  /' &
SINK=$!

sleep 1

ip netns exec "$NETNS" socat -u \
    UDP4-RECV:5001,ip-add-membership=239.1.1.1:veth-mcr0,reuseaddr \
    UDP4-SEND:239.9.9.9:5099,bind=10.0.1.20 -d -d 2>&1 | sed 's/^/[socat relay] /' &
RELAY=$!

sleep 2

# Send 3 packets
echo "=== Sending 3 test packets ==="
for i in {1..3}; do
    echo "Packet $i..."
    ip netns exec "$NETNS" /home/acooks/mcr/target/release/mcrgen \
        --interface 10.0.0.10 --group 239.1.1.1 --port 5001 \
        --rate 5 --size 1024 --count 1 >/dev/null 2>&1 || true
    sleep 0.5
done

echo ""
echo "=== Waiting for captures ==="
sleep 3

kill $RELAY $SINK 2>/dev/null || true
wait $DUMP1 $DUMP2 $DUMP3 2>/dev/null || true

echo ""
echo "=== Results ==="
if [ -f /tmp/debug_sink.bin ]; then
    SIZE=$(stat -c%s /tmp/debug_sink.bin)
    echo "Sink received: $SIZE bytes ($((SIZE / 1024)) packets)"
else
    echo "Sink received: 0 bytes"
fi
