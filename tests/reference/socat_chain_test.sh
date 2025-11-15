#!/bin/bash
#
# Reference Test: socat Multicast Chain Relay
#
# Objective: Prove whether socat can relay multicast packets in the simplest
# possible chain topology with perfect isolation and full observability.
#
# Topology:
#   gen-ns (veth0) <-> (veth1) relay-ns (veth2) <-> (veth3) sink-ns
#   10.0.0.1              10.0.0.2  10.0.1.1         10.0.1.2
#
# This is a CORRECTNESS test, not a performance test.
# We send 5 packets at 1 pps to verify the relay mechanism works.
#
# Design Principles:
# - No external dependencies (no common.sh)
# - Verbose output of every action
# - tcpdump on every interface for third-party verification
# - Synchronous execution where possible
# - Self-contained and independently verifiable

set -euo pipefail

# Test configuration
MCAST_IN="239.1.1.1"
MCAST_OUT="239.9.9.9"
PORT_IN="5001"
PORT_OUT="5099"
PACKET_COUNT=5
SEND_RATE=1  # 1 pps for easy debugging

# Working directory for logs
LOGDIR="/tmp/socat_reference_test"
rm -rf "$LOGDIR"
mkdir -p "$LOGDIR"

echo "=========================================="
echo "socat Multicast Chain Reference Test"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Input:  $MCAST_IN:$PORT_IN"
echo "  Output: $MCAST_OUT:$PORT_OUT"
echo "  Packets: $PACKET_COUNT at $SEND_RATE pps"
echo "  Logs: $LOGDIR"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "[CLEANUP] Stopping all processes and removing namespaces..."
    
    # Kill tcpdump processes
    sudo pkill -f "tcpdump.*veth" || true
    
    # Kill socat
    sudo pkill -f "socat.*UDP4" || true
    
    # Delete namespaces (this automatically deletes veth pairs)
    sudo ip netns del gen-ns 2>/dev/null || true
    sudo ip netns del relay-ns 2>/dev/null || true
    sudo ip netns del sink-ns 2>/dev/null || true
    
    echo "[CLEANUP] Complete"
}

trap cleanup EXIT

# Step 1: Create namespaces
echo "[STEP 1] Creating network namespaces..."
sudo ip netns add gen-ns
sudo ip netns add relay-ns
sudo ip netns add sink-ns
echo "  Created: gen-ns, relay-ns, sink-ns"

# Step 2: Create veth pairs
echo ""
echo "[STEP 2] Creating veth pairs..."
sudo ip link add veth0 type veth peer name veth1
sudo ip link add veth2 type veth peer name veth3
echo "  Created: veth0<->veth1, veth2<->veth3"

# Step 3: Move interfaces to namespaces
echo ""
echo "[STEP 3] Assigning interfaces to namespaces..."
sudo ip link set veth0 netns gen-ns
sudo ip link set veth1 netns relay-ns
sudo ip link set veth2 netns relay-ns
sudo ip link set veth3 netns sink-ns
echo "  gen-ns: veth0"
echo "  relay-ns: veth1, veth2"
echo "  sink-ns: veth3"

# Step 4: Configure IP addresses
echo ""
echo "[STEP 4] Configuring IP addresses..."
sudo ip netns exec gen-ns ip addr add 10.0.0.1/24 dev veth0
sudo ip netns exec relay-ns ip addr add 10.0.0.2/24 dev veth1
sudo ip netns exec relay-ns ip addr add 10.0.1.1/24 dev veth2
sudo ip netns exec sink-ns ip addr add 10.0.1.2/24 dev veth3
echo "  gen-ns veth0: 10.0.0.1/24"
echo "  relay-ns veth1: 10.0.0.2/24"
echo "  relay-ns veth2: 10.0.1.1/24"
echo "  sink-ns veth3: 10.0.1.2/24"

# Step 5: Bring up interfaces
echo ""
echo "[STEP 5] Bringing up all interfaces..."
sudo ip netns exec gen-ns ip link set lo up
sudo ip netns exec gen-ns ip link set veth0 up
sudo ip netns exec relay-ns ip link set lo up
sudo ip netns exec relay-ns ip link set veth1 up
sudo ip netns exec relay-ns ip link set veth2 up
sudo ip netns exec sink-ns ip link set lo up
sudo ip netns exec sink-ns ip link set veth3 up
echo "  All interfaces up"

# Step 6: Configure routing
echo ""
echo "[STEP 6] Configuring routes..."
# Unicast routes for connectivity
sudo ip netns exec gen-ns ip route add 10.0.1.0/24 via 10.0.0.2
sudo ip netns exec sink-ns ip route add 10.0.0.0/24 via 10.0.1.1
echo "  Unicast routes configured"

# CRITICAL: Multicast routes
sudo ip netns exec gen-ns ip route add 224.0.0.0/4 dev veth0
sudo ip netns exec relay-ns ip route add 224.0.0.0/4 dev veth2
echo "  Multicast routes configured"
echo "    gen-ns: 224.0.0.0/4 -> veth0"
echo "    relay-ns: 224.0.0.0/4 -> veth2"

# Step 7: Verify connectivity
echo ""
echo "[STEP 7] Verifying unicast connectivity..."
if sudo ip netns exec gen-ns ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1; then
    echo "  ✓ gen-ns can ping relay-ns (10.0.0.2)"
else
    echo "  ✗ FAILED: gen-ns cannot ping relay-ns"
    exit 1
fi

if sudo ip netns exec relay-ns ping -c 1 -W 1 10.0.1.2 >/dev/null 2>&1; then
    echo "  ✓ relay-ns can ping sink-ns (10.0.1.2)"
else
    echo "  ✗ FAILED: relay-ns cannot ping sink-ns"
    exit 1
fi

# Step 8: Start tcpdump on all interfaces
echo ""
echo "[STEP 8] Starting tcpdump on all interfaces..."
sudo ip netns exec gen-ns tcpdump -i veth0 -n -w "$LOGDIR/veth0.pcap" udp 2>"$LOGDIR/veth0.log" &
sudo ip netns exec relay-ns tcpdump -i veth1 -n -w "$LOGDIR/veth1.pcap" udp 2>"$LOGDIR/veth1.log" &
sudo ip netns exec relay-ns tcpdump -i veth2 -n -w "$LOGDIR/veth2.pcap" udp 2>"$LOGDIR/veth2.log" &
sudo ip netns exec sink-ns tcpdump -i veth3 -n -w "$LOGDIR/veth3.pcap" udp 2>"$LOGDIR/veth3.log" &
sleep 2
echo "  tcpdump running on veth0, veth1, veth2, veth3"
echo "  Packet captures: $LOGDIR/*.pcap"

# Step 9: Start sink receiver
echo ""
echo "[STEP 9] Starting receiver in sink-ns..."
sudo ip netns exec sink-ns socat -u \
    UDP4-RECV:$PORT_OUT,ip-add-membership=$MCAST_OUT:veth3,reuseaddr \
    OPEN:"$LOGDIR/sink_received.bin",creat \
    2>"$LOGDIR/sink.log" &
SINK_PID=$!
sleep 1
echo "  Sink listening on $MCAST_OUT:$PORT_OUT"
echo "  Output: $LOGDIR/sink_received.bin"

# Step 10: Start socat relay
echo ""
echo "[STEP 10] Starting socat relay in relay-ns..."
sudo ip netns exec relay-ns socat -v \
    UDP4-RECV:$PORT_IN,ip-add-membership=$MCAST_IN:veth1,reuseaddr \
    UDP4-SEND:$MCAST_OUT:$PORT_OUT,ip-multicast-if=10.0.1.1 \
    2>"$LOGDIR/relay.log" &
RELAY_PID=$!
sleep 1
echo "  Relay: $MCAST_IN:$PORT_IN -> $MCAST_OUT:$PORT_OUT"
echo "  Relay log: $LOGDIR/relay.log"

# Step 11: Send test packets
echo ""
echo "[STEP 11] Sending $PACKET_COUNT test packets from gen-ns..."
for i in $(seq 1 $PACKET_COUNT); do
    echo "Packet $i from generator" | sudo ip netns exec gen-ns socat STDIN \
        UDP4-SENDTO:$MCAST_IN:$PORT_IN,bind=10.0.0.1 \
        2>"$LOGDIR/generator_$i.log"
    echo "  Sent packet $i/$PACKET_COUNT"
    sleep 1
done

# Step 12: Wait and stop
echo ""
echo "[STEP 12] Waiting for packets to be processed..."
sleep 3

echo ""
echo "[STEP 13] Stopping capture and analyzing results..."
sudo pkill -f "tcpdump.*veth"
sleep 1

# Step 14: Analyze results
echo ""
echo "=========================================="
echo "RESULTS"
echo "=========================================="
echo ""

# Count packets in sink
if [ -f "$LOGDIR/sink_received.bin" ]; then
    SINK_BYTES=$(wc -c < "$LOGDIR/sink_received.bin")
    SINK_PACKETS=$(grep -c "^Packet" "$LOGDIR/sink_received.bin" 2>/dev/null || echo 0)
    echo "Sink received: $SINK_PACKETS packets ($SINK_BYTES bytes)"
else
    SINK_PACKETS=0
    echo "Sink received: 0 packets (no output file)"
fi

# Analyze tcpdump captures
echo ""
echo "Packet counts per interface (from tcpdump):"
for iface in veth0 veth1 veth2 veth3; do
    if [ -f "$LOGDIR/$iface.pcap" ]; then
        COUNT=$(sudo tcpdump -r "$LOGDIR/$iface.pcap" 2>/dev/null | wc -l)
        echo "  $iface: $COUNT packets captured"
    fi
done

# Check relay log
echo ""
echo "Relay activity (from socat -v output):"
if [ -f "$LOGDIR/relay.log" ]; then
    RECEIVED=$(grep -c "^>" "$LOGDIR/relay.log" 2>/dev/null || echo 0)
    SENT=$(grep -c "^<" "$LOGDIR/relay.log" 2>/dev/null || echo 0)
    echo "  Received on input: $RECEIVED"
    echo "  Sent on output: $SENT"
else
    echo "  No relay log found"
fi

# Final verdict
echo ""
echo "=========================================="
if [ "$SINK_PACKETS" -eq "$PACKET_COUNT" ]; then
    echo "✅ SUCCESS: All $PACKET_COUNT packets delivered"
    echo "   socat successfully relayed multicast packets"
elif [ "$SINK_PACKETS" -gt 0 ]; then
    echo "⚠️  PARTIAL: $SINK_PACKETS/$PACKET_COUNT packets delivered"
    echo "   Some packets lost in transit"
else
    echo "❌ FAILURE: No packets delivered to sink"
    echo "   socat relay did not work"
fi
echo "=========================================="
echo ""
echo "Detailed logs available in: $LOGDIR"
echo "  - *.pcap: tcpdump packet captures (analyze with: tcpdump -r file.pcap)"
echo "  - relay.log: socat relay verbose output"
echo "  - sink_received.bin: actual received data"
echo ""

exit 0
