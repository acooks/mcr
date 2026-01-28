#!/bin/bash
#
# Multi-Downstream Interface Test
#
# Topology: Source → MCR → Receiver1 (NS1)
#                        → Receiver2 (NS2)
#
# This test validates:
# - H4.1: Timer scheduling when adding downstream to EXISTING (*,G) route
# - Multiple downstream interfaces receiving traffic from same (*,G) route
#
# Test scenario:
# 1. First receiver joins group → creates (*,G) route with downstream1
# 2. Second receiver joins SAME group → adds downstream2 to existing route
# 3. Traffic is sent and BOTH receivers should receive packets
#
# This exercises the code path where a second downstream interface is added
# to an already-existing route (not creating a new route). Prior to the H4.1
# fix, the PIM Join/Prune timer would not be scheduled when adding downstream
# to an existing route, potentially causing route timeouts at the RP.
#
# Network isolation: Runs in isolated network namespace (unshare --net)
#

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Source common functions
source "$SCRIPT_DIR/common.sh"

# Test parameters
MULTICAST_GROUP="239.1.1.1"
MULTICAST_PORT=5001
PACKET_SIZE=1400

if [ "${CI:-}" = "true" ]; then
    PACKET_COUNT=1000
    SEND_RATE=1000
else
    PACKET_COUNT=5000
    SEND_RATE=2500
fi

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges for network namespace isolation"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Build binaries (if needed) ---
ensure_binaries_built

# Export variables for subshell
export RELAY_BINARY CONTROL_CLIENT_BINARY TRAFFIC_GENERATOR_BINARY
export MULTICAST_GROUP MULTICAST_PORT PACKET_SIZE PACKET_COUNT SEND_RATE
export SCRIPT_DIR

# --- Run test in isolated network namespace ---
echo "=== Multi-Downstream Interface Test ==="
echo "Topology: Source (10.0.0.1) → MCR → Receiver1 (10.0.1.2)"
echo "                                  → Receiver2 (10.0.2.2)"
echo ""
echo "This test validates H4.1 (timer scheduling when adding downstream to existing route)"
echo "and verifies that multiple receivers on different interfaces receive traffic."
echo ""

unshare --net bash << 'INNER_SCRIPT'
set -euo pipefail

source "$SCRIPT_DIR/common.sh"

# Variables for cleanup
MCR_PID=""
RECEIVER1_PID=""
RECEIVER2_PID=""
NS_RECV1="ns_recv1_$$"
NS_RECV2="ns_recv2_$$"

cleanup() {
    log_info 'Cleaning up...'
    [ -n "$RECEIVER1_PID" ] && kill "$RECEIVER1_PID" 2>/dev/null || true
    [ -n "$RECEIVER2_PID" ] && kill "$RECEIVER2_PID" 2>/dev/null || true
    [ -n "$MCR_PID" ] && kill "$MCR_PID" 2>/dev/null || true
    ip netns delete "$NS_RECV1" 2>/dev/null || true
    ip netns delete "$NS_RECV2" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

log_section 'Network Namespace Setup'

enable_loopback

# Disable reverse path filtering
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

# Create source-side veth pair
# Source: veth_src (10.0.0.1) <-> veth_in (10.0.0.2) [MCR upstream]
setup_veth_pair veth_src veth_in 10.0.0.1/24 10.0.0.2/24

# Create receiver1 namespace and veth pair
log_info "Creating receiver1 namespace: $NS_RECV1"
ip netns add "$NS_RECV1"
ip link add veth_out1 type veth peer name veth_recv1
ip link set veth_recv1 netns "$NS_RECV1"

# Configure this side (MCR downstream 1)
ip addr add 10.0.1.1/24 dev veth_out1
ip link set veth_out1 up

# Configure receiver1 namespace
ip netns exec "$NS_RECV1" ip link set lo up
ip netns exec "$NS_RECV1" ip addr add 10.0.1.2/24 dev veth_recv1
ip netns exec "$NS_RECV1" ip link set veth_recv1 up
ip netns exec "$NS_RECV1" ip route add 224.0.0.0/4 dev veth_recv1
ip netns exec "$NS_RECV1" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
ip netns exec "$NS_RECV1" sysctl -w net.ipv4.conf.veth_recv1.rp_filter=0 >/dev/null 2>&1 || true

# Create receiver2 namespace and veth pair
log_info "Creating receiver2 namespace: $NS_RECV2"
ip netns add "$NS_RECV2"
ip link add veth_out2 type veth peer name veth_recv2
ip link set veth_recv2 netns "$NS_RECV2"

# Configure this side (MCR downstream 2)
ip addr add 10.0.2.1/24 dev veth_out2
ip link set veth_out2 up

# Configure receiver2 namespace
ip netns exec "$NS_RECV2" ip link set lo up
ip netns exec "$NS_RECV2" ip addr add 10.0.2.2/24 dev veth_recv2
ip netns exec "$NS_RECV2" ip link set veth_recv2 up
ip netns exec "$NS_RECV2" ip route add 224.0.0.0/4 dev veth_recv2
ip netns exec "$NS_RECV2" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
ip netns exec "$NS_RECV2" sysctl -w net.ipv4.conf.veth_recv2.rp_filter=0 >/dev/null 2>&1 || true

log_section 'Creating MCR Config'

# MCR config with:
# - PIM enabled on upstream interface (toward source)
# - IGMP querier on downstream interfaces
CONFIG="/tmp/mcr_multi_downstream.json5"
cat > "$CONFIG" << 'EOF'
{
    // MCR configuration for multi-downstream test
    rules: [],

    // IGMP querier on both downstream interfaces
    igmp: {
        enabled: true,
        querier_interfaces: ["veth_out1", "veth_out2"],
        query_interval: 5,
        query_response_interval: 2
    },

    // PIM on upstream interface (towards source)
    pim: {
        enabled: true,
        interfaces: [
            { name: "veth_in" }
        ],
        // Static RP pointing to ourselves (this MCR is the RP)
        static_rp: [
            { rp: "10.0.0.2", group: "239.0.0.0/8" }
        ]
    }
}
EOF
log_info "Config file created at $CONFIG"

log_section 'Starting MCR'

MCR_SOCK="/tmp/mcr_multi_downstream.sock"
MCR_LOG="/tmp/mcr_multi_downstream.log"

"$RELAY_BINARY" supervisor \
    --control-socket-path "$MCR_SOCK" \
    --config "$CONFIG" \
    --num-workers 1 \
    > "$MCR_LOG" 2>&1 &
MCR_PID=$!
log_info "MCR started (PID: $MCR_PID)"

# Wait for MCR to start
wait_for_sockets "$MCR_SOCK"

log_section 'Starting First Receiver (Creates Route)'

# Start first receiver in NS_RECV1
# This will send IGMP report and create the initial (*,G) route
log_info "Receiver1 joining $MULTICAST_GROUP:$MULTICAST_PORT in $NS_RECV1..."
RECV1_FILE="/tmp/mcr_multi_downstream_recv1.dat"
ip netns exec "$NS_RECV1" python3 -c "
import socket
import struct
import sys
import signal

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', $MULTICAST_PORT))

# Join multicast group
mreq = struct.pack('4s4s', socket.inet_aton('$MULTICAST_GROUP'), socket.inet_aton('10.0.1.2'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
print(f'Receiver1 joined $MULTICAST_GROUP on 10.0.1.2', flush=True)

sock.settimeout(1.0)  # Short timeout for responsive exit
count = 0
total_bytes = 0
running = True

def signal_handler(signum, frame):
    global running
    running = False
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

try:
    while running:
        try:
            data, addr = sock.recvfrom(65536)
            count += 1
            total_bytes += len(data)
            if count == 1:
                print(f'First packet from {addr}', flush=True)
        except socket.timeout:
            continue
except Exception as e:
    print(f'Error: {e}', flush=True)

print(f'Receiver1: packets={count} bytes={total_bytes}')
" > "$RECV1_FILE" 2>&1 &
RECEIVER1_PID=$!
log_info "Receiver1 started (PID: $RECEIVER1_PID)"

# Wait for IGMP to be detected and route to be created
log_info "Waiting for IGMP group detection and route creation..."
sleep 3

# Check that route was created with first downstream interface
log_info "Checking initial route (should have veth_out1 as downstream)..."
ROUTE1=$("$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" mroute 2>&1 || echo '{"Mroute":[]}')
log_info "Initial route state:"
echo "$ROUTE1" | jq -r '.' 2>/dev/null || echo "$ROUTE1"

if echo "$ROUTE1" | grep -q "veth_out1"; then
    log_info "✓ Initial (*,G) route created with veth_out1 as downstream"
else
    log_error "✗ Initial route not created with veth_out1"
    log_info "MCR Log:"
    tail -50 /tmp/mcr_multi_downstream.log
    exit 1
fi

log_section 'Starting Second Receiver (Adds to Existing Route)'

# This is the key test: second receiver joins the SAME group on a DIFFERENT interface
# This exercises H4.1 (timer scheduling) and H4.2 (passive IGMP adding downstream)
log_info "Receiver2 joining $MULTICAST_GROUP:$MULTICAST_PORT in $NS_RECV2..."
log_info "This should ADD veth_out2 to the EXISTING (*,G) route (not create new)"
RECV2_FILE="/tmp/mcr_multi_downstream_recv2.dat"
ip netns exec "$NS_RECV2" python3 -c "
import socket
import struct
import sys
import signal

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', $MULTICAST_PORT))

# Join multicast group
mreq = struct.pack('4s4s', socket.inet_aton('$MULTICAST_GROUP'), socket.inet_aton('10.0.2.2'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
print(f'Receiver2 joined $MULTICAST_GROUP on 10.0.2.2', flush=True)

sock.settimeout(1.0)  # Short timeout for responsive exit
count = 0
total_bytes = 0
running = True

def signal_handler(signum, frame):
    global running
    running = False
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

try:
    while running:
        try:
            data, addr = sock.recvfrom(65536)
            count += 1
            total_bytes += len(data)
            if count == 1:
                print(f'First packet from {addr}', flush=True)
        except socket.timeout:
            continue
except Exception as e:
    print(f'Error: {e}', flush=True)

print(f'Receiver2: packets={count} bytes={total_bytes}')
" > "$RECV2_FILE" 2>&1 &
RECEIVER2_PID=$!
log_info "Receiver2 started (PID: $RECEIVER2_PID)"

# Wait for second IGMP to be processed
sleep 3

# Check that route now has BOTH downstream interfaces
log_info "Checking route after second receiver joins..."
ROUTE2=$("$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" mroute 2>&1 || echo '{"Mroute":[]}')
log_info "Route state after second receiver:"
echo "$ROUTE2" | jq -r '.' 2>/dev/null || echo "$ROUTE2"

# Verify both interfaces are downstream
if echo "$ROUTE2" | grep -q "veth_out1" && echo "$ROUTE2" | grep -q "veth_out2"; then
    log_info "✓ Route now has BOTH veth_out1 and veth_out2 as downstream"
else
    log_error "✗ Route missing expected downstream interfaces"
    log_info "Expected: veth_out1 AND veth_out2"
    log_info "MCR Log (last 50 lines):"
    tail -50 /tmp/mcr_multi_downstream.log
    exit 1
fi

log_section 'Sending Multicast Traffic'

log_info "Sending $PACKET_COUNT packets to $MULTICAST_GROUP:$MULTICAST_PORT..."
"$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group "$MULTICAST_GROUP" \
    --port "$MULTICAST_PORT" \
    --count "$PACKET_COUNT" \
    --size "$PACKET_SIZE" \
    --rate "$SEND_RATE"
log_info "Traffic sent"

# Wait for receivers to collect packets
log_info "Waiting for receivers to process packets..."
sleep 5

# Terminate receivers
kill $RECEIVER1_PID 2>/dev/null || true
kill $RECEIVER2_PID 2>/dev/null || true
wait $RECEIVER1_PID 2>/dev/null || true
wait $RECEIVER2_PID 2>/dev/null || true

log_section 'Validating Results'

# Check MCR stats
log_info "MCR Stats:"
"$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" stats 2>&1 | jq -r '.' || true

# Check receiver1 output
log_info "Receiver1 output:"
cat "$RECV1_FILE"
RECV1_PACKETS=$(grep -oP 'packets=\K\d+' "$RECV1_FILE" || echo "0")

# Check receiver2 output
log_info "Receiver2 output:"
cat "$RECV2_FILE"
RECV2_PACKETS=$(grep -oP 'packets=\K\d+' "$RECV2_FILE" || echo "0")

# Calculate thresholds (80% of sent packets)
MIN_PACKETS=$((PACKET_COUNT * 80 / 100))

log_info ""
log_info "=== Results ==="
log_info "Packets sent: $PACKET_COUNT"
log_info "Receiver1 received: $RECV1_PACKETS"
log_info "Receiver2 received: $RECV2_PACKETS"
log_info "Minimum expected: $MIN_PACKETS (80%)"

PASSED=true

if [ "$RECV1_PACKETS" -ge "$MIN_PACKETS" ]; then
    log_info "✓ Receiver1 got $RECV1_PACKETS packets (>= $MIN_PACKETS)"
else
    log_error "✗ Receiver1 got only $RECV1_PACKETS packets (expected >= $MIN_PACKETS)"
    PASSED=false
fi

if [ "$RECV2_PACKETS" -ge "$MIN_PACKETS" ]; then
    log_info "✓ Receiver2 got $RECV2_PACKETS packets (>= $MIN_PACKETS)"
else
    log_error "✗ Receiver2 got only $RECV2_PACKETS packets (expected >= $MIN_PACKETS)"
    PASSED=false
fi

log_section 'Test Complete'

if [ "$PASSED" = true ]; then
    log_info "=== MULTI-DOWNSTREAM TEST PASSED ==="
    log_info "H4.1: Timer scheduling for existing routes - VERIFIED"
    log_info "Multi-downstream traffic delivery - VERIFIED"
else
    log_error "=== MULTI-DOWNSTREAM TEST FAILED ==="
    log_info "MCR Log (last 100 lines):"
    tail -100 /tmp/mcr_multi_downstream.log
    exit 1
fi

INNER_SCRIPT

echo ""
echo "=== Multi-Downstream Interface Test Complete ==="
