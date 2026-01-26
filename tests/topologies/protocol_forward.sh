#!/bin/bash
#
# Protocol-Learned Forwarding Test
#
# Topology: Source → MCR (IGMP+PIM) → Receiver
#
# This test validates:
# - IGMP group membership detection from receiver
# - PIM (*,G) route creation from IGMP group
# - Data plane forwarding using protocol-learned routes
# - End-to-end multicast forwarding without static rules
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
    PACKET_COUNT=10000
    SEND_RATE=5000
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
echo "=== Protocol-Learned Forwarding Test ==="
echo "Topology: Source (10.0.0.1) → MCR (10.0.0.2/10.0.1.1) → Receiver (10.0.1.2)"
echo ""

unshare --net bash << 'INNER_SCRIPT'
set -euo pipefail

source "$SCRIPT_DIR/common.sh"

# Variables for cleanup
MCR_PID=""
RECEIVER_PID=""
NS_RECV="ns_recv_$$"

cleanup() {
    log_info 'Cleaning up...'
    [ -n "$RECEIVER_PID" ] && kill "$RECEIVER_PID" 2>/dev/null || true
    [ -n "$MCR_PID" ] && kill "$MCR_PID" 2>/dev/null || true
    # Clean up receiver namespace
    ip netns delete "$NS_RECV" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

log_section 'Network Namespace Setup'

enable_loopback

# Disable reverse path filtering which can drop multicast packets
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

# Create source-side veth pair (both ends in this namespace)
# Source side: veth_src (10.0.0.1) <-> veth_in (10.0.0.2) [MCR upstream]
setup_veth_pair veth_src veth_in 10.0.0.1/24 10.0.0.2/24

# Create receiver namespace and veth pair crossing namespace boundary
# This is required because multicast doesn't deliver across veth pairs
# within the same namespace - the receiver MUST be in a separate namespace
log_info "Creating receiver namespace: $NS_RECV"
ip netns add "$NS_RECV"

# Create veth pair: veth_out (this ns) <-> veth_recv (receiver ns)
ip link add veth_out type veth peer name veth_recv
ip link set veth_recv netns "$NS_RECV"

# Configure this side (MCR downstream)
ip addr add 10.0.1.1/24 dev veth_out
ip link set veth_out up

# Configure receiver side (in separate namespace)
ip netns exec "$NS_RECV" ip link set lo up
ip netns exec "$NS_RECV" ip addr add 10.0.1.2/24 dev veth_recv
ip netns exec "$NS_RECV" ip link set veth_recv up
ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf.veth_recv.rp_filter=0 >/dev/null 2>&1 || true

# Force IGMPv2 for simpler reports
ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf.veth_recv.force_igmp_version=2 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.veth_out.force_igmp_version=2 >/dev/null 2>&1 || true

# Add multicast route in receiver namespace
ip netns exec "$NS_RECV" ip route add 224.0.0.0/4 dev veth_recv 2>/dev/null || true

log_section 'Creating MCR Config'

MCR_LOG=/tmp/mcr_protocol.log
MCR_SOCK=/tmp/mcr_protocol.sock
MCR_CONFIG=/tmp/mcr_protocol.json5

# Clean up stale files
rm -f "$MCR_SOCK" "$MCR_LOG" "$MCR_CONFIG"

# Create config file with IGMP and PIM enabled
# Note: With AF_PACKET, packets are captured at L2 and appear on the local
# interface (veth_out), not the peer interface (veth_recv).
# MCR should be configured on the interface it owns (veth_out).
cat > "$MCR_CONFIG" << 'EOF'
{
    // No static rules - using protocol-learned routes
    rules: [],

    // IGMP querier on MCR's downstream interface (toward receiver)
    // AF_PACKET receives IGMP reports on veth_out (local side of veth pair)
    igmp: {
        enabled: true,
        querier_interfaces: ["veth_out"],
        query_interval: 5,
        query_response_interval: 2
    },

    // PIM on upstream interface (towards source)
    pim: {
        enabled: true,
        interfaces: [
            { name: "veth_in" }
        ],
        // Static RP pointing to ourselves for testing
        static_rp: [
            { rp: "10.0.0.2", group: "239.0.0.0/8" }
        ]
    }
}
EOF

log_info "Config file created at $MCR_CONFIG"

log_section 'Starting MCR'

# Start MCR with config file
"$RELAY_BINARY" supervisor \
    --control-socket-path "$MCR_SOCK" \
    --config "$MCR_CONFIG" \
    --num-workers 1 \
    > "$MCR_LOG" 2>&1 &
MCR_PID=$!

log_info "MCR started (PID: $MCR_PID)"

# Wait for control socket
wait_for_sockets "$MCR_SOCK"

# Verify protocol state
log_info 'Initial protocol state:'
"$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" pim neighbors 2>/dev/null || true
"$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" igmp groups 2>/dev/null || true

log_section 'Starting Receiver (Multicast Group Join)'

# Start receiver that joins multicast group in the receiver namespace
log_info "Receiver joining $MULTICAST_GROUP:$MULTICAST_PORT in namespace $NS_RECV..."

# Create receiver - use Python for reliable multicast reception
# Run in separate namespace so multicast packets cross the veth boundary
RECV_FILE=/tmp/mcr_protocol_recv.dat
RECV_ERR=/tmp/mcr_protocol_recv.err
rm -f "$RECV_FILE" "$RECV_ERR"

ip netns exec "$NS_RECV" python3 -c "
import socket
import struct
import sys
import traceback

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to wildcard to receive all multicast
    sock.bind(('', $MULTICAST_PORT))
    print(f'Bound to port $MULTICAST_PORT', file=sys.stderr)

    # Join multicast group on veth_recv (10.0.1.2) in receiver namespace
    mreq = struct.pack('4s4s', socket.inet_aton('$MULTICAST_GROUP'), socket.inet_aton('10.0.1.2'))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print(f'Joined multicast group $MULTICAST_GROUP on 10.0.1.2', file=sys.stderr)

    # Receive with timeout (5s should be enough to get packets if they're coming)
    sock.settimeout(5.0)
    count = 0
    total_bytes = 0
    print('Waiting for packets...', file=sys.stderr)
    try:
        while count < 100000:  # Max packets
            data, addr = sock.recvfrom(2048)
            count += 1
            total_bytes += len(data)
            if count == 1:
                print(f'First packet from {addr}', file=sys.stderr)
    except socket.timeout:
        print(f'Timeout after receiving {count} packets', file=sys.stderr)

    # Write summary
    with open('$RECV_FILE', 'w') as f:
        f.write(f'packets={count} bytes={total_bytes}\n')
    print(f'Done: {count} packets, {total_bytes} bytes', file=sys.stderr)

except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    with open('$RECV_FILE', 'w') as f:
        f.write(f'error={e}\n')
" > "$RECV_ERR" 2>&1 &
RECEIVER_PID=$!

log_info "Receiver started (PID: $RECEIVER_PID)"

# Wait for IGMP report to be processed
log_info 'Waiting for IGMP group detection...'
sleep 3

# Debug: Show kernel multicast memberships
log_info 'Kernel multicast group memberships:'
log_info '  veth_recv (in receiver namespace):'
ip netns exec "$NS_RECV" ip maddr show dev veth_recv 2>/dev/null || true
log_info '  veth_out (in MCR namespace):'
ip maddr show dev veth_out 2>/dev/null || true
log_info 'Routes (receiver namespace):'
ip netns exec "$NS_RECV" ip route show 2>/dev/null || true
log_info 'rp_filter settings:'
sysctl net.ipv4.conf.all.rp_filter 2>/dev/null || true
ip netns exec "$NS_RECV" sysctl net.ipv4.conf.veth_recv.rp_filter 2>/dev/null || true

# Check if IGMP group was detected
log_info 'IGMP groups after join:'
"$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" igmp groups 2>/dev/null || true

# Check if route was created
log_info 'Multicast routes:'
"$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" mroute 2>/dev/null || true

log_section 'Sending Multicast Traffic'

# Start packet capture on receiver interface (in receiver namespace) to debug what's being sent
PCAP_FILE=/tmp/mcr_protocol_recv.pcap
ip netns exec "$NS_RECV" tcpdump -i veth_recv -c 100 -e -w "$PCAP_FILE" 2>/dev/null &
TCPDUMP_PID=$!
sleep 0.5

# Send traffic from source side
log_info "Sending $PACKET_COUNT packets to $MULTICAST_GROUP:$MULTICAST_PORT..."

"$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group "$MULTICAST_GROUP" \
    --port "$MULTICAST_PORT" \
    --count "$PACKET_COUNT" \
    --size "$PACKET_SIZE" \
    --rate "$SEND_RATE"

log_info 'Traffic sent'

# Wait for processing
sleep 2

# Stop packet capture
kill $TCPDUMP_PID 2>/dev/null || true
sleep 0.5

# Show captured packets (with MAC addresses)
log_info 'Captured packets on veth_recv (with MAC):'
tcpdump -r "$PCAP_FILE" -n -e 2>/dev/null | head -10 || echo "(no packets captured)"

# Wait for receiver to finish (it has 15s timeout, but should receive packets faster)
log_info 'Waiting for receiver to complete...'
wait $RECEIVER_PID 2>/dev/null || true

log_section 'Validating Results'

# Get stats
log_info 'MCR Stats:'
"$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" stats 2>/dev/null || true

# Check logs for forwarding activity
log_info ''
log_info 'MCR Log (last 50 lines):'
tail -50 "$MCR_LOG" 2>/dev/null || true

# Extract key metrics
log_info ''
log_info '=== Results ==='

PASS=true

# Check for IGMP group
if "$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" igmp groups 2>/dev/null | grep -q "$MULTICAST_GROUP"; then
    log_info "✓ IGMP group $MULTICAST_GROUP detected"
else
    log_error "✗ IGMP group $MULTICAST_GROUP NOT detected"
    PASS=false
fi

# Check for route
if "$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" mroute 2>/dev/null | grep -q "$MULTICAST_GROUP"; then
    log_info "✓ Multicast route for $MULTICAST_GROUP created"
else
    log_error "✗ Multicast route for $MULTICAST_GROUP NOT created"
    PASS=false
fi

# Check stats for forwarded packets
STATS_OUTPUT="$("$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" stats 2>/dev/null || echo '')"
if echo "$STATS_OUTPUT" | grep -qE 'packets_relayed.*[1-9]'; then
    log_info '✓ Packets were forwarded (stats)'
    echo "$STATS_OUTPUT" | grep -E 'packets_relayed|bytes_relayed' || true
else
    log_info '⚠ No packets forwarded (stats show 0 or no relay stats)'
    log_info 'This may indicate workers not spawned or rules not synced'
    PASS=false
fi

# Check if receiver actually got packets (end-to-end validation)
if [ -f "$RECV_ERR" ]; then
    log_info "Receiver log:"
    cat "$RECV_ERR"
fi

if [ -f "$RECV_FILE" ] && [ -s "$RECV_FILE" ]; then
    log_info "Receiver output: $(cat $RECV_FILE)"
    RECV_PACKETS=$(grep -oP 'packets=\K[0-9]+' "$RECV_FILE" 2>/dev/null || echo 0)
    EXPECTED_MIN=$((PACKET_COUNT * 80 / 100))  # Expect at least 80%
    if [ "$RECV_PACKETS" -ge "$EXPECTED_MIN" ]; then
        log_info "✓ Receiver got $RECV_PACKETS packets (expected >= $EXPECTED_MIN)"
    else
        log_error "✗ Receiver only got $RECV_PACKETS packets (expected >= $EXPECTED_MIN)"
        PASS=false
    fi
else
    log_error "✗ Receiver got NO packets (file empty or missing)"
    PASS=false
fi

log_section 'Test Complete'

if [ "$PASS" = "true" ]; then
    log_info '=== PROTOCOL FORWARDING TEST PASSED ==='
else
    log_error '=== PROTOCOL FORWARDING TEST FAILED ==='
    exit 1
fi
INNER_SCRIPT

echo ""
echo "=== Protocol Forwarding Test Complete ==="
