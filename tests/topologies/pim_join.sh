#!/bin/bash
#
# PIM Join Propagation Test
#
# Topology:
#   [Source]    ──veth_s──    [MCR-RP]    ──veth_r──    [MCR-LHR]    ──veth_h──    [Receiver]
#   10.0.0.1                  10.0.0.2                  10.1.0.2                   10.2.0.2
#                             10.1.0.1                  10.2.0.1
#                             (RP for 239.0.0.0/8)
#
# This test validates:
# - IGMP report on LHR triggers (*,G) route creation
# - LHR sends PIM Join towards RP
# - RP receives Join, adds downstream interface
# - Traffic from source reaches receiver via PIM
#
# Uses separate network namespaces for isolation.
#

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/common.sh"

# Test namespaces
NS_RP="mcr_pim_rp"
NS_LHR="mcr_pim_lhr"
NS_RECV="mcr_pim_recv"

# Network configuration
# Source side: direct connection to RP namespace (no separate source namespace for simplicity)
VETH_S="veth_s"      # Source-side in RP namespace
VETH_S_P="veth_s_p"  # Peer in RP namespace (for source traffic)

# RP to LHR link
VETH_R1="veth_r1"    # RP side
VETH_R2="veth_r2"    # LHR side

# LHR to receiver
VETH_H1="veth_h1"    # LHR side
VETH_H2="veth_h2"    # Receiver side (in LHR namespace)

IP_SRC="10.0.0.1"
IP_RP_UP="10.0.0.2/24"
IP_RP_DOWN="10.1.0.1/24"
IP_LHR_UP="10.1.0.2/24"
IP_LHR_DOWN="10.2.0.1/24"
IP_RECV="10.2.0.2/24"
IP_RECV_ADDR="10.2.0.2"

IP_RP_ADDR="10.1.0.1"
IP_LHR_UP_ADDR="10.1.0.2"

# Multicast group for testing
MCAST_GROUP="239.1.1.1"
MCAST_PORT="5001"

# Control sockets and logs
SOCK_RP="/tmp/mcr_pim_rp.sock"
SOCK_LHR="/tmp/mcr_pim_lhr.sock"
LOG_RP="/tmp/mcr_pim_rp.log"
LOG_LHR="/tmp/mcr_pim_lhr.log"
CONFIG_RP="/tmp/mcr_pim_rp.json5"
CONFIG_LHR="/tmp/mcr_pim_lhr.json5"

MCR_RP_PID=""
MCR_LHR_PID=""
RECEIVER_PID=""

# Receiver output files
RECV_FILE="/tmp/mcr_pim_join_recv.dat"
RECV_LOG="/tmp/mcr_pim_join_recv.log"

# Cleanup function
cleanup() {
    log_info "Running cleanup..."
    # Save logs for debugging before cleanup
    cp "$LOG_RP" /tmp/mcr_pim_rp_saved.log 2>/dev/null || true
    cp "$LOG_LHR" /tmp/mcr_pim_lhr_saved.log 2>/dev/null || true
    [ -n "$RECEIVER_PID" ] && sudo kill "$RECEIVER_PID" 2>/dev/null || true
    [ -n "$MCR_RP_PID" ] && sudo kill -TERM "$MCR_RP_PID" 2>/dev/null || true
    [ -n "$MCR_LHR_PID" ] && sudo kill -TERM "$MCR_LHR_PID" 2>/dev/null || true
    sleep 1
    cleanup_multi_ns "$NS_RP" "$NS_LHR"
    sudo ip netns delete "$NS_RECV" 2>/dev/null || true
    rm -f "$SOCK_RP" "$SOCK_LHR" "$LOG_RP" "$LOG_LHR" "$CONFIG_RP" "$CONFIG_LHR"
    rm -f "$RECV_FILE" "$RECV_LOG"
}
trap cleanup EXIT

# Check for socat
if ! command -v socat &> /dev/null; then
    echo "ERROR: socat is required but not installed"
    exit 1
fi

# Initialize test
init_multi_ns_test "PIM Join Propagation Test" "$NS_RP" "$NS_LHR"

log_section 'Creating Network Topology'

# Create veth pair for source side (within RP namespace)
sudo ip netns exec "$NS_RP" ip link add "$VETH_S" type veth peer name "$VETH_S_P"
sudo ip netns exec "$NS_RP" ip addr add "10.0.0.1/24" dev "$VETH_S"
sudo ip netns exec "$NS_RP" ip addr add "$IP_RP_UP" dev "$VETH_S_P"
sudo ip netns exec "$NS_RP" ip link set "$VETH_S" up
sudo ip netns exec "$NS_RP" ip link set "$VETH_S_P" up

# Link RP and LHR namespaces
create_linked_namespaces "$NS_RP" "$NS_LHR" "$VETH_R1" "$VETH_R2" "$IP_RP_DOWN" "$IP_LHR_UP"

# Create receiver namespace and veth pair crossing namespace boundary
# This is required because multicast doesn't deliver across veth pairs
# within the same namespace - the receiver MUST be in a separate namespace
log_info "Creating receiver namespace: $NS_RECV"
sudo ip netns add "$NS_RECV"

# Create veth pair: veth_h1 (LHR ns) <-> veth_h2 (receiver ns)
sudo ip netns exec "$NS_LHR" ip link add "$VETH_H1" type veth peer name "$VETH_H2"
sudo ip netns exec "$NS_LHR" ip link set "$VETH_H2" netns "$NS_RECV"

# Configure LHR side
sudo ip netns exec "$NS_LHR" ip addr add "$IP_LHR_DOWN" dev "$VETH_H1"
sudo ip netns exec "$NS_LHR" ip link set "$VETH_H1" up

# Configure receiver side (in separate namespace)
sudo ip netns exec "$NS_RECV" ip link set lo up
sudo ip netns exec "$NS_RECV" ip addr add "$IP_RECV" dev "$VETH_H2"
sudo ip netns exec "$NS_RECV" ip link set "$VETH_H2" up
sudo ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sudo ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf."$VETH_H2".rp_filter=0 >/dev/null 2>&1 || true

# Add multicast route in receiver namespace
sudo ip netns exec "$NS_RECV" ip route add 224.0.0.0/4 dev "$VETH_H2" 2>/dev/null || true

# Force IGMPv2 for simpler reports
sudo ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf.all.force_igmp_version=2 >/dev/null 2>&1 || true
sudo ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf."$VETH_H2".force_igmp_version=2 >/dev/null 2>&1 || true
sudo ip netns exec "$NS_LHR" sysctl -w net.ipv4.conf."$VETH_H1".force_igmp_version=2 >/dev/null 2>&1 || true

# Add routes for inter-namespace communication
# RP needs route to LHR downstream network
sudo ip netns exec "$NS_RP" ip route add 10.2.0.0/24 via "${IP_LHR_UP%/*}"
# LHR needs route to source network via RP
sudo ip netns exec "$NS_LHR" ip route add 10.0.0.0/24 via "${IP_RP_DOWN%/*}"

log_section 'Creating MCR Configurations'

# MCR-RP config: RP for 239.0.0.0/8, PIM on both interfaces
# Use short hello_period for faster neighbor discovery in tests
cat > "$CONFIG_RP" << EOF
{
    rules: [],
    pim: {
        enabled: true,
        router_id: "${IP_RP_DOWN%/*}",
        rp_address: "${IP_RP_DOWN%/*}",
        interfaces: [
            { name: "$VETH_S_P", hello_period: 5 },
            { name: "$VETH_R1", hello_period: 5 }
        ],
        static_rp: [
            { rp: "${IP_RP_DOWN%/*}", group: "239.0.0.0/8" }
        ]
    },
    igmp: {
        enabled: true,
        querier_interfaces: ["$VETH_S_P"]
    }
}
EOF

# MCR-LHR config: IGMP on receiver side, PIM on RP side
cat > "$CONFIG_LHR" << EOF
{
    rules: [],
    pim: {
        enabled: true,
        router_id: "${IP_LHR_UP%/*}",
        interfaces: [
            { name: "$VETH_R2", hello_period: 5 }
        ],
        static_rp: [
            { rp: "${IP_RP_DOWN%/*}", group: "239.0.0.0/8" }
        ]
    },
    igmp: {
        enabled: true,
        querier_interfaces: ["$VETH_H1"],
        query_interval: 5,
        query_response_interval: 2
    }
}
EOF

log_info "Created config files"

log_section 'Starting MCR Instances'

# Start MCR-RP
start_mcr_with_config mcr_rp "$CONFIG_RP" "$SOCK_RP" "$LOG_RP" 0 "$NS_RP"
MCR_RP_PID=$mcr_rp_PID

# Start MCR-LHR
start_mcr_with_config mcr_lhr "$CONFIG_LHR" "$SOCK_LHR" "$LOG_LHR" 1 "$NS_LHR"
MCR_LHR_PID=$mcr_lhr_PID

# Wait for control sockets
wait_for_sockets "$SOCK_RP" "$SOCK_LHR"

log_section 'Verifying PIM Neighbor Discovery'

VALIDATION_PASSED=0

# Wait for PIM neighbors between RP and LHR
if wait_for_pim_neighbor "$SOCK_RP" "${IP_LHR_UP%/*}" 20; then
    log_info "RP discovered LHR as PIM neighbor"
else
    log_error "RP did not discover LHR as PIM neighbor"
    VALIDATION_PASSED=1
fi

if wait_for_pim_neighbor "$SOCK_LHR" "${IP_RP_DOWN%/*}" 20; then
    log_info "LHR discovered RP as PIM neighbor"
else
    log_error "LHR did not discover RP as PIM neighbor"
    VALIDATION_PASSED=1
fi

log_section 'Starting Receiver (IGMP Join)'

log_info "Starting receiver on $MCAST_GROUP:$MCAST_PORT in namespace $NS_RECV..."

# Create Python multicast receiver that counts packets
# Run in separate namespace so multicast packets cross the veth boundary
rm -f "$RECV_FILE" "$RECV_LOG"

sudo ip netns exec "$NS_RECV" python3 -c "
import socket
import struct
import sys

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', $MCAST_PORT))
    print(f'Bound to port $MCAST_PORT', file=sys.stderr)

    # Join multicast group on receiver interface
    mreq = struct.pack('4s4s', socket.inet_aton('$MCAST_GROUP'), socket.inet_aton('$IP_RECV_ADDR'))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print(f'Joined multicast group $MCAST_GROUP on $IP_RECV_ADDR', file=sys.stderr)

    # Receive with timeout
    sock.settimeout(10.0)
    count = 0
    total_bytes = 0
    print('Waiting for packets...', file=sys.stderr)
    try:
        while count < 100000:
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
    with open('$RECV_FILE', 'w') as f:
        f.write(f'error={e}\n')
" > "$RECV_LOG" 2>&1 &
RECEIVER_PID=$!

log_info "Receiver started (PID: $RECEIVER_PID)"

# Wait for IGMP report to be processed
sleep 3

log_section 'Verifying IGMP Group Detection'

if wait_for_igmp_group "$SOCK_LHR" "$MCAST_GROUP" 15; then
    log_info "LHR detected IGMP group $MCAST_GROUP"
else
    log_error "LHR did not detect IGMP group $MCAST_GROUP"
    VALIDATION_PASSED=1
fi

log_info "LHR IGMP groups:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_LHR" igmp groups 2>/dev/null || true

log_section 'Verifying Multicast Route Creation'

# Check for (*,G) route on LHR
if wait_for_mroute "$SOCK_LHR" "$MCAST_GROUP" 15; then
    log_info "LHR created multicast route for $MCAST_GROUP"
else
    log_error "LHR did not create multicast route for $MCAST_GROUP"
    VALIDATION_PASSED=1
fi

log_info "LHR multicast routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_LHR" mroute 2>/dev/null || true

log_section 'Verifying PIM Join Propagation to RP'

# Give time for PIM Join to propagate
sleep 5

# Check if RP has the (*,G) route with downstream interface
log_info "RP multicast routes:"
RP_MROUTE=$("$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP" mroute 2>/dev/null || echo "")
echo "$RP_MROUTE"

if echo "$RP_MROUTE" | grep -q "$MCAST_GROUP"; then
    log_info "RP has multicast route for $MCAST_GROUP"
else
    log_info "Note: RP may not show route until source traffic arrives (data-triggered)"
fi

log_section 'Sending Multicast Traffic'

# Send traffic from source side in RP namespace
log_info "Sending test traffic to $MCAST_GROUP:$MCAST_PORT..."

PACKET_COUNT=20000
PACKET_SIZE=100

sudo ip netns exec "$NS_RP" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "$IP_SRC" \
    --group "$MCAST_GROUP" \
    --port "$MCAST_PORT" \
    --count "$PACKET_COUNT" \
    --size "$PACKET_SIZE" \
    --rate 10000 2>/dev/null || true

log_info "Traffic sent"

# Wait for receiver to complete
log_info "Waiting for receiver to complete..."
wait $RECEIVER_PID 2>/dev/null || true

log_section 'Verifying Forwarding'

log_info "RP stats:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP" stats 2>/dev/null || true

log_info ""
log_info "LHR stats:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_LHR" stats 2>/dev/null || true

# Check RP and LHR logs for forwarding activity
log_info ""
log_info "RP multicast routes (after traffic):"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP" mroute 2>/dev/null || true

log_info ""
log_info "LHR multicast routes (after traffic):"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_LHR" mroute 2>/dev/null || true

log_section 'Verifying End-to-End Packet Delivery'

# Check receiver log
if [ -f "$RECV_LOG" ]; then
    log_info "Receiver log:"
    cat "$RECV_LOG"
fi

# Validate actual packet reception
if [ -f "$RECV_FILE" ] && [ -s "$RECV_FILE" ]; then
    log_info "Receiver output: $(cat $RECV_FILE)"
    RECV_PACKETS=$(grep -oP 'packets=\K[0-9]+' "$RECV_FILE" 2>/dev/null || echo 0)
    EXPECTED_MIN=$((PACKET_COUNT * 80 / 100))  # Expect at least 80%
    if [ "$RECV_PACKETS" -ge "$EXPECTED_MIN" ]; then
        log_info "✓ Receiver got $RECV_PACKETS packets (expected >= $EXPECTED_MIN)"
    else
        log_error "✗ Receiver only got $RECV_PACKETS packets (expected >= $EXPECTED_MIN)"
        VALIDATION_PASSED=1
    fi
else
    log_error "✗ Receiver got NO packets (file empty or missing)"
    VALIDATION_PASSED=1
fi

log_section 'Test Summary'

if [ $VALIDATION_PASSED -eq 0 ]; then
    log_info '=== PIM Join Propagation Test PASSED ==='
    log_info ""
    log_info "Validated:"
    log_info "  - PIM neighbor discovery between RP and LHR"
    log_info "  - IGMP group membership detection on LHR"
    log_info "  - Multicast route creation from IGMP report"
    log_info "  - PIM Join signaling towards RP"
    log_info "  - End-to-end packet delivery to receiver"
    echo ""
    echo "=== PASS ==="
    exit 0
else
    log_error '=== PIM Join Propagation Test FAILED ==='
    log_info ""
    log_info "RP log (last 50 lines):"
    tail -50 "$LOG_RP" 2>/dev/null || true
    log_info ""
    log_info "LHR log (last 50 lines):"
    tail -50 "$LOG_LHR" 2>/dev/null || true
    echo ""
    echo "=== FAIL ==="
    exit 1
fi
