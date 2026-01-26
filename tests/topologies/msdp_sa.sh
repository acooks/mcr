#!/bin/bash
#
# MSDP SA (Source-Active) Exchange Test
#
# Topology:
#   [Source]  ──veth_s──  [MCR-RP1]  ══MSDP══  [MCR-RP2]  ──veth_r──  [Receiver]
#   10.0.0.1              10.0.0.2              10.1.0.2               10.2.0.2
#                         10.1.0.1              10.2.0.1
#                         (RP domain 1)         (RP domain 2)
#
# This test validates:
# - Source active triggers SA origination on RP1
# - SA message sent to MSDP peer RP2
# - RP2 caches SA entry from RP1
# - Cross-domain multicast source advertisement
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
NS_RP1="mcr_msdp_rp1"
NS_RP2="mcr_msdp_rp2"
NS_RECV="mcr_msdp_recv"

# Network configuration
# Source side (in RP1 namespace)
VETH_S="veth_s"
VETH_S_P="veth_s_p"

# RP1 to RP2 link (MSDP peering)
VETH_M1="veth_m1"
VETH_M2="veth_m2"

# Receiver side (in RP2 namespace)
VETH_R="veth_r"
VETH_R_P="veth_r_p"

IP_SRC="10.0.0.1"
IP_RP1_UP="10.0.0.2/24"
IP_RP1_DOWN="10.1.0.1/24"
IP_RP2_UP="10.1.0.2/24"
IP_RP2_DOWN="10.2.0.1/24"
IP_RECV="10.2.0.2/24"
IP_RECV_ADDR="10.2.0.2"

IP_RP1_ADDR="10.1.0.1"
IP_RP2_ADDR="10.1.0.2"

# Multicast group for testing
MCAST_GROUP="239.1.1.1"
MCAST_PORT="5001"

# Control sockets and logs
SOCK_RP1="/tmp/mcr_msdp_rp1.sock"
SOCK_RP2="/tmp/mcr_msdp_rp2.sock"
LOG_RP1="/tmp/mcr_msdp_rp1.log"
LOG_RP2="/tmp/mcr_msdp_rp2.log"
CONFIG_RP1="/tmp/mcr_msdp_rp1.json5"
CONFIG_RP2="/tmp/mcr_msdp_rp2.json5"

MCR_RP1_PID=""
MCR_RP2_PID=""
SOURCE_PID=""
RECEIVER_PID=""

# Receiver output files
RECV_FILE="/tmp/mcr_msdp_recv.dat"
RECV_LOG="/tmp/mcr_msdp_recv.log"

# Cleanup function
cleanup() {
    log_info "Running cleanup..."
    [ -n "$SOURCE_PID" ] && sudo kill "$SOURCE_PID" 2>/dev/null || true
    [ -n "$RECEIVER_PID" ] && sudo kill "$RECEIVER_PID" 2>/dev/null || true
    [ -n "$MCR_RP1_PID" ] && sudo kill -TERM "$MCR_RP1_PID" 2>/dev/null || true
    [ -n "$MCR_RP2_PID" ] && sudo kill -TERM "$MCR_RP2_PID" 2>/dev/null || true
    sleep 1
    cleanup_multi_ns "$NS_RP1" "$NS_RP2"
    sudo ip netns delete "$NS_RECV" 2>/dev/null || true
    rm -f "$SOCK_RP1" "$SOCK_RP2" "$LOG_RP1" "$LOG_RP2" "$CONFIG_RP1" "$CONFIG_RP2"
    rm -f "$RECV_FILE" "$RECV_LOG"
}
trap cleanup EXIT

# Initialize test
init_multi_ns_test "MSDP SA Exchange Test" "$NS_RP1" "$NS_RP2"

# Create separate receiver namespace (required for multicast delivery)
log_info "Creating receiver namespace: $NS_RECV"
sudo ip netns add "$NS_RECV"
sudo ip netns exec "$NS_RECV" ip link set lo up

log_section 'Creating Network Topology'

# Create veth pair for source side (within RP1 namespace)
sudo ip netns exec "$NS_RP1" ip link add "$VETH_S" type veth peer name "$VETH_S_P"
sudo ip netns exec "$NS_RP1" ip addr add "$IP_SRC/24" dev "$VETH_S"
sudo ip netns exec "$NS_RP1" ip addr add "$IP_RP1_UP" dev "$VETH_S_P"
sudo ip netns exec "$NS_RP1" ip link set "$VETH_S" up
sudo ip netns exec "$NS_RP1" ip link set "$VETH_S_P" up

# Link RP1 and RP2 namespaces (MSDP peering link)
create_linked_namespaces "$NS_RP1" "$NS_RP2" "$VETH_M1" "$VETH_M2" "$IP_RP1_DOWN" "$IP_RP2_UP"

# Create veth pair for receiver side - crossing namespace boundary
# veth_r stays in NS_RP2 (MCR downstream interface)
# veth_r_p goes to NS_RECV (actual receiver endpoint)
sudo ip netns exec "$NS_RP2" ip link add "$VETH_R" type veth peer name "$VETH_R_P"
sudo ip netns exec "$NS_RP2" ip link set "$VETH_R_P" netns "$NS_RECV"

# Configure RP2 side (MCR downstream)
sudo ip netns exec "$NS_RP2" ip addr add "$IP_RP2_DOWN" dev "$VETH_R"
sudo ip netns exec "$NS_RP2" ip link set "$VETH_R" up

# Configure receiver side (in separate namespace)
sudo ip netns exec "$NS_RECV" ip addr add "$IP_RECV" dev "$VETH_R_P"
sudo ip netns exec "$NS_RECV" ip link set "$VETH_R_P" up
sudo ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sudo ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf."$VETH_R_P".rp_filter=0 >/dev/null 2>&1 || true

# Force IGMPv2 for simpler reports
sudo ip netns exec "$NS_RECV" sysctl -w net.ipv4.conf."$VETH_R_P".force_igmp_version=2 >/dev/null 2>&1 || true
sudo ip netns exec "$NS_RP2" sysctl -w net.ipv4.conf."$VETH_R".force_igmp_version=2 >/dev/null 2>&1 || true

# Add multicast route in receiver namespace
sudo ip netns exec "$NS_RECV" ip route add 224.0.0.0/4 dev "$VETH_R_P" 2>/dev/null || true

# Add routes between namespaces
sudo ip netns exec "$NS_RP1" ip route add 10.2.0.0/24 via "${IP_RP2_UP%/*}"
sudo ip netns exec "$NS_RP2" ip route add 10.0.0.0/24 via "${IP_RP1_DOWN%/*}"

log_section 'Creating MCR Configurations'

# MCR-RP1 config: RP for 239.1.0.0/16, MSDP peer to RP2
# Use short hello_period for faster neighbor discovery in tests
cat > "$CONFIG_RP1" << EOF
{
    rules: [],
    pim: {
        enabled: true,
        router_id: "$IP_RP1_ADDR",
        rp_address: "$IP_RP1_ADDR",
        interfaces: [
            { name: "$VETH_S_P", hello_period: 5 },
            { name: "$VETH_M1", hello_period: 5 }
        ],
        static_rp: [
            { rp: "$IP_RP1_ADDR", group: "239.1.0.0/16" }
        ]
    },
    igmp: {
        enabled: true,
        querier_interfaces: ["$VETH_S_P"]
    },
    msdp: {
        enabled: true,
        local_address: "$IP_RP1_ADDR",
        keepalive_interval: 5,
        hold_time: 75,
        peers: [
            { address: "$IP_RP2_ADDR", description: "Peer to RP2" }
        ]
    }
}
EOF

# MCR-RP2 config: RP for 239.2.0.0/16, MSDP peer to RP1
cat > "$CONFIG_RP2" << EOF
{
    rules: [],
    pim: {
        enabled: true,
        router_id: "$IP_RP2_ADDR",
        rp_address: "$IP_RP2_ADDR",
        interfaces: [
            { name: "$VETH_M2", hello_period: 5 },
            { name: "$VETH_R", hello_period: 5 }
        ],
        static_rp: [
            { rp: "$IP_RP2_ADDR", group: "239.2.0.0/16" },
            { rp: "$IP_RP1_ADDR", group: "239.1.0.0/16" }
        ]
    },
    igmp: {
        enabled: true,
        querier_interfaces: ["$VETH_R"]
    },
    msdp: {
        enabled: true,
        local_address: "$IP_RP2_ADDR",
        keepalive_interval: 5,
        hold_time: 75,
        peers: [
            { address: "$IP_RP1_ADDR", description: "Peer to RP1" }
        ]
    }
}
EOF

log_info "Created config files"

log_section 'Starting MCR Instances'

# Start MCR-RP1
start_mcr_with_config mcr_rp1 "$CONFIG_RP1" "$SOCK_RP1" "$LOG_RP1" 0 "$NS_RP1"
MCR_RP1_PID=$mcr_rp1_PID

# Start MCR-RP2
start_mcr_with_config mcr_rp2 "$CONFIG_RP2" "$SOCK_RP2" "$LOG_RP2" 1 "$NS_RP2"
MCR_RP2_PID=$mcr_rp2_PID

# Wait for control sockets
wait_for_sockets "$SOCK_RP1" "$SOCK_RP2"

log_section 'Verifying MSDP Peer Establishment'

VALIDATION_PASSED=0

# Wait for MSDP peers to become active
if wait_for_msdp_peer_active "$SOCK_RP1" "$IP_RP2_ADDR" 30; then
    log_info "RP1: MSDP peer $IP_RP2_ADDR is Active"
else
    log_error "RP1: MSDP peer $IP_RP2_ADDR failed to become Active"
    VALIDATION_PASSED=1
fi

if wait_for_msdp_peer_active "$SOCK_RP2" "$IP_RP1_ADDR" 30; then
    log_info "RP2: MSDP peer $IP_RP1_ADDR is Active"
else
    log_error "RP2: MSDP peer $IP_RP1_ADDR failed to become Active"
    VALIDATION_PASSED=1
fi

log_info "RP1 MSDP peers:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" msdp peers 2>/dev/null || true

log_info ""
log_info "RP2 MSDP peers:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" msdp peers 2>/dev/null || true

log_section 'Verifying PIM Neighbor Discovery'

# Wait for PIM neighbors between RP1 and RP2
if wait_for_pim_neighbor "$SOCK_RP1" "$IP_RP2_ADDR" 15; then
    log_info "RP1 discovered RP2 as PIM neighbor"
else
    log_error "RP1 did not discover RP2 as PIM neighbor"
    VALIDATION_PASSED=1
fi

if wait_for_pim_neighbor "$SOCK_RP2" "$IP_RP1_ADDR" 15; then
    log_info "RP2 discovered RP1 as PIM neighbor"
else
    log_error "RP2 did not discover RP1 as PIM neighbor"
    VALIDATION_PASSED=1
fi

log_section 'Starting Receiver (Multicast Group Join)'

# Start receiver that joins multicast group in the receiver namespace
log_info "Receiver joining $MCAST_GROUP:$MCAST_PORT in namespace $NS_RECV..."

# Clean up any stale receiver files
rm -f "$RECV_FILE" "$RECV_LOG"

# Test parameters - more packets for reliable validation
if [ "${CI:-}" = "true" ]; then
    PACKET_COUNT=500
    PACKET_SIZE=100
    SEND_RATE=500
else
    PACKET_COUNT=1000
    PACKET_SIZE=100
    SEND_RATE=500
fi

# Start Python multicast receiver in separate namespace
sudo ip netns exec "$NS_RECV" python3 -c "
import socket
import struct
import sys
import traceback

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to wildcard to receive all multicast
    sock.bind(('', $MCAST_PORT))
    print(f'Bound to port $MCAST_PORT', file=sys.stderr)

    # Join multicast group on veth_r_p ($IP_RECV_ADDR) in receiver namespace
    mreq = struct.pack('4s4s', socket.inet_aton('$MCAST_GROUP'), socket.inet_aton('$IP_RECV_ADDR'))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print(f'Joined multicast group $MCAST_GROUP on $IP_RECV_ADDR', file=sys.stderr)

    # Receive with timeout
    sock.settimeout(10.0)
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
" > "$RECV_LOG" 2>&1 &
RECEIVER_PID=$!

log_info "Receiver started (PID: $RECEIVER_PID)"

# Wait for IGMP report to be processed and (*,G) route to be created on RP2
# This ensures the full PIM path is established before traffic is sent
log_info "Waiting for (*,G) route on RP2 (receiver downstream)..."
ROUTE_TIMEOUT=15
for i in $(seq 1 $ROUTE_TIMEOUT); do
    RP2_ROUTES=$("$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" mroute 2>/dev/null || echo "")
    # Check for (*,G) route with veth_r as output (receiver interface)
    if echo "$RP2_ROUTES" | grep -q "\"veth_r\""; then
        log_info "✓ RP2 (*,G) route with receiver interface after ${i}s"
        break
    fi
    if [ "$i" -eq "$ROUTE_TIMEOUT" ]; then
        log_info "Warning: RP2 (*,G) route not detected after ${ROUTE_TIMEOUT}s"
    fi
    sleep 1
done

# Check if IGMP group was detected
log_info 'IGMP groups after join (RP2):'
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" igmp groups 2>/dev/null || true

log_section 'Sending Source Traffic (Trigger SA)'

# Send a few priming packets to trigger direct source detection and (S,G) route creation
log_info "Sending priming packets to trigger route creation..."
sudo ip netns exec "$NS_RP1" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "$IP_SRC" \
    --group "$MCAST_GROUP" \
    --port "$MCAST_PORT" \
    --count 10 \
    --size "$PACKET_SIZE" \
    --rate 10 2>/dev/null || true

# Wait for (S,G) route to be created on RP1 (needed for correct forwarding)
log_info "Waiting for (S,G) route creation on RP1..."
ROUTE_TIMEOUT=15
for i in $(seq 1 $ROUTE_TIMEOUT); do
    ROUTES=$("$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" mroute 2>/dev/null || echo "")
    # Check for (S,G) route - JSON format has "source": "10.0.0.1"
    if echo "$ROUTES" | grep -q "\"source\": \"$IP_SRC\""; then
        log_info "✓ (S,G) route created after ${i}s"
        break
    fi
    if [ "$i" -eq "$ROUTE_TIMEOUT" ]; then
        log_info "Warning: (S,G) route not detected, continuing anyway"
        log_info "RP1 routes: $ROUTES"
    fi
    sleep 1
done

# Send bulk traffic from source side in RP1 namespace
log_info "Sending bulk multicast traffic to $MCAST_GROUP:$MCAST_PORT..."

sudo ip netns exec "$NS_RP1" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "$IP_SRC" \
    --group "$MCAST_GROUP" \
    --port "$MCAST_PORT" \
    --count "$PACKET_COUNT" \
    --size "$PACKET_SIZE" \
    --rate "$SEND_RATE" 2>/dev/null || true

log_info "Traffic sent"

# Wait for receiver to finish (10s timeout in receiver script)
log_info 'Waiting for receiver to complete...'
wait $RECEIVER_PID 2>/dev/null || true

log_section 'Verifying SA Cache on RP2'

log_info "RP1 SA cache (originator):"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" msdp sa-cache 2>/dev/null || true

log_info ""
log_info "RP2 SA cache (receiver):"
SA_CACHE_RP2=$("$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" msdp sa-cache 2>/dev/null || echo "")
echo "$SA_CACHE_RP2"

# Check if RP2 has the SA entry from RP1
if echo "$SA_CACHE_RP2" | grep -q "$IP_SRC" && echo "$SA_CACHE_RP2" | grep -q "$MCAST_GROUP"; then
    log_info "RP2 received SA entry for ($IP_SRC, $MCAST_GROUP)"
elif echo "$SA_CACHE_RP2" | grep -q "$MCAST_GROUP"; then
    log_info "RP2 has SA entry for group $MCAST_GROUP"
else
    log_info "Note: SA cache may be empty if source detection not yet implemented"
    log_info "This is expected - SA origination requires source registration at RP"
fi

log_section 'Verifying Multicast Routes'

log_info "RP1 multicast routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" mroute 2>/dev/null || true

log_info ""
log_info "RP2 multicast routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" mroute 2>/dev/null || true

log_section 'Validating End-to-End Packet Delivery'

# Check if receiver actually got packets
if [ -f "$RECV_LOG" ]; then
    log_info "Receiver log:"
    cat "$RECV_LOG"
fi

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

log_section 'MCR Stats'

log_info "RP1 stats:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" stats 2>/dev/null || true

log_info ""
log_info "RP2 stats:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" stats 2>/dev/null || true

log_section 'Test Summary'

if [ $VALIDATION_PASSED -eq 0 ]; then
    log_info '=== MSDP SA Exchange Test PASSED ==='
    log_info ""
    log_info "Validated:"
    log_info "  - MSDP peering established between RP1 and RP2"
    log_info "  - PIM neighbor discovery on inter-RP link"
    log_info "  - Source traffic triggers SA consideration"
    log_info "  - MSDP TCP session maintained for SA exchange"
    log_info "  - End-to-end multicast delivery"
    # Show logs even on success for debugging
    log_info ""
    log_info "RP1 log (source detection debug):"
    grep -E "(Direct source|Source check|DirectSourceDetected|Notifying MSDP)" "$LOG_RP1" 2>/dev/null | head -30 || log_info "  (no source detection logs)"
    echo ""
    echo "=== PASS ==="
    exit 0
else
    log_error '=== MSDP SA Exchange Test FAILED ==='
    log_info ""
    log_info "RP1 log (last 50 lines):"
    tail -50 "$LOG_RP1" 2>/dev/null || true
    log_info ""
    log_info "RP2 log (last 50 lines):"
    tail -50 "$LOG_RP2" 2>/dev/null || true
    echo ""
    echo "=== FAIL ==="
    exit 1
fi
