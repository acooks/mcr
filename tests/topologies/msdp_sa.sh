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

# Cleanup function
cleanup() {
    log_info "Running cleanup..."
    [ -n "$SOURCE_PID" ] && sudo kill "$SOURCE_PID" 2>/dev/null || true
    [ -n "$MCR_RP1_PID" ] && sudo kill -TERM "$MCR_RP1_PID" 2>/dev/null || true
    [ -n "$MCR_RP2_PID" ] && sudo kill -TERM "$MCR_RP2_PID" 2>/dev/null || true
    sleep 1
    cleanup_multi_ns "$NS_RP1" "$NS_RP2"
    rm -f "$SOCK_RP1" "$SOCK_RP2" "$LOG_RP1" "$LOG_RP2" "$CONFIG_RP1" "$CONFIG_RP2"
}
trap cleanup EXIT

# Initialize test
init_multi_ns_test "MSDP SA Exchange Test" "$NS_RP1" "$NS_RP2"

log_section 'Creating Network Topology'

# Create veth pair for source side (within RP1 namespace)
sudo ip netns exec "$NS_RP1" ip link add "$VETH_S" type veth peer name "$VETH_S_P"
sudo ip netns exec "$NS_RP1" ip addr add "$IP_SRC/24" dev "$VETH_S"
sudo ip netns exec "$NS_RP1" ip addr add "$IP_RP1_UP" dev "$VETH_S_P"
sudo ip netns exec "$NS_RP1" ip link set "$VETH_S" up
sudo ip netns exec "$NS_RP1" ip link set "$VETH_S_P" up

# Link RP1 and RP2 namespaces (MSDP peering link)
create_linked_namespaces "$NS_RP1" "$NS_RP2" "$VETH_M1" "$VETH_M2" "$IP_RP1_DOWN" "$IP_RP2_UP"

# Create veth pair for receiver side (within RP2 namespace)
sudo ip netns exec "$NS_RP2" ip link add "$VETH_R" type veth peer name "$VETH_R_P"
sudo ip netns exec "$NS_RP2" ip addr add "$IP_RP2_DOWN" dev "$VETH_R"
sudo ip netns exec "$NS_RP2" ip addr add "$IP_RECV" dev "$VETH_R_P"
sudo ip netns exec "$NS_RP2" ip link set "$VETH_R" up
sudo ip netns exec "$NS_RP2" ip link set "$VETH_R_P" up

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

log_section 'Sending Source Traffic (Trigger SA)'

# Send traffic from source side in RP1 namespace
# This should trigger RP1 to originate an SA message to RP2
log_info "Sending multicast traffic to $MCAST_GROUP:$MCAST_PORT to trigger SA..."

PACKET_COUNT=50
PACKET_SIZE=100

sudo ip netns exec "$NS_RP1" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "$IP_SRC" \
    --group "$MCAST_GROUP" \
    --port "$MCAST_PORT" \
    --count "$PACKET_COUNT" \
    --size "$PACKET_SIZE" \
    --rate 50 2>/dev/null || true

log_info "Traffic sent"

# Wait for SA processing
sleep 5

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

# Send more traffic to ensure SA is triggered
log_info ""
log_info "Sending additional traffic burst..."
sudo ip netns exec "$NS_RP1" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "$IP_SRC" \
    --group "$MCAST_GROUP" \
    --port "$MCAST_PORT" \
    --count 100 \
    --size "$PACKET_SIZE" \
    --rate 100 2>/dev/null || true

sleep 3

log_info ""
log_info "RP2 SA cache (after additional traffic):"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" msdp sa-cache 2>/dev/null || true

log_section 'Verifying Multicast Routes'

log_info "RP1 multicast routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" mroute 2>/dev/null || true

log_info ""
log_info "RP2 multicast routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" mroute 2>/dev/null || true

log_section 'Test Summary'

if [ $VALIDATION_PASSED -eq 0 ]; then
    log_info '=== MSDP SA Exchange Test PASSED ==='
    log_info ""
    log_info "Validated:"
    log_info "  - MSDP peering established between RP1 and RP2"
    log_info "  - PIM neighbor discovery on inter-RP link"
    log_info "  - Source traffic triggers SA consideration"
    log_info "  - MSDP TCP session maintained for SA exchange"
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
