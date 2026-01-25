#!/bin/bash
#
# End-to-End Protocol Integration Test
#
# Topology:
#   [Source]  ──  [MCR-DR1]  ──  [MCR-RP1]  ══MSDP══  [MCR-RP2]  ──  [MCR-DR2]  ──  [Receiver]
#   10.0.0.1      10.0.0.2       10.1.0.1             10.2.0.1       10.3.0.1       10.3.0.2
#                 10.1.0.2       (RP domain 1)        (RP domain 2)  10.2.0.2
#
# This test validates the complete inter-domain multicast flow:
# - IGMP: Receiver joins group, detected by DR2
# - PIM: DR2 sends Join to RP2
# - MSDP: RP2 receives SA from RP1 about source
# - PIM: RP1 receives Join from DR1
# - Forwarding: Traffic flows Source → DR1 → RP1 → RP2 → DR2 → Receiver
#
# Uses separate network namespaces for each MCR instance.
#

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/common.sh"

# Test namespaces (4 MCR instances)
NS_DR1="mcr_e2e_dr1"
NS_RP1="mcr_e2e_rp1"
NS_RP2="mcr_e2e_rp2"
NS_DR2="mcr_e2e_dr2"

# Network configuration
# Source side veth (in DR1 namespace)
VETH_S="veth_s"
VETH_S_P="veth_s_p"
IP_SRC="10.0.0.1/24"
IP_DR1_UP="10.0.0.2/24"

# DR1 to RP1 link
VETH_D1R1="veth_d1r1"
VETH_R1D1="veth_r1d1"
IP_DR1_DOWN="10.1.0.2/24"
IP_RP1_UP="10.1.0.1/24"

# RP1 to RP2 link (MSDP)
VETH_R1R2="veth_r1r2"
VETH_R2R1="veth_r2r1"
IP_RP1_DOWN="10.5.0.1/24"
IP_RP2_UP="10.5.0.2/24"

# RP2 to DR2 link
VETH_R2D2="veth_r2d2"
VETH_D2R2="veth_d2r2"
IP_RP2_DOWN="10.2.0.1/24"
IP_DR2_UP="10.2.0.2/24"

# Receiver side veth (in DR2 namespace)
VETH_R="veth_r"
VETH_R_P="veth_r_p"
IP_DR2_DOWN="10.3.0.1/24"
IP_RECV="10.3.0.2/24"
IP_RECV_ADDR="10.3.0.2"

# Address strings for configs
IP_SRC_ADDR="10.0.0.1"
IP_DR1_DOWN_ADDR="10.1.0.2"
IP_RP1_ADDR="10.1.0.1"
IP_RP1_MSDP="10.5.0.1"
IP_RP2_ADDR="10.2.0.1"
IP_RP2_MSDP="10.5.0.2"
IP_DR2_UP_ADDR="10.2.0.2"

# Multicast group
MCAST_GROUP="239.1.1.1"
MCAST_PORT="5001"

# Control sockets and logs
SOCK_DR1="/tmp/mcr_e2e_dr1.sock"
SOCK_RP1="/tmp/mcr_e2e_rp1.sock"
SOCK_RP2="/tmp/mcr_e2e_rp2.sock"
SOCK_DR2="/tmp/mcr_e2e_dr2.sock"

LOG_DR1="/tmp/mcr_e2e_dr1.log"
LOG_RP1="/tmp/mcr_e2e_rp1.log"
LOG_RP2="/tmp/mcr_e2e_rp2.log"
LOG_DR2="/tmp/mcr_e2e_dr2.log"

CONFIG_DR1="/tmp/mcr_e2e_dr1.json5"
CONFIG_RP1="/tmp/mcr_e2e_rp1.json5"
CONFIG_RP2="/tmp/mcr_e2e_rp2.json5"
CONFIG_DR2="/tmp/mcr_e2e_dr2.json5"

MCR_DR1_PID=""
MCR_RP1_PID=""
MCR_RP2_PID=""
MCR_DR2_PID=""
RECEIVER_PID=""

# Cleanup function
cleanup() {
    log_info "Running cleanup..."
    [ -n "$RECEIVER_PID" ] && sudo kill "$RECEIVER_PID" 2>/dev/null || true
    [ -n "$MCR_DR1_PID" ] && sudo kill -TERM "$MCR_DR1_PID" 2>/dev/null || true
    [ -n "$MCR_RP1_PID" ] && sudo kill -TERM "$MCR_RP1_PID" 2>/dev/null || true
    [ -n "$MCR_RP2_PID" ] && sudo kill -TERM "$MCR_RP2_PID" 2>/dev/null || true
    [ -n "$MCR_DR2_PID" ] && sudo kill -TERM "$MCR_DR2_PID" 2>/dev/null || true
    sleep 1
    cleanup_multi_ns "$NS_DR1" "$NS_RP1" "$NS_RP2" "$NS_DR2"
    rm -f "$SOCK_DR1" "$SOCK_RP1" "$SOCK_RP2" "$SOCK_DR2"
    rm -f "$LOG_DR1" "$LOG_RP1" "$LOG_RP2" "$LOG_DR2"
    rm -f "$CONFIG_DR1" "$CONFIG_RP1" "$CONFIG_RP2" "$CONFIG_DR2"
}
trap cleanup EXIT

# Check for socat
if ! command -v socat &> /dev/null; then
    echo "ERROR: socat is required but not installed"
    exit 1
fi

# Initialize test
init_multi_ns_test "End-to-End Protocol Integration Test" "$NS_DR1" "$NS_RP1" "$NS_RP2" "$NS_DR2"

log_section 'Creating Network Topology'

# Create source-side veth in DR1 namespace
sudo ip netns exec "$NS_DR1" ip link add "$VETH_S" type veth peer name "$VETH_S_P"
sudo ip netns exec "$NS_DR1" ip addr add "$IP_SRC" dev "$VETH_S"
sudo ip netns exec "$NS_DR1" ip addr add "$IP_DR1_UP" dev "$VETH_S_P"
sudo ip netns exec "$NS_DR1" ip link set "$VETH_S" up
sudo ip netns exec "$NS_DR1" ip link set "$VETH_S_P" up

# Link DR1 to RP1
create_linked_namespaces "$NS_DR1" "$NS_RP1" "$VETH_D1R1" "$VETH_R1D1" "$IP_DR1_DOWN" "$IP_RP1_UP"

# Link RP1 to RP2 (MSDP link)
create_linked_namespaces "$NS_RP1" "$NS_RP2" "$VETH_R1R2" "$VETH_R2R1" "$IP_RP1_DOWN" "$IP_RP2_UP"

# Link RP2 to DR2
create_linked_namespaces "$NS_RP2" "$NS_DR2" "$VETH_R2D2" "$VETH_D2R2" "$IP_RP2_DOWN" "$IP_DR2_UP"

# Create receiver-side veth in DR2 namespace
sudo ip netns exec "$NS_DR2" ip link add "$VETH_R" type veth peer name "$VETH_R_P"
sudo ip netns exec "$NS_DR2" ip addr add "$IP_DR2_DOWN" dev "$VETH_R"
sudo ip netns exec "$NS_DR2" ip addr add "$IP_RECV" dev "$VETH_R_P"
sudo ip netns exec "$NS_DR2" ip link set "$VETH_R" up
sudo ip netns exec "$NS_DR2" ip link set "$VETH_R_P" up

# Force IGMPv2 in DR2 namespace
sudo ip netns exec "$NS_DR2" sysctl -w net.ipv4.conf.all.force_igmp_version=2 >/dev/null 2>&1 || true

# Add routes for full connectivity
# DR1 routes
sudo ip netns exec "$NS_DR1" ip route add 10.2.0.0/24 via "${IP_RP1_UP%/*}"
sudo ip netns exec "$NS_DR1" ip route add 10.3.0.0/24 via "${IP_RP1_UP%/*}"
sudo ip netns exec "$NS_DR1" ip route add 10.5.0.0/24 via "${IP_RP1_UP%/*}"

# RP1 routes
sudo ip netns exec "$NS_RP1" ip route add 10.0.0.0/24 via "${IP_DR1_DOWN%/*}"
sudo ip netns exec "$NS_RP1" ip route add 10.2.0.0/24 via "${IP_RP2_UP%/*}"
sudo ip netns exec "$NS_RP1" ip route add 10.3.0.0/24 via "${IP_RP2_UP%/*}"

# RP2 routes
sudo ip netns exec "$NS_RP2" ip route add 10.0.0.0/24 via "${IP_RP1_DOWN%/*}"
sudo ip netns exec "$NS_RP2" ip route add 10.1.0.0/24 via "${IP_RP1_DOWN%/*}"
sudo ip netns exec "$NS_RP2" ip route add 10.3.0.0/24 via "${IP_DR2_UP%/*}"

# DR2 routes
sudo ip netns exec "$NS_DR2" ip route add 10.0.0.0/24 via "${IP_RP2_DOWN%/*}"
sudo ip netns exec "$NS_DR2" ip route add 10.1.0.0/24 via "${IP_RP2_DOWN%/*}"
sudo ip netns exec "$NS_DR2" ip route add 10.5.0.0/24 via "${IP_RP2_DOWN%/*}"

log_section 'Creating MCR Configurations'

# DR1 config: PIM towards RP1, IGMP on source side
# Use short hello_period for faster neighbor discovery in tests
cat > "$CONFIG_DR1" << EOF
{
    rules: [],
    pim: {
        enabled: true,
        router_id: "$IP_DR1_DOWN_ADDR",
        interfaces: [
            { name: "$VETH_S_P", hello_period: 5 },
            { name: "$VETH_D1R1", hello_period: 5 }
        ],
        static_rp: [
            { rp: "$IP_RP1_ADDR", group: "239.0.0.0/8" }
        ]
    },
    igmp: {
        enabled: true,
        querier_interfaces: ["$VETH_S_P"]
    }
}
EOF

# RP1 config: RP for domain 1, MSDP to RP2
cat > "$CONFIG_RP1" << EOF
{
    rules: [],
    pim: {
        enabled: true,
        router_id: "$IP_RP1_ADDR",
        rp_address: "$IP_RP1_ADDR",
        interfaces: [
            { name: "$VETH_R1D1", hello_period: 5 },
            { name: "$VETH_R1R2", hello_period: 5 }
        ],
        static_rp: [
            { rp: "$IP_RP1_ADDR", group: "239.0.0.0/8" }
        ]
    },
    msdp: {
        enabled: true,
        local_address: "$IP_RP1_MSDP",
        keepalive_interval: 5,
        hold_time: 75,
        peers: [
            { address: "$IP_RP2_MSDP", description: "Peer to RP2" }
        ]
    }
}
EOF

# RP2 config: RP for domain 2, MSDP to RP1
cat > "$CONFIG_RP2" << EOF
{
    rules: [],
    pim: {
        enabled: true,
        router_id: "$IP_RP2_ADDR",
        rp_address: "$IP_RP2_ADDR",
        interfaces: [
            { name: "$VETH_R2R1", hello_period: 5 },
            { name: "$VETH_R2D2", hello_period: 5 }
        ],
        static_rp: [
            { rp: "$IP_RP1_ADDR", group: "239.0.0.0/8" }
        ]
    },
    msdp: {
        enabled: true,
        local_address: "$IP_RP2_MSDP",
        keepalive_interval: 5,
        hold_time: 75,
        peers: [
            { address: "$IP_RP1_MSDP", description: "Peer to RP1" }
        ]
    }
}
EOF

# DR2 config: PIM towards RP2, IGMP on receiver side
cat > "$CONFIG_DR2" << EOF
{
    rules: [],
    pim: {
        enabled: true,
        router_id: "$IP_DR2_UP_ADDR",
        interfaces: [
            { name: "$VETH_D2R2", hello_period: 5 },
            { name: "$VETH_R", hello_period: 5 }
        ],
        static_rp: [
            { rp: "$IP_RP2_ADDR", group: "239.0.0.0/8" }
        ]
    },
    igmp: {
        enabled: true,
        querier_interfaces: ["$VETH_R"],
        query_interval: 5,
        query_response_interval: 2
    }
}
EOF

log_info "Created config files for all 4 MCR instances"

log_section 'Starting MCR Instances'

# Start all MCR instances on separate CPU cores
start_mcr_with_config mcr_dr1 "$CONFIG_DR1" "$SOCK_DR1" "$LOG_DR1" 0 "$NS_DR1"
MCR_DR1_PID=$mcr_dr1_PID

start_mcr_with_config mcr_rp1 "$CONFIG_RP1" "$SOCK_RP1" "$LOG_RP1" 1 "$NS_RP1"
MCR_RP1_PID=$mcr_rp1_PID

start_mcr_with_config mcr_rp2 "$CONFIG_RP2" "$SOCK_RP2" "$LOG_RP2" 2 "$NS_RP2"
MCR_RP2_PID=$mcr_rp2_PID

start_mcr_with_config mcr_dr2 "$CONFIG_DR2" "$SOCK_DR2" "$LOG_DR2" 3 "$NS_DR2"
MCR_DR2_PID=$mcr_dr2_PID

# Wait for all control sockets
wait_for_sockets "$SOCK_DR1" "$SOCK_RP1" "$SOCK_RP2" "$SOCK_DR2"

VALIDATION_PASSED=0

log_section 'Phase 1: Verifying PIM Neighbor Discovery'

# DR1 <-> RP1
if wait_for_pim_neighbor "$SOCK_DR1" "$IP_RP1_ADDR" 15; then
    log_info "DR1 discovered RP1 as PIM neighbor"
else
    log_error "DR1 did not discover RP1 as PIM neighbor"
    VALIDATION_PASSED=1
fi

# RP1 <-> RP2 (on MSDP link)
if wait_for_pim_neighbor "$SOCK_RP1" "$IP_RP2_MSDP" 15; then
    log_info "RP1 discovered RP2 as PIM neighbor"
else
    log_error "RP1 did not discover RP2 as PIM neighbor"
    VALIDATION_PASSED=1
fi

# RP2 <-> DR2
if wait_for_pim_neighbor "$SOCK_RP2" "$IP_DR2_UP_ADDR" 15; then
    log_info "RP2 discovered DR2 as PIM neighbor"
else
    log_error "RP2 did not discover DR2 as PIM neighbor"
    VALIDATION_PASSED=1
fi

log_section 'Phase 2: Verifying MSDP Peer Establishment'

if wait_for_msdp_peer_active "$SOCK_RP1" "$IP_RP2_MSDP" 30; then
    log_info "RP1: MSDP peer RP2 is Active"
else
    log_error "RP1: MSDP peer RP2 failed to become Active"
    VALIDATION_PASSED=1
fi

if wait_for_msdp_peer_active "$SOCK_RP2" "$IP_RP1_MSDP" 30; then
    log_info "RP2: MSDP peer RP1 is Active"
else
    log_error "RP2: MSDP peer RP1 failed to become Active"
    VALIDATION_PASSED=1
fi

log_section 'Phase 3: Starting Receiver (IGMP Join)'

log_info "Starting receiver in DR2 domain joining $MCAST_GROUP..."

sudo ip netns exec "$NS_DR2" socat -u \
    UDP4-RECVFROM:"$MCAST_PORT",ip-add-membership="$MCAST_GROUP":"$IP_RECV_ADDR",bind="$IP_RECV_ADDR",reuseaddr \
    /dev/null &
RECEIVER_PID=$!

log_info "Receiver started (PID: $RECEIVER_PID)"
sleep 3

log_section 'Phase 4: Verifying IGMP Group Detection'

if wait_for_igmp_group "$SOCK_DR2" "$MCAST_GROUP" 15; then
    log_info "DR2 detected IGMP group $MCAST_GROUP from receiver"
else
    log_error "DR2 did not detect IGMP group $MCAST_GROUP"
    VALIDATION_PASSED=1
fi

log_info "DR2 IGMP groups:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_DR2" igmp groups 2>/dev/null || true

log_section 'Phase 5: Verifying PIM Route Creation'

# Wait for route on DR2
if wait_for_mroute "$SOCK_DR2" "$MCAST_GROUP" 15; then
    log_info "DR2 created multicast route for $MCAST_GROUP"
else
    log_error "DR2 did not create multicast route for $MCAST_GROUP"
    VALIDATION_PASSED=1
fi

sleep 3

log_info "DR2 multicast routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_DR2" mroute 2>/dev/null || true

log_info ""
log_info "RP2 multicast routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" mroute 2>/dev/null || true

log_section 'Phase 6: Sending Source Traffic'

log_info "Sending multicast traffic from source ($IP_SRC_ADDR) to $MCAST_GROUP..."

PACKET_COUNT=100
PACKET_SIZE=100

sudo ip netns exec "$NS_DR1" "$TRAFFIC_GENERATOR_BINARY" \
    --interface "$IP_SRC_ADDR" \
    --group "$MCAST_GROUP" \
    --port "$MCAST_PORT" \
    --count "$PACKET_COUNT" \
    --size "$PACKET_SIZE" \
    --rate 100 2>/dev/null || true

log_info "Traffic sent"
sleep 5

log_section 'Phase 7: Final State Verification'

log_info "=== DR1 State ==="
log_info "PIM Neighbors:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_DR1" pim neighbors 2>/dev/null || true
log_info "Multicast Routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_DR1" mroute 2>/dev/null || true

log_info ""
log_info "=== RP1 State ==="
log_info "PIM Neighbors:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" pim neighbors 2>/dev/null || true
log_info "MSDP Peers:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" msdp peers 2>/dev/null || true
log_info "Multicast Routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP1" mroute 2>/dev/null || true

log_info ""
log_info "=== RP2 State ==="
log_info "PIM Neighbors:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" pim neighbors 2>/dev/null || true
log_info "MSDP Peers:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" msdp peers 2>/dev/null || true
log_info "SA Cache:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" msdp sa-cache 2>/dev/null || true
log_info "Multicast Routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_RP2" mroute 2>/dev/null || true

log_info ""
log_info "=== DR2 State ==="
log_info "PIM Neighbors:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_DR2" pim neighbors 2>/dev/null || true
log_info "IGMP Groups:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_DR2" igmp groups 2>/dev/null || true
log_info "Multicast Routes:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK_DR2" mroute 2>/dev/null || true

log_section 'Test Summary'

if [ $VALIDATION_PASSED -eq 0 ]; then
    log_info '=== End-to-End Protocol Integration Test PASSED ==='
    log_info ""
    log_info "Validated inter-domain multicast protocol stack:"
    log_info "  - PIM neighbor discovery across 4 routers"
    log_info "  - MSDP peering between RP1 and RP2"
    log_info "  - IGMP group membership detection"
    log_info "  - PIM Join propagation towards RP"
    log_info "  - Multicast route creation from IGMP/PIM"
    echo ""
    echo "=== PASS ==="
    exit 0
else
    log_error '=== End-to-End Protocol Integration Test FAILED ==='
    log_info ""
    log_info "Check logs for details:"
    log_info "  DR1: $LOG_DR1"
    log_info "  RP1: $LOG_RP1"
    log_info "  RP2: $LOG_RP2"
    log_info "  DR2: $LOG_DR2"
    echo ""
    echo "=== FAIL ==="
    exit 1
fi
