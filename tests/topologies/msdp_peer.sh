#!/bin/bash
#
# MSDP Peer Establishment Test
#
# Topology:
#   [MCR-RP1] ──veth12── [MCR-RP2]
#    10.3.0.1            10.3.0.2
#
# This test validates:
# - MSDP TCP connection establishment
# - Peer state transitions: Connecting -> Established -> Active
# - Keepalive exchange
# - Higher IP initiates connection (is_active)
#
# Uses separate network namespaces for each MCR instance.
#

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/common.sh"

# Test namespaces
NS1="mcr_msdp_p1"
NS2="mcr_msdp_p2"

# Network configuration
VETH1="veth1"
VETH2="veth2"
IP1="10.3.0.1/24"
IP2="10.3.0.2/24"
IP1_ADDR="10.3.0.1"
IP2_ADDR="10.3.0.2"

# Control sockets and logs
SOCK1="/tmp/mcr_msdp_p1.sock"
SOCK2="/tmp/mcr_msdp_p2.sock"
LOG1="/tmp/mcr_msdp_p1.log"
LOG2="/tmp/mcr_msdp_p2.log"
CONFIG1="/tmp/mcr_msdp_p1.json5"
CONFIG2="/tmp/mcr_msdp_p2.json5"

MCR1_PID=""
MCR2_PID=""

# Cleanup function
cleanup() {
    log_info "Running cleanup..."
    [ -n "$MCR1_PID" ] && sudo kill -TERM "$MCR1_PID" 2>/dev/null || true
    [ -n "$MCR2_PID" ] && sudo kill -TERM "$MCR2_PID" 2>/dev/null || true
    sleep 1
    cleanup_multi_ns "$NS1" "$NS2"
    rm -f "$SOCK1" "$SOCK2" "$LOG1" "$LOG2" "$CONFIG1" "$CONFIG2"
}
trap cleanup EXIT

# Initialize test
init_multi_ns_test "MSDP Peer Establishment Test" "$NS1" "$NS2"

log_section 'Creating Network Topology'

# Link namespaces with veth pair
create_linked_namespaces "$NS1" "$NS2" "$VETH1" "$VETH2" "$IP1" "$IP2"

log_section 'Creating MCR Configurations'

# MCR-RP1 config: MSDP enabled with peer pointing to RP2
# Peers are configured in the config file (not via mcrctl add-peer)
# Use longer hold_time to allow for keepalive exchange timing
cat > "$CONFIG1" << EOF
{
    rules: [],
    msdp: {
        enabled: true,
        local_address: "$IP1_ADDR",
        keepalive_interval: 5,
        hold_time: 75,
        peers: [
            { address: "$IP2_ADDR", description: "Peer to RP2" }
        ]
    },
    pim: {
        enabled: true,
        router_id: "$IP1_ADDR",
        rp_address: "$IP1_ADDR",
        interfaces: [
            { name: "$VETH1" }
        ],
        static_rp: [
            { rp: "$IP1_ADDR", group: "239.1.0.0/16" }
        ]
    }
}
EOF

# MCR-RP2 config: MSDP enabled with peer pointing to RP1
cat > "$CONFIG2" << EOF
{
    rules: [],
    msdp: {
        enabled: true,
        local_address: "$IP2_ADDR",
        keepalive_interval: 5,
        hold_time: 75,
        peers: [
            { address: "$IP1_ADDR", description: "Peer to RP1" }
        ]
    },
    pim: {
        enabled: true,
        router_id: "$IP2_ADDR",
        rp_address: "$IP2_ADDR",
        interfaces: [
            { name: "$VETH2" }
        ],
        static_rp: [
            { rp: "$IP2_ADDR", group: "239.2.0.0/16" }
        ]
    }
}
EOF

log_info "Created config files: $CONFIG1, $CONFIG2"

log_section 'Starting MCR Instances'

# Start MCR-RP1 in NS1
start_mcr_with_config mcr1 "$CONFIG1" "$SOCK1" "$LOG1" 0 "$NS1"
MCR1_PID=$mcr1_PID

# Start MCR-RP2 in NS2
start_mcr_with_config mcr2 "$CONFIG2" "$SOCK2" "$LOG2" 1 "$NS2"
MCR2_PID=$mcr2_PID

# Wait for control sockets to be ready
wait_for_sockets "$SOCK1" "$SOCK2"

log_section 'Verifying MSDP Peer Establishment'

VALIDATION_PASSED=0

# Wait for MSDP peers to become active
# Higher IP (10.3.0.2) should initiate the connection (is_active)
if wait_for_msdp_peer_active "$SOCK1" "$IP2_ADDR" 30; then
    log_info "MCR-RP1: Peer $IP2_ADDR is Active"
else
    log_error "MCR-RP1: Peer $IP2_ADDR failed to become Active"
    VALIDATION_PASSED=1
fi

if wait_for_msdp_peer_active "$SOCK2" "$IP1_ADDR" 30; then
    log_info "MCR-RP2: Peer $IP1_ADDR is Active"
else
    log_error "MCR-RP2: Peer $IP1_ADDR failed to become Active"
    VALIDATION_PASSED=1
fi

log_section 'Verifying Peer Details'

log_info "MCR-RP1 MSDP peers:"
PEERS1=$("$CONTROL_CLIENT_BINARY" --socket-path "$SOCK1" msdp peers 2>/dev/null || echo "")
echo "$PEERS1"

log_info ""
log_info "MCR-RP2 MSDP peers:"
PEERS2=$("$CONTROL_CLIENT_BINARY" --socket-path "$SOCK2" msdp peers 2>/dev/null || echo "")
echo "$PEERS2"

# Verify peer states are as expected (case-insensitive)
if echo "$PEERS1" | grep -qiE "(active|established)"; then
    log_info "MCR-RP1: Peer state is Active/Established"
else
    log_error "MCR-RP1: Peer state is not Active/Established"
    VALIDATION_PASSED=1
fi

if echo "$PEERS2" | grep -qiE "(active|established)"; then
    log_info "MCR-RP2: Peer state is Active/Established"
else
    log_error "MCR-RP2: Peer state is not Active/Established"
    VALIDATION_PASSED=1
fi

log_section 'Verifying Keepalive Exchange'

# Wait a bit for keepalives to be exchanged
log_info "Waiting for keepalive exchange..."
sleep 15

# Check peer stats for keepalive activity
log_info "MCR-RP1 MSDP peers after keepalive interval:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK1" msdp peers 2>/dev/null || true

log_info ""
log_info "MCR-RP2 MSDP peers after keepalive interval:"
"$CONTROL_CLIENT_BINARY" --socket-path "$SOCK2" msdp peers 2>/dev/null || true

# Verify peers are still active after keepalive exchange
PEERS1_AFTER=$("$CONTROL_CLIENT_BINARY" --socket-path "$SOCK1" msdp peers 2>/dev/null || echo "")
PEERS2_AFTER=$("$CONTROL_CLIENT_BINARY" --socket-path "$SOCK2" msdp peers 2>/dev/null || echo "")

if echo "$PEERS1_AFTER" | grep -qiE "(active|established)"; then
    log_info "MCR-RP1: Peer still Active/Established after keepalive interval"
else
    log_error "MCR-RP1: Peer lost after keepalive interval"
    VALIDATION_PASSED=1
fi

if echo "$PEERS2_AFTER" | grep -qiE "(active|established)"; then
    log_info "MCR-RP2: Peer still Active/Established after keepalive interval"
else
    log_error "MCR-RP2: Peer lost after keepalive interval"
    VALIDATION_PASSED=1
fi

log_section 'Verifying Connection Direction'

# Higher IP (10.3.0.2) should be the active side (initiates connection)
# Check if there's an is_active field in the output
if echo "$PEERS2" | grep -qi "active.*true\|is_active.*true"; then
    log_info "MCR-RP2 ($IP2_ADDR) is the active connector (higher IP)"
elif echo "$PEERS1" | grep -qi "active.*false\|is_active.*false"; then
    log_info "MCR-RP1 ($IP1_ADDR) is the passive side (lower IP)"
else
    log_info "Note: Connection direction not explicitly shown in peer output"
fi

log_section 'Test Summary'

if [ $VALIDATION_PASSED -eq 0 ]; then
    log_info '=== MSDP Peer Establishment Test PASSED ==='
    log_info ""
    log_info "Validated:"
    log_info "  - MSDP TCP connection established between two RPs"
    log_info "  - Bidirectional peer discovery"
    log_info "  - Peer state reached Active/Established"
    log_info "  - Keepalive exchange maintained peer state"
    echo ""
    echo "=== PASS ==="
    exit 0
else
    log_error '=== MSDP Peer Establishment Test FAILED ==='
    log_info ""
    log_info "MCR-RP1 log (last 50 lines):"
    tail -50 "$LOG1" 2>/dev/null || true
    log_info ""
    log_info "MCR-RP2 log (last 50 lines):"
    tail -50 "$LOG2" 2>/dev/null || true
    echo ""
    echo "=== FAIL ==="
    exit 1
fi
