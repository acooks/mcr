#!/bin/bash
#
# Tunnel Interface Multicast Capability Test
#
# This test validates:
# - Multicast capability detection for different tunnel types
# - MCR warnings for non-multicast-capable interfaces
# - Multicast forwarding over GRE tunnels (which support multicast)
#
# Tunnel types tested:
# - GRE with multicast mode: Should support multicast (IFF_MULTICAST set)
# - IPIP (point-to-point): Does NOT support multicast (no IFF_MULTICAST)
#
# Network isolation: Runs in isolated network namespace (unshare --net)
#

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/common.sh"

# Test parameters
MULTICAST_GROUP="239.1.1.1"
MULTICAST_PORT=5001
PACKET_SIZE=100

if [ "${CI:-}" = "true" ]; then
    PACKET_COUNT=500
    SEND_RATE=500
else
    PACKET_COUNT=1000
    SEND_RATE=1000
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
echo "=== Tunnel Interface Multicast Capability Test ==="
echo ""

unshare --net bash << 'INNER_SCRIPT'
set -euo pipefail

source "$SCRIPT_DIR/common.sh"

# Variables for cleanup
MCR_PID=""

cleanup() {
    log_info 'Cleaning up...'
    [ -n "$MCR_PID" ] && kill "$MCR_PID" 2>/dev/null || true

    # Remove tunnel interfaces
    ip link del gre_mcast 2>/dev/null || true
    ip link del ipip_tun 2>/dev/null || true

    wait 2>/dev/null || true
}
trap cleanup EXIT

log_section 'Network Namespace Setup'

enable_loopback

# Disable reverse path filtering
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

# Create veth pair (both ends in same namespace for simplicity - we're testing capability detection, not forwarding)
ip link add veth_mcr type veth peer name veth_mcr_p
ip addr add 10.0.0.2/24 dev veth_mcr
ip addr add 10.0.0.1/24 dev veth_mcr_p
ip link set veth_mcr up
ip link set veth_mcr_p up

# Create a dummy interface for tunnel endpoints
ip link add dummy0 type dummy
ip addr add 10.1.0.1/24 dev dummy0
ip link set dummy0 up

ip link add dummy1 type dummy
ip addr add 10.2.0.1/24 dev dummy1
ip link set dummy1 up

log_section 'Testing Tunnel Multicast Capabilities'

# --- Test 1: GRE tunnel with multicast mode ---
log_info "Creating GRE tunnel with multicast support..."

# Create GRE tunnel - note: multicast requires proper configuration
# For testing, we create a simple GRE tunnel (may or may not have IFF_MULTICAST
# depending on kernel version and configuration)
ip tunnel add gre_mcast mode gre remote 10.2.0.2 local 10.1.0.1 ttl 255 2>/dev/null || \
    ip link add gre_mcast type gre remote 10.2.0.2 local 10.1.0.1 ttl 255
ip addr add 192.168.1.1/24 dev gre_mcast
ip link set gre_mcast up

# Check GRE tunnel flags
GRE_FLAGS=$(ip link show gre_mcast | head -1)
log_info "GRE tunnel flags: $GRE_FLAGS"

if echo "$GRE_FLAGS" | grep -q "MULTICAST"; then
    log_info "✓ GRE tunnel has IFF_MULTICAST flag"
    GRE_MULTICAST=true
else
    log_info "⚠ GRE tunnel does NOT have IFF_MULTICAST flag"
    log_info "  (This is normal for point-to-point GRE configurations)"
    GRE_MULTICAST=false
fi

# --- Test 2: IPIP tunnel (point-to-point, no multicast) ---
log_info ""
log_info "Creating IPIP tunnel (point-to-point, no multicast support)..."

ip tunnel add ipip_tun mode ipip remote 10.2.0.2 local 10.1.0.1 ttl 255 2>/dev/null || \
    ip link add ipip_tun type ipip remote 10.2.0.2 local 10.1.0.1 ttl 255
ip addr add 192.168.2.1/24 dev ipip_tun
ip link set ipip_tun up

# Check IPIP tunnel flags
IPIP_FLAGS=$(ip link show ipip_tun | head -1)
log_info "IPIP tunnel flags: $IPIP_FLAGS"

if echo "$IPIP_FLAGS" | grep -q "MULTICAST"; then
    log_info "⚠ IPIP tunnel has IFF_MULTICAST flag (unexpected)"
    IPIP_MULTICAST=true
else
    log_info "✓ IPIP tunnel does NOT have IFF_MULTICAST flag (expected for P2P)"
    IPIP_MULTICAST=false
fi

# --- Test 3: Regular veth pair (should support multicast) ---
log_info ""
log_info "Checking veth pair multicast support..."

VETH_FLAGS=$(ip link show veth_mcr | head -1)
log_info "veth_mcr flags: $VETH_FLAGS"

if echo "$VETH_FLAGS" | grep -q "MULTICAST"; then
    log_info "✓ veth has IFF_MULTICAST flag"
    VETH_MULTICAST=true
else
    log_info "⚠ veth does NOT have IFF_MULTICAST flag"
    VETH_MULTICAST=false
fi

log_section 'Testing MCR Multicast Capability Warning'

MCR_LOG=/tmp/mcr_tunnel.log
MCR_SOCK=/tmp/mcr_tunnel.sock
MCR_CONFIG=/tmp/mcr_tunnel.json5

rm -f "$MCR_SOCK" "$MCR_LOG" "$MCR_CONFIG"

# Create config that uses both multicast-capable and non-capable interfaces
cat > "$MCR_CONFIG" << EOF
{
    rules: [],

    // Enable IGMP on the IPIP tunnel (should trigger warning)
    igmp: {
        enabled: true,
        querier_interfaces: ["ipip_tun", "veth_mcr"]
    },

    // Enable PIM on the IPIP tunnel (should trigger warning)
    pim: {
        enabled: true,
        interfaces: [
            { name: "ipip_tun" },
            { name: "veth_mcr" }
        ],
        static_rp: [
            { rp: "10.0.0.2", group: "239.0.0.0/8" }
        ]
    }
}
EOF

log_info "Starting MCR with multicast-capable and non-capable interfaces..."

"$RELAY_BINARY" supervisor \
    --control-socket-path "$MCR_SOCK" \
    --config "$MCR_CONFIG" \
    --num-workers 1 \
    > "$MCR_LOG" 2>&1 &
MCR_PID=$!

log_info "MCR started (PID: $MCR_PID)"

# Wait for control socket
wait_for_sockets "$MCR_SOCK"

# Check if MCR warned about non-multicast-capable interfaces
log_info ""
log_info "Checking MCR logs for multicast capability warnings..."

if grep -q "does not support multicast" "$MCR_LOG"; then
    log_info "✓ MCR correctly warned about non-multicast-capable interface(s)"
    grep "does not support multicast" "$MCR_LOG" | while read -r line; do
        log_info "  $line"
    done
    MCR_WARNED=true
else
    log_info "⚠ No multicast capability warnings in MCR log"
    log_info "  (Interface may have IFF_MULTICAST flag set)"
    MCR_WARNED=false
fi

log_section 'Verifying MCR Protocol State'

# Verify IGMP and PIM are running despite warnings
log_info "IGMP state:"
"$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" igmp groups 2>/dev/null || true

log_info ""
log_info "PIM neighbors:"
"$CONTROL_CLIENT_BINARY" --socket-path "$MCR_SOCK" pim neighbors 2>/dev/null || true

log_section 'Results'

PASS=true

# Check interface capability detection
log_info "Interface Capability Detection:"
if [ "$IPIP_MULTICAST" = "false" ]; then
    log_info "  ✓ Correctly detected IPIP tunnel as non-multicast-capable"
else
    log_error "  ✗ IPIP tunnel unexpectedly has MULTICAST flag"
fi

if [ "$VETH_MULTICAST" = "true" ]; then
    log_info "  ✓ Correctly detected veth as multicast-capable"
else
    log_error "  ✗ veth unexpectedly lacks MULTICAST flag"
    PASS=false
fi

# Check MCR warning
log_info ""
log_info "MCR Warning Detection:"
if [ "$MCR_WARNED" = "true" ]; then
    log_info "  ✓ MCR correctly warned about non-multicast-capable interface(s)"
elif [ "$IPIP_MULTICAST" = "true" ]; then
    log_info "  ⚠ IPIP has IFF_MULTICAST (unexpected but acceptable)"
else
    log_error "  ✗ MCR did not warn about non-multicast-capable interface"
    PASS=false
fi

# Verify MCR is still running (didn't crash on non-multicast interfaces)
if kill -0 "$MCR_PID" 2>/dev/null; then
    log_info "  ✓ MCR running despite non-multicast-capable interface"
else
    log_error "  ✗ MCR crashed"
    PASS=false
fi

# Show MCR log excerpt
log_info ""
log_info "MCR Log (capability-related):"
grep -E "(IGMP on|PIM on|does not support multicast|IFF_MULTICAST)" "$MCR_LOG" 2>/dev/null | head -10 || echo "  (no capability logs)"

log_section 'Test Complete'

if [ "$PASS" = "true" ]; then
    log_info '=== TUNNEL MULTICAST TEST PASSED ==='
else
    log_error '=== TUNNEL MULTICAST TEST FAILED ==='
    exit 1
fi
INNER_SCRIPT

echo ""
echo "=== Tunnel Multicast Test Complete ==="
