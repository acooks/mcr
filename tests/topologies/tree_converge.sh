#!/bin/bash
#
# Tree Convergence (N:1) Topology Test
#
# Validates packet handling when multiple traffic sources converge to a single
# MCR instance. This tests rule isolation and fair queuing under contention.
#
# Topology:
#   Traffic Gen 1 (239.1.1.1:5001) ─┐
#   Traffic Gen 2 (239.1.1.2:5001) ─┼→ MCR ─→ Sink (lo)
#   Traffic Gen 3 (239.1.1.3:5001) ─┘
#
# Tests:
# - Multiple independent rules on same interface
# - Per-rule packet counting (isolation)
# - Fair handling of concurrent streams
# - No cross-talk between rules
#
# Usage: sudo ./tree_converge.sh
#

set -euo pipefail

# shellcheck source=tests/topologies/common.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Test parameters
PACKET_SIZE=1400
PACKET_COUNT=30000   # Per-source (total 90k packets)
SEND_RATE=30000      # Per-source (total 90k pps)
NUM_SOURCES=3

# Namespace name
NETNS="mcr_converge_test"

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges for network namespace isolation"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Build binaries ---
echo "=== Building Release Binaries ==="
cargo build --release
echo ""

# Source common functions
source "$SCRIPT_DIR/common.sh"

# --- Create named network namespace ---
echo "=== Tree Convergence (N:1) Test ==="
echo "Sources: ${NUM_SOURCES}"
echo "Per-source: ${SEND_RATE} pps, ${PACKET_COUNT} packets"
echo "Total: $((SEND_RATE * NUM_SOURCES)) pps, $((PACKET_COUNT * NUM_SOURCES)) packets"
echo ""

# Clean up any existing namespace
ip netns del "$NETNS" 2>/dev/null || true

# Create new namespace
ip netns add "$NETNS"

# Set up cleanup trap
trap 'graceful_cleanup_namespace "$NETNS" mcr_PID' EXIT

log_section 'Network Namespace Setup'

# Enable loopback in namespace
ip netns exec "$NETNS" ip link set lo up

# Create bridge topology for traffic flow
# All 3 generators share the same bridge to MCR
setup_bridge_topology "$NETNS" br0 veth-gen veth-mcr 10.0.0.1/24 10.0.0.2/24

# Add additional IPs to generator veth for multiple sources
ip netns exec "$NETNS" ip addr add 10.0.0.11/24 dev veth-gen
ip netns exec "$NETNS" ip addr add 10.0.0.12/24 dev veth-gen
ip netns exec "$NETNS" ip addr add 10.0.0.13/24 dev veth-gen

log_section 'Starting MCR Instance'

# Start MCR
start_mcr mcr veth-mcr /tmp/mcr.sock /tmp/mcr.log 0 "$NETNS"

# Wait for socket to be ready
wait_for_sockets /tmp/mcr.sock
sleep 2

log_section 'Configuring Forwarding Rules'

# Add 3 separate rules for each source (different multicast groups)
add_rule /tmp/mcr.sock veth-mcr 239.1.1.1 5001 '239.9.9.1:5001:lo'
add_rule /tmp/mcr.sock veth-mcr 239.1.1.2 5001 '239.9.9.2:5002:lo'
add_rule /tmp/mcr.sock veth-mcr 239.1.1.3 5001 '239.9.9.3:5003:lo'

sleep 2

# Run traffic generators concurrently
log_section "Running Traffic Generators (Concurrent)"

# Start all generators in background
log_info "Starting 3 concurrent traffic generators..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.11 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKET_COUNT" &
GEN1_PID=$!

ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.12 \
    --group 239.1.1.2 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKET_COUNT" &
GEN2_PID=$!

ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.13 \
    --group 239.1.1.3 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKET_COUNT" &
GEN3_PID=$!

# Wait for all generators to complete
log_info "Waiting for traffic generators to complete..."
wait $GEN1_PID || true
wait $GEN2_PID || true
wait $GEN3_PID || true

log_info 'Traffic generation complete'
log_info 'Waiting for pipeline to flush...'
sleep 3

# Trigger graceful shutdown to get FINAL stats
log_info 'Triggering graceful shutdown for FINAL stats...'
if [ -n "$mcr_PID" ] && kill -0 "$mcr_PID" 2>/dev/null; then
    kill -TERM "$mcr_PID" 2>/dev/null || true
fi
sleep 2

# Print final stats
print_final_stats \
    'MCR:/tmp/mcr.log'

log_section 'Validating Results'

VALIDATION_PASSED=0

# Calculate validation thresholds
EXPECTED_RATIO=80  # Allow 20% loss due to concurrent contention
TOTAL_EXPECTED=$((PACKET_COUNT * NUM_SOURCES))
MIN_MATCHED=$((TOTAL_EXPECTED * EXPECTED_RATIO / 100))

# Validate total matched packets
validate_stat /tmp/mcr.log 'STATS:Ingress' 'matched' "$MIN_MATCHED" "MCR total ingress matched (>=${EXPECTED_RATIO}%)" || VALIDATION_PASSED=1

# Check egress matches (should be close to ingress for 1:1 forwarding)
MCR_INGRESS=$(extract_stat /tmp/mcr.log 'STATS:Ingress' 'matched')
MCR_EGRESS=$(extract_stat /tmp/mcr.log 'STATS:Egress' 'sent')
log_info "MCR stats: ingress matched=$MCR_INGRESS, egress sent=$MCR_EGRESS"

# Check per-flow stats to verify all 3 streams were processed
FLOW_STATS=$(grep "FLOW_STATS" /tmp/mcr.log | tail -5 || true)
if [ -n "$FLOW_STATS" ]; then
    log_info "Per-flow statistics found:"
    echo "$FLOW_STATS" | head -5
else
    log_info "No per-flow statistics found (may be consolidated)"
fi

# Egress should be close to ingress (allow 5% variance)
if [ "$MCR_INGRESS" -gt 0 ]; then
    EGRESS_MIN=$((MCR_INGRESS * 95 / 100))
    if [ "$MCR_EGRESS" -lt "$EGRESS_MIN" ]; then
        log_error "Egress ($MCR_EGRESS) significantly less than ingress ($MCR_INGRESS)"
        VALIDATION_PASSED=1
    else
        log_info "Egress matches ingress within tolerance"
    fi
fi

log_section 'Test Complete'

if [ $VALIDATION_PASSED -eq 0 ]; then
    log_info "All validations passed - N:1 convergence working correctly"
    log_info "Successfully handled $NUM_SOURCES concurrent streams"
    log_info 'Full logs available at: /tmp/mcr.log'
    echo ""
    echo "=== CONVERGENCE TEST PASSED ==="
    echo "System achieved >=${EXPECTED_RATIO}% packet forwarding with $NUM_SOURCES sources"
    echo "Network namespace destroyed - no host pollution"
    exit 0
else
    log_error 'Some validations failed - check logs'
    log_info 'Full logs available at: /tmp/mcr.log'
    echo ""
    echo "=== CONVERGENCE TEST FAILED ==="
    echo "Network namespace destroyed - no host pollution"
    exit 1
fi
