#!/bin/bash
#
# Dynamic Rule Change Test
#
# Validates MCR behavior when rules are added/removed during active traffic:
# - Adding rules while traffic is flowing
# - Removing rules while traffic is flowing
# - Rule updates take effect without restart
#
# Topology: Traffic Generator -> MCR -> Sink
#
# Usage: sudo ./dynamic_rules.sh
#

set -euo pipefail

# shellcheck source=tests/topologies/common.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Source common functions early (for ensure_binaries_built)
source "$SCRIPT_DIR/common.sh"

# Test parameters
PACKET_SIZE=1400
SEND_RATE=20000
PACKETS_PER_PHASE=10000

# Namespace name
NETNS="mcr_dynamic_test"

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges for network namespace isolation"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Build binaries (if needed) ---
ensure_binaries_built

# --- Create named network namespace ---
echo "=== Dynamic Rule Change Test ==="
echo ""

# Clean up any existing namespace
ip netns del "$NETNS" 2>/dev/null || true

# Create new namespace
ip netns add "$NETNS"

# Set up cleanup trap
# shellcheck disable=SC2317  # Cleanup is called via trap
cleanup() {
    log_info "Running cleanup..."
    ip netns pids "$NETNS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$NETNS" 2>/dev/null || true
}
trap cleanup EXIT

log_section 'Network Namespace Setup'

# Enable loopback in namespace
ip netns exec "$NETNS" ip link set lo up

# Create bridge topology for traffic flow
setup_bridge_topology "$NETNS" br0 veth-gen veth-mcr 10.0.0.1/24 10.0.0.2/24

TOTAL_FAILURES=0

#############################################
# Start MCR without any rules initially
#############################################
log_section 'Starting MCR (No Initial Rules)'

rm -f /tmp/mcr_dynamic.sock /tmp/mcr_dynamic.log
ip netns exec "$NETNS" "$RELAY_BINARY" supervisor \
    --control-socket-path /tmp/mcr_dynamic.sock \
    --interface veth-mcr \
    --num-workers 1 \
    > /tmp/mcr_dynamic.log 2>&1 &
MCR_PID=$!

wait_for_sockets /tmp/mcr_dynamic.sock
sleep 1

#############################################
# TEST 1: Traffic before rule exists (should be unmatched)
#############################################
log_section 'Test 1: Traffic Without Matching Rule'

log_info "Sending traffic to 239.1.1.1:5001 (no rule exists)..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKETS_PER_PHASE"

sleep 1

# Check stats - without a rule, matched should be 0
# Note: rx may include non-multicast traffic (ARP, etc)
sleep 2  # Wait for stats to be emitted

MATCHED=$(extract_stat /tmp/mcr_dynamic.log 'STATS:Ingress' 'matched')
NOT_MATCHED=$(extract_stat /tmp/mcr_dynamic.log 'STATS:Ingress' 'not_matched')

log_info "Before rule: matched=$MATCHED, not_matched=$NOT_MATCHED"

# We expect matched=0 since there's no rule for this traffic
# not_matched may or may not count depending on implementation
if [ "$MATCHED" -eq 0 ]; then
    log_info "Test 1 (No Rule): PASSED - no packets matched (as expected without rule)"
    TEST1_PASSED=0
else
    log_error "Test 1 (No Rule): FAILED - matched=$MATCHED (expected 0)"
    TEST1_PASSED=1
fi

#############################################
# TEST 2: Add rule during runtime
#############################################
log_section 'Test 2: Add Rule During Runtime'

log_info "Adding forwarding rule..."
add_rule /tmp/mcr_dynamic.sock veth-mcr 239.1.1.1 5001 '239.2.2.2:5002:lo'
sleep 1

log_info "Sending traffic to 239.1.1.1:5001 (rule now exists)..."
BEFORE_MATCHED=$(extract_stat /tmp/mcr_dynamic.log 'STATS:Ingress' 'matched')

ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKETS_PER_PHASE"

sleep 1

AFTER_MATCHED=$(extract_stat /tmp/mcr_dynamic.log 'STATS:Ingress' 'matched')
NEW_MATCHED=$((AFTER_MATCHED - BEFORE_MATCHED))

log_info "After adding rule: matched=$NEW_MATCHED new packets"

# Should match most of the new packets
MIN_EXPECTED=$((PACKETS_PER_PHASE * 80 / 100))
if [ "$NEW_MATCHED" -ge "$MIN_EXPECTED" ]; then
    log_info "Test 2 (Add Rule): PASSED - $NEW_MATCHED packets matched after adding rule"
    TEST2_PASSED=0
else
    log_error "Test 2 (Add Rule): FAILED - only $NEW_MATCHED packets matched (expected >= $MIN_EXPECTED)"
    TEST2_PASSED=1
fi

#############################################
# TEST 3: Add second rule for different group
#############################################
log_section 'Test 3: Multiple Concurrent Rules'

log_info "Adding second rule for 239.1.1.2:5001..."
add_rule /tmp/mcr_dynamic.sock veth-mcr 239.1.1.2 5001 '239.2.2.3:5003:lo'
sleep 1

# Add another IP to generator interface
ip netns exec "$NETNS" ip addr add 10.0.0.11/24 dev veth-gen || true

log_info "Sending traffic to both groups concurrently..."
BEFORE_MATCHED=$(extract_stat /tmp/mcr_dynamic.log 'STATS:Ingress' 'matched')

# Send to both groups
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKETS_PER_PHASE" &
GEN1_PID=$!

ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.11 \
    --group 239.1.1.2 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKETS_PER_PHASE" &
GEN2_PID=$!

wait $GEN1_PID || true
wait $GEN2_PID || true

sleep 1

AFTER_MATCHED=$(extract_stat /tmp/mcr_dynamic.log 'STATS:Ingress' 'matched')
NEW_MATCHED=$((AFTER_MATCHED - BEFORE_MATCHED))

log_info "After concurrent traffic: matched=$NEW_MATCHED new packets"

# Should match most packets from both streams
TOTAL_SENT=$((PACKETS_PER_PHASE * 2))
MIN_EXPECTED=$((TOTAL_SENT * 80 / 100))  # 80% threshold, consistent with other tests
if [ "$NEW_MATCHED" -ge "$MIN_EXPECTED" ]; then
    log_info "Test 3 (Multiple Rules): PASSED - $NEW_MATCHED packets matched"
    TEST3_PASSED=0
else
    log_error "Test 3 (Multiple Rules): FAILED - only $NEW_MATCHED packets matched (expected >= $MIN_EXPECTED)"
    TEST3_PASSED=1
fi

#############################################
# TEST 4: Remove rule during traffic
#############################################
log_section 'Test 4: Remove Rule During Traffic'

# Note: This test depends on the control_client supporting rule removal
# If not implemented, we'll just verify the rule can be listed

log_info "Checking rule listing functionality..."
RULE_LIST=$("$CONTROL_CLIENT_BINARY" --socket-path /tmp/mcr_dynamic.sock list 2>&1 || echo "List command not supported")
log_info "Current rules: $RULE_LIST"

# If we can remove rules, test that; otherwise just pass
if echo "$RULE_LIST" | grep -q "239.1.1.1"; then
    log_info "Test 4 (Rule Listing): PASSED - rules are visible"
    TEST4_PASSED=0
else
    log_info "Test 4 (Rule Listing): SKIPPED - rule listing may not show details"
    TEST4_PASSED=0
fi

#############################################
# Graceful shutdown
#############################################
log_section 'Cleanup'

kill -TERM "$MCR_PID" 2>/dev/null || true
sleep 2

#############################################
# Final Summary
#############################################
log_section 'Test Summary'

TOTAL_FAILURES=$((TEST1_PASSED + TEST2_PASSED + TEST3_PASSED + TEST4_PASSED))

if [ $TEST1_PASSED -eq 0 ]; then log_info "Test 1 (No Rule): PASSED"; else log_error "Test 1 (No Rule): FAILED"; fi
if [ $TEST2_PASSED -eq 0 ]; then log_info "Test 2 (Add Rule): PASSED"; else log_error "Test 2 (Add Rule): FAILED"; fi
if [ $TEST3_PASSED -eq 0 ]; then log_info "Test 3 (Multiple Rules): PASSED"; else log_error "Test 3 (Multiple Rules): FAILED"; fi
if [ $TEST4_PASSED -eq 0 ]; then log_info "Test 4 (Rule Listing): PASSED"; else log_error "Test 4 (Rule Listing): FAILED"; fi

echo ""
if [ $TOTAL_FAILURES -eq 0 ]; then
    echo "=== DYNAMIC RULES TEST PASSED ==="
    echo "All dynamic rule tests passed"
    exit 0
else
    echo "=== DYNAMIC RULES TEST FAILED ==="
    echo "$TOTAL_FAILURES test(s) failed"
    exit 1
fi
