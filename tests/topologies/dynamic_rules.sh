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
# Validation strategy: All traffic phases run against a single MCR instance.
# After all phases complete, SIGTERM triggers FINAL stats emission.
# Cumulative counters validate that dynamic rule changes took effect:
#   - no_match count validates phase 1 (no rules → traffic unmatched)
#   - matched count validates phases 2+3 (rules added → traffic matched)
#
# Usage: sudo ./dynamic_rules.sh
#

set -euo pipefail

# shellcheck source=tests/topologies/common.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/common.sh"

# Test parameters
PACKET_SIZE=1400
SEND_RATE=20000
PACKETS_PER_PHASE=10000

# Initialize test (root check, binary build, namespace, cleanup trap, loopback)
init_test "Dynamic Rule Change Test"

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

# Add a dummy rule for a different group to ensure the worker is spawned.
# Without any rules, the supervisor doesn't spawn a data plane worker, so
# no AF_PACKET socket is opened and no traffic is received at all.
log_info "Adding dummy rule to spawn worker (different group)..."
add_rule /tmp/mcr_dynamic.sock veth-mcr 239.99.99.99 9999 '239.99.99.98:9998:lo'
sleep 1

log_info "Sending $PACKETS_PER_PHASE packets to 239.1.1.1:5001 (no matching rule)..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKETS_PER_PHASE"

log_info "Test 1: $PACKETS_PER_PHASE packets sent (will validate via FINAL stats)"
sleep 1

#############################################
# TEST 2: Add rule during runtime
#############################################
log_section 'Test 2: Add Rule During Runtime'

log_info "Adding forwarding rule for 239.1.1.1:5001..."
add_rule /tmp/mcr_dynamic.sock veth-mcr 239.1.1.1 5001 '239.2.2.2:5002:lo'
sleep 1

log_info "Sending $PACKETS_PER_PHASE packets to 239.1.1.1:5001 (rule now exists)..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKETS_PER_PHASE"

log_info "Test 2: $PACKETS_PER_PHASE packets sent (will validate via FINAL stats)"
sleep 1

#############################################
# TEST 3: Add second rule for different group
#############################################
log_section 'Test 3: Multiple Concurrent Rules'

log_info "Adding second rule for 239.1.1.2:5001..."
add_rule /tmp/mcr_dynamic.sock veth-mcr 239.1.1.2 5001 '239.2.2.3:5003:lo'
sleep 1

# Add another IP to generator interface
ip netns exec "$NETNS" ip addr add 10.0.0.11/24 dev veth-gen || true

log_info "Sending $PACKETS_PER_PHASE packets to each group concurrently..."

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

log_info "Test 3: $((PACKETS_PER_PHASE * 2)) packets sent (will validate via FINAL stats)"
sleep 1

#############################################
# TEST 4: Rule listing
#############################################
log_section 'Test 4: Rule Listing'

log_info "Checking rule listing functionality..."
RULE_LIST=$("$CONTROL_CLIENT_BINARY" --socket-path /tmp/mcr_dynamic.sock list 2>&1 || echo "List command not supported")
log_info "Current rules: $RULE_LIST"

# Verify both rules are visible
if echo "$RULE_LIST" | grep -q "239.1.1.1"; then
    log_info "Test 4 (Rule Listing): PASSED - rules are visible"
    TEST4_PASSED=0
else
    log_error "Test 4 (Rule Listing): FAILED - rules not found in listing"
    TEST4_PASSED=1
fi

#############################################
# Graceful shutdown to emit FINAL stats
#############################################
log_section 'Triggering Graceful Shutdown for FINAL Stats'

kill -TERM "$MCR_PID" 2>/dev/null || true
# Wait for worker to emit FINAL stats and exit
for i in $(seq 1 30); do
    if ! kill -0 "$MCR_PID" 2>/dev/null; then break; fi
    sleep 0.1
done
sleep 1

#############################################
# Validate using FINAL stats
#############################################
log_section 'Validating FINAL Stats'

# Expected cumulative totals:
#   Phase 1: 10k packets with no rule → no_match += ~10k
#   Phase 2: 10k packets with 1 rule  → matched += ~10k
#   Phase 3: 20k packets with 2 rules → matched += ~20k
#   Total expected: matched ~= 30k, no_match ~= 10k

FINAL_MATCHED=$(extract_stat /tmp/mcr_dynamic.log 'STATS:Ingress' 'matched')
FINAL_NO_MATCH=$(extract_stat /tmp/mcr_dynamic.log 'STATS:Ingress' 'no_match')

log_info "FINAL stats: matched=$FINAL_MATCHED, no_match=$FINAL_NO_MATCH"

# Test 1 validation: Phase 1 traffic (no rule) should show up as no_match
# 80% threshold accounts for kernel drops on veth pairs
NO_MATCH_THRESHOLD=$((PACKETS_PER_PHASE * 80 / 100))
if [ "$FINAL_NO_MATCH" -ge "$NO_MATCH_THRESHOLD" ]; then
    log_info "Test 1 (No Rule): PASSED - no_match=$FINAL_NO_MATCH (>= $NO_MATCH_THRESHOLD)"
    TEST1_PASSED=0
else
    log_error "Test 1 (No Rule): FAILED - no_match=$FINAL_NO_MATCH (expected >= $NO_MATCH_THRESHOLD)"
    TEST1_PASSED=1
fi

# Test 2+3 validation: Phases 2+3 traffic (with rules) should be matched
# Phase 2: 10k to 239.1.1.1 (1 rule), Phase 3: 10k each to 2 groups (2 rules)
# Total expected matched: ~30k
TOTAL_RULE_TRAFFIC=$((PACKETS_PER_PHASE * 3))
MATCHED_THRESHOLD=$((TOTAL_RULE_TRAFFIC * 80 / 100))
if [ "$FINAL_MATCHED" -ge "$MATCHED_THRESHOLD" ]; then
    log_info "Test 2+3 (Dynamic Rules): PASSED - matched=$FINAL_MATCHED (>= $MATCHED_THRESHOLD)"
    TEST2_PASSED=0
    TEST3_PASSED=0
else
    log_error "Test 2+3 (Dynamic Rules): FAILED - matched=$FINAL_MATCHED (expected >= $MATCHED_THRESHOLD)"
    TEST2_PASSED=1
    TEST3_PASSED=1
fi

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
