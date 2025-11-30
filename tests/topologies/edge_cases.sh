#!/bin/bash
#
# Edge Case Tests
#
# Validates MCR behavior with boundary conditions:
# - Minimum UDP packet size (8 bytes payload + headers)
# - Maximum MTU packet size (1500 - headers)
# - Large packet count without buffer exhaustion
#
# Topology: Traffic Generator -> MCR -> Sink
#
# Usage: sudo ./edge_cases.sh
#

set -euo pipefail

# shellcheck source=tests/topologies/common.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Source common functions early (for ensure_binaries_built)
source "$SCRIPT_DIR/common.sh"

# Namespace name
NETNS="mcr_edge_test"

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges for network namespace isolation"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Build binaries (if needed) ---
ensure_binaries_built

# --- Create named network namespace ---
echo "=== Edge Case Tests ==="
echo ""

# Clean up any existing namespace
ip netns del "$NETNS" 2>/dev/null || true

# Create new namespace
ip netns add "$NETNS"

# Set up cleanup trap (no PIDs - MCR is killed explicitly in each test phase)
trap 'graceful_cleanup_namespace "$NETNS"' EXIT

log_section 'Network Namespace Setup'

# Enable loopback in namespace
sudo ip netns exec "$NETNS" ip link set lo up

# Create bridge topology for traffic flow
setup_bridge_topology "$NETNS" br0 veth-gen veth-mcr 10.0.0.1/24 10.0.0.2/24

TOTAL_FAILURES=0

#############################################
# TEST 1: Minimum Packet Size
#############################################
log_section 'Test 1: Minimum Packet Size (64 bytes)'

# Start MCR (script runs as root, so no sudo needed)
rm -f /tmp/mcr_edge1.sock /tmp/mcr_edge1.log
ip netns exec "$NETNS" "$RELAY_BINARY" supervisor \
    --control-socket-path /tmp/mcr_edge1.sock \
    --interface veth-mcr \
    --num-workers 1 \
    > /tmp/mcr_edge1.log 2>&1 &
MCR_PID=$!

wait_for_sockets /tmp/mcr_edge1.sock
sleep 1

add_rule /tmp/mcr_edge1.sock veth-mcr 239.1.1.1 5001 '239.2.2.2:5002:lo'
sleep 1

# Send small packets (minimum practical size)
log_info "Sending 10000 packets at 64 bytes each..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate 10000 \
    --size 64 \
    --count 10000

sleep 2

# Graceful shutdown
kill -TERM "$MCR_PID" 2>/dev/null || true
sleep 2

# Validate: expect 90% of 10000 packets matched
if validate_stat_percent /tmp/mcr_edge1.log 'STATS:Ingress' 'matched' 10000 90 "Test 1 (Min Packet Size)"; then
    TEST1_PASSED=0
else
    TEST1_PASSED=1
fi

#############################################
# TEST 2: Maximum Packet Size (MTU)
#############################################
log_section 'Test 2: Maximum Packet Size (1472 bytes - max UDP over 1500 MTU)'

# Start fresh MCR
rm -f /tmp/mcr_edge2.sock /tmp/mcr_edge2.log
ip netns exec "$NETNS" "$RELAY_BINARY" supervisor \
    --control-socket-path /tmp/mcr_edge2.sock \
    --interface veth-mcr \
    --num-workers 1 \
    > /tmp/mcr_edge2.log 2>&1 &
MCR_PID=$!

wait_for_sockets /tmp/mcr_edge2.sock
sleep 1

add_rule /tmp/mcr_edge2.sock veth-mcr 239.1.1.1 5001 '239.2.2.2:5002:lo'
sleep 1

# Send max-size packets (1472 = 1500 MTU - 20 IP header - 8 UDP header)
log_info "Sending 10000 packets at 1472 bytes each..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate 10000 \
    --size 1472 \
    --count 10000

sleep 2

# Graceful shutdown
kill -TERM "$MCR_PID" 2>/dev/null || true
sleep 2

# Validate: expect 90% of 10000 packets matched
if validate_stat_percent /tmp/mcr_edge2.log 'STATS:Ingress' 'matched' 10000 90 "Test 2 (Max Packet Size)"; then
    TEST2_PASSED=0
else
    TEST2_PASSED=1
fi

#############################################
# TEST 3: Buffer Exhaustion Under Load
#############################################
log_section 'Test 3: Buffer Pool Under High Load'

# Start fresh MCR
rm -f /tmp/mcr_edge3.sock /tmp/mcr_edge3.log
ip netns exec "$NETNS" "$RELAY_BINARY" supervisor \
    --control-socket-path /tmp/mcr_edge3.sock \
    --interface veth-mcr \
    --num-workers 1 \
    > /tmp/mcr_edge3.log 2>&1 &
MCR_PID=$!

wait_for_sockets /tmp/mcr_edge3.sock
sleep 1

add_rule /tmp/mcr_edge3.sock veth-mcr 239.1.1.1 5001 '239.2.2.2:5002:lo'
sleep 1

# Send high volume of traffic to stress buffer pool
log_info "Sending 100000 packets at 150k pps to stress buffer pool..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate 150000 \
    --size 1400 \
    --count 100000

sleep 3

# Graceful shutdown
kill -TERM "$MCR_PID" 2>/dev/null || true
sleep 2

# Validate: expect 80% of 100000 packets matched (realistic for 150k pps stress)
# and buffer exhaustion <= 5%
TEST3_PASSED=0
if ! validate_stat_percent /tmp/mcr_edge3.log 'STATS:Ingress' 'matched' 100000 80 "Test 3 packet matching"; then
    TEST3_PASSED=1
fi
if ! validate_stat_max /tmp/mcr_edge3.log 'STATS:Ingress' 'buf_exhaust' 5000 "Test 3 buffer exhaustion (<=5%)"; then
    TEST3_PASSED=1
fi

#############################################
# TEST 4: Zero-Length/Empty Payload Handling
#############################################
log_section 'Test 4: Minimum Valid UDP Packet (46 bytes total - Ethernet minimum)'

# Start fresh MCR
rm -f /tmp/mcr_edge4.sock /tmp/mcr_edge4.log
ip netns exec "$NETNS" "$RELAY_BINARY" supervisor \
    --control-socket-path /tmp/mcr_edge4.sock \
    --interface veth-mcr \
    --num-workers 1 \
    > /tmp/mcr_edge4.log 2>&1 &
MCR_PID=$!

wait_for_sockets /tmp/mcr_edge4.sock
sleep 1

add_rule /tmp/mcr_edge4.sock veth-mcr 239.1.1.1 5001 '239.2.2.2:5002:lo'
sleep 1

# Send minimum Ethernet frame size packets
# Ethernet min is 46 bytes payload (64 with header), but we want at least 8 for UDP header check
log_info "Sending 5000 packets at 46 bytes each..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate 5000 \
    --size 46 \
    --count 5000

sleep 2

# Graceful shutdown
kill -TERM "$MCR_PID" 2>/dev/null || true
sleep 2

# Validate: expect 90% of 5000 packets matched
if validate_stat_percent /tmp/mcr_edge4.log 'STATS:Ingress' 'matched' 5000 90 "Test 4 (Min Valid UDP)"; then
    TEST4_PASSED=0
else
    TEST4_PASSED=1
fi

#############################################
# Final Summary
#############################################
log_section 'Test Summary'

TOTAL_FAILURES=$((TEST1_PASSED + TEST2_PASSED + TEST3_PASSED + TEST4_PASSED))

if [ $TEST1_PASSED -eq 0 ]; then log_info "Test 1 (Min Packet Size): PASSED"; else log_error "Test 1 (Min Packet Size): FAILED"; fi
if [ $TEST2_PASSED -eq 0 ]; then log_info "Test 2 (Max Packet Size): PASSED"; else log_error "Test 2 (Max Packet Size): FAILED"; fi
if [ $TEST3_PASSED -eq 0 ]; then log_info "Test 3 (Buffer Pool): PASSED"; else log_error "Test 3 (Buffer Pool): FAILED"; fi
if [ $TEST4_PASSED -eq 0 ]; then log_info "Test 4 (Min Valid UDP): PASSED"; else log_error "Test 4 (Min Valid UDP): FAILED"; fi

echo ""
if [ $TOTAL_FAILURES -eq 0 ]; then
    echo "=== EDGE CASE TESTS PASSED ==="
    echo "All edge case tests passed"
    exit 0
else
    echo "=== EDGE CASE TESTS FAILED ==="
    echo "$TOTAL_FAILURES test(s) failed"
    exit 1
fi
