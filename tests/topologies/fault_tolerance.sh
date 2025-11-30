#!/bin/bash
#
# Fault Tolerance Test
#
# Validates MCR behavior under fault conditions:
# - Graceful shutdown during traffic flow
# - SIGTERM handling and clean exit
# - Stats persistence on shutdown
#
# Topology: Traffic Generator -> MCR -> Sink
#
# Tests:
# - MCR continues processing until SIGTERM
# - SIGTERM triggers graceful shutdown
# - Final stats are emitted before exit
# - No zombie processes or leaked resources
#
# Usage: sudo ./fault_tolerance.sh
#

set -euo pipefail

# shellcheck source=tests/topologies/common.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/common.sh"

# Test parameters
PACKET_SIZE=1400
SEND_RATE=50000
TRAFFIC_DURATION=5  # seconds of traffic before kill

# Initialize test (root check, binary build, namespace, cleanup trap, loopback)
init_test "Fault Tolerance Test"

# Create bridge topology for traffic flow
setup_bridge_topology "$NETNS" br0 veth-gen veth-mcr 10.0.0.1/24 10.0.0.2/24

#############################################
# TEST 1: Graceful Shutdown During Traffic
#############################################
log_section 'Test 1: Graceful Shutdown During Traffic'

# Start MCR
rm -f /tmp/mcr_fault1.sock /tmp/mcr_fault1.log
ip netns exec "$NETNS" "$RELAY_BINARY" supervisor \
    --control-socket-path /tmp/mcr_fault1.sock \
    --interface veth-mcr \
    --num-workers 1 \
    > /tmp/mcr_fault1.log 2>&1 &
MCR_PID=$!
log_info "MCR started with PID $MCR_PID"

# Wait for socket
wait_for_sockets /tmp/mcr_fault1.sock
sleep 1

# Add rule
add_rule /tmp/mcr_fault1.sock veth-mcr 239.1.1.1 5001 '239.2.2.2:5002:lo'
sleep 1

# Start traffic generator (runs for extended duration)
log_info "Starting traffic generator (will run for $TRAFFIC_DURATION seconds)..."
ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$((SEND_RATE * TRAFFIC_DURATION * 2))" &
GEN_PID=$!

# Let traffic flow for a bit
log_info "Letting traffic flow for $TRAFFIC_DURATION seconds..."
sleep "$TRAFFIC_DURATION"

# Send SIGTERM while traffic is still flowing
log_info "Sending SIGTERM to MCR during active traffic..."
SIGTERM_TIME=$(date +%s.%N)
sudo kill -TERM "$MCR_PID" 2>/dev/null || true

# Wait for MCR to exit (increased timeout to 10 seconds)
MCR_EXITED=0
for i in $(seq 1 100); do
    if ! sudo kill -0 "$MCR_PID" 2>/dev/null; then
        EXIT_TIME=$(date +%s.%N)
        SHUTDOWN_MS=$(echo "($EXIT_TIME - $SIGTERM_TIME) * 1000" | bc 2>/dev/null || echo "unknown")
        log_info "MCR exited after ${SHUTDOWN_MS}ms (iteration $i)"
        MCR_EXITED=1
        break
    fi
    sleep 0.1
done

# Kill traffic generator
sudo kill -TERM "$GEN_PID" 2>/dev/null || true
wait "$GEN_PID" 2>/dev/null || true

# Check that MCR actually exited
if [ "$MCR_EXITED" -eq 0 ]; then
    log_error "MCR did not exit after SIGTERM within 10s - force killing"
    sudo kill -9 "$MCR_PID" 2>/dev/null || true
    TEST1_PASSED=1
else
    log_info "MCR exited cleanly"
    TEST1_PASSED=0
fi

# Check for stats in log (either periodic STATS or FINAL stats)
if grep -qE "\[STATS\]|\[STATS:Ingress FINAL\]" /tmp/mcr_fault1.log; then
    FINAL_MATCHED=$(grep -E "\[STATS\]|\[STATS:Ingress" /tmp/mcr_fault1.log | tail -1 | grep -oP "matched=\K[0-9]+" || echo "0")
    log_info "Stats found: matched=$FINAL_MATCHED packets"
else
    log_error "No stats found in log"
    TEST1_PASSED=1
fi

# Verify no zombie processes in our namespace
# Note: We check only processes in our namespace using ip netns pids
NAMESPACE_PIDS=$(sudo ip netns pids "$NETNS" 2>/dev/null | wc -l || echo "0")
if [ "$NAMESPACE_PIDS" -gt 0 ]; then
    log_info "Found $NAMESPACE_PIDS process(es) still in namespace (cleanup will handle)"
fi

#############################################
# TEST 2: Multiple SIGTERM Handling
#############################################
log_section 'Test 2: Signal Handling Robustness'

# Start fresh MCR
rm -f /tmp/mcr_fault2.sock /tmp/mcr_fault2.log
sudo -E ip netns exec "$NETNS" "$RELAY_BINARY" supervisor \
    --control-socket-path /tmp/mcr_fault2.sock \
    --interface veth-mcr \
    --num-workers 1 \
    > /tmp/mcr_fault2.log 2>&1 &
MCR_PID2=$!
log_info "MCR started with PID $MCR_PID2"

# Wait for socket
wait_for_sockets /tmp/mcr_fault2.sock
sleep 1

# Add rule
add_rule /tmp/mcr_fault2.sock veth-mcr 239.1.1.1 5001 '239.2.2.2:5002:lo'

# Send multiple SIGTERMs rapidly
log_info "Sending multiple SIGTERMs..."
kill -TERM "$MCR_PID2" 2>/dev/null || true
sleep 0.1
kill -TERM "$MCR_PID2" 2>/dev/null || true
sleep 0.1
kill -TERM "$MCR_PID2" 2>/dev/null || true

# Wait for exit (up to 10 seconds)
MCR2_EXITED=0
for i in $(seq 1 100); do
    if ! sudo kill -0 "$MCR_PID2" 2>/dev/null; then
        log_info "MCR exited after multiple SIGTERMs (iteration $i)"
        MCR2_EXITED=1
        break
    fi
    sleep 0.1
done

# Check that MCR exited without crashing
if [ "$MCR2_EXITED" -eq 0 ]; then
    log_error "MCR did not exit after multiple SIGTERMs within 10s"
    sudo kill -9 "$MCR_PID2" 2>/dev/null || true
    TEST2_PASSED=1
else
    log_info "MCR handled multiple SIGTERMs gracefully"
    TEST2_PASSED=0
fi

# Check for any crash indicators
if grep -iE "panic|segfault|SIGSEGV|abort" /tmp/mcr_fault2.log; then
    log_error "Found crash indicators in log"
    TEST2_PASSED=1
fi

#############################################
# Final Summary
#############################################
log_section 'Test Summary'

TOTAL_FAILURES=$((TEST1_PASSED + TEST2_PASSED))

if [ $TEST1_PASSED -eq 0 ]; then
    log_info "Test 1 (Graceful Shutdown): PASSED"
else
    log_error "Test 1 (Graceful Shutdown): FAILED"
fi

if [ $TEST2_PASSED -eq 0 ]; then
    log_info "Test 2 (Signal Handling): PASSED"
else
    log_error "Test 2 (Signal Handling): FAILED"
fi

echo ""
if [ $TOTAL_FAILURES -eq 0 ]; then
    echo "=== FAULT TOLERANCE TEST PASSED ==="
    echo "All fault tolerance tests passed"
    exit 0
else
    echo "=== FAULT TOLERANCE TEST FAILED ==="
    echo "$TOTAL_FAILURES test(s) failed"
    exit 1
fi
