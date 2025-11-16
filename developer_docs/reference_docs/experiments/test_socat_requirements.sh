#!/bin/bash
# Test which requirements are essential for socat multicast relay
# This script tests each requirement independently to determine what's actually needed

set -e

MCAST_ADDR_IN="239.255.0.1"
MCAST_ADDR_OUT="239.255.0.2"
MCAST_PORT="5001"

echo "=== Testing socat Multicast Relay Requirements ==="
echo ""

# Cleanup function
cleanup() {
    sudo ip netns del test-ns 2>/dev/null || true
    sudo pkill -f "socat.*UDP4" 2>/dev/null || true
    rm -f /tmp/test_*.txt /tmp/socat_test_*.log
}

trap cleanup EXIT

# Helper function to run a test
run_test() {
    local test_name="$1"
    local setup_fn="$2"
    local result_file="/tmp/test_${test_name}.txt"
    
    echo "----------------------------------------"
    echo "TEST: $test_name"
    echo "----------------------------------------"
    
    # Cleanup previous
    cleanup
    
    # Create namespace and basic topology
    sudo ip netns add test-ns
    sudo ip netns exec test-ns ip link set lo up
    
    # Create veth pairs
    sudo ip netns exec test-ns ip link add veth-src type veth peer name veth-relay0
    sudo ip netns exec test-ns ip link add veth-relay1 type veth peer name veth-sink
    
    # Configure IPs
    sudo ip netns exec test-ns ip addr add 10.0.1.1/24 dev veth-src
    sudo ip netns exec test-ns ip addr add 10.0.1.2/24 dev veth-relay0
    sudo ip netns exec test-ns ip addr add 10.0.2.1/24 dev veth-relay1
    sudo ip netns exec test-ns ip addr add 10.0.2.2/24 dev veth-sink
    
    # Bring up interfaces
    sudo ip netns exec test-ns ip link set veth-src up
    sudo ip netns exec test-ns ip link set veth-relay0 up
    sudo ip netns exec test-ns ip link set veth-relay1 up
    sudo ip netns exec test-ns ip link set veth-sink up
    
    # Run test-specific setup
    $setup_fn
    
    # Start receiver
    rm -f "$result_file"
    sudo ip netns exec test-ns socat -u \
        UDP4-RECV:${MCAST_PORT},ip-add-membership=${MCAST_ADDR_OUT}:veth-sink,reuseaddr \
        OPEN:"$result_file",creat,append 2>/dev/null &
    local receiver_pid=$!
    sleep 0.5
    
    # Start relay
    sudo ip netns exec test-ns socat -u \
        UDP4-RECV:${MCAST_PORT},ip-add-membership=${MCAST_ADDR_IN}:veth-relay0,reuseaddr \
        UDP4-SEND:${MCAST_ADDR_OUT}:${MCAST_PORT},ip-multicast-if=10.0.2.1,reuseaddr \
        2>/dev/null &
    local relay_pid=$!
    sleep 0.5
    
    # Send test packets
    for i in {1..3}; do
        echo "Packet $i" | sudo ip netns exec test-ns socat STDIN UDP4-SENDTO:${MCAST_ADDR_IN}:${MCAST_PORT},bind=10.0.1.1 2>/dev/null
        sleep 0.2
    done
    
    sleep 1
    
    # Check results
    if [ -f "$result_file" ]; then
        local received=$(wc -l < "$result_file" 2>/dev/null || echo 0)
        if [ "$received" -eq 3 ]; then
            echo "Result: ✅ SUCCESS - $received/3 packets delivered"
            return 0
        else
            echo "Result: ❌ FAILURE - $received/3 packets delivered"
            return 1
        fi
    else
        echo "Result: ❌ FAILURE - No output file created"
        return 1
    fi
}

# Test 1: Baseline - all requirements enabled (should work)
test_baseline() {
    sudo ip netns exec test-ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sudo ip netns exec test-ns ip route add 239.255.0.0/24 dev veth-relay1
}

# Test 2: Without IP forwarding
test_no_ip_forward() {
    # ip_forward defaults to 0, so don't enable it
    sudo ip netns exec test-ns ip route add 239.255.0.0/24 dev veth-relay1
}

# Test 3: Without multicast route
test_no_mcast_route() {
    sudo ip netns exec test-ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
    # Don't add multicast route
}

# Test 4: Neither IP forwarding nor multicast route
test_no_routing() {
    # No routing configuration at all
    :
}

# Test 5: Same multicast address for input and output
test_same_mcast_addr() {
    MCAST_ADDR_OUT="$MCAST_ADDR_IN"  # Use same address
    sudo ip netns exec test-ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sudo ip netns exec test-ns ip route add 239.255.0.0/24 dev veth-relay1
}

# Run all tests
echo "Testing which requirements are ESSENTIAL for socat multicast relay"
echo "=================================================================="
echo ""

run_test "baseline_all_requirements" test_baseline
BASELINE=$?

run_test "without_ip_forwarding" test_no_ip_forward
NO_FORWARD=$?

run_test "without_multicast_route" test_no_mcast_route
NO_ROUTE=$?

run_test "no_routing_at_all" test_no_routing
NO_ROUTING=$?

# Reset for same address test
MCAST_ADDR_OUT="239.255.0.2"
run_test "same_multicast_address" test_same_mcast_addr
SAME_ADDR=$?

echo ""
echo "========================================"
echo "SUMMARY OF RESULTS"
echo "========================================"
echo ""
echo "1. Baseline (all requirements):        $([ $BASELINE -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
echo "2. Without IP forwarding:              $([ $NO_FORWARD -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
echo "3. Without multicast route:            $([ $NO_ROUTE -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
echo "4. Without any routing:                $([ $NO_ROUTING -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
echo "5. Same multicast address (in=out):    $([ $SAME_ADDR -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
echo ""
echo "ESSENTIAL REQUIREMENTS:"
if [ $NO_FORWARD -ne 0 ]; then
    echo "  - IP forwarding: REQUIRED"
else
    echo "  - IP forwarding: NOT required"
fi

if [ $NO_ROUTE -ne 0 ]; then
    echo "  - Multicast route: REQUIRED"
else
    echo "  - Multicast route: NOT required"
fi

if [ $SAME_ADDR -ne 0 ]; then
    echo "  - Different multicast addresses: REQUIRED"
else
    echo "  - Different multicast addresses: NOT required"
fi
echo ""
