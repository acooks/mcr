#!/bin/bash
# Determine minimal requirements for socat multicast relay
# Uses the working 3-namespace topology and removes requirements one by one

set -e

echo "=== Determining Minimal Requirements for socat Multicast Relay ==="
echo ""

# Test configuration
MCAST_IN="239.255.0.1"
MCAST_OUT="239.255.0.2"
PORT="5001"

# Cleanup function
cleanup() {
    sudo ip netns del src-ns 2>/dev/null || true
    sudo ip netns del relay-ns 2>/dev/null || true
    sudo ip netns del sink-ns 2>/dev/null || true
    sudo pkill -f "socat.*UDP4" 2>/dev/null || true
}

trap cleanup EXIT

# Run a single test
run_test() {
    local test_name="$1"
    local skip_ip_forward="$2"
    local skip_mcast_route_relay="$3"
    local skip_mcast_route_src="$4"
    local same_mcast_addr="$5"
    
    echo "========================================" 
    echo "TEST: $test_name"
    echo "========================================" 
    
    cleanup
    
    # Adjust addresses if testing same multicast
    local OUT_ADDR="$MCAST_OUT"
    if [ "$same_mcast_addr" = "yes" ]; then
        OUT_ADDR="$MCAST_IN"
    fi
    
    # Create namespaces
    sudo ip netns add src-ns
    sudo ip netns add relay-ns
    sudo ip netns add sink-ns
    
    # Create and configure veth pairs
    sudo ip link add veth-src0 type veth peer name veth-relay0
    sudo ip link add veth-relay1 type veth peer name veth-sink0
    
    sudo ip link set veth-src0 netns src-ns
    sudo ip link set veth-relay0 netns relay-ns
    sudo ip link set veth-relay1 netns relay-ns
    sudo ip link set veth-sink0 netns sink-ns
    
    sudo ip netns exec src-ns ip addr add 10.0.1.1/24 dev veth-src0
    sudo ip netns exec relay-ns ip addr add 10.0.1.2/24 dev veth-relay0
    sudo ip netns exec relay-ns ip addr add 10.0.2.1/24 dev veth-relay1
    sudo ip netns exec sink-ns ip addr add 10.0.2.2/24 dev veth-sink0
    
    sudo ip netns exec src-ns ip link set veth-src0 up
    sudo ip netns exec relay-ns ip link set veth-relay0 up
    sudo ip netns exec relay-ns ip link set veth-relay1 up
    sudo ip netns exec sink-ns ip link set veth-sink0 up
    sudo ip netns exec src-ns ip link set lo up
    sudo ip netns exec relay-ns ip link set lo up
    sudo ip netns exec sink-ns ip link set lo up
    
    # Unicast routes (always needed for basic connectivity)
    sudo ip netns exec src-ns ip route add 10.0.2.0/24 via 10.0.1.2
    sudo ip netns exec sink-ns ip route add 10.0.1.0/24 via 10.0.2.1
    
    # Optional: IP forwarding
    if [ "$skip_ip_forward" != "yes" ]; then
        sudo ip netns exec relay-ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
    fi
    
    # Optional: Multicast route in relay namespace
    if [ "$skip_mcast_route_relay" != "yes" ]; then
        sudo ip netns exec relay-ns ip route add 239.255.0.0/24 dev veth-relay1
    fi
    
    # Optional: Multicast route in source namespace
    if [ "$skip_mcast_route_src" != "yes" ]; then
        sudo ip netns exec src-ns ip route add 239.255.0.0/24 dev veth-src0
    fi
    
    # Start receiver
    sudo ip netns exec sink-ns socat -u \
        UDP4-RECV:${PORT},ip-add-membership=${OUT_ADDR}:veth-sink0,reuseaddr \
        OPEN:/tmp/sink_recv.txt,creat,append 2>/dev/null &
    sleep 0.3
    
    # Start relay
    sudo ip netns exec relay-ns socat -u \
        UDP4-RECV:${PORT},ip-add-membership=${MCAST_IN}:veth-relay0,reuseaddr \
        UDP4-SEND:${OUT_ADDR}:${PORT},ip-multicast-if=10.0.2.1,reuseaddr 2>/dev/null &
    sleep 0.3
    
    # Send packets
    rm -f /tmp/sink_recv.txt
    for i in {1..3}; do
        echo "Packet $i" | sudo ip netns exec src-ns socat STDIN UDP4-SENDTO:${MCAST_IN}:${PORT},bind=10.0.1.1 2>/dev/null
        sleep 0.1
    done
    
    sleep 0.5
    
    # Check results
    local received=$(wc -l < /tmp/sink_recv.txt 2>/dev/null || echo 0)
    if [ "$received" -eq 3 ]; then
        echo "✅ SUCCESS - 3/3 packets delivered"
        return 0
    else
        echo "❌ FAILURE - $received/3 packets delivered"
        return 1
    fi
}

# Run tests
echo "Running tests to identify minimal requirements..."
echo ""

run_test "1_Baseline_AllRequirements" no no no no
TEST1=$?

run_test "2_Without_IP_Forwarding" yes no no no
TEST2=$?

run_test "3_Without_Relay_McastRoute" no yes no no
TEST3=$?

run_test "4_Without_Source_McastRoute" no no yes no
TEST4=$?

run_test "5_Without_Any_McastRoutes" no yes yes no
TEST5=$?

run_test "6_Same_Multicast_Address" no no no yes
TEST6=$?

run_test "7_Minimal_NoIPForward_NoSrcRoute" yes no yes no
TEST7=$?

echo ""
echo "========================================"
echo "           SUMMARY OF RESULTS"
echo "========================================"
echo ""
printf "%-40s %s\n" "1. Baseline (all requirements):" "$([ $TEST1 -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
printf "%-40s %s\n" "2. Without IP forwarding:" "$([ $TEST2 -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
printf "%-40s %s\n" "3. Without relay mcast route:" "$([ $TEST3 -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
printf "%-40s %s\n" "4. Without source mcast route:" "$([ $TEST4 -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
printf "%-40s %s\n" "5. Without any mcast routes:" "$([ $TEST5 -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
printf "%-40s %s\n" "6. Same multicast address (in=out):" "$([ $TEST6 -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
printf "%-40s %s\n" "7. Minimal (no IP fwd, no src route):" "$([ $TEST7 -eq 0 ] && echo '✅ WORKS' || echo '❌ FAILS')"
echo ""
echo "ESSENTIAL REQUIREMENTS:"
echo ""

# Determine what's required
if [ $TEST2 -ne 0 ]; then
    echo "  ❗ IP forwarding (sysctl net.ipv4.ip_forward=1): REQUIRED"
else
    echo "  ✓  IP forwarding: NOT required"
fi

if [ $TEST3 -ne 0 ]; then
    echo "  ❗ Multicast route in relay namespace: REQUIRED"
else
    echo "  ✓  Multicast route in relay: NOT required"
fi

if [ $TEST4 -ne 0 ]; then
    echo "  ❗ Multicast route in source namespace: REQUIRED"
else
    echo "  ✓  Multicast route in source: NOT required"
fi

if [ $TEST6 -ne 0 ]; then
    echo "  ❗ Different multicast addresses (in ≠ out): REQUIRED"
else
    echo "  ✓  Different multicast addresses: NOT required"
fi

echo ""
cleanup
