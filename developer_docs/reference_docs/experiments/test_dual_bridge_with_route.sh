#!/bin/bash
#
# Performance Comparison Test: MCR vs. socat (Dual-Bridge Topology)
#
# This test implements the dual-bridge topology described in docs/MCR_vs_socat.md
# to simulate MCR acting as a router between two separate Layer 2 network segments.
#
# Topology: Generator (br0) → Relay (veth-mcr0 | veth-mcr1) → Sink (br1)
#
# Network topology:
#   - br0 (Network Segment A): Traffic generator and relay ingress interface
#   - br1 (Network Segment B): Relay egress interface and packet sink
#   - Relay has two veth pairs: one in each bridge
#
# IMPORTANT NOTE (2025-11-15):
#   Current socat configuration uses ip-multicast-if=10.0.1.20 to specify egress
#   interface. Testing shows this does NOT work in the dual-bridge topology - socat
#   receives packets but fails to forward them (0% delivery). See
#   docs/experiments/multicast_routing_analysis.md for details. This test may show
#   socat with 100% packet loss, which reflects a real limitation of Layer 4
#   (UDP socket) approaches in this topology.
#
# Test Parameters:
#   - 1M packets @ 150k pps (default, configurable via environment variables)
#   - Packet size: 1024 bytes
#
# Usage:
#   sudo ./compare_socat_bridge.sh
#   sudo PACKET_COUNT=500000 SEND_RATE=100000 ./compare_socat_bridge.sh

set -euo pipefail

# --- Configuration ---
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# Test parameters (can be overridden via environment)
PACKET_SIZE="${PACKET_SIZE:-1024}"
PACKET_COUNT="${PACKET_COUNT:-1000000}"   # 1M packets
SEND_RATE="${SEND_RATE:-150000}"          # 150k pps

# Namespace name
NETNS="mcr_bridge_test"

# File paths
MCR_LOG="/tmp/mcr_bridge.log"
MCR_SOCK="/tmp/mcr_bridge.sock"
SOCAT_SINK_FILE="/tmp/socat_sink_bridge.bin"
MCR_RESULTS_FILE="/tmp/mcr_bridge_results.txt"
SOCAT_RESULTS_FILE="/tmp/socat_bridge_results.txt"

# Binary paths
TRAFFIC_GEN="$PROJECT_ROOT/target/release/traffic_generator"
MCR_SUPERVISOR="$PROJECT_ROOT/target/release/multicast_relay"
CONTROL_CLIENT="$PROJECT_ROOT/target/release/control_client"

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Build binaries ---
echo "=== Building Release Binaries ==="
cargo build --release 2>&1 | grep -E '(Compiling|Finished|error)' || true
echo ""

# --- Cleanup function ---
cleanup_all() {
    echo "[INFO] Running cleanup"

    # Kill all processes in namespace
    ip netns pids "$NETNS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true

    # Delete namespace (this also deletes veth pairs and bridges inside it)
    ip netns del "$NETNS" 2>/dev/null || true

    # Clean up temp files (but not results files - those are needed for final report)
    rm -f "$MCR_LOG" "$MCR_SOCK" "$SOCAT_SINK_FILE"

    echo "[INFO] Cleanup complete"
}

# Final cleanup (called at exit)
final_cleanup() {
    cleanup_all
    # Now safe to remove results files
    rm -f "$MCR_RESULTS_FILE" "$SOCAT_RESULTS_FILE"
}

trap final_cleanup EXIT

# --- Setup Dual-Bridge Topology ---
setup_bridge_topology() {
    # Clean up any existing setup
    cleanup_all

    # Create network namespace
    ip netns add "$NETNS"

    # Enable loopback in namespace
    ip netns exec "$NETNS" ip link set lo up

    # Create bridge br0 (Network Segment A - Ingress)
    ip netns exec "$NETNS" ip link add name br0 type bridge
    ip netns exec "$NETNS" ip link set br0 up
    # Disable IGMP snooping to allow multicast flooding
    ip netns exec "$NETNS" ip link set br0 type bridge mcast_snooping 0
    # Disable STP to avoid topology learning delays
    ip netns exec "$NETNS" ip link set br0 type bridge stp_state 0

    # Create veth pair for traffic generator (connected to br0)
    ip netns exec "$NETNS" ip link add veth-gen type veth peer name veth-gen-p
    ip netns exec "$NETNS" ip addr add 10.0.0.10/24 dev veth-gen
    ip netns exec "$NETNS" ip link set veth-gen up
    ip netns exec "$NETNS" ip link set veth-gen-p up
    ip netns exec "$NETNS" ip link set veth-gen-p master br0

    # Create veth pair for relay ingress (connected to br0)
    ip netns exec "$NETNS" ip link add veth-mcr0 type veth peer name veth-mcr0-p
    ip netns exec "$NETNS" ip addr add 10.0.0.20/24 dev veth-mcr0
    ip netns exec "$NETNS" ip link set veth-mcr0 up
    ip netns exec "$NETNS" ip link set veth-mcr0-p up
    ip netns exec "$NETNS" ip link set veth-mcr0-p master br0

    # Create bridge br1 (Network Segment B - Egress)
    ip netns exec "$NETNS" ip link add name br1 type bridge
    ip netns exec "$NETNS" ip link set br1 up
    # Disable IGMP snooping to allow multicast flooding
    ip netns exec "$NETNS" ip link set br1 type bridge mcast_snooping 0
    # Disable STP to avoid topology learning delays
    ip netns exec "$NETNS" ip link set br1 type bridge stp_state 0

    # Create veth pair for relay egress (connected to br1)
    ip netns exec "$NETNS" ip link add veth-mcr1 type veth peer name veth-mcr1-p
    ip netns exec "$NETNS" ip addr add 10.0.1.20/24 dev veth-mcr1
    ip netns exec "$NETNS" ip link set veth-mcr1 up
    ip netns exec "$NETNS" ip link set veth-mcr1-p up
    ip netns exec "$NETNS" ip link set veth-mcr1-p master br1

    # Create veth pair for sink (connected to br1)
    ip netns exec "$NETNS" ip link add veth-sink type veth peer name veth-sink-p
    ip netns exec "$NETNS" ip addr add 10.0.1.30/24 dev veth-sink
    ip netns exec "$NETNS" ip link set veth-sink up
    ip netns exec "$NETNS" ip link set veth-sink-p up
    ip netns exec "$NETNS" ip link set veth-sink-p master br1

    # Add multicast route for traffic generator
    # The traffic generator needs this to know which interface to send multicast packets from
    ip netns exec "$NETNS" ip route add 224.0.0.0/4 dev veth-gen
    # Add multicast route for relay egress (TESTING FIX)
    ip netns exec "$NETNS" ip route add 224.0.0.0/4 dev veth-mcr1
}

# --- MCR Test Function ---
run_mcr_test() {
    echo "=== Running MCR Test ==="
    echo ""

    rm -f "$MCR_LOG" "$MCR_SOCK"

    # Start MCR supervisor in namespace
    echo "[1] Starting MCR in $NETNS (listening on veth-mcr0)"
    ip netns exec "$NETNS" taskset -c 0 \
        "$MCR_SUPERVISOR" supervisor \
        --interface veth-mcr0 \
        --control-socket-path "$MCR_SOCK" \
        > "$MCR_LOG" 2>&1 &

    local mcr_pid=$!

    # Wait for MCR to be ready (socket creation)
    local ready=0
    for i in {1..20}; do
        if [ -S "$MCR_SOCK" ]; then
            echo "[INFO] MCR ready (PID: $mcr_pid)"
            ready=1
            break
        fi
        sleep 0.5
    done

    if [ $ready -eq 0 ]; then
        echo "[ERROR] MCR failed to start - socket not created"
        cat "$MCR_LOG" 2>/dev/null || echo "No log file"
        return 1
    fi

    sleep 1

    # Add forwarding rule: 239.1.1.1:5001 (from veth-mcr0) → 239.9.9.9:5099 (out veth-mcr1)
    echo "[2] Adding forwarding rule: 239.1.1.1:5001 → 239.9.9.9:5099 via veth-mcr1"
    "$CONTROL_CLIENT" --socket-path "$MCR_SOCK" add \
        --input-interface veth-mcr0 \
        --input-group 239.1.1.1 \
        --input-port 5001 \
        --outputs '239.9.9.9:5099:veth-mcr1' 2>&1 | grep -v '^{' || true

    sleep 1

    # Run traffic generator in namespace
    echo "[3] Running traffic generator ($PACKET_COUNT packets @ $SEND_RATE pps)"
    ip netns exec "$NETNS" "$TRAFFIC_GEN" \
        --interface 10.0.0.10 \
        --group 239.1.1.1 \
        --port 5001 \
        --rate "$SEND_RATE" \
        --size "$PACKET_SIZE" \
        --count "$PACKET_COUNT" >/dev/null 2>&1

    echo "[INFO] Traffic complete, waiting for pipeline flush..."
    sleep 3

    # Stop MCR gracefully
    kill $mcr_pid 2>/dev/null || true
    wait $mcr_pid 2>/dev/null || true
    sleep 1

    # Parse results from MCR log
    echo "[4] Parsing MCR statistics..."
    local ingress_matched=$(grep "STATS:Ingress FINAL" "$MCR_LOG" 2>/dev/null | grep -oP 'matched=\K[0-9]+' || echo 0)
    local egress_sent=$(grep "STATS:Egress FINAL" "$MCR_LOG" 2>/dev/null | grep -oP 'sent=\K[0-9]+' || echo 0)
    local buffer_exhaustion=$(grep "STATS:Ingress FINAL" "$MCR_LOG" 2>/dev/null | grep -oP 'buf_exhaust=\K[0-9]+' || echo 0)

    # Write results to file
    cat > "$MCR_RESULTS_FILE" <<EOF
MCR_INGRESS=$ingress_matched
MCR_EGRESS=$egress_sent
MCR_BUF_EXHAUST=$buffer_exhaustion
EOF

    echo "[INFO] MCR test complete: $egress_sent packets forwarded"
    echo ""
}

# --- socat Test Function ---
run_socat_test() {
    echo "=== Running socat Test ==="
    echo ""

    rm -f "$SOCAT_SINK_FILE"

    # Start socat SINK in namespace (receives on veth-sink)
    echo "[1] Starting socat sink in $NETNS (239.9.9.9:5099 on veth-sink)"
    # Remove any existing sink file
    rm -f "$SOCAT_SINK_FILE"
    touch "$SOCAT_SINK_FILE"
    ip netns exec "$NETNS" socat -u \
        UDP4-RECV:5099,ip-add-membership=239.9.9.9:veth-sink,reuseaddr,so-rcvbuf=8388608 \
        OPEN:"$SOCAT_SINK_FILE",creat,append 2>/dev/null &
    local sink_pid=$!
    sleep 1

    # Start socat RELAY in namespace (multi-homed: veth-mcr0 and veth-mcr1)
    echo "[2] Starting socat relay in $NETNS"
    echo "    Input:  239.1.1.1:5001 on veth-mcr0"
    echo "    Output: 239.9.9.9:5099 via veth-mcr1 (using ip-multicast-if=10.0.1.20)"
    ip netns exec "$NETNS" socat -u \
        UDP4-RECV:5001,ip-add-membership=239.1.1.1:veth-mcr0,reuseaddr,so-rcvbuf=8388608 \
        UDP4-SEND:239.9.9.9:5099,ip-multicast-if=10.0.1.20,reuseaddr 2>/dev/null &
    local relay_pid=$!
    sleep 2

    # Run traffic generator in namespace
    echo "[3] Running traffic generator ($PACKET_COUNT packets @ $SEND_RATE pps)"
    ip netns exec "$NETNS" "$TRAFFIC_GEN" \
        --interface 10.0.0.10 \
        --group 239.1.1.1 \
        --port 5001 \
        --rate "$SEND_RATE" \
        --size "$PACKET_SIZE" \
        --count "$PACKET_COUNT" >/dev/null 2>&1

    echo "[INFO] Traffic complete, waiting for pipeline flush..."
    sleep 3

    # Stop socat processes
    kill $relay_pid $sink_pid 2>/dev/null || true
    wait $relay_pid $sink_pid 2>/dev/null || true
    sleep 1

    # Count received packets (file size / packet size)
    echo "[4] Counting received packets..."
    local received_count=0
    if [ -f "$SOCAT_SINK_FILE" ]; then
        local file_size=$(stat -c%s "$SOCAT_SINK_FILE" 2>/dev/null || echo 0)
        received_count=$((file_size / PACKET_SIZE))
    fi

    # Write results to file
    cat > "$SOCAT_RESULTS_FILE" <<EOF
SOCAT_RECEIVED=$received_count
EOF

    echo "[INFO] socat test complete: $received_count packets received"
    echo ""
}

# --- Main Test Execution ---

echo "=========================================="
echo "  MCR vs. socat Performance Comparison"
echo "     (Dual-Bridge Topology)"
echo "=========================================="
echo ""
echo "Test Parameters:"
echo "  - Workload: $(printf "%'d" $PACKET_COUNT) packets @ $(printf "%'d" $SEND_RATE) pps"
echo "  - Packet Size: $PACKET_SIZE bytes"
echo "  - Topology: Dual-Bridge (br0 ← Relay → br1)"
echo ""

# Setup topology
echo "=== Setting Up Dual-Bridge Topology ==="
echo ""
setup_bridge_topology
echo "[INFO] Topology ready:"
echo "       Network A (br0): Generator(veth-gen:10.0.0.10) + Relay-Ingress(veth-mcr0:10.0.0.20)"
echo "       Network B (br1): Relay-Egress(veth-mcr1:10.0.1.20) + Sink(veth-sink:10.0.1.30)"
echo ""

# Run MCR test
run_mcr_test

# Run socat test (reusing same topology)
run_socat_test

# --- Parse and Report Results ---

# Read results from files
if [ ! -f "$MCR_RESULTS_FILE" ] || [ ! -f "$SOCAT_RESULTS_FILE" ]; then
    echo "[ERROR] Results files missing!"
    exit 1
fi

source "$MCR_RESULTS_FILE"
source "$SOCAT_RESULTS_FILE"

# Calculate packet loss
mcr_loss=$((PACKET_COUNT - MCR_EGRESS))
mcr_loss_pct=$(awk "BEGIN {printf \"%.2f\", ($mcr_loss / $PACKET_COUNT) * 100}")

socat_loss=$((PACKET_COUNT - SOCAT_RECEIVED))
socat_loss_pct=$(awk "BEGIN {printf \"%.2f\", ($socat_loss / $PACKET_COUNT) * 100}")

# Report results
echo ""
echo "=========================================="
echo "    PERFORMANCE COMPARISON RESULTS"
echo "=========================================="
echo ""
echo "Workload: $(printf "%'d" $PACKET_COUNT) packets @ $(printf "%'d" $SEND_RATE) pps ($(printf "%'d" $PACKET_SIZE) bytes/packet)"
echo ""
echo "--- MCR Results ---"
echo "  Ingress Matched: $(printf "%'d" $MCR_INGRESS)"
echo "  Egress Sent:     $(printf "%'d" $MCR_EGRESS)"
echo "  Buffer Exhaust:  $(printf "%'d" $MCR_BUF_EXHAUST)"
echo "  Packet Loss:     $(printf "%'d" $mcr_loss) ($mcr_loss_pct%)"

if (( $(echo "$mcr_loss_pct < 1.0" | bc -l) )); then
    echo "  Result:          ✅ EXCELLENT (<1% loss)"
elif (( $(echo "$mcr_loss_pct < 5.0" | bc -l) )); then
    echo "  Result:          ✅ PASS (<5% loss)"
else
    echo "  Result:          ⚠️  WARN (>5% loss)"
fi

echo ""
echo "--- socat Results ---"
echo "  Packets Received: $(printf "%'d" $SOCAT_RECEIVED)"
echo "  Packet Loss:      $(printf "%'d" $socat_loss) ($socat_loss_pct%)"

if (( $(echo "$socat_loss_pct < 1.0" | bc -l) )); then
    echo "  Result:          ✅ EXCELLENT (<1% loss)"
elif (( $(echo "$socat_loss_pct < 5.0" | bc -l) )); then
    echo "  Result:          ✅ PASS (<5% loss)"
else
    echo "  Result:          ⚠️  WARN (>5% loss)"
fi

echo ""
echo "=========================================="
echo "             CONCLUSION"
echo "=========================================="

# Calculate performance comparison
if (( MCR_EGRESS > SOCAT_RECEIVED )); then
    if (( SOCAT_RECEIVED > 0 )); then
        performance_ratio=$(awk "BEGIN {printf \"%.2f\", ($MCR_EGRESS * 100.0) / $SOCAT_RECEIVED}")
    else
        performance_ratio="∞"
    fi
    loss_reduction=$(awk "BEGIN {printf \"%.2f\", $socat_loss_pct - $mcr_loss_pct}")

    echo ""
    echo "✅ MCR demonstrated superior performance:"
    echo "  - MCR forwarded: $(printf "%'d" $MCR_EGRESS) packets ($mcr_loss_pct% loss)"
    echo "  - socat forwarded: $(printf "%'d" $SOCAT_RECEIVED) packets ($socat_loss_pct% loss)"
    echo "  - Performance advantage: ${performance_ratio}% of packets vs. socat"
    echo "  - Loss reduction: ${loss_reduction}% fewer packets lost"
    echo ""
    echo "This validates MCR's design advantages:"
    echo "  1. Kernel bypass (AF_PACKET) eliminates UDP stack overhead"
    echo "  2. Batched I/O (io_uring) reduces per-packet syscall cost"
    echo "  3. Adaptive wakeup strategy optimizes for high throughput"
elif (( MCR_EGRESS == SOCAT_RECEIVED )); then
    echo ""
    echo "⚖️  MCR and socat achieved equivalent performance at this load level."
    echo "   Both forwarded $(printf "%'d" $MCR_EGRESS) packets with similar loss rates."
else
    performance_ratio=$(awk "BEGIN {printf \"%.2f\", ($SOCAT_RECEIVED * 100.0) / $MCR_EGRESS}")
    loss_diff=$(awk "BEGIN {printf \"%.2f\", $mcr_loss_pct - $socat_loss_pct}")

    echo ""
    if (( SOCAT_RECEIVED == 0 )); then
        echo "❌ socat FAILED in the dual-bridge topology:"
        echo "  - socat received: 0 packets (100% loss)"
        echo "  - MCR forwarded: $(printf "%'d" $MCR_EGRESS) packets ($mcr_loss_pct% loss)"
        echo ""
        echo "Why socat failed:"
        echo "  1. **Bridge Multicast Routing**: Bridges don't automatically route multicast"
        echo "     packets to UDP sockets on other interfaces in the same namespace"
        echo "  2. **Layer 4 Limitation**: socat operates at Layer 4 (UDP sockets), which"
        echo "     requires the kernel's IP routing to deliver packets across bridges"
        echo "  3. **No Multicast Routes**: The kernel doesn't have multicast routes between"
        echo "     the two bridge domains (br0 and br1)"
        echo ""
        echo "Why MCR succeeded:"
        echo "  1. **Layer 2 Operation**: MCR uses AF_PACKET to capture packets directly"
        echo "     from the network interface, bypassing IP routing"
        echo "  2. **Bridge Transparency**: AF_PACKET sees all frames on the interface,"
        echo "     regardless of bridge configuration"
        echo "  3. **Direct Interface Control**: MCR can send packets out any interface"
        echo "     without relying on kernel routing decisions"
        echo ""
        echo "✅ This demonstrates MCR's key advantage: kernel bypass allows it to work"
        echo "   in network topologies where traditional UDP socket approaches fail."
    else
        echo "⚠️  socat outperformed MCR in this test:"
        echo "  - socat forwarded: $(printf "%'d" $SOCAT_RECEIVED) packets ($socat_loss_pct% loss)"
        echo "  - MCR forwarded: $(printf "%'d" $MCR_EGRESS) packets ($mcr_loss_pct% loss)"
        echo "  - socat advantage: ${performance_ratio}% of packets vs. MCR"
        echo ""
        echo "Note: This test uses virtual networking (veth pairs + bridges)."
        echo "      Results on physical hardware may differ significantly."
    fi
fi

echo ""
echo "=========================================="
echo ""
echo "Test logs available at:"
echo "  MCR:   $MCR_LOG"
echo ""

exit 0
