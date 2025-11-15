#!/bin/bash
#
# Performance Comparison: MCR vs socat (Chain Topology)
#
# Based on the verified socat_chain_test.sh reference implementation.
# This test provides a fair, reliable comparison using the simple chain topology
# that has been proven to work for both MCR and socat.
#
# Topology:
#   gen-ns (veth0) <-> (veth1) relay-ns (veth2) <-> (veth3) sink-ns
#   10.0.0.1              10.0.0.2  10.0.1.1         10.0.1.2
#
# Test Parameters:
#   - Configurable packet count and send rate (defaults: 100k packets @ 50k pps)
#   - Packet size: 1024 bytes
#   - Uses traffic_generator for accurate high-rate generation
#

set -euo pipefail

# --- Configuration ---
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# Test parameters (can be overridden via environment)
PACKET_SIZE="${PACKET_SIZE:-1024}"
PACKET_COUNT="${PACKET_COUNT:-100000}"   # 100k packets default
SEND_RATE="${SEND_RATE:-50000}"          # 50k pps default

# Multicast configuration
MCAST_IN="239.1.1.1"
MCAST_OUT="239.9.9.9"
PORT_IN="5001"
PORT_OUT="5099"

# Binary paths
TRAFFIC_GEN="$PROJECT_ROOT/target/release/traffic_generator"
MCR_SUPERVISOR="$PROJECT_ROOT/target/release/multicast_relay"
CONTROL_CLIENT="$PROJECT_ROOT/target/release/control_client"

# File paths
MCR_LOG="/tmp/mcr_chain.log"
MCR_SOCK="/tmp/mcr_chain.sock"
SOCAT_SINK_FILE="/tmp/socat_sink_chain.bin"
MCR_RESULTS_FILE="/tmp/mcr_chain_results.txt"
SOCAT_RESULTS_FILE="/tmp/socat_chain_results.txt"

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
    
    # Kill processes
    pkill -f "traffic_generator" 2>/dev/null || true
    pkill -f "multicast_relay" 2>/dev/null || true
    pkill -f "socat.*UDP4" 2>/dev/null || true
    
    # Delete namespaces
    ip netns del gen-ns 2>/dev/null || true
    ip netns del relay-ns 2>/dev/null || true
    ip netns del sink-ns 2>/dev/null || true
    
    # Clean up temp files (but not results files)
    rm -f "$MCR_LOG" "$MCR_SOCK" "$SOCAT_SINK_FILE"
    
    echo "[INFO] Cleanup complete"
}

final_cleanup() {
    cleanup_all
    rm -f "$MCR_RESULTS_FILE" "$SOCAT_RESULTS_FILE"
}

trap final_cleanup EXIT

# --- Setup Chain Topology ---
setup_chain_topology() {
    cleanup_all
    
    echo "[INFO] Setting up chain topology..."
    
    # Create namespaces
    ip netns add gen-ns
    ip netns add relay-ns
    ip netns add sink-ns
    
    # Create veth pairs
    ip link add veth0 type veth peer name veth1
    ip link add veth2 type veth peer name veth3
    
    # Assign to namespaces
    ip link set veth0 netns gen-ns
    ip link set veth1 netns relay-ns
    ip link set veth2 netns relay-ns
    ip link set veth3 netns sink-ns
    
    # Configure IP addresses
    ip netns exec gen-ns ip addr add 10.0.0.1/24 dev veth0
    ip netns exec relay-ns ip addr add 10.0.0.2/24 dev veth1
    ip netns exec relay-ns ip addr add 10.0.1.1/24 dev veth2
    ip netns exec sink-ns ip addr add 10.0.1.2/24 dev veth3
    
    # Bring up interfaces
    ip netns exec gen-ns ip link set lo up
    ip netns exec gen-ns ip link set veth0 up
    ip netns exec relay-ns ip link set lo up
    ip netns exec relay-ns ip link set veth1 up
    ip netns exec relay-ns ip link set veth2 up
    ip netns exec sink-ns ip link set lo up
    ip netns exec sink-ns ip link set veth3 up
    
    # Configure routes
    ip netns exec gen-ns ip route add 10.0.1.0/24 via 10.0.0.2
    ip netns exec sink-ns ip route add 10.0.0.0/24 via 10.0.1.1
    
    # Multicast routes (CRITICAL for socat)
    ip netns exec gen-ns ip route add 224.0.0.0/4 dev veth0
    ip netns exec relay-ns ip route add 224.0.0.0/4 dev veth2
    
    echo "[INFO] Chain topology ready"
}

# --- MCR Test Function ---
run_mcr_test() {
    echo ""
    echo "=== Running MCR Test ==="
    
    # Start MCR
    echo "[1] Starting MCR in relay-ns"
    rm -f "$MCR_LOG" "$MCR_SOCK"
    ip netns exec relay-ns "$MCR_SUPERVISOR" \
        --socket-path "$MCR_SOCK" \
        --log-file "$MCR_LOG" &
    local mcr_pid=$!
    
    # Wait for MCR to be ready
    for i in {1..10}; do
        if [ -S "$MCR_SOCK" ]; then
            break
        fi
        sleep 0.5
    done
    
    if [ ! -S "$MCR_SOCK" ]; then
        echo "[ERROR] MCR failed to start"
        return 1
    fi
    
    # Configure MCR relay
    echo "[2] Configuring MCR relay"
    "$CONTROL_CLIENT" --socket "$MCR_SOCK" \
        add-relay veth1 "$MCAST_IN" "$PORT_IN" veth2 "$MCAST_OUT" "$PORT_OUT"
    
    sleep 1
    echo "[INFO] MCR ready (PID: $mcr_pid)"
    
    # Start sink (just count bytes received)
    echo "[3] Starting receiver in sink-ns"
    rm -f /tmp/mcr_sink_chain.bin
    ip netns exec sink-ns socat -u \
        UDP4-RECV:$PORT_OUT,ip-add-membership=$MCAST_OUT:veth3,reuseaddr \
        OPEN:/tmp/mcr_sink_chain.bin,creat 2>/dev/null &
    sleep 1
    
    # Run traffic generator
    echo "[4] Running traffic generator ($PACKET_COUNT packets @ $SEND_RATE pps)"
    ip netns exec gen-ns "$TRAFFIC_GEN" \
        --interface 10.0.0.1 \
        --group "$MCAST_IN" \
        --port "$PORT_IN" \
        --rate "$SEND_RATE" \
        --count "$PACKET_COUNT" \
        --size "$PACKET_SIZE" \
        2>&1 | tee /tmp/mcr_generator.log
    
    sleep 2
    
    # Get statistics
    echo "[5] Retrieving MCR statistics..."
    "$CONTROL_CLIENT" --socket "$MCR_SOCK" stats > "$MCR_RESULTS_FILE"
    
    # Count received bytes
    local bytes_received=0
    if [ -f /tmp/mcr_sink_chain.bin ]; then
        bytes_received=$(wc -c < /tmp/mcr_sink_chain.bin)
    fi
    
    local packets_received=$((bytes_received / PACKET_SIZE))
    
    echo "[INFO] MCR test complete"
    echo "      Sent: $PACKET_COUNT packets"
    echo "      Received: $packets_received packets"
    
    # Stop MCR
    kill $mcr_pid 2>/dev/null || true
    sleep 1
}

# --- socat Test Function ---
run_socat_test() {
    echo ""
    echo "=== Running socat Test ==="
    
    # Start sink
    echo "[1] Starting socat sink in sink-ns"
    rm -f "$SOCAT_SINK_FILE"
    touch "$SOCAT_SINK_FILE"
    ip netns exec sink-ns socat -u \
        UDP4-RECV:$PORT_OUT,ip-add-membership=$MCAST_OUT:veth3,reuseaddr \
        OPEN:"$SOCAT_SINK_FILE",creat,append 2>/dev/null &
    local sink_pid=$!
    sleep 1
    
    # Start socat relay
    echo "[2] Starting socat relay in relay-ns"
    echo "    Input:  $MCAST_IN:$PORT_IN on veth1"
    echo "    Output: $MCAST_OUT:$PORT_OUT via veth2 (ip-multicast-if=10.0.1.1)"
    ip netns exec relay-ns socat -u \
        UDP4-RECV:$PORT_IN,ip-add-membership=$MCAST_IN:veth1,reuseaddr \
        UDP4-SEND:$MCAST_OUT:$PORT_OUT,ip-multicast-if=10.0.1.1 2>/dev/null &
    local relay_pid=$!
    sleep 2
    
    # Run traffic generator
    echo "[3] Running traffic generator ($PACKET_COUNT packets @ $SEND_RATE pps)"
    ip netns exec gen-ns "$TRAFFIC_GEN" \
        --interface 10.0.0.1 \
        --group "$MCAST_IN" \
        --port "$PORT_IN" \
        --rate "$SEND_RATE" \
        --count "$PACKET_COUNT" \
        --size "$PACKET_SIZE" \
        2>&1 | tee /tmp/socat_generator.log
    
    sleep 2
    
    # Count received packets
    echo "[4] Counting received packets..."
    local bytes_received=0
    if [ -f "$SOCAT_SINK_FILE" ]; then
        bytes_received=$(wc -c < "$SOCAT_SINK_FILE")
    fi
    
    local packets_received=$((bytes_received / PACKET_SIZE))
    
    echo "[INFO] socat test complete"
    echo "      Sent: $PACKET_COUNT packets"
    echo "      Received: $packets_received packets"
    
    # Save results
    echo "packets_received=$packets_received" > "$SOCAT_RESULTS_FILE"
    echo "packets_sent=$PACKET_COUNT" >> "$SOCAT_RESULTS_FILE"
    
    # Stop processes
    kill $sink_pid $relay_pid 2>/dev/null || true
    sleep 1
}

# --- Main Execution ---
clear
echo "=========================================="
echo "  MCR vs. socat Performance Comparison"
echo "  - Topology: Chain (gen → relay → sink)"
echo "  - Workload: $(printf "%'d" $PACKET_COUNT) packets @ $(printf "%'d" $SEND_RATE) pps"
echo "=========================================="
echo ""

# Setup topology
setup_chain_topology

# Run MCR test
run_mcr_test

# Re-setup topology for clean state
setup_chain_topology

# Run socat test
run_socat_test

# --- Generate Report ---
echo ""
echo "=========================================="
echo "           FINAL RESULTS"
echo "=========================================="
echo ""
echo "Workload: $(printf "%'d" $PACKET_COUNT) packets @ $(printf "%'d" $SEND_RATE) pps ($PACKET_SIZE bytes/packet)"
echo ""

# Parse MCR results
if [ -f "$MCR_RESULTS_FILE" ]; then
    MCR_INGRESS=$(grep "packets_received" "$MCR_RESULTS_FILE" | head -1 | cut -d'=' -f2 || echo "0")
    MCR_EGRESS=$(grep "packets_sent" "$MCR_RESULTS_FILE" | tail -1 | cut -d'=' -f2 || echo "0")
else
    MCR_INGRESS=0
    MCR_EGRESS=0
fi

# Parse socat results
if [ -f "$SOCAT_RESULTS_FILE" ]; then
    SOCAT_RECEIVED=$(grep "packets_received" "$SOCAT_RESULTS_FILE" | cut -d'=' -f2 || echo "0")
else
    SOCAT_RECEIVED=0
fi

# Calculate metrics
mcr_loss_pct=$(awk "BEGIN {printf \"%.2f\", (1 - $MCR_EGRESS / $PACKET_COUNT) * 100}")
socat_loss_pct=$(awk "BEGIN {printf \"%.2f\", (1 - $SOCAT_RECEIVED / $PACKET_COUNT) * 100}")

echo "--- MCR Results ---"
echo "  Ingress:  $(printf "%'d" $MCR_INGRESS) packets received"
echo "  Egress:   $(printf "%'d" $MCR_EGRESS) packets forwarded"
echo "  Loss:     $mcr_loss_pct%"
echo ""

echo "--- socat Results ---"
echo "  Received: $(printf "%'d" $SOCAT_RECEIVED) packets"
echo "  Loss:     $socat_loss_pct%"
echo ""

# Performance comparison
if (( MCR_EGRESS > SOCAT_RECEIVED )); then
    improvement=$(awk "BEGIN {printf \"%.1f\", ($MCR_EGRESS / ($SOCAT_RECEIVED + 1)) * 100 - 100}")
    echo "🏆 MCR forwarded $improvement% more packets than socat"
elif (( SOCAT_RECEIVED > MCR_EGRESS )); then
    difference=$(awk "BEGIN {printf \"%.1f\", ($SOCAT_RECEIVED / ($MCR_EGRESS + 1)) * 100 - 100}")
    echo "⚖️  socat forwarded $difference% more packets than MCR"
else
    echo "⚖️  MCR and socat achieved equivalent performance at this load level."
fi

echo ""
echo "=========================================="
echo ""
echo "Log files:"
echo "  MCR:   $MCR_LOG"
echo "  Stats: $MCR_RESULTS_FILE"
echo ""

exit 0
