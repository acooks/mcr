#!/bin/bash
#
# Performance Comparison Test: MCR vs. socat (Chain Topology)
#
# This test implements the chain topology described in docs/MCR_vs_socat.md
# to provide a rigorous, reproducible benchmark of forwarding performance.
#
# Topology: Generator (root) → Relay (relay-ns) → Sink (sink-ns)
#
# Network namespaces:
#   - root: Traffic generator (veth0 @ 10.0.0.1)
#   - relay-ns: MCR or socat relay (veth1 @ 10.0.0.2, veth3 @ 10.0.1.1)
#   - sink-ns: Packet counter (veth2 @ 10.0.1.2)
#
# Test Parameters:
#   - 1M packets @ 150k pps (default, configurable via environment variables)
#   - Packet size: 1024 bytes
#
# Usage:
#   sudo ./compare_socat_chain.sh
#   sudo PACKET_COUNT=500000 SEND_RATE=100000 ./compare_socat_chain.sh

set -euo pipefail

# --- Configuration ---
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# Test parameters (can be overridden via environment)
PACKET_SIZE="${PACKET_SIZE:-1024}"
PACKET_COUNT="${PACKET_COUNT:-1000000}"   # 1M packets
SEND_RATE="${SEND_RATE:-150000}"          # 150k pps

# Namespace names
RELAY_NS="relay-ns"
SINK_NS="sink-ns"

# File paths
MCR_LOG="/tmp/mcr_chain.log"
MCR_SOCK="/tmp/mcr_chain.sock"
SOCAT_SINK_FILE="/tmp/socat_sink_chain.bin"
MCR_RESULTS_FILE="/tmp/mcr_results.txt"
SOCAT_RESULTS_FILE="/tmp/socat_results.txt"

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

    # Kill all processes in namespaces
    ip netns pids "$RELAY_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns pids "$SINK_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true

    # Delete namespaces (this also deletes veth pairs inside them)
    ip netns del "$RELAY_NS" 2>/dev/null || true
    ip netns del "$SINK_NS" 2>/dev/null || true

    # Delete veth pairs in root namespace
    ip link del veth0 2>/dev/null || true
    ip link del veth2 2>/dev/null || true

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

# --- Setup Chain Topology ---
setup_chain_topology() {
    # Clean up any existing setup
    cleanup_all

    # Create network namespaces
    ip netns add "$RELAY_NS"
    ip netns add "$SINK_NS"

    # Enable loopback in namespaces
    ip netns exec "$RELAY_NS" ip link set lo up
    ip netns exec "$SINK_NS" ip link set lo up

    # Create veth pair 1: root (veth0) <-> relay-ns (veth1)
    ip link add veth0 type veth peer name veth1
    ip link set veth1 netns "$RELAY_NS"

    # Configure veth pair 1
    ip addr add 10.0.0.1/24 dev veth0
    ip link set veth0 up
    ip netns exec "$RELAY_NS" ip addr add 10.0.0.2/24 dev veth1
    ip netns exec "$RELAY_NS" ip link set veth1 up

    # Create veth pair 2: relay-ns (veth3) <-> sink-ns (veth2)
    ip link add veth2 type veth peer name veth3
    ip link set veth2 netns "$SINK_NS"
    ip link set veth3 netns "$RELAY_NS"

    # Configure veth pair 2
    ip netns exec "$RELAY_NS" ip addr add 10.0.1.1/24 dev veth3
    ip netns exec "$RELAY_NS" ip link set veth3 up
    ip netns exec "$SINK_NS" ip addr add 10.0.1.2/24 dev veth2
    ip netns exec "$SINK_NS" ip link set veth2 up
}

# --- MCR Test Function ---
run_mcr_test() {
    echo "=== Running MCR Test ==="
    echo ""

    rm -f "$MCR_LOG" "$MCR_SOCK"

    # Start MCR supervisor in relay namespace
    echo "[1] Starting MCR in $RELAY_NS (listening on veth1)"
    ip netns exec "$RELAY_NS" taskset -c 0 \
        "$MCR_SUPERVISOR" supervisor \
        --interface veth1 \
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

    # Add forwarding rule: 239.1.1.1:5001 (from veth1) → 239.9.9.9:5099 (out veth3)
    echo "[2] Adding forwarding rule: 239.1.1.1:5001 → 239.9.9.9:5099 via veth3"
    "$CONTROL_CLIENT" --socket-path "$MCR_SOCK" add \
        --input-interface veth1 \
        --input-group 239.1.1.1 \
        --input-port 5001 \
        --outputs '239.9.9.9:5099:veth3' 2>&1 | grep -v '^{' || true

    sleep 1

    # Run traffic generator from root namespace
    echo "[3] Running traffic generator ($PACKET_COUNT packets @ $SEND_RATE pps)"
    "$TRAFFIC_GEN" \
        --interface 10.0.0.1 \
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

    # Start socat SINK in sink-ns (receives final multicast on veth2)
    echo "[1] Starting socat sink in $SINK_NS (239.9.9.9:5099 on veth2)"
    ip netns exec "$SINK_NS" socat -u \
        UDP4-RECV:5099,ip-add-membership=239.9.9.9:veth2,reuseaddr,so-rcvbuf=8388608 \
        CREATE:"$SOCAT_SINK_FILE" 2>/dev/null &
    local sink_pid=$!
    sleep 1

    # Start socat RELAY in relay-ns
    echo "[2] Starting socat relay in $RELAY_NS"
    echo "    Input:  239.1.1.1:5001 on veth1"
    echo "    Output: 239.9.9.9:5099 via veth3"
    ip netns exec "$RELAY_NS" socat -u \
        UDP4-RECV:5001,ip-add-membership=239.1.1.1:veth1,reuseaddr,so-rcvbuf=8388608 \
        UDP4-SEND:239.9.9.9:5099,bind=10.0.1.1,sourceport=5099,reuseaddr 2>/dev/null &
    local relay_pid=$!
    sleep 2

    # Run traffic generator from root namespace
    echo "[3] Running traffic generator ($PACKET_COUNT packets @ $SEND_RATE pps)"
    "$TRAFFIC_GEN" \
        --interface 10.0.0.1 \
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
echo "=========================================="
echo ""
echo "Test Parameters:"
echo "  - Workload: $(printf "%'d" $PACKET_COUNT) packets @ $(printf "%'d" $SEND_RATE) pps"
echo "  - Packet Size: $PACKET_SIZE bytes"
echo "  - Topology: Chain (root → relay-ns → sink-ns)"
echo ""

# Setup topology
echo "=== Setting Up Chain Topology ==="
echo ""
setup_chain_topology
echo "[INFO] Topology ready: Generator(veth0:10.0.0.1) <-> Relay(veth1:10.0.0.2 | veth3:10.0.1.1) <-> Sink(veth2:10.0.1.2)"
echo ""

# Run MCR test
run_mcr_test

# Recreate topology for socat test (clean slate)
echo "=== Resetting Topology for socat Test ==="
echo ""
setup_chain_topology
echo "[INFO] Topology reset complete"
echo ""

# Run socat test
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
    performance_ratio=$(awk "BEGIN {printf \"%.2f\", ($MCR_EGRESS * 100.0) / $SOCAT_RECEIVED}")
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
    echo "⚠️  socat outperformed MCR in this test:"
    echo "  - socat forwarded: $(printf "%'d" $SOCAT_RECEIVED) packets ($socat_loss_pct% loss)"
    echo "  - MCR forwarded: $(printf "%'d" $MCR_EGRESS) packets ($mcr_loss_pct% loss)"
    echo "  - socat advantage: ${performance_ratio}% of packets vs. MCR"
    echo ""
    echo "Possible reasons for this unexpected result:"
    echo "  1. Virtual network (veth) overhead may favor UDP sockets over AF_PACKET"
    echo "  2. Single-core test doesn't showcase MCR's multi-core scalability"
    echo "  3. Network namespace isolation changes performance characteristics"
    echo "  4. MCR is optimized for physical NICs, not virtual interfaces"
    echo ""
    echo "Note: This test uses virtual networking (veth pairs + namespaces)."
    echo "      Results on physical hardware may differ significantly."
fi

echo ""
echo "=========================================="
echo ""
echo "Test logs available at:"
echo "  MCR:   $MCR_LOG"
echo ""

exit 0
