#!/bin/bash
#
# Multi-Stream Scaling Test: MCR vs socat
#
# Tests how MCR and socat performance scales with increasing numbers of concurrent
# multicast streams. Based on the verified compare_socat_chain.sh implementation.
#
# Usage: sudo [ENV_VARS] ./multi_stream_scaling.sh [max_streams]
#
# Environment Variables:
#   PER_STREAM_PACKETS  - Number of packets per stream (default: 10000)
#                         For steady-state tests, use 100000+ for ~50s+ per stream
#   PER_STREAM_RATE     - Packets per second per stream (default: 2000)
#   NUM_WORKERS         - Number of MCR worker processes (default: 4)
#   PACKET_SIZE         - Packet payload size in bytes (default: 1024)
#
# Examples:
#   sudo ./multi_stream_scaling.sh 20
#     - Tests up to 20 streams with default settings (10k packets/stream @ 2k pps)
#
#   sudo PER_STREAM_PACKETS=100000 ./multi_stream_scaling.sh 50
#     - Tests up to 50 streams with 100k packets/stream for longer steady-state observation
#
#   sudo NUM_WORKERS=8 PER_STREAM_RATE=5000 ./multi_stream_scaling.sh 150
#     - Tests up to 150 streams with 8 workers @ 5k pps per stream (750k pps aggregate)
#
# Default: Tests 1, 2, 5, 10, 20 streams (adds 50, 100, 150 if max_streams allows)
#

set -euo pipefail

# --- Configuration ---
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# Test parameters
PACKET_SIZE="${PACKET_SIZE:-1024}"
PER_STREAM_PACKETS="${PER_STREAM_PACKETS:-10000}"  # 10k packets per stream
PER_STREAM_RATE="${PER_STREAM_RATE:-2000}"         # 2k pps per stream (150 streams × 2000 = 300k pps)
MAX_STREAMS="${1:-150}"
NUM_WORKERS="${NUM_WORKERS:-4}"  # 4 workers (can scale up with environment variable)

# Binary paths
TRAFFIC_GEN="$PROJECT_ROOT/target/release/mcrgen"
MCR_SUPERVISOR="$PROJECT_ROOT/target/release/mcrd"
CONTROL_CLIENT="$PROJECT_ROOT/target/release/mcrctl"

# File paths
MCR_SOCK="/tmp/mcr_multistream.sock"
RESULTS_DIR="/tmp/multistream_test_$$"

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Increase IGMP membership limit ---
# Default Linux limit is 20, we need to support 150+ streams
ORIGINAL_IGMP_LIMIT=$(cat /proc/sys/net/ipv4/igmp_max_memberships)
echo 200 > /proc/sys/net/ipv4/igmp_max_memberships
echo "[INFO] Increased IGMP membership limit from $ORIGINAL_IGMP_LIMIT to 200"

# Restore original limit on exit
trap "echo $ORIGINAL_IGMP_LIMIT > /proc/sys/net/ipv4/igmp_max_memberships 2>/dev/null || true" EXIT

# --- Build binaries ---
echo "=== Building Release Binaries ==="
cargo build --release 2>&1 | grep -E '(Compiling|Finished|error)' || true
echo ""

# --- Cleanup function ---
cleanup_all() {
    echo "[INFO] Running cleanup"

    # Delete namespaces FIRST - kills processes inside them
    ip netns del gen-ns 2>/dev/null || true
    ip netns del relay-ns 2>/dev/null || true
    ip netns del sink-ns 2>/dev/null || true

    # Kill any remaining processes
    pkill -9 -f "mcrgen" 2>/dev/null || true
    pkill -9 -f "mcrd" 2>/dev/null || true
    pkill -9 -f "socat.*UDP4" 2>/dev/null || true

    # Clean up files
    rm -f "$MCR_SOCK"

    echo "[INFO] Cleanup complete"
}

trap cleanup_all EXIT INT TERM

# --- Generate multicast address for stream number ---
# For streams 1-254: 239.1.1.N
# For streams 255-508: 239.1.2.N-254
get_mcast_addr() {
    local stream=$1
    local prefix="239.1"
    local third_octet=$(( (stream - 1) / 254 + 1 ))
    local fourth_octet=$(( (stream - 1) % 254 + 1 ))
    echo "$prefix.$third_octet.$fourth_octet"
}

# --- Setup Chain Topology ---
setup_topology() {
    cleanup_all

    echo "[INFO] Setting up chain topology..."

    ip netns add gen-ns
    ip netns add relay-ns
    ip netns add sink-ns

    ip link add veth0 type veth peer name veth1
    ip link add veth2 type veth peer name veth3

    ip link set veth0 netns gen-ns
    ip link set veth1 netns relay-ns
    ip link set veth2 netns relay-ns
    ip link set veth3 netns sink-ns

    ip netns exec gen-ns ip addr add 10.0.0.1/24 dev veth0
    ip netns exec relay-ns ip addr add 10.0.0.2/24 dev veth1
    ip netns exec relay-ns ip addr add 10.0.1.1/24 dev veth2
    ip netns exec sink-ns ip addr add 10.0.1.2/24 dev veth3

    ip netns exec gen-ns ip link set lo up
    ip netns exec gen-ns ip link set veth0 up
    ip netns exec relay-ns ip link set lo up
    ip netns exec relay-ns ip link set veth1 up
    ip netns exec relay-ns ip link set veth2 up
    ip netns exec sink-ns ip link set lo up
    ip netns exec sink-ns ip link set veth3 up

    ip netns exec gen-ns ip route add 10.0.1.0/24 via 10.0.0.2
    ip netns exec sink-ns ip route add 10.0.0.0/24 via 10.0.1.1

    ip netns exec gen-ns ip route add 224.0.0.0/4 dev veth0
    ip netns exec relay-ns ip route add 224.0.0.0/4 dev veth2

    echo "[INFO] Chain topology ready"
}

# --- MCR Test Function ---
run_mcr_test() {
    local num_streams=$1
    local test_dir="$RESULTS_DIR/mcr_${num_streams}stream"
    mkdir -p "$test_dir"

    echo ""
    echo "=== MCR Test: $num_streams stream(s) ==="

    # Start MCR
    echo "[1] Starting MCR in relay-ns with $NUM_WORKERS workers"
    rm -f "$MCR_SOCK"
    ip netns exec relay-ns "$MCR_SUPERVISOR" supervisor \
        --control-socket-path "$MCR_SOCK" \
        --num-workers "$NUM_WORKERS" \
        --interface veth1 >"$test_dir/mcr.log" 2>&1 &
    local mcr_pid=$!

    # Wait for MCR socket
    for i in {1..20}; do
        if [ -S "$MCR_SOCK" ]; then
            break
        fi
        sleep 0.5
    done

    # Wait for MCR to be ready
    for i in {1..20}; do
        if ip netns exec relay-ns "$CONTROL_CLIENT" --socket-path "$MCR_SOCK" list-rules >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done

    # Configure forwarding rules for all streams
    echo "[2] Configuring $num_streams forwarding rule(s)"
    local rules_added=0
    for stream in $(seq 1 $num_streams); do
        local in_group=$(get_mcast_addr $stream)
        local in_port=$((5000 + stream))
        local out_group=$(get_mcast_addr $stream | sed 's/^239\.1\./239.10./')
        local out_port=$((6000 + stream))

        if ip netns exec relay-ns "$CONTROL_CLIENT" --socket-path "$MCR_SOCK" add \
            --input-interface veth1 \
            --input-group "$in_group" \
            --input-port "$in_port" \
            --outputs "$out_group:$out_port:veth2" >/dev/null 2>&1; then
            rules_added=$((rules_added + 1))
        else
            echo "[ERROR] Failed to add rule $stream ($in_group:$in_port)"
            echo "[ERROR] Only $rules_added of $num_streams rules were added"
            return 1
        fi

        # Add small delay between rules for stability
        [ $((stream % 10)) -eq 0 ] && sleep 0.1
    done

    if [ $rules_added -ne $num_streams ]; then
        echo "[ERROR] Rule configuration incomplete: $rules_added/$num_streams"
        return 1
    fi

    sleep 1

    # Start sink receivers for all streams
    echo "[3] Starting $num_streams sink receiver(s)"
    for stream in $(seq 1 $num_streams); do
        local out_group=$(get_mcast_addr $stream | sed 's/^239\.1\./239.10./')
        local out_port=$((6000 + stream))
        local sink_file="$test_dir/sink_$stream.bin"

        ip netns exec sink-ns socat -u \
            UDP4-RECV:$out_port,ip-add-membership=$out_group:veth3,reuseaddr \
            OPEN:$sink_file,creat 2>/dev/null &
    done

    sleep 1

    # Run traffic generators in parallel
    echo "[4] Sending traffic on $num_streams stream(s) ($PER_STREAM_PACKETS packets each @ $PER_STREAM_RATE pps)"
    local total_expected=$((num_streams * PER_STREAM_PACKETS))
    local aggregate_rate=$((num_streams * PER_STREAM_RATE))
    echo "     Aggregate: $aggregate_rate pps"
    local gen_pids=()

    for stream in $(seq 1 $num_streams); do
        local in_group=$(get_mcast_addr $stream)
        local in_port=$((5000 + stream))

        ip netns exec gen-ns "$TRAFFIC_GEN" \
            --interface 10.0.0.1 \
            --group "$in_group" \
            --port "$in_port" \
            --rate "$PER_STREAM_RATE" \
            --count "$PER_STREAM_PACKETS" \
            --size "$PACKET_SIZE" >>"$test_dir/generator_$stream.log" 2>&1 &
        gen_pids+=($!)
    done

    # Wait for all generators to complete
    for pid in "${gen_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    sleep 2

    # Count received packets
    echo "[5] Counting received packets"
    local total_bytes=0
    for stream in $(seq 1 $num_streams); do
        local sink_file="$test_dir/sink_$stream.bin"
        if [ -f "$sink_file" ]; then
            local bytes=$(wc -c < "$sink_file")
            total_bytes=$((total_bytes + bytes))
        fi
    done

    local packets_received=$((total_bytes / PACKET_SIZE))
    local loss_pct=$(awk "BEGIN {printf \"%.2f\", (1 - $packets_received / $total_expected) * 100}")

    echo "[INFO] MCR: Sent $total_expected, Received $packets_received, Loss $loss_pct%"

    # Save results
    echo "$num_streams,$total_expected,$packets_received,$loss_pct" >> "$RESULTS_DIR/mcr_results.csv"

    # Stop MCR
    kill $mcr_pid 2>/dev/null || true
    sleep 1
}

# --- socat Test Function ---
run_socat_test() {
    local num_streams=$1
    local test_dir="$RESULTS_DIR/socat_${num_streams}stream"
    mkdir -p "$test_dir"

    echo ""
    echo "=== socat Test: $num_streams stream(s) ==="

    # Start sink receivers for all streams
    echo "[1] Starting $num_streams socat sink(s)"
    for stream in $(seq 1 $num_streams); do
        local out_group=$(get_mcast_addr $stream | sed 's/^239\.1\./239.10./')
        local out_port=$((6000 + stream))
        local sink_file="$test_dir/sink_$stream.bin"

        ip netns exec sink-ns socat -u \
            UDP4-RECV:$out_port,ip-add-membership=$out_group:veth3,reuseaddr \
            OPEN:$sink_file,creat 2>/dev/null &
    done

    sleep 1

    # Start relay processes for all streams
    echo "[2] Starting $num_streams socat relay process(es)"
    for stream in $(seq 1 $num_streams); do
        local in_group=$(get_mcast_addr $stream)
        local in_port=$((5000 + stream))
        local out_group=$(get_mcast_addr $stream | sed 's/^239\.1\./239.10./')
        local out_port=$((6000 + stream))

        ip netns exec relay-ns socat -u \
            UDP4-RECV:$in_port,ip-add-membership=$in_group:veth1,reuseaddr \
            UDP4-SEND:$out_group:$out_port,ip-multicast-if=10.0.1.1 2>/dev/null &
    done

    sleep 2

    # Run traffic generators in parallel
    echo "[3] Sending traffic on $num_streams stream(s) ($PER_STREAM_PACKETS packets each @ $PER_STREAM_RATE pps)"
    local total_expected=$((num_streams * PER_STREAM_PACKETS))
    local aggregate_rate=$((num_streams * PER_STREAM_RATE))
    echo "     Aggregate: $aggregate_rate pps"
    local gen_pids=()

    for stream in $(seq 1 $num_streams); do
        local in_group=$(get_mcast_addr $stream)
        local in_port=$((5000 + stream))

        ip netns exec gen-ns "$TRAFFIC_GEN" \
            --interface 10.0.0.1 \
            --group "$in_group" \
            --port "$in_port" \
            --rate "$PER_STREAM_RATE" \
            --count "$PER_STREAM_PACKETS" \
            --size "$PACKET_SIZE" >/dev/null 2>&1 &
        gen_pids+=($!)
    done

    # Wait for all generators to complete
    for pid in "${gen_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    sleep 2

    # Count received packets
    echo "[4] Counting received packets"
    local total_bytes=0
    for stream in $(seq 1 $num_streams); do
        local sink_file="$test_dir/sink_$stream.bin"
        if [ -f "$sink_file" ]; then
            local bytes=$(wc -c < "$sink_file")
            total_bytes=$((total_bytes + bytes))
        fi
    done

    local packets_received=$((total_bytes / PACKET_SIZE))
    local loss_pct=$(awk "BEGIN {printf \"%.2f\", (1 - $packets_received / $total_expected) * 100}")

    echo "[INFO] socat: Sent $total_expected, Received $packets_received, Loss $loss_pct%"

    # Save results
    echo "$num_streams,$total_expected,$packets_received,$loss_pct" >> "$RESULTS_DIR/socat_results.csv"
}

# --- Main Execution ---
clear
echo "=========================================="
echo "  Multi-Stream Scaling Test"
echo "  MCR vs. socat Performance"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Max streams:       $MAX_STREAMS"
echo "  Per-stream load:   $PER_STREAM_PACKETS packets @ $PER_STREAM_RATE pps"
echo "  Packet size:       $PACKET_SIZE bytes"
echo "=========================================="
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"
echo "streams,expected,received,loss_pct" > "$RESULTS_DIR/mcr_results.csv"
echo "streams,expected,received,loss_pct" > "$RESULTS_DIR/socat_results.csv"

# Test at different stream counts: 1, 2, 5, 10, 20, 50, 100, 150
STREAM_COUNTS=(1 2 5 10 20)
if [ $MAX_STREAMS -ge 50 ]; then
    STREAM_COUNTS+=(50)
fi
if [ $MAX_STREAMS -ge 100 ]; then
    STREAM_COUNTS+=(100)
fi
if [ $MAX_STREAMS -ge 150 ]; then
    STREAM_COUNTS+=(150)
fi

for num_streams in "${STREAM_COUNTS[@]}"; do
    if [ $num_streams -gt $MAX_STREAMS ]; then
        break
    fi

    echo ""
    echo "=========================================="
    echo "  Testing with $num_streams stream(s)"
    echo "=========================================="

    # Setup fresh topology
    setup_topology

    # Run MCR test
    run_mcr_test $num_streams

    # Setup fresh topology again
    setup_topology

    # Run socat test
    run_socat_test $num_streams
done

# --- Generate Final Report ---
echo ""
echo "=========================================="
echo "           FINAL RESULTS"
echo "=========================================="
echo ""

echo "MCR Results:"
echo "Streams | Expected | Received | Loss %"
echo "--------|----------|----------|--------"
tail -n +2 "$RESULTS_DIR/mcr_results.csv" | while IFS=, read streams exp rec loss; do
    printf "%7s | %8s | %8s | %6s%%\n" "$streams" "$exp" "$rec" "$loss"
done

echo ""
echo "socat Results:"
echo "Streams | Expected | Received | Loss %"
echo "--------|----------|----------|--------"
tail -n +2 "$RESULTS_DIR/socat_results.csv" | while IFS=, read streams exp rec loss; do
    printf "%7s | %8s | %8s | %6s%%\n" "$streams" "$exp" "$rec" "$loss"
done

echo ""
echo "=========================================="
echo ""
echo "Detailed results saved to: $RESULTS_DIR"
echo ""

exit 0
