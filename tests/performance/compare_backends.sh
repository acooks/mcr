#!/bin/bash
# Performance Comparison: Mutex vs Lock-Free Backend
#
# This script runs the same workload on both backends and compares:
# - Throughput (packets/sec)
# - CPU usage
# - Shutdown latency

set -e
set -u

echo "==================================================================="
echo "       MCR Backend Performance Comparison"
echo "       Mutex Backend vs Lock-Free Backend"
echo "==================================================================="
echo ""

# Cleanup
cleanup() {
    sudo pkill -9 mcrd 2>/dev/null || true
    sudo rm -f /tmp/mcr_perf_*.sock /dev/shm/mcr_* 2>/dev/null || true
}
trap cleanup EXIT

# Test configuration
TEST_PACKETS=10000
TEST_DURATION=5

# Function to run a single test
run_test() {
    local BACKEND="$1"
    local FEATURE_FLAG="$2"
    local SOCKET="/tmp/mcr_perf_${BACKEND}.sock"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Testing: ${BACKEND} Backend"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Build
    echo "[1/5] Building ${BACKEND} backend..."
    if [ -n "$FEATURE_FLAG" ]; then
        cargo build --release --features "$FEATURE_FLAG" --quiet
    else
        cargo build --release --quiet
    fi

    # Start supervisor
    echo "[2/5] Starting supervisor..."
    cleanup
    sudo ./target/release/mcrd supervisor \
        --control-socket-path "$SOCKET" \
        --num-workers 1 \
        --interface lo \
        2>&1 > /tmp/mcr_perf_${BACKEND}.log &
    SUPERVISOR_PID=$!

    # Wait for socket
    local TIMEOUT=10
    local START=$(date +%s)
    while ! [ -S "$SOCKET" ]; do
        if [ "$(($(date +%s) - START))" -gt "$TIMEOUT" ]; then
            echo "ERROR: Timeout waiting for socket"
            return 1
        fi
        sleep 0.1
    done
    sudo chmod 666 "$SOCKET"
    sleep 1

    # Get PID for CPU monitoring
    DATA_PLANE_PID=$(pgrep -P $SUPERVISOR_PID | head -1)
    echo "   Supervisor PID: $SUPERVISOR_PID"
    echo "   Data Plane PID: $DATA_PLANE_PID"

    # Measure idle CPU (sample for 2 seconds)
    echo "[3/5] Measuring idle CPU usage..."
    sleep 1
    IDLE_CPU=$(ps -p $DATA_PLANE_PID -o %cpu= 2>/dev/null | awk '{print $1}' || echo "0")
    echo "   Idle CPU: ${IDLE_CPU}%"

    # Run traffic test
    echo "[4/5] Running traffic test (${TEST_PACKETS} packets)..."

    # Add forwarding rule
    ./target/release/mcrctl --socket-path "$SOCKET" add \
        --input-interface lo \
        --input-group 239.1.1.1 \
        --input-port 5001 \
        --outputs "239.10.10.10:6001:lo" \
        2>&1 > /dev/null

    # Get initial stats
    STATS_BEFORE=$(./target/release/mcrctl --socket-path "$SOCKET" stats 2>/dev/null | grep -oP 'packets_relayed:\s*\K\d+' || echo "0")

    # Send traffic
    START_TIME=$(date +%s.%N)
    ./target/release/mcrgen \
        --interface 127.0.0.1 \
        --group 239.1.1.1 \
        --port 5001 \
        --size 1400 \
        --count $TEST_PACKETS \
        --rate 100000 \
        2>&1 > /tmp/traffic_${BACKEND}.log
    END_TIME=$(date +%s.%N)

    # Get final stats and calculate throughput
    sleep 1
    STATS_AFTER=$(./target/release/mcrctl --socket-path "$SOCKET" stats 2>/dev/null | grep -oP 'packets_relayed:\s*\K\d+' || echo "0")
    PACKETS_RELAYED=$((STATS_AFTER - STATS_BEFORE))
    DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    THROUGHPUT=$(echo "scale=2; $PACKETS_RELAYED / $DURATION" | bc)

    # Sample CPU during load
    LOAD_CPU=$(ps -p $DATA_PLANE_PID -o %cpu= 2>/dev/null | awk '{print $1}' || echo "0")

    echo "   Packets sent: ${TEST_PACKETS}"
    echo "   Packets relayed: ${PACKETS_RELAYED}"
    echo "   Duration: ${DURATION}s"
    echo "   Throughput: ${THROUGHPUT} pps"
    echo "   CPU under load: ${LOAD_CPU}%"

    # Test shutdown latency
    echo "[5/5] Measuring shutdown latency..."
    SHUTDOWN_START=$(date +%s.%N)
    sudo kill -TERM $SUPERVISOR_PID
    wait $SUPERVISOR_PID 2>/dev/null || true
    SHUTDOWN_END=$(date +%s.%N)
    SHUTDOWN_TIME=$(echo "$SHUTDOWN_END - $SHUTDOWN_START" | bc)
    echo "   Shutdown time: ${SHUTDOWN_TIME}s"

    # Extract stats from logs
    echo ""
    echo "Final statistics from log:"
    grep -E "STATS:.*FINAL" /tmp/mcr_perf_${BACKEND}.log | tail -2 || echo "   (no stats found)"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Save results
    cat > /tmp/results_${BACKEND}.txt <<EOF
backend=$BACKEND
packets_sent=$TEST_PACKETS
packets_relayed=$PACKETS_RELAYED
duration=$DURATION
throughput=$THROUGHPUT
idle_cpu=$IDLE_CPU
load_cpu=$LOAD_CPU
shutdown_time=$SHUTDOWN_TIME
EOF
}

# Run tests
echo ""
run_test "mutex" ""
sleep 2
run_test "lock_free" "lock_free_buffer_pool"

# Compare results
echo "==================================================================="
echo "                     COMPARISON SUMMARY"
echo "==================================================================="
echo ""

# Load results
source /tmp/results_mutex.txt
MUTEX_THROUGHPUT=$throughput
MUTEX_IDLE_CPU=$idle_cpu
MUTEX_LOAD_CPU=$load_cpu
MUTEX_SHUTDOWN=$shutdown_time
MUTEX_RELAYED=$packets_relayed

source /tmp/results_lock_free.txt
LF_THROUGHPUT=$throughput
LF_IDLE_CPU=$idle_cpu
LF_LOAD_CPU=$load_cpu
LF_SHUTDOWN=$shutdown_time
LF_RELAYED=$packets_relayed

# Display comparison
printf "%-25s %15s %15s\n" "Metric" "Mutex" "Lock-Free"
printf "%-25s %15s %15s\n" "-------------------------" "---------------" "---------------"
printf "%-25s %15s %15s\n" "Packets relayed" "$MUTEX_RELAYED" "$LF_RELAYED"
printf "%-25s %15s %15s\n" "Throughput (pps)" "$MUTEX_THROUGHPUT" "$LF_THROUGHPUT"
printf "%-25s %15s %15s\n" "Idle CPU (%)" "$MUTEX_IDLE_CPU" "$LF_IDLE_CPU"
printf "%-25s %15s %15s\n" "Load CPU (%)" "$MUTEX_LOAD_CPU" "$LF_LOAD_CPU"
printf "%-25s %15s %15s\n" "Shutdown time (s)" "$MUTEX_SHUTDOWN" "$LF_SHUTDOWN"

echo ""

# Calculate improvements
if [ "$MUTEX_THROUGHPUT" != "0" ] && [ "$LF_THROUGHPUT" != "0" ]; then
    THROUGHPUT_IMPROVEMENT=$(echo "scale=1; ($LF_THROUGHPUT - $MUTEX_THROUGHPUT) / $MUTEX_THROUGHPUT * 100" | bc)
    echo "Throughput improvement: ${THROUGHPUT_IMPROVEMENT}%"
fi

echo ""
echo "==================================================================="
echo ""
echo "Detailed logs:"
echo "  Mutex backend: /tmp/mcr_perf_mutex.log"
echo "  Lock-free backend: /tmp/mcr_perf_lock_free.log"
echo ""

cleanup
