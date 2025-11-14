#!/bin/bash
# High-Throughput Performance Comparison: Mutex vs Lock-Free Backend
#
# Sends packets at high rates to compare throughput and packet loss

set -e
set -u

echo "==================================================================="
echo "       High-Throughput Backend Comparison"
echo "       Testing at 10k, 50k, and 100k packets/sec"
echo "==================================================================="
echo ""

# Cleanup
cleanup() {
    sudo pkill -9 multicast_relay 2>/dev/null || true
    sudo rm -f /tmp/mcr_throughput_*.sock /dev/shm/mcr_* 2>/dev/null || true
}
trap cleanup EXIT

# Test configurations: packets, rate, description
TEST_CONFIGS=(
    "50000:10000:Low rate (10k pps)"
    "50000:50000:Medium rate (50k pps)"
    "50000:100000:High rate (100k pps)"
)

# Function to run a single test
run_test() {
    local BACKEND="$1"
    local FEATURE_FLAG="$2"
    local PACKET_COUNT="$3"
    local RATE="$4"
    local DESC="$5"
    local SOCKET="/tmp/mcr_throughput_${BACKEND}.sock"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "${BACKEND} Backend - ${DESC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Build
    if [ -n "$FEATURE_FLAG" ]; then
        cargo build --release --features "$FEATURE_FLAG" --quiet 2>&1 | grep -v "warning:" || true
    else
        cargo build --release --quiet 2>&1 | grep -v "warning:" || true
    fi

    # Start supervisor
    cleanup
    sudo ./target/release/multicast_relay supervisor \
        --control-socket-path "$SOCKET" \
        --num-workers 1 \
        --interface lo \
        2>&1 > /tmp/mcr_throughput_${BACKEND}_${RATE}.log &
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

    # Add forwarding rule
    ./target/release/control_client --socket-path "$SOCKET" add \
        --input-interface lo \
        --input-group 239.1.1.1 \
        --input-port 5001 \
        --outputs "239.10.10.10:6001:lo" \
        2>&1 > /dev/null

    # Send traffic
    echo "Sending ${PACKET_COUNT} packets at ${RATE} pps..."
    START_TIME=$(date +%s.%N)
    ./target/release/traffic_generator \
        --interface 127.0.0.1 \
        --group 239.1.1.1 \
        --port 5001 \
        --size 1400 \
        --count $PACKET_COUNT \
        --rate $RATE \
        2>&1 > /tmp/traffic_${BACKEND}_${RATE}.log
    END_TIME=$(date +%s.%N)
    DURATION=$(echo "$END_TIME - $START_TIME" | bc)

    # Wait for processing
    sleep 2

    # Get stats from log
    INGRESS_MATCHED=$(grep "STATS:Ingress FINAL" /tmp/mcr_throughput_${BACKEND}_${RATE}.log | grep -oP 'matched=\K\d+' || echo "0")
    INGRESS_SENT=$(grep "STATS:Ingress FINAL" /tmp/mcr_throughput_${BACKEND}_${RATE}.log | grep -oP 'egr_sent=\K\d+' || echo "0")
    EGRESS_SUBMITTED=$(grep "STATS:Egress FINAL" /tmp/mcr_throughput_${BACKEND}_${RATE}.log | grep -oP 'submitted=\K\d+' || echo "0")
    EGRESS_SENT=$(grep "STATS:Egress FINAL" /tmp/mcr_throughput_${BACKEND}_${RATE}.log | grep -oP 'sent=\K\d+' || echo "0")
    BUFFER_EXHAUST=$(grep "STATS:Ingress FINAL" /tmp/mcr_throughput_${BACKEND}_${RATE}.log | grep -oP 'buf_exhaust=\K\d+' || echo "0")

    # Calculate metrics
    if [ "$PACKET_COUNT" -gt 0 ]; then
        INGRESS_MATCH_PCT=$(echo "scale=1; $INGRESS_MATCHED * 100 / $PACKET_COUNT" | bc)
        INGRESS_TO_EGRESS_PCT=$(echo "scale=1; $INGRESS_SENT * 100 / $INGRESS_MATCHED" | bc 2>/dev/null || echo "0")
        EGRESS_DELIVERY_PCT=$(echo "scale=1; $EGRESS_SENT * 100 / $INGRESS_SENT" | bc 2>/dev/null || echo "0")
        BUFFER_LOSS_PCT=$(echo "scale=1; $BUFFER_EXHAUST * 100 / $INGRESS_MATCHED" | bc 2>/dev/null || echo "0")
    else
        INGRESS_MATCH_PCT=0
        INGRESS_TO_EGRESS_PCT=0
        EGRESS_DELIVERY_PCT=0
        BUFFER_LOSS_PCT=0
    fi

    THROUGHPUT=$(echo "scale=0; $EGRESS_SENT / $DURATION" | bc)

    # Display results
    echo "  Duration: ${DURATION}s"
    echo "  Ingress matched: ${INGRESS_MATCHED} / ${PACKET_COUNT} (${INGRESS_MATCH_PCT}%)"
    echo "  Ingress → Egress: ${INGRESS_SENT} (${INGRESS_TO_EGRESS_PCT}%)"
    echo "  Egress submitted: ${EGRESS_SUBMITTED}"
    echo "  Egress sent: ${EGRESS_SENT} (${EGRESS_DELIVERY_PCT}%)"
    echo "  Buffer exhaustion: ${BUFFER_EXHAUST} (${BUFFER_LOSS_PCT}%)"
    echo "  Throughput: ${THROUGHPUT} pps"

    # Shutdown
    sudo kill -TERM $SUPERVISOR_PID 2>/dev/null || true
    wait $SUPERVISOR_PID 2>/dev/null || true

    # Save results
    cat > /tmp/results_${BACKEND}_${RATE}.txt <<EOF
packets=$PACKET_COUNT
rate=$RATE
ingress_matched=$INGRESS_MATCHED
ingress_sent=$INGRESS_SENT
egress_submitted=$EGRESS_SUBMITTED
egress_sent=$EGRESS_SENT
buffer_exhaust=$BUFFER_EXHAUST
duration=$DURATION
throughput=$THROUGHPUT
EOF

    echo ""
}

# Run all test configurations
for config in "${TEST_CONFIGS[@]}"; do
    IFS=':' read -r PACKETS RATE DESC <<< "$config"

    echo ""
    echo "==================================================================="
    echo "TEST: ${DESC}"
    echo "==================================================================="
    echo ""

    run_test "mutex" "" "$PACKETS" "$RATE" "$DESC"
    sleep 2
    run_test "lock_free" "lock_free_buffer_pool" "$PACKETS" "$RATE" "$DESC"
    sleep 2
done

# Generate comparison summary
echo "==================================================================="
echo "                  THROUGHPUT COMPARISON SUMMARY"
echo "==================================================================="
echo ""

for config in "${TEST_CONFIGS[@]}"; do
    IFS=':' read -r PACKETS RATE DESC <<< "$config"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "${DESC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Load results
    source /tmp/results_mutex_${RATE}.txt
    MUTEX_SENT=$egress_sent
    MUTEX_THROUGHPUT=$throughput
    MUTEX_BUFFER_LOSS=$buffer_exhaust

    source /tmp/results_lock_free_${RATE}.txt
    LF_SENT=$egress_sent
    LF_THROUGHPUT=$throughput
    LF_BUFFER_LOSS=$buffer_exhaust

    printf "%-25s %15s %15s\n" "Metric" "Mutex" "Lock-Free"
    printf "%-25s %15s %15s\n" "-------------------------" "---------------" "---------------"
    printf "%-25s %15s %15s\n" "Packets sent" "$MUTEX_SENT" "$LF_SENT"
    printf "%-25s %15s %15s\n" "Throughput (pps)" "$MUTEX_THROUGHPUT" "$LF_THROUGHPUT"
    printf "%-25s %15s %15s\n" "Buffer exhaustion" "$MUTEX_BUFFER_LOSS" "$LF_BUFFER_LOSS"

    # Calculate improvement
    if [ "$MUTEX_THROUGHPUT" != "0" ] && [ "$LF_THROUGHPUT" != "0" ]; then
        IMPROVEMENT=$(echo "scale=1; ($LF_THROUGHPUT - $MUTEX_THROUGHPUT) * 100 / $MUTEX_THROUGHPUT" | bc)
        echo ""
        echo "Throughput difference: ${IMPROVEMENT}%"
    fi

    echo ""
done

echo "==================================================================="
echo ""
echo "Detailed logs:"
echo "  /tmp/mcr_throughput_*.log"
echo "  /tmp/traffic_*.log"
echo ""

cleanup
