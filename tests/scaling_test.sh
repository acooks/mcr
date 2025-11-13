#!/bin/bash
#
# Scaling Test - Verify 1:1 Forwarding at Multiple Packet Counts
#
# Tests packet forwarding accuracy at 10, 1000, 10000, and 1000000 packets

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges"
    echo "Please run with: sudo $0"
    exit 1
fi

# Build
echo "=== Building ==="
cargo build --release --quiet

echo ""
echo "=== Scaling Test: Multiple Packet Counts ==="
echo ""

# Load common functions and variables
source "$SCRIPT_DIR/topologies/common.sh"

# Export binaries for use in namespace
RELAY_BIN="$RELAY_BINARY"
CONTROL_BIN="$CONTROL_CLIENT_BINARY"
TRAFFIC_BIN="$TRAFFIC_GENERATOR_BINARY"

# Test configurations: count, rate, drain_time
TEST_CASES=(
    "10:10:2"           # 10 packets at 10 pps, 2s drain
    "1000:1000:3"       # 1k packets at 1k pps (1s send + 2s drain)
    "10000:10000:4"     # 10k packets at 10k pps (1s send + 3s drain)
    "1000000:50000:25"  # 1M packets at 50k pps (20s send + 5s drain)
)

FAILED_TESTS=0
PASSED_TESTS=0

for test_case in "${TEST_CASES[@]}"; do
    IFS=':' read -r PACKET_COUNT RATE DRAIN_TIME <<< "$test_case"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Testing: $PACKET_COUNT packets at $RATE pps"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    set +e  # Temporarily disable exit on error
    unshare --net bash -c "
set -euo pipefail

# Load common functions in namespace
source $SCRIPT_DIR/topologies/common.sh
trap cleanup_all EXIT

# Setup
enable_loopback
setup_veth_pair veth0 veth0p 10.0.0.1/24 10.0.0.2/24

# Clean up old files
rm -f /tmp/test_mcr_scale.log
rm -f /tmp/test_relay.sock
rm -f /tmp/test_mcr.sock

# Start MCR instance
taskset -c 0 '$RELAY_BIN' supervisor \
    --relay-command-socket-path /tmp/test_relay.sock \
    --control-socket-path /tmp/test_mcr.sock \
    --interface veth0p \
    --num-workers 1 \
    > /tmp/test_mcr_scale.log 2>&1 &
MCR_PID=\$!

# Wait for socket (up to 5 seconds)
for i in {1..50}; do
    if [ -S /tmp/test_mcr.sock ]; then
        echo \"[TEST] Socket found after \${i}0ms\"
        break
    fi
    sleep 0.1
done

if [ ! -S /tmp/test_mcr.sock ]; then
    echo \"[TEST] ERROR: Socket not found after 5 seconds\"
    exit 1
fi

# Give MCR an additional moment to fully initialize
sleep 2

# Add rule
'$CONTROL_BIN' --socket-path /tmp/test_mcr.sock add \
    --input-interface veth0p \
    --input-group 239.1.1.1 \
    --input-port 5001 \
    --outputs '239.2.2.2:5002:lo' > /dev/null

sleep 1

# Send packets
'$TRAFFIC_BIN' \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --count $PACKET_COUNT \
    --size 1400 \
    --rate $RATE > /dev/null 2>&1

# Wait for pipeline to drain
sleep $DRAIN_TIME

# Kill MCR gracefully
kill \$MCR_PID 2>/dev/null || true
wait \$MCR_PID 2>/dev/null || true
sync

# Extract final counts
INGRESS_MATCHED=\$(grep 'STATS:Ingress FINAL' /tmp/test_mcr_scale.log | grep -oP 'matched=\K[0-9]+' || echo 0)
INGRESS_EGR_SENT=\$(grep 'STATS:Ingress FINAL' /tmp/test_mcr_scale.log | grep -oP 'egr_sent=\K[0-9]+' || echo 0)
EGRESS_CH_RECV=\$(grep 'STATS:Egress' /tmp/test_mcr_scale.log | tail -1 | grep -oP 'ch_recv=\K[0-9]+' || echo 0)
EGRESS_SENT=\$(grep 'STATS:Egress' /tmp/test_mcr_scale.log | tail -1 | grep -oP 'sent=\K[0-9]+' || echo 0)

echo \"Ingress matched:    \$INGRESS_MATCHED\"
echo \"Ingress egr_sent:   \$INGRESS_EGR_SENT\"
echo \"Egress ch_recv:     \$EGRESS_CH_RECV\"
echo \"Egress sent:        \$EGRESS_SENT\"

# Validate 1:1 forwarding
if [ \$INGRESS_MATCHED -eq $PACKET_COUNT ] && [ \$INGRESS_EGR_SENT -eq $PACKET_COUNT ] && [ \$EGRESS_CH_RECV -eq $PACKET_COUNT ] && [ \$EGRESS_SENT -eq $PACKET_COUNT ]; then
    echo \"✅ PASS: Perfect 1:1 forwarding\"
    exit 0
else
    echo \"❌ FAIL: Count mismatch (expected $PACKET_COUNT)\"
    echo \"Full log: /tmp/test_mcr_scale.log\"
    exit 1
fi

"
    TEST_EXIT_CODE=$?
    set -e  # Re-enable exit on error

    if [ $TEST_EXIT_CODE -eq 0 ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "=== FINAL RESULTS ==="
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Passed: $PASSED_TESTS / ${#TEST_CASES[@]}"
echo "Failed: $FAILED_TESTS / ${#TEST_CASES[@]}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo "✅ ALL TESTS PASSED"
    exit 0
else
    echo "❌ SOME TESTS FAILED"
    exit 1
fi
