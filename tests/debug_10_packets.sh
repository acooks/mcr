#!/bin/bash
#
# Minimal Debug Test - 10 Packets Only
#
# Send exactly 10 packets and trace every step to find the 2x bug

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
echo "=== Debug Test: 10 Packets Only ==="
echo ""

# Load common functions and variables
source "$SCRIPT_DIR/topologies/common.sh"

# Export binaries for use in namespace
RELAY_BIN="$RELAY_BINARY"
CONTROL_BIN="$CONTROL_CLIENT_BINARY"
TRAFFIC_BIN="$TRAFFIC_GENERATOR_BINARY"

unshare --net bash -c "
set -euo pipefail

# Load common functions in namespace
source $SCRIPT_DIR/topologies/common.sh
trap cleanup_all EXIT

# Setup
enable_loopback
setup_veth_pair veth0 veth0p 10.0.0.1/24 10.0.0.2/24

# Clean up old log file
rm -f /tmp/test_mcr.log

# Start ONE MCR instance
echo '[TEST] Starting MCR on veth0p'
taskset -c 0 '$RELAY_BIN' supervisor \
    --relay-command-socket-path /tmp/test_relay.sock \
    --control-socket-path /tmp/test_mcr.sock \
    --interface veth0p \
    --num-workers 1 \
    > /tmp/test_mcr.log 2>&1 &
MCR_PID=\$!
echo \"[TEST] MCR PID: \$MCR_PID\"

# Wait for socket
for i in {1..30}; do
    [ -S /tmp/test_mcr.sock ] && break
    sleep 0.1
done
sleep 1

# Add rule
echo '[TEST] Adding forwarding rule'
'$CONTROL_BIN' --socket-path /tmp/test_mcr.sock add \
    --input-interface veth0p \
    --input-group 239.1.1.1 \
    --input-port 5001 \
    --outputs '239.2.2.2:5002:lo' > /dev/null

sleep 1

# Send EXACTLY 10 packets at 10 pps
echo '[TEST] Sending 10 packets at 10 pps'
'$TRAFFIC_BIN' \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --count 10 \
    --size 1400 \
    --rate 10 2>&1 | grep -v '^Sending'

echo '[TEST] Waiting for pipeline to drain...'
sleep 5

# Kill MCR
echo '[TEST] Stopping MCR'
kill \$MCR_PID 2>/dev/null || true
wait \$MCR_PID 2>/dev/null || true
sync  # Ensure all buffered output is written to disk

echo ''
echo '=== RESULTS ==='
echo ''
echo 'Ingress Stats (should show 10 matched, 10 egr_sent):'
grep 'STATS:Ingress' /tmp/test_mcr.log | grep -v ' 0 '

echo ''
echo 'Egress Stats (should show 10 submitted, 10 sent):'
grep 'STATS:Egress' /tmp/test_mcr.log | grep -v ' 0 '

echo ''
echo '=== ANALYSIS ==='
INGRESS_MATCHED=\$(grep 'STATS:Ingress' /tmp/test_mcr.log | tail -1 | grep -oP 'matched=\K[0-9]+' || echo 0)
INGRESS_EGR_SENT=\$(grep 'STATS:Ingress' /tmp/test_mcr.log | tail -1 | grep -oP 'egr_sent=\K[0-9]+' || echo 0)
EGRESS_SUBMITTED=\$(grep 'STATS:Egress' /tmp/test_mcr.log | tail -1 | grep -oP 'submitted=\K[0-9]+' || echo 0)
EGRESS_SENT=\$(grep 'STATS:Egress' /tmp/test_mcr.log | tail -1 | grep -oP 'sent=\K[0-9]+' || echo 0)

echo \"Ingress matched:    \$INGRESS_MATCHED (expect 10)\"
echo \"Ingress egr_sent:   \$INGRESS_EGR_SENT (expect 10)\"
echo \"Egress submitted:   \$EGRESS_SUBMITTED (expect 10)\"
echo \"Egress sent:        \$EGRESS_SENT (expect 10)\"

echo ''
if [ \$INGRESS_MATCHED -eq 10 ] && [ \$INGRESS_EGR_SENT -eq 10 ] && [ \$EGRESS_SUBMITTED -eq 10 ] && [ \$EGRESS_SENT -eq 10 ]; then
    echo '✅ TEST PASSED: All 10 packets forwarded correctly (1:1 forwarding verified)'
    echo '   Ingress and egress final stats printed successfully via graceful shutdown'
    exit 0
elif [ \$EGRESS_SUBMITTED -eq 10 ] && [ \$EGRESS_SENT -eq 10 ] && [ \$INGRESS_MATCHED -lt 10 ]; then
    echo '⚠️  PARTIAL PASS: Egress shows 10 packets, but ingress final stats missing'
    echo '   This means graceful shutdown did not complete properly'
    echo ''
    echo 'Full log available at: /tmp/test_mcr.log'
    exit 1
elif [ \$EGRESS_SUBMITTED -eq \$((INGRESS_EGR_SENT * 2)) ]; then
    echo '❌ BUG CONFIRMED: Egress submitted 2x what ingress sent!'
    echo ''
    echo 'Full log available at: /tmp/test_mcr.log'
    exit 1
else
    echo '⚠️  Unexpected count mismatch'
    echo ''
    echo 'Full log available at: /tmp/test_mcr.log'
    exit 1
fi
"

RESULT=$?
echo ""
if [ $RESULT -eq 0 ]; then
    echo "=== ✅ Test PASSED ==="
else
    echo "=== ❌ Test FAILED ==="
    echo "Check /tmp/test_mcr.log for details"
fi

exit $RESULT
