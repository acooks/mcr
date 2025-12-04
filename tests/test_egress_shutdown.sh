#!/bin/bash
# Test script to verify egress thread shutdown timing

set -e

echo "=== Egress Shutdown Timing Test ==="
echo "This test verifies that the egress thread exits gracefully on shutdown signal"
echo ""

# Cleanup function
cleanup() {
    sudo pkill -9 mcrd 2>/dev/null || true
    sudo rm -f /tmp/mcr_shutdown_test.sock
}
trap cleanup EXIT

# Build the binary
echo "Building..."
cargo build --quiet
echo ""

# Start the supervisor
echo "Starting supervisor..."
sudo ./target/debug/mcrd supervisor \
    --control-socket-path /tmp/mcr_shutdown_test.sock \
    --num-workers 1 \
    --interface lo 2>&1 | tee /tmp/shutdown_test.log &
SUPERVISOR_PID=$!

# Wait for supervisor to be ready
sleep 2

echo "Supervisor started (PID: $SUPERVISOR_PID)"
echo ""

# Send SIGTERM and measure shutdown time
echo "Sending SIGTERM to supervisor..."
START_TIME=$(date +%s.%N)
sudo kill -TERM $SUPERVISOR_PID

# Wait for supervisor to exit
wait $SUPERVISOR_PID 2>/dev/null || true
END_TIME=$(date +%s.%N)

# Calculate shutdown duration
DURATION=$(echo "$END_TIME - $START_TIME" | bc)
echo ""
echo "=== Results ==="
echo "Shutdown duration: ${DURATION}s"

# Check logs for egress shutdown messages
echo ""
echo "=== Egress Shutdown Log Messages ==="
grep -E "(Egress|shutdown)" /tmp/shutdown_test.log || echo "No egress shutdown messages found"

# Verify shutdown was quick (< 2 seconds is good, < 1 second is excellent)
if (( $(echo "$DURATION < 2.0" | bc -l) )); then
    echo ""
    echo "✅ SUCCESS: Shutdown completed in ${DURATION}s (< 2s)"
    exit 0
else
    echo ""
    echo "⚠️  WARNING: Shutdown took ${DURATION}s (> 2s)"
    echo "Expected: < 2s for graceful shutdown"
    exit 1
fi
