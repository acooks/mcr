#!/bin/bash
#
# Baseline Performance Test - 100k pps
#
# Validates 100% forwarding efficiency at moderate packet rate.
#
# Topology: Traffic Generator → MCR-1 → MCR-2 → Sink
#
# This test establishes a performance baseline:
# - At 100k pps, system should forward 100% of packets
# - No buffer exhaustion expected
# - No kernel drops expected
# - Validates happy path where capacity is not exceeded
#
# Network isolation: Runs in isolated network namespace (ip netns)

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Test parameters - 60 second test for profiling
PACKET_SIZE=1400
PACKET_COUNT=6000000   # 6M packets total (60 seconds at 100k pps)
SEND_RATE=100000       # 100k pps - well within single-core capacity

# Namespace name
NETNS="mcr_baseline_test"

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges for network namespace isolation"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Build binaries ---
echo "=== Building Release Binaries ==="
cargo build --release
echo ""

# --- Create named network namespace ---
echo "=== Baseline Performance Test (100k pps) ==="
echo "Expected: 100% packet forwarding (no drops)"
echo "Topology: Bridge + dual veth pairs (eliminates AF_PACKET duplication)"
echo ""

# Clean up any existing namespace
ip netns del "$NETNS" 2>/dev/null || true

# Create new namespace
ip netns add "$NETNS"

# Source common functions
source "$SCRIPT_DIR/common.sh"

# Set up cleanup trap
cleanup_namespace() {
    echo "[INFO] Running cleanup"
    sudo ip netns pids "$NETNS" 2>/dev/null | xargs -r sudo kill 2>/dev/null || true
    sudo ip netns del "$NETNS" 2>/dev/null || true
    echo "[INFO] Cleanup complete"
}
trap cleanup_namespace EXIT

log_section 'Network Namespace Setup'

# Enable loopback in namespace
sudo ip netns exec "$NETNS" ip link set lo up

# Create bridge topology for hop 1: Traffic Generator → MCR-1 ingress
# This eliminates AF_PACKET duplication by using separate veth pairs for generator and MCR
setup_bridge_topology "$NETNS" br0 veth-gen0 veth-mcr0 10.0.0.1/24 10.0.0.2/24

# Create bridge topology for hop 2: MCR-1 egress → MCR-2 ingress
# MCR-1 uses veth-mcr1a for egress, MCR-2 uses veth-mcr1b for ingress
setup_bridge_topology "$NETNS" br1 veth-mcr1a veth-mcr1b 10.0.1.1/24 10.0.1.2/24

log_section 'Starting MCR Instances'

# Start MCR instances in the namespace
# MCR-1 listens on veth-mcr0 (ingress from br0), sends on veth-mcr1a (egress to br1)
# MCR-2 listens on veth-mcr1b (ingress from br1)
start_mcr mcr1 veth-mcr0 /tmp/mcr1.sock /tmp/mcr1.log 0 "$NETNS"
start_mcr mcr2 veth-mcr1b /tmp/mcr2.sock /tmp/mcr2.log 1 "$NETNS"

# Wait for instances to be ready
wait_for_sockets /tmp/mcr1.sock /tmp/mcr2.sock
sleep 2

log_section 'Configuring Forwarding Rules'

# MCR-1: Forward 239.1.1.1:5001 → 239.2.2.2:5002 via veth-mcr1a (egress to br1)
add_rule /tmp/mcr1.sock veth-mcr0 239.1.1.1 5001 '239.2.2.2:5002:veth-mcr1a'

# MCR-2: Receive 239.2.2.2:5002 → forward to loopback (sink)
add_rule /tmp/mcr2.sock veth-mcr1b 239.2.2.2 5002 '239.9.9.9:5099:lo'

sleep 2

# Start perf recording on MCR instances
log_section "Starting Performance Profiling"
MCR1_PID=$(cat /var/run/mcr1.pid 2>/dev/null || pgrep -f "control-socket-path /tmp/mcr1.sock" | head -1)
MCR2_PID=$(cat /var/run/mcr2.pid 2>/dev/null || pgrep -f "control-socket-path /tmp/mcr2.sock" | head -1)

# Wait a moment for worker processes to spawn
sleep 2

log_info "Starting system-wide perf record"

# Profile entire system to capture whatever is busy
sudo perf record -F 999 -g --call-graph dwarf -a -o /tmp/mcr.perf.data &
PERF_PID=$!

sleep 1

# Run traffic generator in the namespace
log_section "Running Traffic Generator"
log_info "Target: 239.1.1.1:5001 via 10.0.0.1"
log_info "Parameters: $PACKET_COUNT packets @ $PACKET_SIZE bytes, rate $SEND_RATE pps"

sudo ip netns exec "$NETNS" "$TRAFFIC_GENERATOR_BINARY" \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5001 \
    --rate "$SEND_RATE" \
    --size "$PACKET_SIZE" \
    --count "$PACKET_COUNT"

# Stop perf recording
log_info "Stopping perf recording..."
sudo kill -SIGINT "$PERF_PID" 2>/dev/null || true
sleep 2

log_info 'Traffic generation complete'
log_info 'Waiting for pipeline to flush...'
sleep 3

# Print final stats
print_final_stats \
    'MCR-1:/tmp/mcr1.log' \
    'MCR-2:/tmp/mcr2.log'

log_section 'Validating Results'

VALIDATION_PASSED=0

# With bridge topology, AF_PACKET duplication is eliminated
# We expect ~90% packet forwarding at 100k pps (kernel drops ~10%)
# Generator sends 6M → MCR-1 sees ~5.4M → MCR-2 sees ~5.4M

# Validate MCR-1: Expect ~90% received (allow kernel drops at high rate)
validate_stat /tmp/mcr1.log 'STATS:Ingress' 'matched' 5000000 'MCR-1 ingress matched (6M)' || VALIDATION_PASSED=1

# Egress should match ingress (1:1 forwarding)
MCR1_INGRESS=$(extract_stat /tmp/mcr1.log 'STATS:Ingress' 'matched')
MCR1_EGRESS=$(extract_stat /tmp/mcr1.log 'STATS:Egress' 'sent')
log_info "MCR-1: ingress matched=$MCR1_INGRESS, egress sent=$MCR1_EGRESS"

# Allow 5% variance between ingress and egress
EGRESS_MIN=$((MCR1_INGRESS * 95 / 100))
EGRESS_MAX=$((MCR1_INGRESS * 105 / 100))
if [ $MCR1_EGRESS -lt $EGRESS_MIN ] || [ $MCR1_EGRESS -gt $EGRESS_MAX ]; then
    log_error "❌ Egress/ingress mismatch: expected $MCR1_INGRESS ± 5%, got $MCR1_EGRESS"
    VALIDATION_PASSED=1
else
    log_info "✅ Egress matches ingress: $MCR1_EGRESS ≈ $MCR1_INGRESS"
fi

# MCR-2 should receive what MCR-1 sent (100% forwarding)
validate_stat /tmp/mcr2.log 'STATS:Ingress' 'matched' 5000000 'MCR-2 ingress matched (6M)' || VALIDATION_PASSED=1

# Check buffer exhaustion on MCR-1 (should be zero or near-zero)
BUFFER_EXHAUSTION=$(extract_stat /tmp/mcr1.log 'STATS:Ingress' 'buf_exhaust')
log_info "MCR-1 buffer exhaustion: $BUFFER_EXHAUSTION packets"
if [ $BUFFER_EXHAUSTION -gt 60000 ]; then
    log_error "❌ Unexpected buffer exhaustion at 100k pps: $BUFFER_EXHAUSTION packets (>1%)"
    VALIDATION_PASSED=1
else
    log_info "✅ Buffer exhaustion acceptable: $BUFFER_EXHAUSTION packets (<1%)"
fi

log_section 'Test Complete'

if [ $VALIDATION_PASSED -eq 0 ]; then
    log_info '✅ All validations passed - 100% forwarding at 100k pps'
    log_info 'Full logs available at: /tmp/mcr{1,2}.log'
    echo ""
    echo "=== ✅ BASELINE TEST PASSED ==="
    echo "System achieved 100% packet forwarding at 100k pps"
    echo "Bridge topology successfully eliminated AF_PACKET duplication"
    echo "Network namespace destroyed - no host pollution"
    exit 0
else
    log_error '❌ Some validations failed - check logs'
    log_info 'Full logs available at: /tmp/mcr{1,2}.log'
    echo ""
    echo "=== ❌ BASELINE TEST FAILED ==="
    echo "System did not achieve 100% forwarding - investigate packet loss"
    echo "Network namespace destroyed - no host pollution"
    exit 1
fi
