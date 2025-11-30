#!/bin/bash
#
# Unified Baseline Performance Test
#
# Validates packet forwarding efficiency at configurable rates.
#
# Topology: Traffic Generator -> MCR-1 -> MCR-2 -> Sink
#
# Usage:
#   ./baseline_test.sh [OPTIONS]
#
# Options:
#   --rate RATE         Packets per second (default: 100000)
#   --packets COUNT     Total packets to send (default: 100000)
#   --profiling         Enable perf profiling (generates /tmp/mcr.perf.data)
#   --help              Show this help message
#
# Environment variables (override command-line defaults):
#   PACKET_SIZE         Packet size in bytes (default: 1400)
#   PACKET_COUNT        Total packets (overridden by --packets)
#   SEND_RATE           Packets per second (overridden by --rate)
#
# Network isolation: Runs in isolated network namespace (ip netns)
#

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/common.sh"

# Default test parameters (can be overridden by env vars or CLI args)
DEFAULT_PACKET_SIZE=1400
DEFAULT_PACKET_COUNT=100000
DEFAULT_SEND_RATE=100000

# Parse command line arguments
PROFILING_ENABLED=false
CLI_RATE=""
CLI_PACKETS=""

show_help() {
    head -30 "$0" | grep -E "^#" | sed 's/^# *//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --rate)
            CLI_RATE="$2"
            shift 2
            ;;
        --packets)
            CLI_PACKETS="$2"
            shift 2
            ;;
        --profiling)
            PROFILING_ENABLED=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Priority: CLI args > env vars > defaults
PACKET_SIZE=${PACKET_SIZE:-$DEFAULT_PACKET_SIZE}
PACKET_COUNT=${CLI_PACKETS:-${PACKET_COUNT:-$DEFAULT_PACKET_COUNT}}
SEND_RATE=${CLI_RATE:-${SEND_RATE:-$DEFAULT_SEND_RATE}}

# Calculate test duration for display
TEST_DURATION_S=$((PACKET_COUNT / SEND_RATE))

# Print custom header before init_test (which will skip default header)
echo "=== Baseline Performance Test ==="
echo "Rate: ${SEND_RATE} pps"
echo "Packets: ${PACKET_COUNT} (${TEST_DURATION_S}s at target rate)"
echo "Profiling: ${PROFILING_ENABLED}"
echo "Topology: Bridge + dual veth pairs (eliminates AF_PACKET duplication)"
echo ""

# Initialize test (root check, binary build, namespace, cleanup trap, loopback)
# Empty title to skip default header (we printed custom one above)
init_test "" mcr1_PID mcr2_PID

# Create bridge topology for hop 1: Traffic Generator -> MCR-1 ingress
# This eliminates AF_PACKET duplication by using separate veth pairs for generator and MCR
setup_bridge_topology "$NETNS" br0 veth-gen0 veth-mcr0 10.0.0.1/24 10.0.0.2/24

# Create bridge topology for hop 2: MCR-1 egress -> MCR-2 ingress
# MCR-1 uses veth-mcr1a for egress, MCR-2 uses veth-mcr1b for ingress
setup_bridge_topology "$NETNS" br1 veth-mcr1a veth-mcr1b 10.0.1.1/24 10.0.1.2/24

log_section 'Starting MCR Instances'

# Start MCR instances in the namespace
# MCR-1 on core 0, MCR-2 on core 1 (consistent assignment)
start_mcr mcr1 veth-mcr0 /tmp/mcr1.sock /tmp/mcr1.log 0 "$NETNS"
start_mcr mcr2 veth-mcr1b /tmp/mcr2.sock /tmp/mcr2.log 1 "$NETNS"

# Wait for instances to be ready
wait_for_sockets /tmp/mcr1.sock /tmp/mcr2.sock
sleep 2

log_section 'Configuring Forwarding Rules'

# MCR-1: Forward 239.1.1.1:5001 -> 239.2.2.2:5002 via veth-mcr1a (egress to br1)
add_rule /tmp/mcr1.sock veth-mcr0 239.1.1.1 5001 '239.2.2.2:5002:veth-mcr1a'

# MCR-2: Receive 239.2.2.2:5002 -> forward to loopback (sink)
add_rule /tmp/mcr2.sock veth-mcr1b 239.2.2.2 5002 '239.9.9.9:5099:lo'

sleep 2

# --- Optional: Start perf profiling ---
PERF_PID=""
if [ "$PROFILING_ENABLED" = true ]; then
    log_section "Starting Performance Profiling"
    log_info "Starting system-wide perf record"

    # Profile entire system to capture whatever is busy
    sudo perf record -F 999 -g --call-graph dwarf -a -o /tmp/mcr.perf.data &
    PERF_PID=$!

    sleep 1
fi

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

# --- Stop perf profiling if enabled ---
if [ -n "$PERF_PID" ]; then
    log_info "Stopping perf recording..."
    sudo kill -SIGINT "$PERF_PID" 2>/dev/null || true
    sleep 2
fi

log_info 'Traffic generation complete'
log_info 'Waiting for pipeline to flush...'
sleep 3

# Trigger graceful shutdown to get FINAL stats before validation
# IMPORTANT: Kill MCR-1 (sender) first and wait for it to drain its egress queue.
# Then kill MCR-2 (receiver) so it can receive all packets MCR-1 is flushing.
log_info 'Triggering graceful shutdown for FINAL stats...'

# Step 1: Kill MCR-1 first (the sender)
if [ -n "$mcr1_PID" ] && sudo kill -0 "$mcr1_PID" 2>/dev/null; then
    log_info "Sending SIGTERM to MCR-1 (PID $mcr1_PID) to drain egress queue..."
    sudo kill -TERM "$mcr1_PID" 2>/dev/null || true
fi

# Step 2: Wait for MCR-1 to fully exit (drains its send queue)
log_info 'Waiting for MCR-1 to drain and exit...'
for i in $(seq 1 30); do
    if [ -n "$mcr1_PID" ] && ! sudo kill -0 "$mcr1_PID" 2>/dev/null; then
        log_info "MCR-1 exited after ${i}00ms"
        break
    fi
    sleep 0.1
done

# Step 3: Give bridge time to forward any remaining packets to MCR-2
sleep 1

# Step 4: Now kill MCR-2 (the receiver)
if [ -n "$mcr2_PID" ] && sudo kill -0 "$mcr2_PID" 2>/dev/null; then
    log_info "Sending SIGTERM to MCR-2 (PID $mcr2_PID)..."
    sudo kill -TERM "$mcr2_PID" 2>/dev/null || true
fi
sleep 2  # Wait for FINAL stats to be written

# Print final stats
print_final_stats \
    'MCR-1:/tmp/mcr1.log' \
    'MCR-2:/tmp/mcr2.log'

log_section 'Validating Results'

VALIDATION_PASSED=0

# Calculate validation thresholds based on rate
# At lower rates (<=100k pps), expect ~95% forwarding
# At higher rates (>100k pps), expect ~80% forwarding (kernel drops increase)
if [ "$SEND_RATE" -le 100000 ]; then
    EXPECTED_RATIO=95
else
    EXPECTED_RATIO=80
fi

MAX_BUFFER_EXHAUSTION=$((PACKET_COUNT / 100))  # Allow 1% buffer exhaustion

# Validate MCR-1: Check matched packets (percentage based on rate)
validate_stat_percent /tmp/mcr1.log 'STATS:Ingress' 'matched' "$PACKET_COUNT" "$EXPECTED_RATIO" "MCR-1 ingress matched" || VALIDATION_PASSED=1

# Egress should match ingress (1:1 forwarding, allow 5% variance)
MCR1_INGRESS=$(extract_stat /tmp/mcr1.log 'STATS:Ingress' 'matched')
MCR1_EGRESS=$(extract_stat /tmp/mcr1.log 'STATS:Egress' 'sent')
validate_values_match "$MCR1_EGRESS" "$MCR1_INGRESS" 5 "MCR-1 egress matches ingress" || VALIDATION_PASSED=1

# MCR-2 should receive what MCR-1 sent
validate_stat_percent /tmp/mcr2.log 'STATS:Ingress' 'matched' "$PACKET_COUNT" "$EXPECTED_RATIO" "MCR-2 ingress matched" || VALIDATION_PASSED=1

# Check buffer exhaustion on MCR-1 (should be <1%)
validate_stat_max /tmp/mcr1.log 'STATS:Ingress' 'buf_exhaust' "$MAX_BUFFER_EXHAUSTION" "MCR-1 buffer exhaustion (<1%)" || VALIDATION_PASSED=1

log_section 'Test Complete'

if [ $VALIDATION_PASSED -eq 0 ]; then
    log_info "All validations passed - >=${EXPECTED_RATIO}% forwarding at ${SEND_RATE} pps"
    log_info 'Full logs available at: /tmp/mcr{1,2}.log'
    if [ "$PROFILING_ENABLED" = true ]; then
        log_info 'Perf data available at: /tmp/mcr.perf.data'
        log_info 'Generate flamegraph: perf script -i /tmp/mcr.perf.data | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg'
    fi
    echo ""
    echo "=== BASELINE TEST PASSED ==="
    echo "System achieved >=${EXPECTED_RATIO}% packet forwarding at ${SEND_RATE} pps"
    echo "Network namespace destroyed - no host pollution"
    exit 0
else
    log_error 'Some validations failed - check logs'
    log_info 'Full logs available at: /tmp/mcr{1,2}.log'
    echo ""
    echo "=== BASELINE TEST FAILED ==="
    echo "System did not achieve expected throughput - investigate packet loss"
    echo "Network namespace destroyed - no host pollution"
    exit 1
fi
