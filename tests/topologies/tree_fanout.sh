#!/bin/bash
#
# Tree Topology Test (1:N Fanout - Head-End Replication)
#
# Topology: Traffic Generator → MCR-1 ┬→ MCR-2
#                                       ├→ MCR-3
#                                       └→ MCR-4
#
# This test validates:
# - Head-end replication (1 input → N outputs)
# - Buffer pool performance under traffic amplification (3x)
# - Per-output stats tracking
# - Egress queue management with multiple destinations
#
# Network isolation: Runs in isolated network namespace (unshare --net)
# - All veth interfaces exist only in the test namespace
# - Namespace auto-destroyed on exit (no host pollution)
#

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Source common functions early (for ensure_binaries_built)
source "$SCRIPT_DIR/common.sh"

# Test parameters
PACKET_SIZE=1400

# CI runners have limited virtualized networking - use conservative rates
if [ "${CI:-}" = "true" ]; then
    PACKET_COUNT=50000    # 50k packets for CI
    SEND_RATE=50000       # 50k pps for CI
else
    PACKET_COUNT=500000   # 500k packets for realistic validation
    SEND_RATE=300000      # Higher rate now that cores don't compete
fi

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges for network namespace isolation"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Build binaries (if needed) ---
ensure_binaries_built

# --- Run test in isolated network namespace ---
echo "=== Starting Test in Isolated Network Namespace ==="
echo "Namespace will be automatically destroyed on exit (no host pollution)"
echo ""

unshare --net bash -c "
set -euo pipefail

# Source common functions
source $SCRIPT_DIR/common.sh

# Buffer pool sizing for 3x amplification scenario
# Default: 1000 small buffers (sized for 1:1 forwarding)
# Amplification: Need 4x capacity (ingress + 3x egress copies)
export MCR_BUFFER_POOL_SMALL=4000    # 4x default (1400-byte packets)
export MCR_BUFFER_POOL_STANDARD=2000  # 4x default
export MCR_BUFFER_POOL_JUMBO=800      # 4x default

# Set up cleanup trap
trap 'graceful_cleanup_unshare mcr1_PID mcr2_PID mcr3_PID mcr4_PID' EXIT

log_section 'Network Namespace Setup'

# Enable loopback
enable_loopback

# Create veth pairs for tree topology
# Traffic Gen → veth0 → veth0p (MCR-1 ingress)
# MCR-1 egress → veth1a → veth1b (MCR-2 ingress)
# MCR-1 egress → veth2a → veth2b (MCR-3 ingress)
# MCR-1 egress → veth3a → veth3b (MCR-4 ingress)
setup_veth_pair veth0 veth0p 10.0.0.1/24 10.0.0.2/24
setup_veth_pair veth1a veth1b 10.0.1.1/24 10.0.1.2/24
setup_veth_pair veth2a veth2b 10.0.2.1/24 10.0.2.2/24
setup_veth_pair veth3a veth3b 10.0.3.1/24 10.0.3.2/24

log_section 'Starting MCR Instances'

# Start MCR instances on separate CPU cores to avoid contention
# MCR-1 (root node with 3 outputs)
start_mcr mcr1 veth0p /tmp/mcr1.sock /tmp/mcr1.log 0

# MCR-2, MCR-3, MCR-4 (leaf nodes)
start_mcr mcr2 veth1b /tmp/mcr2.sock /tmp/mcr2.log 1
start_mcr mcr3 veth2b /tmp/mcr3.sock /tmp/mcr3.log 2
start_mcr mcr4 veth3b /tmp/mcr4.sock /tmp/mcr4.log 3

# Wait for all instances to be ready
wait_for_sockets /tmp/mcr1.sock /tmp/mcr2.sock /tmp/mcr3.sock /tmp/mcr4.sock
sleep 2

log_section 'Configuring Forwarding Rules'

# MCR-1: Receive on veth0p (239.1.1.1:5001) → Forward to 3 destinations (HEAD-END REPLICATION)
log_info 'MCR-1: Configuring 1:3 head-end replication (single rule, multiple outputs)'

# Use mcrctl directly to add single rule with multiple outputs
\$CONTROL_CLIENT_BINARY --socket-path /tmp/mcr1.sock add \
    --input-interface veth0p \
    --input-group 239.1.1.1 \
    --input-port 5001 \
    --outputs '239.2.2.2:5002:veth1a' \
    --outputs '239.3.3.3:5003:veth2a' \
    --outputs '239.4.4.4:5004:veth3a' > /dev/null

# MCR-2, MCR-3, MCR-4: Add dummy rules to match and count packets
add_rule /tmp/mcr2.sock veth1b 239.2.2.2 5002 '239.9.9.9:5099:lo'
add_rule /tmp/mcr3.sock veth2b 239.3.3.3 5003 '239.9.9.9:5099:lo'
add_rule /tmp/mcr4.sock veth3b 239.4.4.4 5004 '239.9.9.9:5099:lo'
log_info 'MCR-2, MCR-3, MCR-4: Terminus nodes with dummy rules for packet counting'

sleep 2

# Run traffic generator (no real-time log monitoring)
run_traffic 10.0.0.1 239.1.1.1 5001 $PACKET_COUNT $PACKET_SIZE $SEND_RATE

log_info 'Waiting for pipeline to flush...'
sleep 5

# Print final stats
print_final_stats \
    'MCR-1:/tmp/mcr1.log' \
    'MCR-2:/tmp/mcr2.log' \
    'MCR-3:/tmp/mcr3.log' \
    'MCR-4:/tmp/mcr4.log'

log_section 'Validating Results'

# Calculate thresholds based on packet count
# MCR-1 ingress: ~10% of packets (conservative for CI)
# Leaf nodes: ~8% of packets each (lower due to hop)
MCR1_MIN_INGRESS=\$(($PACKET_COUNT * 10 / 100))
LEAF_MIN_INGRESS=\$(($PACKET_COUNT * 8 / 100))

log_info \"Validation thresholds: MCR-1 ingress min=\$MCR1_MIN_INGRESS, Leaf ingress min=\$LEAF_MIN_INGRESS\"

# Validate MCR-1 (head-end replication: 1 ingress → 3 egress outputs)
VALIDATION_PASSED=0

# Extract MCR-1 stats for proportional validation
MCR1_INGRESS=\$(extract_stat /tmp/mcr1.log 'STATS:Ingress' 'matched')
MCR1_EGRESS=\$(extract_stat /tmp/mcr1.log 'STATS:Egress' 'sent')

# Minimum ingress threshold (sanity check - should process some packets)
validate_stat /tmp/mcr1.log 'STATS:Ingress' 'matched' \$MCR1_MIN_INGRESS 'MCR-1 ingress matched' || VALIDATION_PASSED=1

# Key invariant: egress should be ~3x ingress (1:3 replication)
# Allow 10% tolerance for timing/flush variations
EXPECTED_EGRESS=\$((MCR1_INGRESS * 3))
validate_values_match \$MCR1_EGRESS \$EXPECTED_EGRESS 10 'MCR-1 egress ≈ 3× ingress' || VALIDATION_PASSED=1

# Validate MCR-2, MCR-3, MCR-4 (each leaf should receive ~1/3 of egress)
# Allow lower threshold since veth pairs can drop packets under load
validate_stat /tmp/mcr2.log 'STATS:Ingress' 'matched' \$LEAF_MIN_INGRESS 'MCR-2 ingress matched' || VALIDATION_PASSED=1
validate_stat /tmp/mcr3.log 'STATS:Ingress' 'matched' \$LEAF_MIN_INGRESS 'MCR-3 ingress matched' || VALIDATION_PASSED=1
validate_stat /tmp/mcr4.log 'STATS:Ingress' 'matched' \$LEAF_MIN_INGRESS 'MCR-4 ingress matched' || VALIDATION_PASSED=1

log_section 'Test Complete'

if [ \$VALIDATION_PASSED -eq 0 ]; then
    log_info '✅ All validations passed'
    log_info 'Full logs available at: /tmp/mcr{1,2,3,4}.log'
    exit 0
else
    log_error '❌ Some validations failed - check logs'
    log_info 'Full logs available at: /tmp/mcr{1,2,3,4}.log'
    exit 1
fi

# Cleanup happens via trap (namespace auto-destroyed)
"

RESULT=$?

echo ""
if [ $RESULT -eq 0 ]; then
    echo "=== ✅ Test PASSED ==="
else
    echo "=== ❌ Test FAILED ==="
fi

echo "Network namespace destroyed - no host pollution"
exit $RESULT
