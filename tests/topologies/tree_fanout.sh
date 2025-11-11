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

# Test parameters
PACKET_SIZE=1400
PACKET_COUNT=500000   # Fewer packets (will be amplified 3x)
SEND_RATE=300000      # Lower rate for stability

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

# --- Run test in isolated network namespace ---
echo "=== Starting Test in Isolated Network Namespace ==="
echo "Namespace will be automatically destroyed on exit (no host pollution)"
echo ""

unshare --net bash -c "
set -euo pipefail

# Source common functions
source $SCRIPT_DIR/common.sh

# Set up cleanup trap
trap cleanup_all EXIT

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

# Start MCR-1 (root node with 3 outputs)
start_mcr mcr1 veth0p /tmp/mcr1.sock /tmp/mcr1.log

# Start MCR-2, MCR-3, MCR-4 (leaf nodes)
start_mcr mcr2 veth1b /tmp/mcr2.sock /tmp/mcr2.log
start_mcr mcr3 veth2b /tmp/mcr3.sock /tmp/mcr3.log
start_mcr mcr4 veth3b /tmp/mcr4.sock /tmp/mcr4.log

# Wait for all instances to be ready
wait_for_sockets /tmp/mcr1.sock /tmp/mcr2.sock /tmp/mcr3.sock /tmp/mcr4.sock
sleep 2

log_section 'Configuring Forwarding Rules'

# MCR-1: Receive on veth0p (239.1.1.1:5001) → Forward to 3 destinations (HEAD-END REPLICATION)
log_info 'MCR-1: Configuring 1:3 head-end replication'
add_rule /tmp/mcr1.sock veth0p 239.1.1.1 5001 '239.2.2.2:5002:veth1a'
# Note: Current implementation requires separate rules for each output
# TODO: Future enhancement - single rule with multiple outputs
add_rule /tmp/mcr1.sock veth0p 239.1.1.1 5001 '239.3.3.3:5003:veth2a'
add_rule /tmp/mcr1.sock veth0p 239.1.1.1 5001 '239.4.4.4:5004:veth3a'

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

# Validate MCR-1 (should receive all packets, replicate 3x egress)
VALIDATION_PASSED=0
validate_stat /tmp/mcr1.log 'STATS:Ingress' 'matched' 400000 'MCR-1 ingress matched' || VALIDATION_PASSED=1
validate_stat /tmp/mcr1.log 'STATS:Egress' 'sent' 500000 'MCR-1 egress sent (3x amplification)' || VALIDATION_PASSED=1

# Validate MCR-2, MCR-3, MCR-4 (should each receive ~1/3 of MCR-1 egress)
# Note: Due to buffer exhaustion, expect some packet loss
validate_stat /tmp/mcr2.log 'STATS:Ingress' 'matched' 100000 'MCR-2 ingress matched' || VALIDATION_PASSED=1
validate_stat /tmp/mcr3.log 'STATS:Ingress' 'matched' 100000 'MCR-3 ingress matched' || VALIDATION_PASSED=1
validate_stat /tmp/mcr4.log 'STATS:Ingress' 'matched' 100000 'MCR-4 ingress matched' || VALIDATION_PASSED=1

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
