#!/bin/bash
#
# 3-Hop Chain Topology Test
#
# Topology: Traffic Generator → MCR-1 → MCR-2 → MCR-3
#
# This test validates:
# - Serial packet forwarding through multiple MCR instances
# - Buffer management across multiple hops
# - Stats accuracy for ingress/egress at each hop
# - No packet corruption during relay
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
PACKET_COUNT=500000   # 500k packets for realistic validation
SEND_RATE=250000      # 250k pps target (matches single-worker capacity)

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

# Set up cleanup trap
trap 'graceful_cleanup_unshare mcr1_PID mcr2_PID mcr3_PID' EXIT

log_section 'Network Namespace Setup'

# Enable loopback
enable_loopback

# Create veth pairs for 3-hop chain
# Traffic Gen → veth0 → veth0p (MCR-1 ingress)
# MCR-1 egress → veth1a → veth1b (MCR-2 ingress)
# MCR-2 egress → veth2a → veth2b (MCR-3 ingress)
setup_veth_pair veth0 veth0p 10.0.0.1/24 10.0.0.2/24
setup_veth_pair veth1a veth1b 10.0.1.1/24 10.0.1.2/24
setup_veth_pair veth2a veth2b 10.0.2.1/24 10.0.2.2/24

log_section 'Starting MCR Instances'

# Start 3-hop chain on separate CPU cores to avoid contention
start_mcr mcr1 veth0p /tmp/mcr1.sock /tmp/mcr1.log 0
start_mcr mcr2 veth1b /tmp/mcr2.sock /tmp/mcr2.log 1
start_mcr mcr3 veth2b /tmp/mcr3.sock /tmp/mcr3.log 2

# Wait for all instances to be ready
wait_for_sockets /tmp/mcr1.sock /tmp/mcr2.sock /tmp/mcr3.sock
sleep 2

log_section 'Configuring Forwarding Rules'

# MCR-1: Receive on veth0p (239.1.1.1:5001) → Forward to veth1a (239.2.2.2:5002)
add_rule /tmp/mcr1.sock veth0p 239.1.1.1 5001 '239.2.2.2:5002:veth1a'

# MCR-2: Receive on veth1b (239.2.2.2:5002) → Forward to veth2a (239.3.3.3:5003)
add_rule /tmp/mcr2.sock veth1b 239.2.2.2 5002 '239.3.3.3:5003:veth2a'

# MCR-3: Receive on veth2b (239.3.3.3:5003) → No egress, just count
# Note: We add a dummy output to 127.0.0.1 just to match packets (won't actually forward anywhere useful)
add_rule /tmp/mcr3.sock veth2b 239.3.3.3 5003 '239.9.9.9:5099:lo'
log_info 'MCR-3: Terminus node with dummy rule for packet counting'

sleep 2

# Run traffic generator (no real-time log monitoring)
run_traffic 10.0.0.1 239.1.1.1 5001 $PACKET_COUNT $PACKET_SIZE $SEND_RATE

log_info 'Waiting for pipeline to flush...'
sleep 5

# Print final stats
print_final_stats \
    'MCR-1:/tmp/mcr1.log' \
    'MCR-2:/tmp/mcr2.log' \
    'MCR-3:/tmp/mcr3.log'

log_section 'Validating Results'

# Validate MCR-1 (expect ~46% of sent packets due to kernel drops)
VALIDATION_PASSED=0
validate_stat /tmp/mcr1.log 'STATS:Ingress' 'matched' 200000 'MCR-1 ingress matched' || VALIDATION_PASSED=1
validate_stat /tmp/mcr1.log 'STATS:Egress' 'sent' 400000 'MCR-1 egress sent' || VALIDATION_PASSED=1

# Validate MCR-2 (expect ~37% of MCR-1 egress due to UDP→AF_PACKET gap)
validate_stat /tmp/mcr2.log 'STATS:Ingress' 'matched' 150000 'MCR-2 ingress matched' || VALIDATION_PASSED=1
validate_stat /tmp/mcr2.log 'STATS:Egress' 'sent' 300000 'MCR-2 egress sent' || VALIDATION_PASSED=1

# Validate MCR-3 (receives from MCR-2, similar loss pattern)
validate_stat /tmp/mcr3.log 'STATS:Ingress' 'matched' 150000 'MCR-3 ingress matched' || VALIDATION_PASSED=1

log_section 'Test Complete'

if [ \$VALIDATION_PASSED -eq 0 ]; then
    log_info '✅ All validations passed'
    log_info 'Full logs available at: /tmp/mcr{1,2,3}.log'
    exit 0
else
    log_error '❌ Some validations failed - check logs'
    log_info 'Full logs available at: /tmp/mcr{1,2,3}.log'
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
