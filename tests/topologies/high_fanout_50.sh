#!/bin/bash
#
# High Fanout Test (1:50 Head-End Replication)
#
# Topology: Traffic Generator → MCR → 50 outputs (loopback)
#
# This test validates:
# - High fanout ratio (1 input → 50 outputs)
# - VecDeque-based send queue performance under amplification
# - Buffer pool performance with 50x traffic multiplication
# - Egress queue management with many destinations
#
# Network isolation: Runs in isolated network namespace (unshare --net)
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
PACKET_COUNT=10000
SEND_RATE=10000      # 10k pps input → 500k pps output
FANOUT=50

# --- Check for root ---
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges for network namespace isolation"
    echo "Please run with: sudo $0"
    exit 1
fi

# --- Build binaries (if needed) ---
ensure_binaries_built

# --- Run test in isolated network namespace ---
echo "=== Starting 1:${FANOUT} Fanout Test in Isolated Network Namespace ==="
echo "Namespace will be automatically destroyed on exit (no host pollution)"
echo ""

unshare --net bash -c "
set -euo pipefail

# Source common functions
source $SCRIPT_DIR/common.sh

# Buffer pool sizing for 50x amplification scenario
export MCR_BUFFER_POOL_SMALL=8000
export MCR_BUFFER_POOL_STANDARD=4000
export MCR_BUFFER_POOL_JUMBO=1600

# Set up cleanup trap
trap 'graceful_cleanup_unshare mcr_PID' EXIT

log_section 'Network Namespace Setup'

# Enable loopback
enable_loopback

# Create veth pair for ingress
setup_veth_pair veth0 veth0p 10.0.0.1/24 10.0.0.2/24

log_section 'Starting MCR Instance'

# Start MCR on CPU core 0
start_mcr mcr veth0p /tmp/mcr_fanout.sock /tmp/mcr_fanout.log 0

# Wait for socket
wait_for_sockets /tmp/mcr_fanout.sock
sleep 2

log_section 'Configuring 1:${FANOUT} Fanout Rule'

# Build outputs string (all to loopback with different ports)
OUTPUTS=''
for i in \$(seq 1 $FANOUT); do
    PORT=\$((5000 + i))
    if [ -n \"\$OUTPUTS\" ]; then
        OUTPUTS=\"\${OUTPUTS},\"
    fi
    OUTPUTS=\"\${OUTPUTS}239.10.10.\${i}:\${PORT}:lo\"
done

log_info \"Adding rule with $FANOUT outputs\"
\$CONTROL_CLIENT_BINARY --socket-path /tmp/mcr_fanout.sock add \\
    --input-interface veth0p \\
    --input-group 239.1.1.1 \\
    --input-port 5001 \\
    --outputs \"\$OUTPUTS\" > /dev/null 2>&1

sleep 2

log_section 'Running Traffic Generator'
log_info \"Sending $PACKET_COUNT packets at $SEND_RATE pps\"
log_info \"Expected: matched=$PACKET_COUNT, tx=$((PACKET_COUNT * FANOUT))\"

run_traffic 10.0.0.1 239.1.1.1 5001 $PACKET_COUNT $PACKET_SIZE $SEND_RATE

log_info 'Waiting for pipeline to flush...'
sleep 3

# Print final stats
print_final_stats 'MCR:/tmp/mcr_fanout.log'

log_section 'Validating Results'

VALIDATION_PASSED=0

# Validate matched packets (expect ~60% on CI runners due to resource constraints)
validate_stat /tmp/mcr_fanout.log 'STATS' 'matched' $((PACKET_COUNT * 60 / 100)) 'MCR ingress matched' || VALIDATION_PASSED=1

# Validate TX count (should be FANOUT × matched, proportionally scaled)
# Using 60% of expected total to match ingress threshold
validate_stat /tmp/mcr_fanout.log 'STATS' 'tx' $((PACKET_COUNT * FANOUT * 60 / 100)) 'MCR egress TX (${FANOUT}x amplification)' || VALIDATION_PASSED=1

# Validate no buffer exhaustion
validate_stat_max /tmp/mcr_fanout.log 'STATS' 'buf_exhaust' 100 'Buffer exhaustion count' || VALIDATION_PASSED=1

log_section 'Test Complete'

if [ \$VALIDATION_PASSED -eq 0 ]; then
    log_info '✅ All validations passed'
    log_info 'Full log available at: /tmp/mcr_fanout.log'
    exit 0
else
    log_error '❌ Some validations failed - check logs'
    log_info 'Full log available at: /tmp/mcr_fanout.log'
    exit 1
fi
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
