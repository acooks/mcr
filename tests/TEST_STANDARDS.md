# MCR Test Standards

## Overview
This document defines the standard structure and practices for all MCR integration tests.

## Test File Structure

### 1. Standard Header
```bash
#!/bin/bash
#
# Test Name - Brief Description
#
# Purpose: Detailed description of what this test validates
# Requirements: sudo, veth interfaces, etc.
# Expected Duration: ~X seconds

set -euo pipefail
```

### 2. Script Location Detection
```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"
```

### 3. Root Check (for tests requiring sudo)
```bash
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test requires root privileges"
    echo "Please run with: sudo $0"
    exit 1
fi
```

### 4. Load Common Functions
```bash
# Load common test infrastructure
source "$SCRIPT_DIR/topologies/common.sh"
```

### 5. Build Step
```bash
echo "=== Building ==="
cargo build --release --quiet
```

### 6. Test Execution
Use network namespace isolation:
```bash
unshare --net bash -c "
set -euo pipefail

# Load common functions in namespace
source \$SCRIPT_DIR/topologies/common.sh
trap cleanup_all EXIT

# Test logic here...
"
```

### 7. Cleanup
Use trap to ensure cleanup:
```bash
trap cleanup_all EXIT
```

## Statistics Parsing Standards

### Use FINAL Stats for Accuracy
When validating packet counts, always prefer `STATS:Ingress FINAL` over periodic stats:

```bash
# ✅ CORRECT: Use FINAL stats
INGRESS_MATCHED=$(grep 'STATS:Ingress FINAL' /tmp/test.log | grep -oP 'matched=\K[0-9]+' || echo 0)

# ❌ INCORRECT: Using last periodic stat (may be incomplete)
INGRESS_MATCHED=$(grep 'STATS:Ingress' /tmp/test.log | tail -1 | grep -oP 'matched=\K[0-9]+')
```

### Field Extraction Patterns
Current stats format:
```
[STATS:Ingress] total: recv=N matched=N egr_sent=N filtered=N no_match=N buf_exhaust=N | interval: +X recv, +Y matched (X/Y pps)
[STATS:Ingress FINAL] total: recv=N matched=N egr_sent=N filtered=N no_match=N buf_exhaust=N
[STATS:Egress] total: sent=N submitted=N ch_recv=N errors=N bytes=N | interval: +X pkts (Y pps)
```

Standard extraction patterns:
```bash
# Ingress final stats
INGRESS_RECV=$(grep 'STATS:Ingress FINAL' $LOG | grep -oP 'recv=\K[0-9]+' || echo 0)
INGRESS_MATCHED=$(grep 'STATS:Ingress FINAL' $LOG | grep -oP 'matched=\K[0-9]+' || echo 0)
INGRESS_EGR_SENT=$(grep 'STATS:Ingress FINAL' $LOG | grep -oP 'egr_sent=\K[0-9]+' || echo 0)

# Egress final stats (use last periodic stat)
EGRESS_SENT=$(grep 'STATS:Egress' $LOG | tail -1 | grep -oP 'sent=\K[0-9]+' || echo 0)
EGRESS_CH_RECV=$(grep 'STATS:Egress' $LOG | tail -1 | grep -oP 'ch_recv=\K[0-9]+' || echo 0)
EGRESS_SUBMITTED=$(grep 'STATS:Egress' $LOG | tail -1 | grep -oP 'submitted=\K[0-9]+' || echo 0)
```

## Validation Standards

### 1:1 Forwarding Validation
For single-output rules, validate perfect forwarding:
```bash
if [ $INGRESS_MATCHED -eq $EXPECTED ] && \
   [ $INGRESS_EGR_SENT -eq $EXPECTED ] && \
   [ $EGRESS_CH_RECV -eq $EXPECTED ] && \
   [ $EGRESS_SENT -eq $EXPECTED ]; then
    echo "✅ PASS: Perfect 1:1 forwarding ($EXPECTED packets)"
    exit 0
else
    echo "❌ FAIL: Count mismatch"
    echo "  Expected: $EXPECTED"
    echo "  Ingress matched: $INGRESS_MATCHED"
    echo "  Ingress egr_sent: $INGRESS_EGR_SENT"
    echo "  Egress ch_recv: $EGRESS_CH_RECV"
    echo "  Egress sent: $EGRESS_SENT"
    exit 1
fi
```

### Multi-Output Validation
For rules with multiple outputs, expect multiplication:
```bash
EXPECTED_OUTPUT=$((INGRESS_MATCHED * NUM_OUTPUTS))
if [ $EGRESS_SENT -eq $EXPECTED_OUTPUT ]; then
    echo "✅ PASS: Correct fanout (${NUM_OUTPUTS}x)"
    exit 0
fi
```

## Timing and Synchronization Standards

### MCR Startup
```bash
# Start MCR
taskset -c 0 "$RELAY_BIN" supervisor \
    --relay-command-socket-path /tmp/test_relay.sock \
    --control-socket-path /tmp/test_mcr.sock \
    --interface $IFACE \
    --num-workers 1 \
    > /tmp/test.log 2>&1 &
MCR_PID=$!

# Wait for control socket (up to 5 seconds)
for i in {1..50}; do
    if [ -S /tmp/test_mcr.sock ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S /tmp/test_mcr.sock ]; then
    echo "ERROR: Control socket not found after 5 seconds"
    exit 1
fi

# Allow time for full initialization
sleep 2
```

### Graceful Shutdown
```bash
# Send traffic
"$TRAFFIC_BIN" --interface $SRC_IP --group $GROUP --port $PORT \
    --count $COUNT --size $SIZE --rate $RATE > /dev/null 2>&1

# Wait for pipeline to drain
DRAIN_TIME=$(echo "scale=0; ($COUNT / $RATE) + 5" | bc)
sleep $DRAIN_TIME

# Graceful shutdown (triggers final stats)
kill $MCR_PID 2>/dev/null || true
wait $MCR_PID 2>/dev/null || true
sync  # Ensure logs are flushed
```

## File Organization Standards

### Test Categories
```
tests/
├── debug_*.sh           # Debug/diagnostic tests (small packet counts)
├── scaling_*.sh         # Scaling tests (multiple packet counts)
├── data_plane_*.sh      # Data plane specific tests
├── topologies/          # Multi-hop topology tests
│   ├── common.sh        # Shared functions
│   ├── baseline_*.sh    # Baseline topology tests
│   ├── chain_*.sh       # Chain topology tests
│   └── tree_*.sh        # Tree topology tests
└── e2e/                 # End-to-end tests
    ├── common.sh
    └── *.sh
```

### Log File Naming
```bash
# Use descriptive log file names
/tmp/mcr_${TEST_NAME}.log         # Main log
/tmp/mcr_${INSTANCE_ID}.log       # For multi-instance tests
```

### Cleanup Patterns
```bash
# Clean up old files before test
rm -f /tmp/test_*.log
rm -f /tmp/test_*.sock

# Cleanup function
cleanup_all() {
    echo "[INFO] Running cleanup"
    killall -q multicast_relay 2>/dev/null || true
    rm -f /tmp/test_*.sock
    # Don't remove logs - they're useful for debugging
}
```

## Output Standards

### Progress Messages
```bash
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Testing: Description"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
```

### Result Messages
```bash
# Pass
echo "✅ PASS: Test description (N packets)"

# Fail
echo "❌ FAIL: Test description"
echo "  Reason: specific failure reason"
echo "  Log: /tmp/test.log"

# Partial/Warning
echo "⚠️  WARNING: Test description"
```

### Summary Reports
```bash
echo ""
echo "=== FINAL RESULTS ==="
echo "Passed: $PASSED / $TOTAL"
echo "Failed: $FAILED / $TOTAL"
echo ""
if [ $FAILED -eq 0 ]; then
    echo "✅ ALL TESTS PASSED"
    exit 0
else
    echo "❌ SOME TESTS FAILED"
    exit 1
fi
```

## Example: Standard Test Template

```bash
#!/bin/bash
#
# Template Test - Description
#
# Purpose: What this test validates
# Requirements: sudo, specific setup, etc.

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

# Load common functions
source "$SCRIPT_DIR/topologies/common.sh"

# Export binaries
RELAY_BIN="$RELAY_BINARY"
CONTROL_BIN="$CONTROL_CLIENT_BINARY"
TRAFFIC_BIN="$TRAFFIC_GENERATOR_BINARY"

echo ""
echo "=== Test: Description ==="
echo ""

unshare --net bash -c "
set -euo pipefail

source $SCRIPT_DIR/topologies/common.sh
trap cleanup_all EXIT

# Setup
enable_loopback
setup_veth_pair veth0 veth0p 10.0.0.1/24 10.0.0.2/24

# Clean up old files
rm -f /tmp/test.log /tmp/test_relay.sock /tmp/test_mcr.sock

# Start MCR
taskset -c 0 '$RELAY_BIN' supervisor \
    --relay-command-socket-path /tmp/test_relay.sock \
    --control-socket-path /tmp/test_mcr.sock \
    --interface veth0p \
    --num-workers 1 \
    > /tmp/test.log 2>&1 &
MCR_PID=\$!

# Wait for socket
for i in {1..50}; do
    [ -S /tmp/test_mcr.sock ] && break
    sleep 0.1
done
[ ! -S /tmp/test_mcr.sock ] && echo 'ERROR: Socket not found' && exit 1
sleep 2

# Add rule
'$CONTROL_BIN' --socket-path /tmp/test_mcr.sock add \
    --input-interface veth0p \
    --input-group 239.1.1.1 \
    --input-port 5001 \
    --outputs '239.2.2.2:5002:lo' > /dev/null

sleep 1

# Send traffic
'$TRAFFIC_BIN' --interface 10.0.0.1 --group 239.1.1.1 --port 5001 \
    --count 1000 --size 1400 --rate 1000 > /dev/null 2>&1

# Wait for pipeline drain
sleep 3

# Graceful shutdown
kill \$MCR_PID 2>/dev/null || true
wait \$MCR_PID 2>/dev/null || true
sync

# Extract stats
INGRESS_MATCHED=\$(grep 'STATS:Ingress FINAL' /tmp/test.log | grep -oP 'matched=\K[0-9]+' || echo 0)
INGRESS_EGR_SENT=\$(grep 'STATS:Ingress FINAL' /tmp/test.log | grep -oP 'egr_sent=\K[0-9]+' || echo 0)
EGRESS_CH_RECV=\$(grep 'STATS:Egress' /tmp/test.log | tail -1 | grep -oP 'ch_recv=\K[0-9]+' || echo 0)
EGRESS_SENT=\$(grep 'STATS:Egress' /tmp/test.log | tail -1 | grep -oP 'sent=\K[0-9]+' || echo 0)

# Validate
if [ \$INGRESS_MATCHED -eq 1000 ] && [ \$INGRESS_EGR_SENT -eq 1000 ] && \
   [ \$EGRESS_CH_RECV -eq 1000 ] && [ \$EGRESS_SENT -eq 1000 ]; then
    echo '✅ PASS: Perfect 1:1 forwarding (1000 packets)'
    exit 0
else
    echo '❌ FAIL: Count mismatch'
    echo \"  Ingress matched: \$INGRESS_MATCHED (expect 1000)\"
    echo \"  Ingress egr_sent: \$INGRESS_EGR_SENT (expect 1000)\"
    echo \"  Egress ch_recv: \$EGRESS_CH_RECV (expect 1000)\"
    echo \"  Egress sent: \$EGRESS_SENT (expect 1000)\"
    exit 1
fi
"

exit $?
```

## Migration Checklist for Existing Tests

When updating an existing test to these standards:

- [ ] Add proper header with description and requirements
- [ ] Use `set -euo pipefail`
- [ ] Add root privilege check
- [ ] Source common.sh from correct location
- [ ] Use `unshare --net` for isolation
- [ ] Clean up old files before test
- [ ] Use proper socket wait loop (up to 5 seconds)
- [ ] Add 2-second initialization delay after socket appears
- [ ] Parse `STATS:Ingress FINAL` for ingress counts
- [ ] Parse last `STATS:Egress` for egress counts
- [ ] Use graceful shutdown (kill + wait + sync)
- [ ] Validate all relevant counters
- [ ] Use standardized output format (✅/❌/⚠️)
- [ ] Return proper exit codes (0=pass, 1=fail)
