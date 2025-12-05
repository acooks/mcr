#!/bin/bash
# Test that mcrd works correctly with Linux capabilities instead of root
#
# This test verifies the capability-based operation documented in REFERENCE.md:
# 1. mcrd can start without sudo when capabilities are set
# 2. Workers spawn correctly
# 3. Relay socket ownership is changed to nobody:nobody (CAP_CHOWN)
#
# Prerequisites:
#   - Build: just build-release
#   - Set capabilities: just set-caps (requires sudo once)
#
# Run: ./tests/capabilities_test.sh (no sudo needed!)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MCRD="$PROJECT_ROOT/target/release/mcrd"
MCRCTL="$PROJECT_ROOT/target/release/mcrctl"
CONTROL_SOCKET="/tmp/mcr_caps_test_$$.sock"
RELAY_SOCKET="/tmp/mcr_relay_commands.sock"

cleanup() {
    if [[ -n "${MCR_PID:-}" ]]; then
        kill "$MCR_PID" 2>/dev/null || true
        wait "$MCR_PID" 2>/dev/null || true
    fi
    rm -f "$CONTROL_SOCKET" 2>/dev/null || true
    # Relay socket may be owned by nobody
    sudo rm -f "$RELAY_SOCKET" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== MCR Capabilities Test ==="
echo ""

# Check we're NOT running as root
if [[ $EUID -eq 0 ]]; then
    echo "ERROR: This test should be run WITHOUT sudo"
    echo "It verifies that mcrd works with capabilities instead of root."
    exit 1
fi

# Check binary exists
if [[ ! -x "$MCRD" ]]; then
    echo "ERROR: mcrd not found at $MCRD"
    echo "Run: just build-release"
    exit 1
fi

# Check capabilities are set
CAPS=$(getcap "$MCRD" 2>/dev/null || true)
if [[ -z "$CAPS" ]] || ! echo "$CAPS" | grep -q "cap_net_raw"; then
    echo "ERROR: Capabilities not set on mcrd"
    echo "Run: just set-caps"
    exit 1
fi

echo "Binary: $MCRD"
echo "Capabilities: $CAPS"
echo ""

# Clean up any stale sockets (may need sudo for nobody-owned relay socket)
sudo rm -f "$CONTROL_SOCKET" "$RELAY_SOCKET" 2>/dev/null || true

# Test 1: Start mcrd without sudo
echo "Test 1: Starting mcrd without sudo..."
"$MCRD" supervisor --control-socket-path "$CONTROL_SOCKET" &
MCR_PID=$!
sleep 1

if ! ps -p "$MCR_PID" > /dev/null 2>&1; then
    echo "FAILED: mcrd did not start"
    exit 1
fi
echo "  PASS: mcrd running as $(ps -p $MCR_PID -o user= | tr -d ' ') (PID $MCR_PID)"

# Test 2: Check relay socket ownership (CAP_CHOWN)
echo ""
echo "Test 2: Checking relay socket ownership..."
if [[ ! -S "$RELAY_SOCKET" ]]; then
    echo "FAILED: Relay socket not created"
    exit 1
fi

SOCKET_OWNER=$(stat -c '%U' "$RELAY_SOCKET")
if [[ "$SOCKET_OWNER" != "nobody" ]]; then
    echo "FAILED: Relay socket owned by '$SOCKET_OWNER', expected 'nobody'"
    exit 1
fi
echo "  PASS: Relay socket owned by nobody (CAP_CHOWN working)"

# Test 3: Control socket responds
echo ""
echo "Test 3: Testing control socket..."
PING=$("$MCRCTL" --socket-path "$CONTROL_SOCKET" ping 2>&1 || true)
if ! echo "$PING" | grep -qi "pong"; then
    echo "FAILED: Ping failed: $PING"
    exit 1
fi
echo "  PASS: Control socket responding"

echo ""
echo "=== All capability tests passed ==="
echo ""
echo "Note: To test worker spawning with capabilities, run the integration"
echo "tests which create veth pairs and verify full packet forwarding."
