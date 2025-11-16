#!/usr/bin/env bash
# Run tests in isolated network namespace
# This ensures tests don't interfere with host networking and can run in parallel

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <test-binary> [test-args...]"
    echo ""
    echo "Example:"
    echo "  $0 ./target/debug/deps/integration-xyz123 --ignored --test-threads=1"
    exit 1
fi

TEST_BINARY="$1"
shift
TEST_ARGS="$@"

# Generate unique namespace name using PID
NETNS_NAME="mcr-test-$$"

# Cleanup function
cleanup() {
    echo "Cleaning up namespace $NETNS_NAME"
    ip netns del "$NETNS_NAME" 2>/dev/null || true
}

# Ensure cleanup on exit, interrupt, or termination
trap cleanup EXIT INT TERM

echo "Creating network namespace: $NETNS_NAME"
ip netns add "$NETNS_NAME"

# Set up loopback in the namespace (required for many tests)
ip netns exec "$NETNS_NAME" ip link set lo up

# Optional: Set up veth pair for tests that need external connectivity
# Uncomment if needed:
# ip link add veth0 type veth peer name veth1
# ip link set veth1 netns "$NETNS_NAME"
# ip addr add 10.200.0.1/24 dev veth0
# ip link set veth0 up
# ip netns exec "$NETNS_NAME" ip addr add 10.200.0.2/24 dev veth1
# ip netns exec "$NETNS_NAME" ip link set veth1 up

echo "Running tests in namespace: $NETNS_NAME"
echo "Test binary: $TEST_BINARY"
echo "Test args: $TEST_ARGS"
echo ""

# Run the test binary inside the namespace
# Preserve environment variables with -E flag (important for Rust test harness)
sudo -E ip netns exec "$NETNS_NAME" "$TEST_BINARY" $TEST_ARGS

EXIT_CODE=$?

echo ""
echo "Tests completed with exit code: $EXIT_CODE"
exit $EXIT_CODE
