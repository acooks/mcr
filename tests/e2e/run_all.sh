#!/bin/bash

# Master script to run all End-to-End tests

set -e

E2E_DIR="$(dirname "$0")"
COMMON_SCRIPT="$E2E_DIR/common.sh"

# Source the common functions to get cleanup and other helpers
# This is primarily for the 'cleanup' trap, but also for 'cargo build'
. "$COMMON_SCRIPT"

# Ensure cleanup runs on script exit
trap cleanup EXIT

# Build the project once for all tests
echo "--- Building project for E2E tests ---"
cargo build --features integration_test

TEST_FILES=(
    "$E2E_DIR/01_happy_path_forwarding.t"
    # "$E2E_DIR/02_rule_management.t"
    # "$E2E_DIR/03_stats_verification.t"
    # "$E2E_DIR/04_worker_restart_resilience.t"
)

TOTAL_TESTS=${#TEST_FILES[@]}
PASSED_TESTS=0
FAILED_TESTS=0

echo "--- Running $TOTAL_TESTS End-to-End tests ---"

for test_file in "${TEST_FILES[@]}"; do
    echo "\n>>> Running test: $(basename "$test_file") <<<
"
    if "$test_file"; then
        echo "✅ PASSED: $(basename "$test_file")"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "❌ FAILED: $(basename "$test_file")"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
done

echo "\n--- Test Summary ---"
echo "Total: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $FAILED_TESTS"

if [ "$FAILED_TESTS" -gt 0 ]; then
    echo "Some tests failed."
    exit 1
else
    echo "All tests passed."
    exit 0
fi
