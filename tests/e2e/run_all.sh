#!/bin/bash

# This script runs all end-to-end tests for the mcrd.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Cleanup old namespaces ---
echo "--- Cleaning up any old test namespaces ---"
sudo ip -all netns delete
# The above might fail if there are no namespaces, so we ignore errors.
# A more specific command would be:
# sudo ip netns | grep mcr_e2e_test | xargs -r sudo ip netns del
# But the -all command is simpler and sufficient for a test environment.
echo "Cleanup complete."

# --- Build Project ---
echo "--- Building project for E2E tests ---"
cargo build

# --- Run Tests ---
TEST_DIR=$(dirname "$0")
PASSED_COUNT=0
FAILED_COUNT=0

for test_file in "$TEST_DIR"/*.t; do
    echo -e "\n>>> Running test: $(basename "$test_file") <<<
"
    if "$test_file"; then
        echo "✅ PASSED: $(basename "$test_file")"
        ((PASSED_COUNT++))
    else
        echo "❌ FAILED: $(basename "$test_file")"
        ((FAILED_COUNT++))
    fi
done

# --- Summary ---
echo -e "\n--- Test Summary ---"
echo "Total: $((PASSED_COUNT + FAILED_COUNT))"
echo "Passed: $PASSED_COUNT"
echo "Failed: $FAILED_COUNT"

if [ "$FAILED_COUNT" -ne 0 ]; then
    echo "Some tests failed."
    exit 1
fi
