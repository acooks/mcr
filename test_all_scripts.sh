#!/bin/bash
#
# Run all shell script tests and document results
#
# This script runs each test individually and captures:
# - Exit code (pass/fail)
# - Duration
# - Key output
# - Any errors

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results arrays
declare -a PASSED_TESTS
declare -a FAILED_TESTS
declare -a SKIPPED_TESTS

# Create test run directory with timestamp
TEST_RUN_DIR="test_results/run_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TEST_RUN_DIR"
echo "Test results will be saved to: $TEST_RUN_DIR"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    sudo pkill -9 multicast_relay 2>/dev/null || true
    sudo pkill -9 socat 2>/dev/null || true
    sudo rm -f /dev/shm/mcr_* 2>/dev/null || true
    sudo rm -f /tmp/*.sock 2>/dev/null || true
    sudo rm -f /tmp/mcr_* 2>/dev/null || true
}

# Run a single test
run_test() {
    local test_name="$1"
    local test_path="$2"
    local timeout_sec="${3:-60}"

    echo -e "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${YELLOW}Testing: $test_name${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Cleanup before test
    cleanup
    sleep 1

    # Create test-specific directory
    local test_dir="$TEST_RUN_DIR/$test_name"
    mkdir -p "$test_dir"

    local start_time=$(date +%s)
    local main_log="$test_dir/test_output.log"

    # Capture any MCR process logs that might be created during test
    # We'll copy them after the test runs
    local tmp_mcr_logs=(/tmp/mcr*.log)

    if timeout "${timeout_sec}" sudo "$test_path" > "$main_log" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${GREEN}✅ PASSED${NC} (${duration}s)"
        echo "PASSED" > "$test_dir/status"
        echo "$duration" > "$test_dir/duration"
        PASSED_TESTS+=("$test_name")

        # Show key stats
        grep -E "(PASS|✅|matched=|sent=)" "$main_log" | tail -5 || true
    else
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [ $exit_code -eq 124 ]; then
            echo -e "${RED}❌ FAILED (TIMEOUT after ${duration}s)${NC}"
            echo "TIMEOUT" > "$test_dir/status"
        else
            echo -e "${RED}❌ FAILED (exit code: $exit_code, ${duration}s)${NC}"
            echo "FAILED" > "$test_dir/status"
        fi

        echo "$exit_code" > "$test_dir/exit_code"
        echo "$duration" > "$test_dir/duration"
        FAILED_TESTS+=("$test_name")

        # Show error details
        echo -e "\n${RED}Error output:${NC}"
        tail -20 "$main_log"
    fi

    # Copy any MCR logs that were created during the test
    for log in /tmp/mcr*.log; do
        if [ -f "$log" ]; then
            cp "$log" "$test_dir/" 2>/dev/null || true
        fi
    done

    # Copy any other test-specific logs from /tmp
    for log in /tmp/test_*.log; do
        if [ -f "$log" ]; then
            local basename=$(basename "$log")
            if [ "$basename" != "test_${test_name}.log" ]; then
                cp "$log" "$test_dir/" 2>/dev/null || true
            fi
        fi
    done

    echo -e "Test logs saved to: $test_dir"
}

echo "═══════════════════════════════════════════════════════════"
echo "           MCR Shell Script Test Suite"
echo "═══════════════════════════════════════════════════════════"

# Test 1: Debug test (10 packets)
run_test "debug_10_packets" "./tests/debug_10_packets.sh" 60

# Test 2: Data plane debug
run_test "data_plane_debug" "./tests/data_plane_debug.sh" 60

# Test 3: Data plane pipeline (loopback)
run_test "data_plane_pipeline" "./tests/data_plane_pipeline.sh" 90

# Test 4: Data plane pipeline (veth)
run_test "data_plane_pipeline_veth" "./tests/data_plane_pipeline_veth.sh" 90

# Test 5: Data plane E2E
run_test "data_plane_e2e" "./tests/data_plane_e2e.sh" 90

# Test 6: Scaling test
run_test "scaling_test" "./tests/scaling_test.sh" 120

# Test 7: Baseline 50k (topology)
run_test "baseline_50k" "./tests/topologies/baseline_50k.sh" 120

# Test 8: Chain 3-hop (topology)
run_test "chain_3hop" "./tests/topologies/chain_3hop.sh" 120

# Test 9: Tree fanout (topology)
run_test "tree_fanout" "./tests/topologies/tree_fanout.sh" 120

# Final cleanup
cleanup

# Summary
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                    TEST SUMMARY"
echo "═══════════════════════════════════════════════════════════"

echo -e "\n${GREEN}Passed: ${#PASSED_TESTS[@]}${NC}"
for test in "${PASSED_TESTS[@]}"; do
    echo -e "  ${GREEN}✅${NC} $test"
done

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo -e "\n${RED}Failed: ${#FAILED_TESTS[@]}${NC}"
    for test in "${FAILED_TESTS[@]}"; do
        echo -e "  ${RED}❌${NC} $test"
    done
fi

if [ ${#SKIPPED_TESTS[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Skipped: ${#SKIPPED_TESTS[@]}${NC}"
    for test in "${SKIPPED_TESTS[@]}"; do
        echo -e "  ${YELLOW}⊘${NC} $test"
    done
fi

echo ""
echo "═══════════════════════════════════════════════════════════"

TOTAL_TESTS=$((${#PASSED_TESTS[@]} + ${#FAILED_TESTS[@]} + ${#SKIPPED_TESTS[@]}))
echo -e "Total: $TOTAL_TESTS tests"
echo -e "Pass rate: $(( ${#PASSED_TESTS[@]} * 100 / TOTAL_TESTS ))%"

# Create summary file
{
    echo "MCR Shell Script Test Suite - Run $(date)"
    echo "=========================================="
    echo ""
    echo "Test Results Directory: $TEST_RUN_DIR"
    echo ""
    echo "Summary:"
    echo "  Total tests: $TOTAL_TESTS"
    echo "  Passed: ${#PASSED_TESTS[@]}"
    echo "  Failed: ${#FAILED_TESTS[@]}"
    echo "  Skipped: ${#SKIPPED_TESTS[@]}"
    echo "  Pass rate: $(( ${#PASSED_TESTS[@]} * 100 / TOTAL_TESTS ))%"
    echo ""
    echo "Passed Tests:"
    for test in "${PASSED_TESTS[@]}"; do
        echo "  ✅ $test"
    done
    echo ""
    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo "Failed Tests:"
        for test in "${FAILED_TESTS[@]}"; do
            echo "  ❌ $test"
        done
        echo ""
    fi
    if [ ${#SKIPPED_TESTS[@]} -gt 0 ]; then
        echo "Skipped Tests:"
        for test in "${SKIPPED_TESTS[@]}"; do
            echo "  ⊘ $test"
        done
        echo ""
    fi
    echo "Individual test logs can be found in subdirectories:"
    for test in "${PASSED_TESTS[@]}" "${FAILED_TESTS[@]}" "${SKIPPED_TESTS[@]}"; do
        echo "  $TEST_RUN_DIR/$test/"
    done
} > "$TEST_RUN_DIR/SUMMARY.txt"

echo ""
echo "Full summary saved to: $TEST_RUN_DIR/SUMMARY.txt"

if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed${NC}"
    exit 1
fi
