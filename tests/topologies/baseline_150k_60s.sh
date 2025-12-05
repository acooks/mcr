#!/bin/bash
#
# Baseline Performance Test - 150k pps for 60 seconds (with profiling)
#
# Wrapper script that invokes the unified baseline_test.sh for high-rate profiling runs.
# Generates perf data at /tmp/mcr.perf.data for flamegraph analysis.
#
# NOTE: This test is SKIPPED in CI environments because:
# - It requires sustained high-rate packet processing (150k pps for 60s)
# - CI runners have limited CPU and virtualized networking
# - The 100k test provides sufficient validation; this is for profiling
#
# For detailed documentation, see baseline_test.sh --help
#
# Usage: sudo ./baseline_150k_60s.sh
#

set -euo pipefail

# Skip in CI - this is a profiling test, not a validation test
# CI runners can't sustain 150k pps due to virtualized networking
if [ "${CI:-}" = "true" ]; then
    echo "[INFO] Skipping baseline_150k_60s.sh in CI environment"
    echo "[INFO] This is a profiling test requiring high-performance hardware"
    echo "[INFO] The baseline_100k.sh test provides sufficient CI validation"
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$SCRIPT_DIR/baseline_test.sh" --rate 150000 --packets 9000000 --profiling "$@"
