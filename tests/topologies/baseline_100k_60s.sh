#!/bin/bash
#
# Baseline Performance Test - 100k pps for 60 seconds (with profiling)
#
# Wrapper script that invokes the unified baseline_test.sh for extended profiling runs.
# Generates perf data at /tmp/mcr.perf.data for flamegraph analysis.
#
# For detailed documentation, see baseline_test.sh --help
#
# Usage: sudo ./baseline_100k_60s.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$SCRIPT_DIR/baseline_test.sh" --rate 100000 --packets 6000000 --profiling "$@"
