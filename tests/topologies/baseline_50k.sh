#!/bin/bash
#
# Baseline Performance Test - 50k pps
#
# Wrapper script that invokes the unified baseline_test.sh with 50k pps settings.
# For detailed documentation, see baseline_test.sh --help
#
# Usage: sudo ./baseline_50k.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$SCRIPT_DIR/baseline_test.sh" --rate 50000 --packets 100000 "$@"
