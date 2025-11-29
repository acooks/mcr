#!/bin/bash
#
# Baseline Performance Test - 100k pps
#
# Wrapper script that invokes the unified baseline_test.sh with 100k pps settings.
# For detailed documentation, see baseline_test.sh --help
#
# Usage: sudo ./baseline_100k.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$SCRIPT_DIR/baseline_test.sh" --rate 100000 --packets 100000 "$@"
