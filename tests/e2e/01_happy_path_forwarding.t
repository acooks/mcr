#!/bin/bash

# End-to-End Test: Happy Path Forwarding
#
# Verifies that the multicast_relay can successfully receive, forward,
# and retransmit a multicast stream according to a dynamically configured rule.

set -e
set -o pipefail

# Source common functions
E2E_DIR="$(dirname "$0")"
. "$E2E_DIR/common.sh"

# --- Test Specific Configuration ---
INPUT_GROUP="224.10.10.1"
INPUT_PORT="5001"
OUTPUT_GROUP="225.10.10.1"
OUTPUT_PORT="6001"
PACKET_COUNT=10
PACKET_PAYLOAD="E2E-TEST-PACKET"

# --- Main Test Logic ---

# Ensure cleanup runs on script exit
trap cleanup EXIT

setup_namespace
start_listener "$OUTPUT_GROUP" "$OUTPUT_PORT"
start_relay

add_rule \
    "e2e-data-test-01" \
    "$VETH_NS" \
    "$INPUT_GROUP" \
    "$INPUT_PORT" \
    "$OUTPUT_GROUP" \
    "$OUTPUT_PORT" \
    "$VETH_NS"

send_packets \
    "$INPUT_GROUP" \
    "$INPUT_PORT" \
    "$PACKET_COUNT" \
    "$PACKET_PAYLOAD"

assert_packet_count "$PACKET_COUNT"

cleanup # Explicit cleanup for clarity, though trap also handles it
