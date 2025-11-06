#!/bin/bash

# This script automates the testing of the io_uring AF_PACKET proof-of-concept.
# It requires sudo privileges to create and manage network namespaces and interfaces.

set -e

echo "--- Building the Proof-of-Concept Binary ---"
# Build the binary within its own crate
cargo build

# The path to the built binary
POC_BINARY="./target/debug/poc_io_uring_af_packet"

# Use bash -c to run the rest of the script with elevated privileges,
# so the user only has to enter their password once.
sudo bash -c "'
set -e

# --- Setup ---
echo "Creating network namespace poc-ns..."
ip netns add poc-ns

echo "Creating veth pair veth-host <--> veth-ns..."
ip link add veth-host type veth peer name veth-ns
ip link set veth-ns netns poc-ns

echo "Configuring interfaces..."
ip link set veth-host up
ip addr add 192.168.200.1/24 dev veth-host
ip netns exec poc-ns ip link set lo up
ip netns exec poc-ns ip link set veth-ns up
ip netns exec poc-ns ip addr add 192.168.200.2/24 dev veth-ns

# --- Execution ---
echo "Running PoC in background inside namespace, logging to /tmp/poc_output.log..."
ip netns exec poc-ns $POC_BINARY veth-ns > /tmp/poc_output.log &
POC_PID=\$!
sleep 1

echo "Generating traffic from host to namespace..."
ping -c 3 192.168.200.2

# --- Teardown & Verification ---
echo "Terminating PoC process..."
kill \$POC_PID
wait \$POC_PID || true

echo ""
echo "--- Captured PoC Output ---"
cat /tmp/poc_output.log
echo "---------------------------"
echo ""

# --- Final Cleanup ---
echo "Cleaning up network namespace and log file..."
ip netns del poc-ns
rm /tmp/poc_output.log

echo "Test complete."
'"
