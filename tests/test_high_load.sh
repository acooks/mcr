#!/bin/bash

# Exit on error
set -e

# Build the project
cargo build --release

# Start the relay in the background
./target/release/mcrd &
RELAY_PID=$!
echo "Relay started with PID $RELAY_PID"

# Wait for the relay to start
sleep 2

# Add 50 forwarding rules
for i in {1..50}; do
    INPUT_GROUP="224.0.1.$i"
    OUTPUT_GROUP="224.0.2.$i"
    INTERFACE="127.0.0.1" # Assuming loopback for testing
    ./target/release/mcrctl add --input-group $INPUT_GROUP --input-port 5000 --outputs "$OUTPUT_GROUP:5000:$INTERFACE"
done

echo "Added 50 forwarding rules."

# Start 50 traffic generators
PIDS=()
for i in {1..50}; do
    INPUT_GROUP="224.0.1.$i"
    INTERFACE="127.0.0.1"
    ./target/release/mcrgen --group $INPUT_GROUP --port 5000 --interface $INTERFACE --rate 100000 &
    PIDS+=($!)
done

echo "Started 50 traffic generators."

# Run for 30 seconds
echo "Running test for 30 seconds..."
sleep 30

# Clean up
echo "Cleaning up..."
kill $RELAY_PID
for PID in "${PIDS[@]}"; do
    kill $PID
done

echo "Test finished."
