#!/bin/bash
# Build all binaries in release mode
# Run this once before testing

set -e

echo "=== Building all binaries in release mode ==="
cargo build --release --bins

echo ""
echo "=== Build complete ==="
echo ""
echo "Binaries built:"
ls -lh target/release/multicast_relay
ls -lh target/release/control_client
ls -lh target/release/traffic_generator
echo ""
echo "MD5 checksums:"
md5sum target/release/multicast_relay
md5sum target/release/control_client
md5sum target/release/traffic_generator
echo ""
echo "✓ All binaries ready in: target/release/"
echo ""
echo "Run tests with:"
echo "  cargo test --release -- --ignored --test-threads=1"
echo "  sudo tests/data_plane_pipeline_veth.sh"
