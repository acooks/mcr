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
ls -lh target/release/mcrd
ls -lh target/release/mcrctl
ls -lh target/release/mcrgen
echo ""
echo "MD5 checksums:"
md5sum target/release/mcrd
md5sum target/release/mcrctl
md5sum target/release/mcrgen
echo ""
echo "✓ All binaries ready in: target/release/"
echo ""
echo "Run tests with:"
echo "  cargo test --release -- --ignored --test-threads=1"
echo "  sudo tests/data_plane_pipeline_veth.sh"
