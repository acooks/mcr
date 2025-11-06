#!/bin/bash

# This script runs all the checks that are performed in the CI pipeline.
# It is intended to be run from the root of the multicast_relay submodule.
# The script will exit immediately if any command fails.
set -e

echo "--- Running Formatting Check (cargo fmt) ---"
cargo fmt --all -- --check

echo "\n--- Running Linter (cargo clippy) ---"
cargo clippy --all-targets -- -D warnings

echo "\n--- Running Tests (cargo test) ---"
cargo test --all-targets

echo "\n--- Running Coverage Check (cargo tarpaulin) ---"
# We set a low threshold for now, this can be increased later.
cargo tarpaulin --ignore-tests --workspace --skip-clean --fail-under 8.6

echo "\n✅ All checks passed!"

