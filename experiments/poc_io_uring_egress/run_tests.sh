#!/bin/bash
#
# Run io_uring Egress Tests and Benchmarks
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}=== io_uring Egress Test Suite ===${NC}"
echo ""

# Step 1: Build
echo -e "${YELLOW}[Step 1]${NC} Building in release mode..."
cargo build --release
echo -e "${GREEN}✓${NC} Build complete"
echo ""

# Step 2: Run unit tests
echo -e "${YELLOW}[Step 2]${NC} Running unit tests..."
cargo test --release
echo -e "${GREEN}✓${NC} Unit tests passed"
echo ""

# Step 3: Run functional test
echo -e "${YELLOW}[Step 3]${NC} Running functional tests..."
cargo run --release --bin functional_test
echo -e "${GREEN}✓${NC} Functional tests complete"
echo ""

# Step 4: Run Criterion benchmarks
echo -e "${YELLOW}[Step 4]${NC} Running Criterion benchmarks..."
echo "This will take several minutes..."
echo ""
cargo bench
echo ""
echo -e "${GREEN}✓${NC} Benchmarks complete"
echo ""

echo -e "${BLUE}=== Test Summary ===${NC}"
echo ""
echo "Results saved to:"
echo "  - Criterion HTML reports: ${SCRIPT_DIR}/target/criterion/"
echo ""
echo "To view Criterion HTML reports:"
echo "  firefox target/criterion/report/index.html"
echo ""
echo -e "${GREEN}✓ All tests complete!${NC}"
