#!/bin/bash
#
# Run Buffer Pool Performance Benchmarks
#
# This script runs the complete benchmark suite and optional perf analysis
# for the buffer pool performance experiment.

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}=== Buffer Pool Performance Benchmark Suite ===${NC}"
echo ""

# Step 1: Build
echo -e "${YELLOW}[Step 1]${NC} Building in release mode..."
cargo build --release
echo -e "${GREEN}✓${NC} Build complete"
echo ""

# Step 2: Run unit tests
echo -e "${YELLOW}[Step 2]${NC} Running unit tests..."
cargo test --release
echo -e "${GREEN}✓${NC} Tests passed"
echo ""

# Step 3: Run exhaustion tests
echo -e "${YELLOW}[Step 3]${NC} Running exhaustion behavior tests..."
cargo test --release --lib exhaustion_test -- --nocapture
echo -e "${GREEN}✓${NC} Exhaustion tests complete"
echo ""

# Step 4: Run Criterion benchmarks
echo -e "${YELLOW}[Step 4]${NC} Running Criterion benchmarks..."
echo "This will take several minutes..."
echo ""
cargo bench
echo ""
echo -e "${GREEN}✓${NC} Benchmarks complete"
echo ""

# Step 5: Optional perf analysis
if command -v perf &> /dev/null; then
    echo -e "${YELLOW}[Step 5]${NC} Running perf analysis (optional)..."
    echo "Would you like to run perf stat analysis? (requires sudo)"
    echo "This measures cache behavior and CPU performance counters."
    read -p "Run perf analysis? [y/N]: " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "Building test binary for perf analysis..."
        cargo build --release --bin perf_test 2>/dev/null || {
            echo "Note: perf_test binary not found, creating simple test..."
            cat > src/bin/perf_test.rs << 'EOF'
use poc_buffer_pool_performance::BufferPool;

fn main() {
    let mut pool = BufferPool::new(false);

    // Allocate/deallocate in a tight loop for perf measurement
    for _ in 0..10_000_000 {
        let buffer = pool.allocate(1000).unwrap();
        pool.deallocate(buffer);
    }
}
EOF
            cargo build --release --bin perf_test
        }

        echo ""
        echo "Running perf stat (10M allocations)..."
        echo ""
        sudo perf stat -e cycles,instructions,cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses \
            ./target/release/perf_test 2>&1 | tee perf_results.txt

        echo ""
        echo -e "${GREEN}✓${NC} Perf analysis complete (saved to perf_results.txt)"
    else
        echo "Skipping perf analysis"
    fi
else
    echo -e "${YELLOW}[Step 5]${NC} Skipping perf analysis (perf not installed)"
fi

echo ""
echo -e "${BLUE}=== Benchmark Summary ===${NC}"
echo ""
echo "Results saved to:"
echo "  - Criterion HTML reports: ${SCRIPT_DIR}/target/criterion/"
echo "  - Exhaustion test output: (see above)"
if [ -f "perf_results.txt" ]; then
    echo "  - Perf analysis: ${SCRIPT_DIR}/perf_results.txt"
fi
echo ""
echo "To view Criterion HTML reports:"
echo "  firefox target/criterion/report/index.html"
echo ""
echo -e "${GREEN}✓ All benchmarks complete!${NC}"
