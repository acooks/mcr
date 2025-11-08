#!/usr/bin/env bash
# Unsafe Code Usage Checker
# Tracks and limits unsafe code usage in the codebase

set -euo pipefail

# Configuration
MAX_UNSAFE_BLOCKS=20        # Maximum allowed unsafe blocks in src/
MAX_UNSAFE_PERCENTAGE=0.5   # Maximum percentage of codebase with unsafe
BASELINE_FILE=".unsafe_baseline"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔒 Checking unsafe code usage...${NC}"

# Count unsafe blocks in src/
UNSAFE_BLOCKS=$(grep -r "unsafe {" src/ --include="*.rs" 2>/dev/null | wc -l || echo "0")
UNSAFE_LINES=$(grep -r "unsafe" src/ --include="*.rs" 2>/dev/null | wc -l || echo "0")
TOTAL_LINES=$(find src -name "*.rs" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "1")

# Calculate percentage
UNSAFE_PERCENTAGE=$(echo "scale=4; ($UNSAFE_LINES / $TOTAL_LINES) * 100" | bc)

# Display current statistics
echo -e "\n${BLUE}Current Unsafe Usage:${NC}"
echo "  Unsafe blocks:     $UNSAFE_BLOCKS"
echo "  Unsafe lines:      $UNSAFE_LINES"
echo "  Total lines:       $TOTAL_LINES"
echo "  Unsafe percentage: ${UNSAFE_PERCENTAGE}%"

# Check against limits
FAIL=0

if [ "$UNSAFE_BLOCKS" -gt "$MAX_UNSAFE_BLOCKS" ]; then
    echo -e "\n${RED}❌ FAIL: Too many unsafe blocks!${NC}"
    echo "  Found: $UNSAFE_BLOCKS, Maximum allowed: $MAX_UNSAFE_BLOCKS"
    FAIL=1
fi

# Check percentage (convert to integer comparison by multiplying by 10000)
UNSAFE_PCT_INT=$(echo "$UNSAFE_PERCENTAGE * 10000" | bc | cut -d. -f1)
MAX_PCT_INT=$(echo "$MAX_UNSAFE_PERCENTAGE * 10000" | bc | cut -d. -f1)

if [ "$UNSAFE_PCT_INT" -gt "$MAX_PCT_INT" 2>/dev/null ]; then
    echo -e "\n${RED}❌ FAIL: Unsafe code percentage too high!${NC}"
    echo "  Found: ${UNSAFE_PERCENTAGE}%, Maximum allowed: ${MAX_UNSAFE_PERCENTAGE}%"
    FAIL=1
fi

# Check for unsafe functions without safety documentation
echo -e "\n${BLUE}Checking for undocumented unsafe functions...${NC}"
UNDOCUMENTED=$(grep -B 3 "pub unsafe fn\|pub(crate) unsafe fn\|unsafe fn" src/ -r --include="*.rs" | \
    grep -v "# Safety" | \
    grep "unsafe fn" || true)

if [ -n "$UNDOCUMENTED" ]; then
    echo -e "${YELLOW}⚠️  WARNING: Found unsafe functions without '# Safety' documentation:${NC}"
    echo "$UNDOCUMENTED" | grep "unsafe fn"
    echo -e "\n${YELLOW}Consider adding safety documentation to these functions.${NC}"
fi

# Update baseline if it doesn't exist
if [ ! -f "$BASELINE_FILE" ]; then
    echo "$UNSAFE_BLOCKS" > "$BASELINE_FILE"
    echo -e "\n${GREEN}📊 Created baseline: $UNSAFE_BLOCKS unsafe blocks${NC}"
else
    BASELINE=$(cat "$BASELINE_FILE")
    if [ "$UNSAFE_BLOCKS" -gt "$BASELINE" ]; then
        INCREASE=$((UNSAFE_BLOCKS - BASELINE))
        echo -e "\n${YELLOW}⚠️  WARNING: Unsafe code increased by $INCREASE blocks (was $BASELINE, now $UNSAFE_BLOCKS)${NC}"
        echo "  If this increase is justified, update baseline with:"
        echo "  echo $UNSAFE_BLOCKS > $BASELINE_FILE"
    elif [ "$UNSAFE_BLOCKS" -lt "$BASELINE" ]; then
        DECREASE=$((BASELINE - UNSAFE_BLOCKS))
        echo -e "\n${GREEN}✅ Unsafe code decreased by $DECREASE blocks (was $BASELINE, now $UNSAFE_BLOCKS)${NC}"
        echo "  Update baseline with:"
        echo "  echo $UNSAFE_BLOCKS > $BASELINE_FILE"
    else
        echo -e "\n${GREEN}✅ Unsafe usage unchanged from baseline ($BASELINE blocks)${NC}"
    fi
fi

# Check for specific unsafe patterns that should be avoided
echo -e "\n${BLUE}Checking for dangerous unsafe patterns...${NC}"

# Check for transmute
TRANSMUTE_COUNT=$(grep -r "transmute" src/ --include="*.rs" 2>/dev/null | wc -l || echo "0")
if [ "$TRANSMUTE_COUNT" -gt "0" ]; then
    echo -e "${YELLOW}⚠️  Found $TRANSMUTE_COUNT use(s) of std::mem::transmute${NC}"
    grep -n "transmute" src/ --include="*.rs" 2>/dev/null || true
fi

# Check for raw pointer dereference
RAW_DEREF_COUNT=$(grep -r "\*const\|\*mut" src/ --include="*.rs" | grep -v "// " | grep -v "//" | wc -l || echo "0")
if [ "$RAW_DEREF_COUNT" -gt "5" ]; then
    echo -e "${YELLOW}⚠️  Found $RAW_DEREF_COUNT raw pointer type declarations${NC}"
fi

# Summary
echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [ "$FAIL" -eq "0" ]; then
    echo -e "${GREEN}✅ Unsafe code check PASSED${NC}"
    echo -e "${GREEN}   All unsafe usage is within acceptable limits${NC}"
    exit 0
else
    echo -e "${RED}❌ Unsafe code check FAILED${NC}"
    echo -e "${RED}   Review and reduce unsafe code usage${NC}"
    exit 1
fi
