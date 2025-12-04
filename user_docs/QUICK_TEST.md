# Quick Performance Test Guide

## TL;DR - Test the Fixes Now

```bash
# 1. Setup kernel (one-time per boot)
./scripts/setup_kernel_tuning.sh

# 2. Run performance test
sudo tests/data_plane_pipeline_veth.sh 2>&1 | tee results.txt

# 3. Check results
grep "Actual packet rate" results.txt
grep "STATS:Ingress FINAL" results.txt
grep "STATS:Egress FINAL" results.txt
```

---

## What Changed

**Applied 2 critical fixes:**

1. ✅ **io_uring queue depth:** 128 → 1024 (supports 300k+ pps)
2. ✅ **UDP socket buffer:** default (~208 KB) → 4 MB (prevents blocking)

**Expected performance:**

- Egress throughput: 439k pps (validated)
- Buffer exhaustion: 0% (perfect backpressure)
- Packet loss: 0% (under tested conditions)

---

## Interpreting Results

### Look for these metrics in the output

**Traffic Generator:**

```text
Actual packet rate: ~808k pps (achieved)
```

- Sends 10M packets at high rate
- Actual throughput: ~9 Gbps

**MCR-1 Stats:**

```text
[STATS:Ingress FINAL] total: recv=X matched=X egr_sent=X ... buf_exhaust=X
[STATS:Egress FINAL] total: sent=X submitted=X ch_recv=X errors=X bytes=X
```

**Calculate rates:**

```bash
# Get test duration from output
DURATION=$(grep "Elapsed time" results.txt | cut -d: -f2 | cut -d's' -f1)

# Get packet counts
INGRESS=$(grep "STATS:Ingress FINAL" results.txt | grep -oP 'recv=\K[0-9]+')
EGRESS=$(grep "STATS:Egress FINAL" results.txt | grep -oP 'sent=\K[0-9]+')
BUF_EXHAUST=$(grep "STATS:Ingress FINAL" results.txt | grep -oP 'buf_exhaust=\K[0-9]+')

# Calculate rates
echo "Ingress rate: $(($INGRESS / $DURATION)) pps"
echo "Egress rate: $(($EGRESS / $DURATION)) pps"
echo "Buffer exhaustion: $((100 * $BUF_EXHAUST / $INGRESS))%"
```

### Success Criteria

✅ **EXCELLENT (Production Ready):**

- Egress ≥ 400k pps
- Buffer exhaustion = 0%
- No errors

✅ **GOOD:**

- Egress 300-399k pps
- Buffer exhaustion < 10%
- No errors

⚠️ **NEEDS TUNING:**

- Egress < 300k pps
- Buffer exhaustion > 10%
- Check kernel tuning and configuration

---

## Quick Comparison

### Historical (Before Optimization)

```text
Ingress:  689k pps  ✅
Egress:   97k pps   ❌ (Bottlenecked)
Buf Ex:   86%       ❌
```

### Current (Validated Performance)

```text
Ingress:  439k pps  ✅
Egress:   439k pps  ✅ (143% of original target)
Buf Ex:   0%        ✅ (Perfect)
```

See `developer_docs/PERFORMANCE_VALIDATION_REPORT.md` for detailed validation.

---

## Troubleshooting

### "Binary not found"

```bash
cargo build --release --bins
```

### "Permission denied" on test

```bash
# Must run with sudo
sudo tests/data_plane_pipeline_veth.sh
```

### "Cannot set SO_SNDBUF"

```bash
# Kernel limit too low
./scripts/setup_kernel_tuning.sh
```

### Test still shows low performance

Try increasing socket buffer:

```bash
# Try 8 MB
MCR_SOCKET_SNDBUF=8388608 sudo tests/data_plane_pipeline_veth.sh
```

---

## Files Changed

- `src/worker/unified_loop.rs` - Queue depth 1024, socket buffer 4MB
- `scripts/setup_kernel_tuning.sh` - Kernel config helper (NEW)
- Binary rebuilt: `target/release/mcrd`

---

## More Details

- **Performance Fix Summary:** [`PERFORMANCE_REGRESSION_FIX_SUMMARY_Nov2025.md`](../developer_docs/reports/PERFORMANCE_REGRESSION_FIX_SUMMARY_Nov2025.md)
- **Testing:** [`PRACTICAL_TESTING_GUIDE.md`](../developer_docs/testing/PRACTICAL_TESTING_GUIDE.md)
