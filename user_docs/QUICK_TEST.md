# Quick Performance Test

## Run a Performance Test

```bash
# Setup kernel tuning (once per boot)
sudo ./scripts/setup_kernel_tuning.sh

# Run the veth pipeline test
sudo ./tests/data_plane_pipeline_veth.sh
```

## Expected Results

**Healthy system:**

- Egress throughput: 400k+ pps
- Buffer exhaustion: 0%
- No errors

## Interpreting Output

Look for these lines in the output:

```text
[STATS:Ingress FINAL] total: recv=X matched=X egr_sent=X ... buf_exhaust=X
[STATS:Egress FINAL] total: sent=X submitted=X ch_recv=X errors=X bytes=X
```

Key metrics:

- `recv` - packets received
- `matched` - packets matching rules
- `sent` - packets successfully forwarded
- `buf_exhaust` - should be 0 (indicates backpressure)
- `errors` - should be 0

## Troubleshooting

### Binary not found

```bash
cargo build --release
```

### Permission denied

```bash
sudo ./tests/data_plane_pipeline_veth.sh
```

### Cannot set SO_SNDBUF

```bash
sudo ./scripts/setup_kernel_tuning.sh
```

### Low performance

Try increasing socket buffer:

```bash
MCR_SOCKET_SNDBUF=8388608 sudo ./tests/data_plane_pipeline_veth.sh
```
