# /dev/null Egress Sink Proposal

**Date**: 2025-11-16
**Status**: Proposal
**Priority**: Medium (Performance Testing Enhancement)

## Motivation

During test framework validation, we identified that `test_scale_1m_packets` shows:

```text
Ingress: recv=1000018 matched=1000000 egr_sent=1000000 ✅
Egress: sent=0 ch_recv=0 ❌
```

A `/dev/null` egress sink would help:
1. **Isolate ingress performance** - Measure pure ingress throughput without network I/O overhead
2. **Debug egress issues** - Validate that ingress→egress channel is working
3. **Simplify tests** - No need for receiver setup in some performance tests
4. **Benchmark limits** - Find maximum packet processing rate without network bottlenecks

## Use Cases

### 1. Ingress-Only Performance Testing

Measure pure packet reception and matching performance:

```rust
#[tokio::test]
async fn test_ingress_max_throughput() {
    let mcr = start_mcr().await?;

    // Configure with /dev/null sink
    mcr.add_rule(Rule {
        input: "239.1.1.1:5000@eth0",
        output: "devnull",  // No actual egress
    }).await?;

    send_packets(10_000_000, rate_unlimited).await?;

    let stats = mcr.get_stats().await?;
    assert!(stats.ingress.matched == 10_000_000);
    // Egress sent=0 is expected behavior
}
```

### 2. Channel Communication Debugging

Verify ingress→egress channel works before testing network egress:

```rust
#[tokio::test]
async fn test_ingress_egress_channel() {
    let mcr = start_mcr_with_devnull_sink().await?;

    send_packets(1000).await?;

    let stats = mcr.get_stats().await?;
    assert_eq!(stats.ingress.egr_sent, 1000, "Ingress sent to channel");
    assert_eq!(stats.egress.ch_recv, 1000, "Egress received from channel");
    assert_eq!(stats.egress.sent, 1000, "Egress 'sent' to /dev/null");
}
```

This would have helped diagnose the current test failure where `ch_recv=0`.

### 3. Multi-Stream Scaling Tests

Test scaling without network I/O becoming the bottleneck:

```bash
# Test 100 concurrent streams without network overhead
for stream in {1..100}; do
    control_client add --input "239.1.1.$stream:5000@eth0" --output "devnull"
done

send_traffic_to_all_streams
# Measure pure MCR processing capability
```

### 4. CPU Profiling

Profile CPU usage of packet processing without I/O noise:

```bash
perf record -g ./multicast_relay --output devnull ...
# Clean CPU profile of packet matching logic
```

## Implementation Options

### Option 1: Special Output Syntax

```bash
control_client add \
  --input-interface eth0 \
  --input-group 239.1.1.1 \
  --input-port 5000 \
  --output "devnull"  # Special keyword
```

**Pros**:
- Simple to implement
- Clear intent in configuration
- No network resources needed

**Cons**:
- Special case in output parsing
- Not a "real" multicast group

### Option 2: Dummy Network Sink

```bash
control_client add \
  --input-interface eth0 \
  --input-group 239.1.1.1 \
  --input-port 5000 \
  --output "0.0.0.0:0:null"  # Special address
```

**Pros**:
- Fits existing syntax
- Exercises full egress path
- Tests egress socket creation/sending

**Cons**:
- Still creates UDP socket
- OS might reject 0.0.0.0:0
- Less clear intent

### Option 3: Egress Flag

```bash
control_client add \
  --input-interface eth0 \
  --input-group 239.1.1.1 \
  --input-port 5000 \
  --output "239.2.2.2:6000:eth1" \
  --discard  # Flag to discard instead of send
```

**Pros**:
- Exercises full pipeline
- Can still configure "output" for testing
- Clear opt-in behavior

**Cons**:
- More complex CLI
- Still processes full egress path

## Recommended Approach

### Option 1: Special "devnull" output keyword

This provides the clearest benefit for the use cases:

### Code Changes Required

**1. Output Parsing** (`src/cli/mod.rs` or similar):

```rust
pub enum OutputDestination {
    Multicast {
        group: IpAddr,
        port: u16,
        interface: String,
    },
    DevNull,  // New variant
}

impl FromStr for OutputDestination {
    fn from_str(s: &str) -> Result<Self> {
        if s.eq_ignore_ascii_case("devnull") || s.eq_ignore_ascii_case("/dev/null") {
            return Ok(OutputDestination::DevNull);
        }

        // Parse normal multicast output format
        // ...
    }
}
```

**2. Egress Worker** (`src/worker/egress.rs`):

```rust
match output_dest {
    OutputDestination::Multicast { group, port, interface } => {
        // Existing egress logic
        send_packet_to_network(&packet, group, port, interface)?;
    }
    OutputDestination::DevNull => {
        // Just increment stats, discard packet
        stats.sent += 1;
        stats.bytes += packet.len();
        // Packet is dropped here
    }
}
```

**3. Stats Reporting**:
Add clarity to stats when using devnull:

```text
Egress: sent=1000000 (to devnull) ch_recv=1000000 errors=0
```

## Testing Strategy

### Validate the /dev/null Sink Works

```rust
#[tokio::test]
async fn test_devnull_sink_basic() {
    let mcr = start_mcr().await?;
    mcr.add_rule("239.1.1.1:5000@eth0", "devnull").await?;

    send_packets(1000).await?;

    let stats = mcr.get_stats().await?;
    assert_eq!(stats.ingress.matched, 1000);
    assert_eq!(stats.egress.ch_recv, 1000);
    assert_eq!(stats.egress.sent, 1000);
    // No actual network packets sent
}
```

### Use in Existing Failing Test

Apply to `test_scale_1m_packets` to isolate the issue:

```rust
#[tokio::test]
#[ignore]
async fn test_scale_1m_packets_devnull() {
    // Same setup as original test
    // But use "devnull" output instead of network

    // This will reveal if the issue is:
    // - Ingress→Egress channel (if ch_recv still 0)
    // - Network egress only (if ch_recv = 1M)
}
```

## Performance Benefits

Expected improvements from avoiding network I/O:

| Metric | With Network | With /dev/null | Improvement |
|--------|-------------|----------------|-------------|
| Max PPS (single stream) | ~150k | ~500k+ | 3-4x |
| CPU per packet | ~6µs | ~2µs | 3x |
| Jitter | Variable | Minimal | Stable |
| Multi-stream scaling | Limited by NIC | Limited by CPU | Clear |

These are rough estimates - actual measurements needed.

## Related Issues

This would help debug:
1. **Current test failure**: `test_scale_1m_packets` showing `ch_recv=0`
2. **Multi-stream scaling**: Tests in `tests/performance/multi_stream_scaling.sh`
3. **Worker performance**: Isolate worker overhead from network overhead

## Alternative: Drop Rules (Future)

A more general solution could be "rule actions":

```bash
--action forward  # Default, send to egress
--action drop     # Count but discard
--action sample   # Forward 1 in N packets
```

But `/dev/null` sink is simpler and solves immediate testing needs.

## Next Steps

1. **Implement** `devnull` output keyword in CLI parsing
2. **Add** egress worker logic for devnull destination
3. **Create test** validating devnull sink behavior
4. **Apply** to `test_scale_1m_packets` to isolate current issue
5. **Document** in TESTING.md as debugging technique

## Open Questions

1. Should devnull still join IGMP group on input interface?
   - **Recommendation**: Yes - ingress should behave normally

2. Should devnull create egress socket?
   - **Recommendation**: No - defeats the purpose

3. Should we support mixing devnull and real outputs?
   - **Recommendation**: Not initially - keep it simple

4. What if someone actually has a network interface named "devnull"?
   - **Recommendation**: Require exact match on "devnull" keyword, case-insensitive

## References

- Test failure: `docs/testing/test_framework_validation_results.md`
- Egress implementation: `src/worker/egress.rs`
- CLI parsing: (need to locate exact file)
- Similar feature in other tools:
  - `iperf -d /dev/null` - discard mode
  - `tcpdump -w /dev/null` - count without saving
  - `dd if=... of=/dev/null` - measure read speed
