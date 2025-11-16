# Test Framework Validation Results

**Date**: 2025-11-16
**Status**: ✅ Framework Working, ⚠️ Tests Failing (Bit-Rot Confirmed)

## Executive Summary

The network namespace test framework has been successfully implemented and validated. The framework correctly:
- Builds test binaries as a regular user
- Finds and executes privileged tests with sudo
- Runs tests in isolated network namespaces
- Provides clear output and failure reporting

**Critical Finding**: All 8 ignored integration tests are failing, confirming the bit-rot issue. The tests haven't run regularly, and code changes have broken them.

## Test Framework Implementation

### New justfile Targets

```bash
# Build test binaries (run as user)
just build-test

# Run unit tests only (no root required)
just test-unit

# Run lightweight integration tests (no root required)
just test-integration-light

# Run privileged integration tests (requires sudo)
just test-integration-privileged

# Run all tests in sequence
just test-all

# Quick tests only (unit + light integration)
just test-quick
```

### Framework Workflow

**Phase 1: Build** (as regular user)
```bash
just build-test
```
- Compiles test binaries with `cargo test --no-run`
- Compiles release binaries with `cargo build --release`
- No privilege escalation during compilation

**Phase 2: Execute** (with sudo)
```bash
just test-integration-privileged
```
- Finds pre-built test binary: `target/debug/deps/integration-*`
- Runs with sudo: `sudo -E "$TEST_BINARY" --ignored --test-threads=1 --nocapture`
- Tests create their own network namespaces via `NetworkNamespace::enter()`

## Validation Results

### Framework Status: ✅ Working Correctly

**Test Execution**: Successfully ran all 8 ignored tests
- Test discovery: ✅ Found test binary `integration-ecf9645beee77a53`
- Privilege escalation: ✅ sudo -E working correctly
- Namespace isolation: ✅ Tests running in isolated namespaces
- Test reporting: ✅ Clear output with pass/fail status
- Duration: 180.74 seconds total

### Test Results: ⚠️ All 8 Tests Failing

**Failure Summary**:
```
test result: FAILED. 0 passed; 8 failed; 0 ignored; 0 measured; 12 filtered out
```

**Failed Tests**:
1. `test_basic::test_minimal_10_packets` - Zero packets received
2. `test_basic::test_single_hop_1000_packets` - Zero packets matched
3. `test_scaling::test_scale_1000_packets` - Zero packets forwarded
4. `test_scaling::test_scale_10000_packets` - Zero packets forwarded
5. `test_scaling::test_scale_1m_packets` - Ingress working (1M matched), egress broken (0 sent)
6. `test_topologies::test_baseline_2hop_100k_packets` - Both MCR instances: zero packets
7. `test_topologies::test_chain_3hop` - All 3 MCR instances: zero packets
8. `test_topologies::test_tree_fanout_1_to_3` - CLI parsing error for multi-output rules

## Failure Analysis

### Common Pattern: Zero Packets Received/Forwarded

**7 out of 8 tests** show the same pattern:
```
Ingress: recv=0 matched=0 egr_sent=0 filtered=0 no_match=0 buf_exhaust=0
Egress: sent=0 submitted=0 ch_recv=0 errors=0 bytes=0
```

**Likely Root Causes**:
1. **Ingress socket not receiving**: Multicast packets not reaching the socket
2. **Network setup issues**: Routing, IGMP, or interface configuration
3. **Process startup timing**: MCR not ready when packets sent
4. **Namespace isolation**: Network connectivity issues in test namespaces

### test_scale_1m_packets: Partial Success

This test shows interesting behavior:
```
Ingress: recv=1000018 matched=1000000 egr_sent=1000000 filtered=18 no_match=0 buf_exhaust=0
Egress: sent=0 submitted=0 ch_recv=0 errors=0 bytes=0
```

**Analysis**:
- ✅ Ingress working: Received and matched 1M packets
- ✅ Ingress→Egress channel: Sent 1M packets to egress
- ❌ Egress broken: `ch_recv=0` - egress never received from channel
- ❌ No packets sent: `sent=0` - egress didn't transmit

**This points to an egress channel or worker lifecycle issue.**

### test_tree_fanout_1_to_3: CLI Parsing Error

```
Error: Failed to add rule: error: invalid value
'239.2.2.2:5002:veth1a,239.3.3.3:5003:veth2a,239.4.4.4:5004:veth3a'
for '--outputs <OUTPUTS>': Invalid format. Expected group:port:interface[:dtls]
```

**Analysis**:
- Test attempts to add multiple outputs with comma-separated format
- CLI parser expects different format or doesn't support multiple outputs
- Test may be using outdated API format

## File References

**Test Failures Locations**:
- `tests/integration/test_basic.rs:201` - test_minimal_10_packets panic
- `tests/integration/test_basic.rs:114` - test_single_hop_1000_packets panic
- `tests/integration/test_scaling.rs:95` - test_scale_1000_packets panic
- `tests/integration/test_scaling.rs:170` - test_scale_10000_packets panic
- `tests/integration/test_scaling.rs:275` - test_scale_1m_packets panic
- `tests/integration/test_topologies.rs:153` - test_baseline_2hop_100k_packets panic
- `tests/integration/test_topologies.rs:309` - test_chain_3hop panic

**Framework Implementation**:
- `justfile:122-167` - New test framework targets
- `scripts/run-tests-in-netns.sh` - Network namespace wrapper (not needed for Rust tests)

## Next Steps

### Immediate Actions

1. **Debug test_scale_1m_packets first** (has most diagnostic info)
   - Investigate why egress `ch_recv=0` despite ingress `egr_sent=1000000`
   - Check worker process lifecycle and channel setup
   - Review egress worker initialization

2. **Debug ingress packet reception**
   - Check why `recv=0` in most tests
   - Verify multicast socket binding and IGMP membership
   - Validate network namespace routing and interface setup
   - Add debug logging to understand packet flow

3. **Fix CLI parsing for multi-output rules**
   - Review `--outputs` parameter format
   - Update test or fix CLI parser for comma-separated outputs

### Testing Recommendations

**Run with backtraces for better diagnostics**:
```bash
RUST_BACKTRACE=1 just test-integration-privileged
```

**Test individual failing tests**:
```bash
just build-test
sudo -E target/debug/deps/integration-* --ignored --test test_scale_1m_packets --nocapture
```

**Check MCR logs from failed tests**:
```bash
cat /tmp/test_mcr_*.log
```

## Conclusion

### Framework Success ✅

The test framework is working exactly as designed:
- Clean separation between build (user) and test (root) phases
- Correct test binary discovery and execution
- Network namespace isolation working via `NetworkNamespace::enter()`
- Clear reporting of failures

**The framework has successfully achieved its goal: preventing test bit-rot by making privileged tests runnable.**

### Bit-Rot Confirmed ⚠️

All 8 ignored tests are failing, validating the original hypothesis:
> "the actual problem is that the tests have bit-rotted, because they never run,
> because they require root and because we don't have a good, repeatable test-running framework"

The framework now exists. Next phase: fix the tests.

### Path Forward

1. Use this framework regularly: `just test-all`
2. Fix tests one by one, starting with test_scale_1m_packets (most diagnostic info)
3. Once tests pass, add to CI/CD pipeline
4. Make `just check` or `just test-all` part of pre-commit workflow

The investment in the test framework will pay off as tests get fixed and stay fixed.
