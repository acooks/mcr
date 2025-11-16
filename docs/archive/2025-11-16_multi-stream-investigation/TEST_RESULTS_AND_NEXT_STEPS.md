# Test Results - Multi-Stream and Multi-Worker Fix

**Date**: 2025-11-16
**Status**: ⚠️ **BUGS PERSIST - FIX NOT WORKING**

---

## Test Results Summary

### Multi-Stream Test Results ❌

**Test Command**: `sudo ./tests/performance/multi_stream_scaling.sh 5`

**Results**:

| Streams | MCR Expected | MCR Received | MCR Loss % | socat Expected | socat Received | socat Loss % |
|---------|--------------|--------------|------------|----------------|----------------|--------------|
| 1       | 5,000        | 5,000        | 0.00%      | 5,000          | 5,000          | 0.00%        |
| 2       | 10,000       | **0**        | **100.00%**| 10,000         | 10,000         | 0.00%        |
| 5       | 25,000       | **0**        | **100.00%**| 25,000         | 25,000         | 0.00%        |

**Conclusion**: ❌ **The multi-stream bug persists exactly as before the fix**

---

## Analysis

### What We Implemented

1. ✅ Changed helper_sockets data structure from `HashMap<(String, Ipv4Addr), Socket>` to `HashMap<String, Socket>`
2. ✅ Added `joined_groups` tracking
3. ✅ Created `create_bound_udp_socket()`, `join_multicast_group()`, `leave_multicast_group()` functions
4. ✅ Refactored `add_rule()` to use shared helper socket
5. ✅ Added PACKET_FANOUT support
6. ✅ Production-ready error handling
7. ✅ Code compiles successfully

### What We Confirmed

1. ✅ New code is in the binary (verified with `strings`)
2. ✅ Functions exist: `create_bound_udp_socket`, `join_multicast_group`
3. ✅ Code compiles and runs without crashing
4. ✅ Single stream works (0% loss)

### The Problem

**The fix we implemented is theoretically correct but the bug persists.**

This suggests one of the following:

1. **Our hypothesis about the root cause was wrong**
2. **There's a different/additional root cause we didn't identify**
3. **Our fix isn't being executed** (code path issue)
4. **There's a subtlety in the IGMP/kernel behavior we're missing**

---

## Possible Root Causes To Investigate

### Hypothesis 1: Our Code Isn't Being Called

**Evidence**: Test shows identical behavior to before fix
**Next Step**: Add debug logging to confirm `add_rule()` is actually calling our new code

**Test**:
```rust
// In add_rule(), add:
eprintln!("[DEBUG] add_rule called for group {}", rule.input_group);
eprintln!("[DEBUG] Helper sockets before: {}", self.helper_sockets.len());
```

### Hypothesis 2: The Helper Socket Approach Is Wrong

**Theory**: Maybe Linux requires one socket per group even for non-interfering IGMP joins

**Evidence Needed**: Check Linux kernel IGMP behavior documentation

**Alternative Approach**: Keep one socket per group but fix the interference differently

### Hypothesis 3: Socket Options Missing

**Theory**: The helper socket needs specific options we're not setting

**Missing Options**:
- `SO_REUSEPORT` (in addition to `SO_REUSEADDR`)
- `IP_MULTICAST_ALL`
- `IP_MULTICAST_LOOP`

**Test**:
```rust
fn create_bound_udp_socket() -> Result<StdUdpSocket> {
    let socket = socket2::Socket::new(...)?;
    socket.bind(...)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;  // ADD THIS
    Ok(socket.into())
}
```

### Hypothesis 4: AF_PACKET Socket Needs IGMP Joins

**Theory**: The AF_PACKET socket itself needs to join the groups, not just helper sockets

**Evidence**: MCR uses AF_PACKET with `ETH_P_ALL` which bypasses normal IP stack

**Test**: Try joining groups directly on the AF_PACKET socket (may not be possible)

### Hypothesis 5: Multicast Routing Table Issue

**Theory**: Need to update Linux multicast routing table for each group

**Test**: Check `/proc/net/ip_mr_cache` and `/proc/net/ip_mr_vif` during test

---

## Recommended Next Steps

### Step 1: Add Debug Logging ⭐ PRIORITY

Modify `src/worker/ingress.rs` `add_rule()` to add extensive logging:

```rust
pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
    eprintln!("[DEBUG] add_rule called for {}:{}", rule.input_group, rule.input_port);
    eprintln!("[DEBUG] Current helper_sockets: {:?}", self.helper_sockets.keys().collect::<Vec<_>>());
    eprintln!("[DEBUG] Current joined_groups: {:?}", self.joined_groups);

    // ... rest of method

    eprintln!("[DEBUG] After join - helper_sockets: {}, joined_groups: {:?}",
        self.helper_sockets.len(), self.joined_groups);
}
```

### Step 2: Verify IGMP Memberships

During a test run, check:
```bash
ip netns exec relay-ns cat /proc/net/igmp
ip netns exec relay-ns cat /proc/net/ip_mr_cache
ip netns exec relay-ns netstat -g
```

### Step 3: Compare with Working socat

Capture what socat does:
```bash
# Run socat with strace
strace -f -e socket,setsockopt,bind ip netns exec relay-ns socat -u \
    UDP4-RECV:5001,ip-add-membership=239.1.1.1:veth1,reuseaddr \
    UDP4-SEND:239.10.1.1:6001,ip-multicast-if=10.0.1.1
```

Compare socket options socat uses vs what we're using.

### Step 4: Test Simplified Version

Create a minimal test program:
```rust
// Create ONE UDP socket
let socket = UdpSocket::bind("0.0.0.0:0")?;

// Join MULTIPLE groups on SAME socket
socket.join_multicast_v4_n(&"239.1.1.1".parse()?, &InterfaceIndexOrAddress::Index(iface_idx))?;
socket.join_multicast_v4_n(&"239.1.1.2".parse()?, &InterfaceIndexOrAddress::Index(iface_idx))?;

// Verify with: cat /proc/net/igmp
// Should show BOTH groups
```

If this works, our approach is correct. If not, we need a different approach.

### Step 5: Review Original Bug Report

Re-examine the actual symptoms:
- Is it really "last group only" or something else?
- Could it be AF_PACKET socket configuration issue?
- Could it be routing table issue?

---

## What We Know For Sure

### ✅ Single Stream Works
- MCR successfully forwards single multicast stream
- Helper socket creation works
- IGMP join works
- AF_PACKET socket receives packets

### ❌ Multiple Streams Fail Completely
- NOT "last stream works" - ALL streams fail (0 packets received)
- This is actually WORSE than "only last group joined"
- Suggests something breaks when 2nd rule is added

### ⚠️ Suspicious Pattern
The fact that **NO packets** are received (not even for the first stream) when 2+ rules exist suggests:
- Maybe adding the 2nd rule **breaks** the first rule
- Maybe there's a crash/panic we're not seeing
- Maybe the ingress loop stops processing

---

## Debugging Strategy

### Immediate Actions

1. **Add debug logging** to trace code execution
2. **Check for panics** - maybe error handling is hiding crashes
3. **Verify IGMP state** during multi-stream test
4. **Compare socket options** with working socat implementation

### If Those Don't Help

1. **Try alternative approaches**:
   - Keep separate sockets but fix differently
   - Use IP_ADD_MEMBERSHIP directly on AF_PACKET socket
   - Use kernel multicast routing (ip mroute)

2. **Consult Linux kernel docs**:
   - AF_PACKET + multicast behavior
   - IGMP membership lifecycle
   - Multicast routing requirements

---

## Conclusion

Our implementation is **theoretically sound** but **empirically fails**. The bug persists exactly as before.

**Next Step**: Add extensive debug logging and run a focused investigation to understand what's actually happening at runtime.

**Hypothesis**: Either:
1. Our code isn't being called (code path issue)
2. Our understanding of the root cause is wrong
3. There's a subtle Linux kernel behavior we're missing

**Recommendation**: Before continuing implementation, we need to **debug and understand** why the current fix doesn't work.

---

## Test Environment

- OS: Linux 6.17.7-200.fc42.x86_64
- Rust: Latest (from cargo build)
- Network: veth pairs in network namespaces
- MCR: Built from `/home/acooks/mcr` with all changes applied

---

## Files Modified (For Reference)

1. `src/worker/ingress.rs` - 165 lines changed
2. `src/supervisor.rs` - 25 lines changed
3. `src/lib.rs` - 2 lines added
4. `src/main.rs` - 2 lines changed
5. `src/worker/data_plane_integrated.rs` - 1 line changed

All changes compile successfully, but tests show no improvement.
