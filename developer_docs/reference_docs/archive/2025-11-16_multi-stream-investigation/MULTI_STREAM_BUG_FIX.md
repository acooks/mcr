# Multi-Stream Bug Fix Plan

**Date**: 2025-11-16
**Status**: Proposed
**Bug**: MCR experiences 100% packet loss with 2+ concurrent multicast streams

---

## Problem Summary

**Observed Behavior**:
- ✅ Single stream: 10,000/10,000 packets delivered (0% loss)
- ❌ Two streams: 0/20,000 packets delivered (100% loss)
- ❌ Five streams: 0/50,000 packets delivered (100% loss)

**Root Cause**: Silent panic in `add_rule()` method when helper socket creation fails

**Location**: `src/worker/ingress.rs:136-138`

---

## Root Cause Analysis

### Current Problematic Code

```rust
pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
    let key = (rule.input_group, rule.input_port);
    self.rules.insert(key, rule.clone());

    // Create helper socket to send IGMP joins
    let helper_key = (rule.input_interface.clone(), rule.input_group);
    self.helper_sockets.entry(helper_key).or_insert_with(|| {
        setup_helper_socket(&rule.input_interface, rule.input_group).unwrap()  // ← PANIC!
    });

    self.logger.info(
        Facility::Ingress,
        &format!("Rule added: {}:{} -> {} outputs", ...)
    );
    Ok(())
}
```

### Why This Causes 100% Packet Loss

1. **First rule succeeds**: Helper socket created, IGMP join succeeds for `239.1.1.1`
2. **Second rule fails**: `setup_helper_socket()` returns `Err(...)` for some reason
3. **Panic occurs**: `.unwrap()` panics, crashing the worker thread
4. **Silent failure**: Panic may not be visible in test output
5. **No IGMP join**: Second multicast group (`239.1.1.2`) is never joined
6. **NIC filtering**: Network interface card filters out packets for unjoined groups
7. **AF_PACKET never sees packets**: Despite using `ETH_P_ALL`, packets are dropped at hardware level

### Possible Failure Scenarios

1. **Permission denied**: Namespace restrictions on multicast joins
2. **Resource exhaustion**: Kernel limit on multicast group memberships
3. **Interface not ready**: Race condition where interface is temporarily unavailable
4. **Port conflict**: Though unlikely with port 0 binding
5. **IGMP limit**: `/proc/sys/net/ipv4/igmp_max_memberships` exceeded

---

## Proposed Fix Strategy

### Fix #1: Replace `.unwrap()` with Proper Error Handling

**Priority**: Critical
**Impact**: Prevents silent panics, provides diagnostic information

#### Implementation

**File**: `src/worker/ingress.rs`
**Lines**: 130-150

**Current Code**:
```rust
pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
    let key = (rule.input_group, rule.input_port);
    self.rules.insert(key, rule.clone());

    let helper_key = (rule.input_interface.clone(), rule.input_group);
    self.helper_sockets.entry(helper_key).or_insert_with(|| {
        setup_helper_socket(&rule.input_interface, rule.input_group).unwrap()
    });

    self.logger.info(
        Facility::Ingress,
        &format!(
            "Rule added: {}:{} -> {} outputs (total rules: {})",
            rule.input_group,
            rule.input_port,
            rule.outputs.len(),
            self.rules.len()
        ),
    );
    Ok(())
}
```

**Proposed Fix**:
```rust
pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
    let key = (rule.input_group, rule.input_port);
    self.rules.insert(key, rule.clone());

    // Create helper socket to send IGMP joins for this multicast group.
    // This ensures switches/routers forward the multicast traffic to our interface.
    let helper_key = (rule.input_interface.clone(), rule.input_group);

    // Only create helper socket if we don't already have one for this (interface, group) pair
    if !self.helper_sockets.contains_key(&helper_key) {
        match setup_helper_socket(&rule.input_interface, rule.input_group) {
            Ok(socket) => {
                self.helper_sockets.insert(helper_key, socket);
                self.logger.info(
                    Facility::Ingress,
                    &format!(
                        "IGMP join successful: {} on {} (total groups: {})",
                        rule.input_group,
                        rule.input_interface,
                        self.helper_sockets.len()
                    ),
                );
            }
            Err(e) => {
                // Log the error but don't panic - allow the rule to be added anyway
                // The rule might still work if another process has already joined the group
                self.logger.error(
                    Facility::Ingress,
                    &format!(
                        "Failed to join multicast group {} on {}: {}",
                        rule.input_group, rule.input_interface, e
                    ),
                );

                // Optionally: Remove the rule we just added since it won't work
                // self.rules.remove(&key);
                // return Err(e);

                // Or: Continue anyway and let the user debug
                self.logger.warning(
                    Facility::Ingress,
                    "Rule added but IGMP join failed - packets may be dropped at NIC level",
                );
            }
        }
    }

    self.logger.info(
        Facility::Ingress,
        &format!(
            "Rule added: {}:{} -> {} outputs (total rules: {})",
            rule.input_group,
            rule.input_port,
            rule.outputs.len(),
            self.rules.len()
        ),
    );
    Ok(())
}
```

**Key Changes**:
1. Explicit check for existing helper socket before attempting creation
2. Match on `Result` instead of `.unwrap()`
3. Detailed logging for both success and failure cases
4. Error is logged but doesn't panic the thread
5. Provides diagnostic information (group count, error message)

---

### Fix #2: Add Logging Helper to Track Helper Socket Creation

**Priority**: High
**Impact**: Provides visibility into IGMP join operations

#### Add Warning Facility

**File**: `src/logging.rs` (if it exists, otherwise in relevant logging module)

Add a `warning()` method to the Logger if it doesn't already exist:

```rust
impl Logger {
    // ... existing methods ...

    pub fn warning(&self, facility: Facility, message: &str) {
        // Implementation similar to error() but with WARNING level
        eprintln!("[WARN][{}] {}", facility, message);
    }
}
```

---

### Fix #3: Add Diagnostic Stats for Helper Sockets

**Priority**: Medium
**Impact**: Helps debug IGMP issues in production

#### Add Stats Fields

**File**: `src/worker/ingress.rs` (in the IngressStats struct)

```rust
struct IngressStats {
    // ... existing fields ...

    igmp_joins_attempted: u64,
    igmp_joins_succeeded: u64,
    igmp_joins_failed: u64,
}
```

#### Update Stats in add_rule()

```rust
pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
    // ... rule insertion code ...

    if !self.helper_sockets.contains_key(&helper_key) {
        self.stats.igmp_joins_attempted += 1;

        match setup_helper_socket(&rule.input_interface, rule.input_group) {
            Ok(socket) => {
                self.stats.igmp_joins_succeeded += 1;
                self.helper_sockets.insert(helper_key, socket);
                // ... logging ...
            }
            Err(e) => {
                self.stats.igmp_joins_failed += 1;
                // ... error handling ...
            }
        }
    }

    // ... rest of method ...
}
```

#### Display in Final Stats

**File**: `src/worker/ingress.rs` (in `print_final_stats()` method)

```rust
fn print_final_stats(&self) {
    self.logger.info(
        Facility::Ingress,
        &format!("=== FINAL INGRESS STATISTICS ==="),
    );
    // ... existing stats ...
    self.logger.info(
        Facility::Ingress,
        &format!(
            "IGMP joins: {} attempted, {} succeeded, {} failed",
            self.stats.igmp_joins_attempted,
            self.stats.igmp_joins_succeeded,
            self.stats.igmp_joins_failed
        ),
    );
    self.logger.info(
        Facility::Ingress,
        &format!("Active helper sockets: {}", self.helper_sockets.len()),
    );
}
```

---

### Fix #4: Improve Test Diagnostics

**Priority**: Medium
**Impact**: Makes test failures more debugable

#### Add IGMP Membership Check to Test

**File**: `tests/performance/multi_stream_scaling.sh`

Add diagnostic output after adding rules:

```bash
# After line 156 (after adding all rules)
echo "[2.5] Verifying IGMP memberships"
ip netns exec relay-ns cat /proc/net/igmp | grep -E "(veth1|239\.)" || echo "WARNING: No IGMP memberships found"

# Count expected vs actual
expected_groups=$num_streams
actual_groups=$(ip netns exec relay-ns cat /proc/net/igmp | grep "239\." | wc -l)
if [ "$actual_groups" -ne "$expected_groups" ]; then
    echo "WARNING: Expected $expected_groups IGMP groups, found $actual_groups"
fi
```

#### Add Verbose MCR Output Option

```bash
# Add environment variable to enable verbose MCR logging
if [ "${MCR_VERBOSE:-0}" = "1" ]; then
    ip netns exec relay-ns "$MCR_SUPERVISOR" supervisor \
        --control-socket-path "$MCR_SOCK" \
        --num-workers 1 \
        --interface veth1 2>&1 | tee /tmp/mcr_verbose.log &
else
    # Existing silent version
    ip netns exec relay-ns "$MCR_SUPERVISOR" supervisor \
        --control-socket-path "$MCR_SOCK" \
        --num-workers 1 \
        --interface veth1 >/dev/null 2>&1 &
fi
```

---

## Testing Strategy

### Phase 1: Verify the Fix

1. **Apply Fix #1** (error handling in add_rule)
2. **Run multi-stream test** with verbose logging:
   ```bash
   sudo MCR_VERBOSE=1 ./tests/performance/multi_stream_scaling.sh 5
   ```
3. **Check for error messages** in MCR output
4. **Verify IGMP memberships** are created for all groups

### Phase 2: Add Diagnostic Improvements

1. **Apply Fixes #2 and #3** (logging and stats)
2. **Run test again** and verify diagnostic output
3. **Confirm stats show** correct IGMP join counts

### Phase 3: Regression Testing

1. **Test single stream** - ensure it still works (should be 0% loss)
2. **Test 2 streams** - should now work correctly
3. **Test 5 streams** - should work correctly
4. **Test 10+ streams** - verify scalability
5. **Test high packet rates** - combine with existing performance tests

---

## Expected Outcomes

### Before Fix

| Streams | Expected | Received | Loss %  |
|---------|----------|----------|---------|
| 1       | 10,000   | 10,000   | 0.00%   |
| 2       | 20,000   | 0        | 100.00% |
| 5       | 50,000   | 0        | 100.00% |

### After Fix

| Streams | Expected | Received | Loss %  |
|---------|----------|----------|---------|
| 1       | 10,000   | 10,000   | 0.00%   |
| 2       | 20,000   | 20,000   | 0.00%   |
| 5       | 50,000   | 50,000   | 0.00%   |
| 10      | 100,000  | 100,000  | 0.00%   |

*(Assuming no other underlying issues)*

---

## Risks and Mitigations

### Risk 1: Underlying Issue Not Addressed

**Scenario**: The `.unwrap()` was never actually panicking; there's a different root cause

**Mitigation**:
- Fix #1 adds extensive logging that will reveal the actual issue
- IGMP membership checks in test will show if joins are failing
- Stats tracking will quantify the problem

### Risk 2: IGMP Joins Are Succeeding But Packets Still Dropped

**Scenario**: Helper sockets join groups successfully, but packets still don't arrive

**Mitigation**:
- Add packet capture diagnostics to test
- Check kernel multicast routing table
- Verify NIC driver and hardware support for multicast filtering
- Test on different hardware/virtual network setups

### Risk 3: Performance Regression

**Scenario**: Additional logging/checking slows down rule addition

**Mitigation**:
- Logging only occurs during rule addition (not per-packet)
- Rule addition is infrequent (configuration phase)
- No impact on data plane performance

---

## Alternative Approaches

### Alternative 1: Retry Logic for Helper Socket Creation

Instead of just logging the error, retry the IGMP join:

```rust
let mut attempts = 0;
let max_attempts = 3;

while attempts < max_attempts {
    match setup_helper_socket(&rule.input_interface, rule.input_group) {
        Ok(socket) => {
            self.helper_sockets.insert(helper_key, socket);
            break;
        }
        Err(e) if attempts < max_attempts - 1 => {
            attempts += 1;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err(e) => {
            self.logger.error(...);
            return Err(e);
        }
    }
}
```

**Pros**: More resilient to transient failures
**Cons**: Adds latency to rule addition; may mask underlying issues

### Alternative 2: Fail Fast - Return Error on IGMP Failure

Instead of continuing when IGMP join fails, return error immediately:

```rust
if !self.helper_sockets.contains_key(&helper_key) {
    let socket = setup_helper_socket(&rule.input_interface, rule.input_group)
        .context("Failed to create helper socket for IGMP join")?;
    self.helper_sockets.insert(helper_key, socket);
}
```

**Pros**: Clear failure signal; easier debugging
**Cons**: Less graceful; might fail in cases where the rule could still work

### Alternative 3: Lazy Helper Socket Creation

Don't create helper sockets in `add_rule()`. Instead, create them lazily when the first packet for a group arrives:

**Pros**: Avoids IGMP join failures if groups aren't actually used
**Cons**: Complex implementation; first packets might be dropped; defeats purpose of IGMP

---

## Recommendation

**Primary Fix**: Apply **Fix #1** (proper error handling) with **warning** log level when IGMP fails but continue rule addition.

**Rationale**:
1. Prevents panics and silent failures
2. Provides diagnostic information
3. Doesn't fail aggressively (some environments might work despite IGMP failures)
4. Easy to adjust behavior based on test results

**Secondary Fixes**: Apply **Fix #2** and **Fix #3** for better observability.

**Test Enhancement**: Apply **Fix #4** for better test diagnostics.

---

## Implementation Checklist

- [ ] Fix #1: Replace `.unwrap()` in `add_rule()` with proper error handling
- [ ] Fix #2: Add warning log method to Logger (if needed)
- [ ] Fix #3: Add IGMP stats tracking to IngressStats
- [ ] Fix #4: Add IGMP verification to test script
- [ ] Test: Run multi-stream test with 2 streams
- [ ] Test: Run multi-stream test with 5 streams
- [ ] Test: Run multi-stream test with 10 streams
- [ ] Test: Verify single-stream still works (regression check)
- [ ] Test: Check IGMP memberships during test execution
- [ ] Document: Update test results in experiment docs
- [ ] Commit: Changes with proper commit message

---

## Success Criteria

1. ✅ Multi-stream test passes with 0% loss for 2+ streams
2. ✅ No panics or crashes during rule addition
3. ✅ Clear diagnostic messages when IGMP joins fail
4. ✅ Stats accurately report IGMP join success/failure
5. ✅ Test verifies IGMP memberships match expected count
6. ✅ Single-stream performance unchanged (regression check)

---

## Next Steps After Fix

Once multi-stream bug is fixed, tackle the **multi-worker duplication bug**:

**Multi-Worker Bug**: When using `--num-workers 2`, packets are duplicated (1.28x instead of load-balanced)

**Likely Cause**: All workers are receiving the same packets instead of distributing them

**Investigation Area**: AF_PACKET socket configuration and packet fanout mechanism
