# Research Session Notes - 2025-11-15

## Session Goal

Determine if socat can relay multicast traffic and what requirements are needed.

## What We Learned

### 1. socat CAN relay multicast (in some topologies)

- Confirmed socat has the necessary socket options
- Working socat command pattern:
  ```bash
  socat -u \
    UDP4-RECV:5001,ip-add-membership=239.255.0.1:veth-relay0,reuseaddr \
    UDP4-SEND:239.255.0.2:5001,ip-multicast-if=10.0.2.1,reuseaddr
  ```
- Requires different input/output multicast addresses

### 2. Topology Matters

**3-Namespace Topology (WORKS):**
```text
src-ns ↔ relay-ns ↔ sink-ns
[isolated]  [relay]  [isolated]
```
- Result: 5/5 packets (100% success)
- Requirements: Different mcast groups, relay egress route

**MCR's Dual-Bridge Topology (FAILS):**
```text
Single namespace with br0, br1
Multi-homed relay: veth-mcr0, veth-mcr1
```
- Result: 0 packets for BOTH socat and MCR
- Suggests test infrastructure issue or fundamental limitation

### 3. Testing Issues Discovered

1. **Wrong topology**: 3-namespace test doesn't match MCR's use case
2. **Verification gaps**: Some "disabled" settings weren't actually disabled
3. **Background processes**: Created hung processes that interfered with testing
4. **Repeatability**: Test results may not be reliable due to above issues

## Key Insights

1. **socat's capabilities exist** - It has the right socket options
2. **Applicability unclear** - Success in isolated topology ≠ success in production
3. **Need proper testing** - Must use MCR's actual topology (single namespace, dual-bridge, multi-homed)
4. **Test infrastructure** - Even MCR failed in dual-bridge test, suggesting test needs debugging

## Next Steps (Recommendations)

1. **Fix dual-bridge test** - Debug why both MCR and socat get 0%
2. **Proper multi-homed test** - Create test matching MCR topology but simpler for debugging
3. **Validate socat** - Determine if it can work in realistic multi-homed scenarios
4. **OR** - Accept that isolated 3-namespace topology is sufficient for comparison purposes

## Files Created/Modified

- `test_socat_single_bridge.sh` - 3-namespace test (works but wrong topology)
- `test_dual_bridge_with_route.sh` - Modified MCR test with relay route (still fails)
- `README.md` - Updated with findings and limitations
- Multiple test variant scripts (test_no_*.sh)

## Conclusion

socat CAN relay multicast in controlled conditions, but applicability to MCR's real-world multi-homed topology remains unproven. Further investigation needed with correct topology.
