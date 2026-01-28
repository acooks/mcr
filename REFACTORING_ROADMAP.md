# MCR Refactoring Roadmap

This document tracks technical debt, refactoring opportunities, and optimization tasks identified in the MCR codebase.

## Status Legend

- [ ] Not started
- [x] Completed
- [~] In progress

---

## Completed Work

### Socket API Consolidation (Jan 2025)

- [x] Extract shared validation module (`src/validation.rs`)
- [x] Extract ProtocolState to `src/supervisor/protocol_state.rs`
- [x] Add safe socket creation wrappers (`create_raw_ip_socket`, `create_packet_socket`, `create_ioctl_socket`)
- [x] Add safe setsockopt wrappers (`set_ip_hdrincl`, `set_ip_pktinfo`, `set_packet_auxdata`, `join_multicast_group`)
- [x] Add eventfd wrapper (`create_eventfd`)
- [x] Add multicast socket option wrappers (`set_multicast_if_by_index`, `set_multicast_if_by_addr`, `set_multicast_ttl`)
- [x] Refactor protocol_state.rs to use safe wrappers
- [x] Refactor adaptive_wakeup.rs tests to use eventfd wrapper
- [x] Refactor unified_loop.rs to use multicast wrappers

---

## High Priority

### H4: Protocol State Bugs ✓ COMPLETED (Jan 2025)

**Risk:** Protocol failures, route timeouts, silent failures

- [x] **H4.1** Missing timer when adding downstream to existing (*,G) route - **BUG**
  - File: `src/supervisor/protocol_state.rs` lines 561-576
  - Issue: New route creation scheduled PimJoinPrune timer, but adding downstream
    to EXISTING route did NOT schedule timer
  - Fix: Added timer scheduling to existing route update path (mirrors new route path)

- [x] **H4.2** Incomplete passive IGMP route handling - **BUG**
  - File: `src/supervisor/protocol_state.rs` lines 752-791
  - Issue: Passive IGMP path lacked downstream update logic for existing routes
  - Fix: Added else branch mirroring active IGMP path

- [x] **H4.3** Critical error handling - silent failures on critical paths
  - File: `src/supervisor/protocol_state.rs`
  - Issues fixed:
    - Line 2046: MSDP Connect command - added warning log on failure
    - Line 2094: MSDP Keepalive command - added warning log on failure
    - Line 2129: MSDP Disconnect command - added warning log on failure
  - Notes:
    - Lines 295-302: PIM Hello timer already logs warning (acceptable)
    - Line 2628: Already uses `?` for proper error propagation (not a bug)

### H1: Memory Safety - Bounded Collections ✓ COMPLETED (Jan 2025)

**Risk:** Memory exhaustion under attack or misconfiguration

- [x] **H1.1** Add max capacity to `rules` HashMap in unified_loop.rs
  - Added `max_rules` config (default 10k), rejects when limit reached
- [x] **H1.2** Add max capacity to `flow_counters` with LRU eviction
  - Added `max_flow_counters` config (default 100k), evicts lowest packet count
- [x] **H1.3** Add max capacity to `egress_sockets` HashMap
  - Added `max_egress_sockets` config (default 10k), evicts at capacity
- [x] **H1.4** Add metrics for collection sizes
  - Added `rules_rejected`, `flow_counters_evicted`, `egress_sockets_evicted` stats

### H2: Test Coverage - Critical Infrastructure ✓ COMPLETED (Jan 2025)

**Risk:** Unsafe code in socket helpers is untested

- [x] **H2.1** Add unit tests for socket creation functions (3 tests + 4 ignored)
- [x] **H2.2** Add unit tests for socket option functions (2 tests + 7 ignored)
- [x] **H2.3** Add unit tests for eventfd wrapper (6 tests)
- [x] **H2.4** Add unit tests for interface lookup functions (2 tests)
  - Ignored tests require CAP_NET_RAW: `cargo test -- --ignored`

### H3: Performance - Interface Lookup Caching ✓ COMPLETED (Jan 2025)

**Risk:** O(n) interface scan on every socket operation

- [x] **H3.1** Create InterfaceCache struct with TTL-based refresh (30s default)
- [x] **H3.2** Provide O(1) lookup methods: `get_index`, `get_capability`, `get_name_by_index`
- [x] **H3.3** Add global singleton via `global_interface_cache()`
- [x] **H3.4** Add netlink-based cache invalidation on interface changes ✓ COMPLETED (Jan 2025)
  - Added `netlink_monitor` module using rtnetlink crate
  - Monitors RTM_NEWLINK and RTM_DELLINK events via RTMGRP_LINK multicast group
  - Automatically refreshes interface cache when interfaces are added/removed/changed
  - TTL-based refresh remains as fallback

---

## Medium Priority

### M1: Code Duplication - Error Handling ✓ COMPLETED (Jan 2025)

**Impact:** 30+ lines of repetitive error handling

- [x] **M1.1** Create `check_libc_result()` helper function
- [x] **M1.2** Refactor 9 socket option functions to use helper
  - `set_ip_hdrincl`, `set_ip_pktinfo`, `set_packet_auxdata`
  - `join_multicast_group`, `set_multicast_if_by_index`, `set_multicast_if_by_addr`
  - `set_multicast_ttl`, `set_bind_to_device`, `set_tcp_nodelay`
  - Note: `set_recv_buffer_size` has different return type, kept as-is

### M2: Code Duplication - Interface Flags ✓ COMPLETED (Jan 2025)

**Impact:** ~20 lines duplicated

- [x] **M2.1** Extract `extract_interface_capability()` helper
- [x] **M2.2** Refactor `get_interface_capability()` to use helper (14 → 4 lines)
- [x] **M2.3** Refactor `get_multicast_capable_interfaces()` to use helper (14 → 6 lines)

### M3: Error Handling Consistency ✓ REVIEWED (Jan 2025)

**Impact:** Mixed error types across codebase

- [x] **M3.1** Document error handling strategy
  - Decision: `io::Error` for I/O operations, `anyhow` for configuration/setup
  - MSDP TCP uses `io::Result` appropriately for async I/O
- [x] **M3.2** MSDP TCP error handling - KEPT AS-IS
  - `io::Error::new()` with specific ErrorKinds is correct for network I/O
- [x] **M3.3** Bare error returns in `pre_exec` - KEPT AS-IS
  - API constraint: `pre_exec` closures must return `io::Result`

### M4: Architecture - Large Functions ✓ REVIEWED (Jan 2025)

**Impact:** Maintainability

- [x] **M4.1** Client command handler - ALREADY EXTRACTED
  - `handle_client()` function exists at line 599
- [x] **M4.2** Rule sync logic - ALREADY EXTRACTED
  - `sync_rules_to_workers()` function exists at line 252
- [ ] **M4.3** Extract protocol event processing (optional)
  - `ProtocolCoordinator::process_pending_events()` exists but inline in run()
  - Low priority: further extraction adds complexity without clear benefit
- [x] **M4.4** TODO at line 1723-1726 - DOCUMENTED
  - Issue: Worker count vs lazy socket creation
  - Plan: Implement lazy AF_PACKET socket creation per interface

### M5: Test Coverage - Protocol and Worker ✓ REVIEWED (Jan 2025)

**Impact:** Reliability

- [ ] **M5.1** Add protocol socket creation tests (requires CAP_NET_RAW)
  - Covered by integration tests in `tests/integration/`
- [x] **M5.2** Buffer pool tests - ALREADY COMPREHENSIVE
  - `test_pool_exhaustion`, `test_concurrent_acquire_release_simulation`
  - `test_zero_capacity_pool`, `test_arc_cloning`
- [x] **M5.3** Command reader tests - ALREADY EXIST
  - `test_frame_too_large`, `test_invalid_json`
  - `test_partial_frame_data`, `test_partial_frame_length`

### M6: Performance - Clone Reduction

**Impact:** Unnecessary allocations

- [ ] **M6.1** Audit clone operations in supervisor/mod.rs
  - File: `src/supervisor/mod.rs`
  - Identify clones that could use Arc references
  - Lines: 211, 220-221, 236, 723, 1247, 1277, 1286, 1328, 1336, 1387, 1395, 1944

- [ ] **M6.2** Refactor hot-path clones to use Arc
  - Focus on event channels and logger clones

### M7: Code Duplication - Route Creation ✓ COMPLETED (Jan 2025)

**Impact:** ~160 lines of duplicated code reduced

- [x] **M7.1** Add `impl From<&StarGState> for StarGRoute`
  - File: `src/mroute.rs`
  - Eliminated 5 duplicate StarGRoute creation sites

- [x] **M7.2** Add `impl From<&SGState> for SGRoute`
  - File: `src/mroute.rs`
  - Eliminated 1 duplicate SGRoute creation site

### M8: Deep Nesting - IGMP Route Creation (Jan 2025)

**Impact:** 7 levels of nesting, hard to read/maintain, 95% code duplication

- [ ] **M8.1** Extract helper: `create_star_g_route_state()`
  - Creates StarGState with group, rp, upstream, downstream

- [ ] **M8.2** Extract helper: `send_pim_star_g_join()`
  - Determines upstream neighbor, builds Join packet, schedules timer

- [ ] **M8.3** Extract helper: `determine_pim_upstream_neighbor()`
  - RP direct neighbor check with fallback logic (lines 483-495, 686-697)

- [ ] **M8.4** Refactor IGMP handler to use early returns
  - Reduce nesting from 7 levels to 2-3 levels
  - Consolidate active (407-565) and passive (623-735) paths

### M9: Oversized Function - handle_timer_expired() (Jan 2025)

**Impact:** 308-line function with 13 timer types, hard to test

- [ ] **M9.1** Extract IGMP timer handlers
  - `handle_igmp_general_query_timer()` (33 lines)
  - `handle_igmp_group_query_timer()` (35 lines)
  - Consolidate shared query logic (~35 lines saved)

- [ ] **M9.2** Extract PIM timer handlers
  - `handle_pim_join_prune_timer()` (56 lines) - highest priority
  - `handle_pim_hello_timer()` (34 lines)

- [ ] **M9.3** Extract MSDP timer handlers
  - `handle_msdp_connect_retry_timer()` (36 lines)
  - `handle_msdp_keepalive_timer()` (39 lines)

---

## Low Priority

### L1: Dead Code Cleanup

**Impact:** Maintenance burden

- [x] **L1.0** Remove dead adaptive_wakeup module ✓ COMPLETED (Jan 2025)
  - Deleted `src/worker/adaptive_wakeup.rs` (435 lines)
  - Orphaned code from legacy two-thread data plane (ingress.rs/egress.rs removed Nov 2025)
  - Current unified_loop.rs uses io_uring submit_and_wait() directly

- [x] **L1.1** Remove unused socket helper functions ✓ COMPLETED (Jan 2025)
  - Removed `set_bind_to_device()` and `set_tcp_nodelay()` (~35 lines)
  - Kept `get_multicast_capable_interfaces()` - used in tests, useful public API

- [x] **L1.2** Remove duplicate constant ✓ COMPLETED (Jan 2025)
  - Removed duplicate `ALL_PIM_ROUTERS` from protocol_state.rs
  - All usages already import from `crate::protocols::pim`

- [x] **L1.3** Evaluate unused diagnostic field ✓ REVIEWED (Jan 2025)
  - `interface_name` field in unified_loop.rs - KEPT
  - Intentionally reserved for future diagnostic/logging use (documented)

- [x] **L1.4** Remove legacy msdp_tcp function ✓ COMPLETED (Jan 2025)
  - Removed `process_connection_messages()` (~40 lines)
  - Replaced by `process_reader_messages()` which is actively used

### L2: String Allocation Optimization

**Impact:** Minor performance improvement

- [ ] **L2.1** Create string constants for common responses
  - File: `src/supervisor/command_handler.rs`
  - Replace `.to_string()` calls with constants where possible

- [ ] **L2.2** Consider `Cow<'static, str>` for Response type
  - Allows both static and dynamic strings without allocation

### L3: Dependency Audit

**Impact:** Build size and complexity

- [x] **L3.1** Remove tokio-uring dependency ✓ COMPLETED (Jan 2025)
  - Removed `tokio-uring` - worker only used it as runtime wrapper
  - Worker async code uses standard tokio features (UnixStream)
  - Data plane uses `io_uring` crate directly for performance
  - Eliminated duplicate io-uring versions (v0.6.4 via tokio-uring, v0.7.11 direct)

- [x] **L3.3** Remove unused/replaceable dependencies ✓ COMPLETED (Jan 2025)
  - Removed `sysinfo` (completely unused)
  - Removed `log` crate (replaced 4 `error!()` calls with custom `log_error!` macro)
  - Removed `num_cpus` (replaced with `std::thread::available_parallelism()`)
  - Reduced direct dependencies from 21 to 18
  - Reduced dependency tree from 109 to 103 crates

- [x] **L3.4** Replace pnet with nix::ifaddrs ✓ COMPLETED (Jan 2025)
  - pnet contributed 28 unique crates to dependency tree (including regex, proc-macros)
  - Only used for `pnet::datalink::interfaces()` to enumerate network interfaces
  - Created `get_interfaces()` using `nix::ifaddrs::getifaddrs()` (nix already a dependency)
  - Added `NetworkInterface` and `IpNetwork` types as pnet replacements
  - Reduced direct dependencies from 18 to 17
  - Reduced dependency tree from 239 to 211 crates

- [ ] **L3.2** Document error crate usage
  - Clarify when to use anyhow vs thiserror
  - Add to contributing guidelines

### L4: Documentation

**Impact:** Onboarding and maintenance

- [x] **L4.1** Document unsafe code rationale ✓ COMPLETED (Jan 2025)
  - Reduced unsafe blocks from 72 to 63 (9 removed)
  - Removed unused `create_eventfd()` wrapper (production uses `nix::sys::eventfd::EventFd`)
  - Replaced `libc::if_indextoname` with `nix::net::if_::if_indextoname` in protocol_state.rs
  - Added SAFETY comments to ringbuffer.rs lock-free operations
  - Added SAFETY comments to socket_helpers.rs socket creation and bind operations

- [ ] **L4.2** Document socket_helpers API
  - Add module-level documentation
  - Document when to use each function

---

## Metrics

### Code Quality Targets

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Unsafe blocks | 63 | <50 | In progress (was 72) |
| Test coverage (socket_helpers) | 31 tests | >80% | ✓ Done |
| Duplicate error patterns | 5 | 0 | ✓ Reduced (was 14) |
| Dead code functions | 0 | 0 | ✓ Done |

### Performance Targets

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Interface lookup | O(1) cached | O(1) cached | ✓ Done |
| Max rules per worker | 10k (configurable) | Configurable limit | ✓ Done |
| Max flow counters | 100k (configurable) | Configurable limit | ✓ Done |
| Max egress sockets | 10k (configurable) | Configurable limit | ✓ Done |

---

## Notes

### Completed Refactoring Summary (Jan 2025)

1. **Validation module** - Centralized address/interface/port validation
2. **ProtocolState extraction** - Reduced supervisor/mod.rs from 6,798 to 3,037 lines
3. **Socket wrappers** - Eliminated ~210 lines of unsafe code duplication
4. **Eventfd wrapper** - Simplified eventfd creation in socket_helpers.rs
5. **Multicast wrappers** - Consolidated IP_MULTICAST_IF/TTL handling
6. **Bounded collections (H1)** - Memory-safe limits with eviction for rules, flows, sockets
7. **Socket_helpers tests (H2)** - 37 new tests (22 passing, 11 ignored requiring CAP_NET_RAW)
8. **Interface cache (H3)** - O(1) lookups via InterfaceCache with 30s TTL
9. **Error handling helpers (M1)** - `check_libc_result()` eliminated ~50 lines duplication
10. **Interface capability helper (M2)** - `extract_interface_capability()` reduced ~20 lines
11. **Dead code removal (L1.0)** - Deleted adaptive_wakeup.rs (435 lines of orphaned code)
12. **Dead code removal (L1.1-L1.4)** - Removed unused socket helpers, duplicate constant, legacy function (~80 lines)
13. **Unsafe code audit (L4.1)** - Reduced unsafe blocks 72→63, added SAFETY comments, replaced libc calls with nix wrappers
14. **Netlink monitor (H3.4)** - Real-time interface change detection via RTMGRP_LINK multicast group
15. **Dependency reduction (L3.3)** - Removed sysinfo, log, num_cpus; reduced deps 21→18, tree 109→103
16. **pnet removal (L3.4)** - Replaced pnet with nix::ifaddrs for interface enumeration; reduced tree by 28 crates (239→211)

### Guidelines for Future Work

- Prefer safe wrappers over raw unsafe blocks
- Add tests before refactoring critical code
- Document safety invariants for remaining unsafe code
- Use `anyhow::Context` for error chain context
