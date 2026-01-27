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
- [ ] **H3.4** (Future) Add netlink-based cache invalidation on interface changes

---

## Medium Priority

### M1: Code Duplication - Error Handling

**Impact:** 30+ lines of repetitive error handling

- [ ] **M1.1** Create libc result helper function
  - File: `src/supervisor/socket_helpers.rs`

  ```rust
  fn check_libc_result(result: i32, context: &str) -> Result<()> {
      if result < 0 {
          Err(anyhow::anyhow!("{}: {}", context, std::io::Error::last_os_error()))
      } else {
          Ok(())
      }
  }
  ```

- [ ] **M1.2** Refactor all 14 socket option functions to use helper
  - `set_ip_hdrincl`, `set_ip_pktinfo`, `set_packet_auxdata`
  - `join_multicast_group`, `set_multicast_if_by_index`, `set_multicast_if_by_addr`
  - `set_multicast_ttl`, `set_bind_to_device`, `set_tcp_nodelay`
  - `set_recv_buffer_size`

### M2: Code Duplication - Interface Flags

**Impact:** ~20 lines duplicated

- [ ] **M2.1** Extract interface flag extraction helper
  - File: `src/supervisor/socket_helpers.rs`

  ```rust
  fn extract_interface_capability(iface: &pnet::datalink::NetworkInterface) -> InterfaceCapability
  ```

- [ ] **M2.2** Refactor `get_interface_capability()` to use helper

- [ ] **M2.3** Refactor `get_multicast_capable_interfaces()` to use helper

### M3: Error Handling Consistency

**Impact:** Mixed error types across codebase

- [ ] **M3.1** Document error handling strategy
  - Create `docs/ERROR_HANDLING.md`
  - Define when to use anyhow vs thiserror
  - Define error context requirements

- [ ] **M3.2** Standardize MSDP TCP error handling
  - File: `src/protocols/msdp_tcp.rs`
  - Replace `io::Error::new()` with anyhow where appropriate
  - Lines: 48-51, 70-73, 194, 216, 370, 386, 433, 451, 562, 604

- [ ] **M3.3** Add context to bare error returns
  - File: `src/worker/unified_loop.rs:1072-1074`
  - File: `src/supervisor/worker_manager.rs:160-177`

### M4: Architecture - Large Functions

**Impact:** Maintainability

- [ ] **M4.1** Extract client command handler from supervisor run loop
  - File: `src/supervisor/mod.rs`
  - Extract `handle_client_command()` function

- [ ] **M4.2** Extract rule sync logic
  - File: `src/supervisor/mod.rs`
  - Extract `sync_rules_to_workers()` function

- [ ] **M4.3** Extract protocol event processing
  - File: `src/supervisor/mod.rs`
  - Extract `process_protocol_events()` function

- [ ] **M4.4** Investigate TODO at line 1713-1714
  - File: `src/supervisor/mod.rs`
  - Document the architectural issue
  - Create plan to address

### M5: Test Coverage - Protocol and Worker

**Impact:** Reliability

- [ ] **M5.1** Add protocol socket creation tests
  - File: `src/supervisor/protocol_state.rs`
  - Test: `create_igmp_socket`, `create_pim_socket`
  - Use mock interfaces or integration tests

- [ ] **M5.2** Add buffer pool edge case tests
  - File: `src/worker/buffer_pool.rs`
  - Test: Pool exhaustion behavior
  - Test: Concurrent allocation stress

- [ ] **M5.3** Add command reader tests
  - File: `src/worker/command_reader.rs`
  - Test: Frame parsing
  - Test: Invalid frame handling

### M6: Performance - Clone Reduction

**Impact:** Unnecessary allocations

- [ ] **M6.1** Audit clone operations in supervisor/mod.rs
  - File: `src/supervisor/mod.rs`
  - Identify clones that could use Arc references
  - Lines: 211, 220-221, 236, 723, 1247, 1277, 1286, 1328, 1336, 1387, 1395, 1944

- [ ] **M6.2** Refactor hot-path clones to use Arc
  - Focus on event channels and logger clones

---

## Low Priority

### L1: Dead Code Cleanup

**Impact:** Maintenance burden

- [ ] **L1.1** Evaluate unused socket helper functions
  - File: `src/supervisor/socket_helpers.rs`
  - `set_bind_to_device()` - line 514-539
  - `set_tcp_nodelay()` - line 543-562
  - `get_multicast_capable_interfaces()` - line 242
  - Decision: Remove or document intended use

- [ ] **L1.2** Evaluate unused constants
  - File: `src/supervisor/protocol_state.rs`
  - `ALL_PIM_ROUTERS` constant - line 32
  - Decision: Use in multicast joins or remove

- [ ] **L1.3** Evaluate unused diagnostic field
  - File: `src/worker/unified_loop.rs:154-155`
  - `interface_name` field marked dead
  - Decision: Implement diagnostics or remove

- [ ] **L1.4** Evaluate unused msdp_tcp function
  - File: `src/protocols/msdp_tcp.rs:574`
  - Decision: Remove or document intended use

### L2: String Allocation Optimization

**Impact:** Minor performance improvement

- [ ] **L2.1** Create string constants for common responses
  - File: `src/supervisor/command_handler.rs`
  - Replace `.to_string()` calls with constants where possible

- [ ] **L2.2** Consider `Cow<'static, str>` for Response type
  - Allows both static and dynamic strings without allocation

### L3: Dependency Audit

**Impact:** Build size and complexity

- [ ] **L3.1** Audit io-uring vs tokio-uring usage
  - Check if both crates are necessary
  - Consider consolidating to tokio-uring only

- [ ] **L3.2** Document error crate usage
  - Clarify when to use anyhow vs thiserror
  - Add to contributing guidelines

### L4: Documentation

**Impact:** Onboarding and maintenance

- [ ] **L4.1** Document unsafe code rationale
  - Add safety comments to remaining unsafe blocks
  - Especially in `src/logging/ringbuffer.rs`

- [ ] **L4.2** Document socket_helpers API
  - Add module-level documentation
  - Document when to use each function

---

## Metrics

### Code Quality Targets

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Unsafe blocks | ~75 | <50 | Pending |
| Test coverage (socket_helpers) | 37 tests | >80% | ✓ Done |
| Duplicate error patterns | 14 | 0 | Pending |
| Dead code functions | 4 | 0 | Pending |

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
4. **Eventfd wrapper** - Simplified test code in adaptive_wakeup.rs
5. **Multicast wrappers** - Consolidated IP_MULTICAST_IF/TTL handling
6. **Bounded collections (H1)** - Memory-safe limits with eviction for rules, flows, sockets
7. **Socket_helpers tests (H2)** - 37 new tests (22 passing, 11 ignored requiring CAP_NET_RAW)
8. **Interface cache (H3)** - O(1) lookups via InterfaceCache with 30s TTL

### Guidelines for Future Work

- Prefer safe wrappers over raw unsafe blocks
- Add tests before refactoring critical code
- Document safety invariants for remaining unsafe code
- Use `anyhow::Context` for error chain context
