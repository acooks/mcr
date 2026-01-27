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

### H1: Memory Safety - Bounded Collections

**Risk:** Memory exhaustion under attack or misconfiguration

- [ ] **H1.1** Add max capacity to `rules` HashMap in unified_loop.rs:164
  - File: `src/worker/unified_loop.rs`
  - Add constant `MAX_RULES` and check before insertion

- [ ] **H1.2** Add max capacity to `flow_counters` HashMap in unified_loop.rs:167
  - File: `src/worker/unified_loop.rs`
  - Implement LRU eviction for stale flow entries

- [ ] **H1.3** Add max capacity to `egress_sockets` HashMap in unified_loop.rs:170
  - File: `src/worker/unified_loop.rs`
  - Evict oldest unused sockets when limit reached

- [ ] **H1.4** Add metrics for collection sizes
  - Expose current sizes via stats API for monitoring

### H2: Test Coverage - Critical Infrastructure

**Risk:** Unsafe code in socket helpers is untested

- [ ] **H2.1** Add unit tests for socket creation functions
  - File: `src/supervisor/socket_helpers.rs`
  - Test: `create_raw_ip_socket`, `create_packet_socket`, `create_ioctl_socket`
  - Test: Error cases (invalid protocol, permission denied simulation)

- [ ] **H2.2** Add unit tests for socket option functions
  - File: `src/supervisor/socket_helpers.rs`
  - Test: `set_ip_hdrincl`, `set_ip_pktinfo`, `set_packet_auxdata`
  - Test: `join_multicast_group`, `set_multicast_if_by_index`, `set_multicast_if_by_addr`

- [ ] **H2.3** Add unit tests for eventfd wrapper
  - File: `src/supervisor/socket_helpers.rs`
  - Test: `create_eventfd` with various flag combinations

- [ ] **H2.4** Add unit tests for interface lookup functions
  - File: `src/supervisor/socket_helpers.rs`
  - Test: `get_interface_index` with valid/invalid interfaces
  - Test: `get_interface_capability` edge cases

### H3: Performance - Interface Lookup Caching

**Risk:** O(n) interface scan on every socket operation

- [ ] **H3.1** Create InterfaceCache struct
  - File: `src/supervisor/socket_helpers.rs`
  - Cache `pnet::datalink::interfaces()` results
  - Add TTL-based refresh (e.g., 30 seconds)

- [ ] **H3.2** Replace direct `pnet::datalink::interfaces()` calls
  - Update `get_interface_index()` to use cache
  - Update `get_interface_capability()` to use cache
  - Update `get_multicast_capable_interfaces()` to use cache

- [ ] **H3.3** Add cache invalidation on interface changes
  - Optional: Use netlink to detect interface changes

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

| Metric | Current | Target |
|--------|---------|--------|
| Unsafe blocks | ~75 | <50 |
| Test coverage (socket_helpers) | 0% | >80% |
| Duplicate error patterns | 14 | 0 |
| Dead code functions | 4 | 0 |

### Performance Targets

| Metric | Current | Target |
|--------|---------|--------|
| Interface lookup | O(n) per call | O(1) cached |
| Max rules per worker | Unbounded | Configurable limit |
| Max egress sockets | Unbounded | Configurable limit |

---

## Notes

### Completed Refactoring Summary (Jan 2025)

1. **Validation module** - Centralized address/interface/port validation
2. **ProtocolState extraction** - Reduced supervisor/mod.rs from 6,798 to 3,037 lines
3. **Socket wrappers** - Eliminated ~210 lines of unsafe code duplication
4. **Eventfd wrapper** - Simplified test code in adaptive_wakeup.rs
5. **Multicast wrappers** - Consolidated IP_MULTICAST_IF/TTL handling

### Guidelines for Future Work

- Prefer safe wrappers over raw unsafe blocks
- Add tests before refactoring critical code
- Document safety invariants for remaining unsafe code
- Use `anyhow::Context` for error chain context
