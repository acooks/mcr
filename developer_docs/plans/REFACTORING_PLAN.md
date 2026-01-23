# Codebase Refactoring Plan

Last updated: January 2026

## Overview

This document outlines opportunities for refactoring and improving the MCR codebase structure. Findings are categorized by priority based on impact to maintainability, testability, and scalability.

## Priority Legend

- **HIGH** - Significant maintainability impact, should be addressed soon
- **MEDIUM** - Quality improvements, technical debt reduction
- **LOW** - Nice-to-have, minor improvements

---

## HIGH Priority

### 1. Split supervisor.rs (6,050 lines)

**Location:** `src/supervisor.rs`

**Problem:** The file is the largest in the codebase and mixes multiple concerns:

- Protocol state management (ProtocolState, IGMP/PIM/MSDP event handlers)
- Worker lifecycle management (Supervisor, Worker, InterfaceWorkers)
- Timer scheduling (TimerState, ProtocolTimerManager)
- CLI query handlers (get_pim_neighbors, get_igmp_groups, etc.)
- MRIB compilation and rule synchronization

**Impact:** Maintainability bottleneck, difficult to navigate, hard to test components in isolation.

**Proposed Structure:**

```text
src/supervisor/
├── mod.rs                  # Re-exports, orchestration (~500 lines)
├── protocol_state.rs       # ProtocolState struct and methods (~800 lines)
├── event_handlers.rs       # handle_igmp_event, handle_pim_event, handle_msdp_event (~1000 lines)
├── worker_manager.rs       # Supervisor, Worker, InterfaceWorkers (~1200 lines)
├── timer_manager.rs        # TimerState, ProtocolTimerManager (~600 lines)
├── query_handlers.rs       # CLI response handlers (~400 lines)
└── command_handler.rs      # handle_supervisor_command (~1500 lines)
```

**Implementation Steps:**

1. [ ] Create `src/supervisor/` directory structure
2. [ ] Extract `ProtocolState` and related methods to `protocol_state.rs`
3. [ ] Extract event handlers to `event_handlers.rs`
4. [ ] Extract worker management to `worker_manager.rs`
5. [ ] Extract timer management to `timer_manager.rs`
6. [ ] Extract query handlers to `query_handlers.rs`
7. [ ] Keep orchestration and main loop in `mod.rs`
8. [ ] Update imports throughout codebase
9. [ ] Verify all tests pass

---

### 2. Decouple Protocols from MRIB

**Location:** `src/supervisor.rs` (event handlers), `src/protocols/*.rs`

**Problem:** Protocol event handlers directly mutate MRIB and emit subscription events. This creates tight coupling that makes protocols difficult to test in isolation.

**Current Pattern:**

```rust
// In handle_igmp_event()
fn handle_igmp_event(&mut self, event: IgmpEvent) {
    match event {
        IgmpEvent::MembershipChange { .. } => {
            // Directly updates MRIB
            self.mrib.add_igmp_membership(...);
            // Directly emits events
            self.emit_event(ProtocolEventNotification::IgmpMembershipChange { .. });
        }
    }
}
```

**Proposed Pattern:**

```rust
trait ProtocolHandler {
    type Event;
    type Output;

    fn handle_event(&mut self, event: Self::Event) -> ProtocolResult<Self::Output>;
}

struct ProtocolResult<T> {
    state_changes: Vec<StateChange>,
    timer_requests: Vec<TimerRequest>,
    notifications: Vec<ProtocolEventNotification>,
    output: T,
}

// Supervisor applies results
fn process_protocol_event(&mut self, event: ProtocolEvent) {
    let result = self.protocol_handler.handle_event(event);

    // Apply state changes
    for change in result.state_changes {
        self.mrib.apply(change);
    }

    // Schedule timers
    for timer in result.timer_requests {
        self.timer_tx.send(timer);
    }

    // Emit notifications
    for notification in result.notifications {
        self.emit_event(notification);
    }
}
```

**Benefits:**

- Protocols can be unit tested without MRIB
- Clear separation of "what happened" vs "what to do about it"
- Easier to add new protocols

**Implementation Steps:**

1. [ ] Define `ProtocolHandler` trait in `src/protocols/mod.rs`
2. [ ] Define `ProtocolResult` and `StateChange` types
3. [ ] Refactor IGMP handler to return results instead of mutating
4. [ ] Refactor PIM handler
5. [ ] Refactor MSDP handler
6. [ ] Update supervisor to apply results
7. [ ] Add unit tests for protocol handlers in isolation

---

### 3. Extract Timestamp Utility

**Location:** `src/mroute.rs` lines 100-106 and 191-197

**Problem:** Identical complex code for converting `Instant` to Unix timestamp:

```rust
created_at: self.created_at.elapsed().as_secs().saturating_add(
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(self.created_at.elapsed().as_secs()),
),
```

**Solution:** Extract to utility function or store Unix timestamp at creation time.

**Implementation:**

```rust
// src/util.rs (new file) or src/mroute.rs
fn instant_to_unix_timestamp(instant: std::time::Instant) -> u64 {
    let elapsed = instant.elapsed().as_secs();
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(elapsed)
}
```

**Implementation Steps:**

1. [ ] Create utility function
2. [ ] Replace duplicated code in `StarGRoute::to_forwarding_rules()`
3. [ ] Replace duplicated code in `SGRoute::to_forwarding_rules()`
4. [ ] Consider storing Unix timestamp at route creation instead

---

## MEDIUM Priority

### 4. Audit unwrap()/expect() Usage

**Locations:** Throughout codebase (654 occurrences)

| File | Count |
|------|-------|
| src/supervisor.rs | 86 |
| src/protocols/msdp.rs | 96 |
| src/protocols/pim.rs | 80 |
| src/control_client.rs | 80 |
| src/worker/unified_loop.rs | 45 |
| Other files | ~267 |

**Problem:** Many `unwrap()` calls are in packet parsing paths where malformed data could cause panics in production.

**Categories:**

1. **Safe unwraps** - On const data or after validation (document with comments)
2. **Test-only unwraps** - Acceptable in test code
3. **Should be Result** - Parsing/IO operations that can fail
4. **Should be Option** - Lookups that might not find data

**Implementation Steps:**

1. [ ] Audit supervisor.rs unwraps (86)
2. [ ] Audit protocol parsing unwraps (176 in protocols/)
3. [ ] Convert packet parsing panics to Result returns
4. [ ] Add `// SAFETY:` comments for intentionally safe unwraps
5. [ ] Consider using `anyhow` context for better error messages

---

### 5. Consolidate Config Validation

**Location:** `src/config.rs` lines 456-745

**Problem:** 7 separate validation functions with repeated patterns:

- `validate_interface_name()`
- `validate_pim_config()`
- `validate_igmp_config()`
- `validate_msdp_config()`
- `validate_control_plane_config()`
- `validate_group_prefix()`
- Various inline validations

**Proposed Solution:** Create reusable validation primitives:

```rust
// src/validation.rs (new file)
pub trait Validate {
    fn validate(&self) -> Result<(), ConfigError>;
}

pub fn validate_non_empty(value: &str, field_name: &str) -> Result<(), ConfigError> { ... }
pub fn validate_max_length(value: &str, max: usize, field_name: &str) -> Result<(), ConfigError> { ... }
pub fn validate_interface_name(name: &str) -> Result<(), ConfigError> { ... }
pub fn validate_unicast_ipv4(addr: Ipv4Addr, field_name: &str) -> Result<(), ConfigError> { ... }
pub fn validate_multicast_ipv4(addr: Ipv4Addr, field_name: &str) -> Result<(), ConfigError> { ... }
pub fn validate_range<T: Ord>(value: T, min: T, max: T, field_name: &str) -> Result<(), ConfigError> { ... }
```

**Implementation Steps:**

1. [ ] Create `src/validation.rs` with common validators
2. [ ] Refactor `validate_interface_name()` to use common validators
3. [ ] Refactor protocol config validators
4. [ ] Implement `Validate` trait for config structs
5. [ ] Update `Config::validate()` to use trait

---

### 6. Reorganize Worker Module

**Location:** `src/worker/`

**Current Structure (unclear separation):**

```text
src/worker/
├── mod.rs                    (380 lines) - Entry point, privilege dropping
├── unified_loop.rs           (1,273 lines) - Main data plane loop
├── packet_parser.rs          (1,404 lines) - All protocol parsing
├── buffer_pool.rs            (407 lines) - Buffer management
├── command_reader.rs         (185 lines) - Command parsing
├── data_plane_integrated.rs  (77 lines) - Integration wrapper
└── adaptive_wakeup.rs        (458 lines) - Wakeup strategies
```

**Proposed Structure:**

```text
src/worker/
├── mod.rs                    # Re-exports, entry point
├── lifecycle.rs              # Privilege dropping, CPU affinity, shutdown
├── data_plane/
│   ├── mod.rs               # UnifiedDataPlane struct
│   ├── receive.rs           # Receive buffer management
│   ├── send.rs              # Send queue and batch submission
│   └── stats.rs             # Statistics tracking
├── parsing/
│   ├── mod.rs               # ParsedPacket, common types
│   ├── ipv4.rs              # IPv4 header parsing
│   ├── udp.rs               # UDP parsing
│   ├── igmp.rs              # IGMP parsing
│   └── pim.rs               # PIM parsing
├── io/
│   ├── buffer_pool.rs       # Buffer management
│   ├── command_reader.rs    # Command parsing
│   └── adaptive_wakeup.rs   # Wakeup strategies
```

**Implementation Steps:**

1. [ ] Create directory structure
2. [ ] Split `packet_parser.rs` by protocol
3. [ ] Split `unified_loop.rs` into receive/send/stats
4. [ ] Move utilities to `io/` submodule
5. [ ] Update imports
6. [ ] Verify tests pass

---

### 7. Implement Lazy Socket Creation

**Location:** `src/supervisor.rs` (worker spawning)

**Problem:** Workers create all AF_PACKET sockets upfront, causing resource exhaustion on systems with many interfaces.

**Current Comment:**

```rust
// TODO: ARCHITECTURAL FIX NEEDED
// Per architecture (D21, D23): One worker per CPU core, rules hashed to cores.
// The --num-workers override exists to avoid resource exhaustion on single-interface tests
// until lazy socket creation is implemented.
```

**Proposed Solution:**

1. Workers start without sockets
2. First rule for an interface triggers socket creation
3. Socket pool tracks: interface -> (socket_fd, refcount)
4. Last rule removal triggers socket cleanup

**Implementation Steps:**

1. [ ] Design socket pool data structure
2. [ ] Modify worker initialization to defer socket creation
3. [ ] Add socket creation on first rule addition
4. [ ] Add socket cleanup on last rule removal
5. [ ] Update fanout group management
6. [ ] Add tests for socket lifecycle

---

## LOW Priority

### 8. Consolidate Display Implementations

**Location:** `src/lib.rs` (10 impl Display blocks)

**Problem:** Repetitive pattern across enum Display implementations.

**Solution Options:**

1. Use `strum` crate with `#[derive(Display)]`
2. Define string constants and simple match
3. Use macro to generate implementations

**Example with strum:**

```rust
use strum_macros::Display;

#[derive(Display)]
pub enum RuleSource {
    #[strum(serialize = "static")]
    Static,
    #[strum(serialize = "dynamic")]
    Dynamic,
    // ...
}
```

**Implementation Steps:**

1. [ ] Evaluate adding `strum` dependency
2. [ ] Convert enum Display implementations
3. [ ] Verify serialization compatibility

---

### 9. Create Shared Test Fixtures

**Location:** Tests scattered across 15+ modules

**Problem:** Test helper functions duplicated across modules:

- `create_test_rule()` in multiple files
- Test config builders repeated
- No shared test utilities

**Proposed Solution:**

```text
tests/
├── common/
│   ├── mod.rs
│   ├── fixtures.rs      # Test data builders
│   ├── config.rs        # Test config helpers
│   └── protocol.rs      # Protocol test helpers
├── integration/
│   └── ...
└── unit/
    └── ...
```

**Implementation Steps:**

1. [ ] Create `tests/common/` module
2. [ ] Extract common test helpers
3. [ ] Create builder patterns for test data
4. [ ] Update existing tests to use shared fixtures

---

### 10. Standardize API Naming

**Problem:** Inconsistent naming across the codebase:

| Pattern | Examples |
|---------|----------|
| Group address | `input_group`, `group`, `group_addr`, `group_address` |
| Enable/Add | `add_igmp_membership()`, `enable_igmp()`, `EnableIgmpQuerier` |
| Response types | `IgmpGroups` vs `PimNeighbors` (plural vs singular) |

**Proposed Convention:**

- Internal: Always use `group_address` or `group_addr`
- CLI flags: Use `--group` for brevity
- API responses: Use plural noun form (`Groups`, `Neighbors`, `Peers`)
- Methods: `enable_*` for features, `add_*` for entries, `set_*` for config

**Implementation Steps:**

1. [ ] Document naming conventions in CONTRIBUTING.md
2. [ ] Audit and list all inconsistencies
3. [ ] Create migration plan (may require API version bump)
4. [ ] Apply renames with backwards compatibility aliases

---

## Implementation Roadmap

### Phase 1: Critical Structure (Weeks 1-2)

1. Split supervisor.rs into modules
2. Extract timestamp utility
3. Begin protocol/MRIB decoupling design

### Phase 2: Quality Improvements (Weeks 3-4)

1. Audit and fix critical unwrap() calls
2. Implement validation framework
3. Complete protocol/MRIB decoupling

### Phase 3: Organization (Weeks 5-6)

1. Reorganize worker module
2. Implement lazy socket creation
3. Create shared test fixtures

### Phase 4: Polish (Weeks 7-8)

1. Consolidate Display implementations
2. Standardize API naming
3. Documentation updates

---

## Effort Estimates

| Task | Priority | Effort | Risk |
|------|----------|--------|------|
| Split supervisor.rs | HIGH | 20-30h | Medium |
| Protocol/MRIB decoupling | HIGH | 15-20h | High |
| Timestamp utility | HIGH | 1h | Low |
| Unwrap audit | MEDIUM | 20-30h | Medium |
| Validation framework | MEDIUM | 10h | Low |
| Worker reorganization | MEDIUM | 15h | Medium |
| Lazy socket creation | MEDIUM | 15-20h | High |
| Display consolidation | LOW | 3h | Low |
| Test fixtures | LOW | 8h | Low |
| API naming | LOW | 10h | Medium |

**Total Estimated Effort:** 115-145 hours

---

## Success Criteria

1. No single file exceeds 2,000 lines
2. All protocol handlers can be unit tested without MRIB
3. Zero unwrap() calls in packet parsing paths
4. Config validation uses shared primitives
5. Worker module has clear submodule structure
6. All existing tests continue to pass
