# Technical Debt

This document tracks known architectural issues that need to be addressed.

## Critical: AF_PACKET Socket FD Passing for Privilege Separation

**Status**: Needs implementation
**Priority**: Critical (Security)
**Architecture References**: Section 8 (Security and Privilege Model)

### Current Issue

Data plane workers currently run as **root** and cannot drop privileges properly. This is a significant security issue.

**Root Cause**: Workers need `CAP_NET_RAW` to create AF_PACKET sockets, but Linux **clears ambient capabilities when `setuid()` is called**. This means:
1. Worker starts as root
2. Worker tries to drop privileges to `nobody` while retaining `CAP_NET_RAW`
3. The `setuid()` call clears all ambient capabilities
4. Child threads don't inherit `CAP_NET_RAW`
5. AF_PACKET socket creation fails with `EPERM`

### Proper Solution: FD Passing Architecture

Implement proper privilege separation via file descriptor passing:

1. **Supervisor (runs as root)**:
   - When spawning a data plane worker, determine which interfaces it needs
   - Create AF_PACKET socket(s) for those interfaces (has full root privileges)
   - Pass socket FDs to worker via SCM_RIGHTS (already used for other sockets)

2. **Worker (drops to nobody)**:
   - Receives AF_PACKET socket FDs from supervisor
   - Drops ALL privileges completely (no capabilities retained)
   - Uses pre-created sockets for packet I/O

This is the **textbook solution** for privilege separation with raw sockets.

### Benefits

- Workers run with zero privileges (true least-privilege)
- Follows Unix security best practices
- Simpler than managing capabilities across threads
- More secure - no risk of capability escalation

### Implementation Steps

1. Extend `spawn_data_plane_worker()` to create AF_PACKET sockets
2. Pass socket FDs via SCM_RIGHTS alongside command/request streams
3. Update `IngressLoop::new()` to accept pre-created socket FD
4. Remove CAP_NET_RAW retention from worker privilege drop
5. Update tests to verify workers run as `nobody` with no capabilities

### Temporary Workaround

Data plane workers currently run as **root** without dropping privileges. This is noted in the code with TODO comments:
- `src/worker/mod.rs:223-244` - Privilege drop disabled

---

## Critical: Lazy AF_PACKET Socket Creation

**Status**: Needs implementation
**Priority**: High
**Architecture References**: D21, D23

### Current Issue

Data plane workers currently create AF_PACKET sockets **eagerly** on startup using a global `--interface` parameter passed from the supervisor. This causes multiple problems:

1. **Resource Exhaustion**: When spawning N workers (one per CPU core), all N workers create identical AF_PACKET sockets on the same interface, exhausting kernel resources (file descriptors, socket buffers, io_uring queues).

2. **Architectural Violation**: Per the architecture document (D21, D23):
   - Workers should be assigned rules via consistent hashing
   - Each worker handles rules for multiple interfaces as assigned
   - Interfaces should come from `ForwardingRule.input_interface`, not a global parameter

3. **Inefficient**: Multiple identical sockets capture duplicate packets unnecessarily.

### Proper Solution

Implement **lazy socket creation**:

1. Workers start with **no AF_PACKET sockets**
2. When supervisor assigns a rule to a worker via `RelayCommand::AddRule`:
   - Worker extracts `rule.input_interface`
   - If no socket exists for that interface yet, create one (worker retains `CAP_NET_RAW` for this)
   - Add rule to the per-interface rule lookup table
3. Each worker maintains a `HashMap<String, AF_PACKET_Socket>` mapping interface names to sockets
4. Multiple rules on the same worker sharing an interface reuse the same socket

### Temporary Workarounds

Until lazy socket creation is implemented:

- **`--num-workers` parameter**: Allows limiting worker count for single-interface tests (e.g., `--num-workers 1` for loopback tests)
- **`--interface` parameter**: Global interface parameter (should be removed once lazy creation works)

### Files Affected

- `src/worker/data_plane_integrated.rs:97-107` - Eager socket creation
- `src/worker/ingress.rs` - IngressLoop::new() creates socket immediately
- `src/lib.rs:41-45` - Temporary --interface parameter
- `src/supervisor.rs:165-171` - Temporary --num-workers logic

### Implementation Steps

1. Modify `IngressLoop` to support creating sockets lazily when rules are added
2. Change `IngressLoop::new()` to NOT require an interface - start with empty socket map
3. Add `IngressLoop::ensure_socket_for_interface()` called from `add_rule()`
4. Update `IngressLoop::run()` to poll all interface sockets (not just one)
5. Remove `--interface` from supervisor CLI
6. Remove `input_interface_name` from `DataPlaneConfig`
7. Update tests to verify multi-interface handling per worker

## Related: Remove Global --interface Parameter

**Status**: Blocked by lazy socket creation
**Priority**: High
**Architecture References**: D21

The supervisor's `--interface` parameter is an architectural violation. Per D21:

> The `ForwardingRule` structure includes a mandatory `input_interface` field. The application supports configuring rules across multiple distinct input and output interfaces.

Interfaces should come from rules, not be specified globally. This parameter exists only to support the current eager socket creation and should be removed once lazy creation is implemented.

---

*Last Updated*: 2025-01-09
