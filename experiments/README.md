# Experiments Directory

This directory contains standalone proof-of-concept (PoC) code used to de-risk complex technical decisions and explore tricky implementation patterns before integrating them into the main application.

## Purpose

As stated in testing/PRACTICAL_TESTING_GUIDE.md:

> For particularly complex or high-risk features, we will first build small, standalone prototypes in the `experiments/` directory. These prototypes serve multiple critical purposes:
>
> - **Risk Reduction:** Isolate and de-risk core technical challenges
> - **Demonstration:** Provide concrete, runnable examples
> - **Teaching Aid:** Onboard new contributors with focused examples

**These are not disposable code** - they are treasured artifacts that ensure continuity of knowledge within the project.

---

## Experiments Index

### 1. `closure_passing_test.rs`

**Topic:** Async Closure Passing

**Problem:** How to pass async closures to a function expecting `FnMut` when the closure needs to be called multiple times.

**Key Learning:** Demonstrates the signature mismatch between async functions (which return `Future<Output=T>`) and sync function pointers.

**Status:** Minimal example isolating the problem. See `poc_closure_ownership.rs` for the solution.

**Run:** `cargo run --bin closure_passing_test`

---

### 2. `poc_closure_ownership.rs`

**Topic:** Correct Ownership for `FnMut` Closures

**Problem:** When a closure captures a non-Copy type (like `PathBuf` or `String`), calling it multiple times can violate the `FnMut` contract by moving the captured value.

**Key Learning:**

- Demonstrates proper cloning strategies for captured variables
- Shows how to maintain ownership across multiple closure invocations
- Critical for supervisor spawn pattern implementation

**Architectural Impact:** Used to design the supervisor's worker spawning interface.

**Run:** `cargo run --bin poc_closure_ownership`

---

### 3. `poc_io_uring_af_packet/`

**Topic:** `io_uring` Integration with `AF_PACKET` Sockets

**Problem:** Can raw `AF_PACKET` file descriptors created via `libc` be integrated with `tokio-uring`?

**Key Learning:**

- Proves D7 (io_uring integration) and D1 (AF_PACKET usage) are compatible
- Demonstrates low-level socket setup without high-level abstractions
- Created after challenges with `nix` crate abstractions

**Architectural Impact:** **Critical** - This validates the core ingress data path design.

**Related Designs:** D1 (AF_PACKET), D7 (io_uring), D2 (core affinity)

**Run:** `cd poc_io_uring_af_packet && sudo ./run_test.sh`

**Documentation:** See `poc_io_uring_af_packet/README.md`

---

### 4. `poc_tokio_uring_concurrency/`

**Topic:** Task Management in Single-Threaded `tokio-uring`

**Problem:** `tokio-uring` is single-threaded, so types don't need to be `Send`. But `tokio::spawn` requires `Send`. How do we spawn concurrent tasks?

**Key Learning:**

- Use `tokio::task::spawn_local` instead of `tokio::spawn`
- Demonstrates correct pattern for managing multiple background tasks
- Shows how to dynamically start/stop tasks using `JoinHandle::abort()`

**Architectural Impact:** Provides blueprint for `worker/mod.rs` task management.

**Related Designs:** D2 (core-pinned threads), D7 (tokio-uring)

**Run:** `cd poc_tokio_uring_concurrency && cargo run`

**Documentation:** See `poc_tokio_uring_concurrency/README.md`

---

### 5. `poc_supervisor_lifecycle/`

**Topic:** Supervisor Process Lifecycle Management

**Problem:** How does the supervisor track and restart worker processes?

**Key Learning:**

- Demonstrates process spawning and monitoring
- Shows signal handling for worker failures
- Explores patterns for maintaining master state

**Architectural Impact:** Foundation for D18 (Supervisor Pattern for Resilience).

**Related Designs:** D18 (supervisor restart logic), D24 (privilege separation)

**Run:** `cd poc_supervisor_lifecycle && cargo run`

---

### 6. `poc_supervisor_failure_handling/`

**Topic:** Supervisor Failure Detection and Recovery

**Problem:** How does the supervisor detect when a worker crashes and trigger a restart?

**Key Learning:**

- Demonstrates process exit status monitoring
- Explores different failure detection strategies
- Tests restart logic edge cases

**Architectural Impact:** Complements D18 implementation.

**Related Designs:** D18 (supervisor pattern), D19 (network state reconciliation)

**Run:** `cd poc_supervisor_failure_handling && cargo run`

---

### 7. `poc_helper_socket_igmp/` ✅ COMPLETED

**Topic:** Helper Socket Pattern for IGMP + NIC Filtering

**Problem:** Can we use an AF_INET socket SOLELY to trigger IGMP joins while receiving packets via a separate AF_PACKET socket?

**Key Learning:**

- ✅ Kernel maintains IGMP membership for unread sockets
- ✅ NIC MAC filtering programmed correctly from helper socket
- ✅ AF_PACKET receives packets, helper socket remains empty
- ✅ Sockets operate independently without interference
- **Critical Bug:** Must use `into_raw_fd()` not `as_raw_fd()` for ownership

**Architectural Impact:** **CRITICAL** - Validates D6, D4, D3. Core ingress path design confirmed viable!

**Related Designs:** D6 (Helper Socket Pattern), D4 (Hardware Filtering), D3 (Userspace Demux), D1 (AF_PACKET)

**Status:** ✅ **VALIDATED** (2025-11-07) - No architectural redesign needed, proceed with data plane!

**Run:** `cd poc_helper_socket_igmp && sudo ./run_test.sh`

**Documentation:** See `poc_helper_socket_igmp/README.md` for complete findings

---

### 8. `poc_fd_passing_privdrop/` ✅ COMPLETED

**Topic:** File Descriptor Passing with Privilege Drop

**Problem:** Can AF_PACKET sockets created with CAP_NET_RAW be passed to unprivileged worker processes and still function correctly?

**Key Learning:**

- ✅ Socket capabilities survive FD passing to unprivileged process (UID/GID 65534)
- ✅ SCM_RIGHTS successfully transfers socket FD via Unix domain socketpair
- ✅ Privilege drop is complete and irreversible (CAP_NET_RAW verified gone)
- ✅ Unprivileged process can call `recvfrom()` on passed AF_PACKET socket
- **nix 0.30 API:** `sendmsg()`/`recvmsg()` accept raw `i32` FDs (not `BorrowedFd`)
- **Fork safety:** Parent/child must close opposite socket ends

**Architectural Impact:** **CRITICAL** - Validates D24 (Privilege Separation). Security architecture confirmed viable!

**Related Designs:** D24 (Privilege Separation), D1 (AF_PACKET), D18 (Supervisor Pattern), D7 (io_uring)

**Status:** ✅ **VALIDATED** (2025-11-07) - Workers can safely run as unprivileged users!

**Run:** `cd poc_fd_passing_privdrop && ./run_test.sh`

**Documentation:** See `poc_fd_passing_privdrop/README.md` for complete findings

---

## Experiment Lifecycle

### When to Create an Experiment

Create a new experiment when:

1. **High Technical Risk:** The approach hasn't been proven to work
2. **Complex Integration:** Multiple subsystems need to interact in a non-obvious way
3. **Performance Critical:** Need to validate performance characteristics before committing
4. **Team Knowledge Gap:** Concept needs clear demonstration for team understanding

### When to Archive an Experiment

Experiments are **never deleted** but may be moved to `experiments/archive/` when:

- The pattern has been successfully integrated into the main codebase
- The codebase has evolved such that the problem no longer exists
- The experiment has been superseded by a better approach (keep both!)

### Documentation Requirements

Each experiment should have:

- Clear problem statement (what are we trying to prove?)
- Key learnings (what did we discover?)
- Architectural impact (how does this affect the design?)
- Run instructions (how to reproduce the experiment)

---

## Running All Experiments

Most experiments are standalone and can be run independently:

```bash
# Rust file experiments (in main Cargo workspace)
cargo run --bin closure_passing_test
cargo run --bin poc_closure_ownership

# Directory-based experiments (self-contained crates)
cd experiments/poc_io_uring_af_packet && sudo ./run_test.sh
cd experiments/poc_tokio_uring_concurrency && cargo run
cd experiments/poc_supervisor_lifecycle && cargo run
cd experiments/poc_supervisor_failure_handling && cargo run
```

**Note:** Some experiments require elevated privileges (`sudo`) for network namespace manipulation.

---

## Related Documentation

- **testing/PRACTICAL_TESTING_GUIDE.md** - Overall testing philosophy, explains the role of prototypes
- **ARCHITECTURE.md** - Design decisions that experiments validate
- **IMPLEMENTATION_PLAN.md** - Integration plan for proven patterns
- **DEVLOG.md** - Historical record of why experiments were created

---

## Contributing New Experiments

When adding a new experiment:

1. **Use clear, descriptive names:** `poc_<feature>_<specific_challenge>`
2. **Add to this README:** Update the index with problem, learnings, and impact
3. **Include a README (for directory-based experiments):** Explain how to run it
4. **Reference design decisions:** Link to relevant D-numbers in ARCHITECTURE.md
5. **Keep it minimal:** Only include code necessary to prove the concept
6. **Make it runnable:** Should work with `cargo run` or a simple script

---

**Remember:** These experiments are knowledge artifacts. Treat them as documentation, not throwaway code.
