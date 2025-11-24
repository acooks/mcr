# PoC: File Descriptor Passing with Privilege Drop

**Status:** 🔴 **CRITICAL PRIORITY** - Blocks privilege separation architecture

This experiment validates a core security architecture assumption (D24) for the multicast relay application.

## The Problem

The privilege separation model requires:

1. **Supervisor (privileged)** creates `AF_PACKET` sockets (requires `CAP_NET_RAW`)
2. **Passes socket FDs** to unprivileged worker processes via Unix domain socket + `SCM_RIGHTS`
3. **Workers (unprivileged)** use sockets without ever having `CAP_NET_RAW`

**This is unproven.** If socket capabilities don't survive FD passing to unprivileged processes, **the entire security architecture fails**.

## Why This Pattern?

The relay needs to:
- Create `AF_PACKET` sockets (requires root/CAP_NET_RAW)
- Process packets in unprivileged worker processes (minimize attack surface)
- Isolate privilege requirements to supervisor only

The FD passing pattern achieves this by:
- Supervisor creates sockets with necessary capabilities
- Workers receive pre-created sockets via file descriptor passing
- Workers never need privileges themselves

## What Could Go Wrong?

**Unproven Assumptions:**

1. **Socket Capabilities Survive?**
   - Does an `AF_PACKET` socket created with `CAP_NET_RAW` still work after being passed to an unprivileged process?
   - Do socket options (binding, protocol) transfer correctly?

2. **Receive Operations Work?**
   - Can the unprivileged process call `recvfrom()` on the passed socket?
   - Does packet capture continue to work without privileges?

3. **io_uring Compatibility?**
   - Can the passed FD be used with `io_uring` operations in the unprivileged process?

## Experiment Design

### Process Architecture

```text
┌────────────────────────────────┐
│   Privileged Parent (root)     │
│                                │
│  1. Create AF_PACKET socket    │──┐ Requires CAP_NET_RAW
│     (bound to interface)       │  │
│                                │  │
│  2. Create Unix socketpair     │  │
│                                │  │
│  3. Fork child process         │  │
│         │                      │  │
│         │                      │  │
│         ▼                      │  │
│  4. Pass AF_PACKET FD          │  │
│     via SCM_RIGHTS       ──────┼──┘
└────────────────────────────────┘
         │
         │ (socketpair)
         │
         ▼
┌────────────────────────────────┐
│   Child Process                │
│                                │
│  5. Receive FD from parent     │◄─┐
│                                │  │
│  6. Drop ALL privileges        │  │ setuid(nobody)
│     (setuid/setgid to nobody)  │──┘ setgid(nobody)
│                                │
│  7. Verify CAP_NET_RAW gone    │──┐ Try create new
│     (cannot create new socket) │  │ AF_PACKET socket
│                                │◄─┘ (should fail)
│  8. Use passed AF_PACKET FD    │──┐
│     to receive packets         │  │ recvfrom() on
│                                │◄─┘ passed FD
└────────────────────────────────┘
```

### Test Procedure

The experiment:

1. **Checks root** - Must be running as root initially
2. **Creates AF_PACKET socket** - Privileged operation
3. **Creates Unix socketpair** - For IPC between parent/child
4. **Forks child process** - Using `fork()`
5. **Parent passes FD** - Via `sendmsg()` with `SCM_RIGHTS`
6. **Child receives FD** - Via `recvmsg()` with `SCM_RIGHTS`
7. **Child drops privileges** - `setuid(nobody)`, `setgid(nobody)`
8. **Child verifies no privileges** - Attempts to create new AF_PACKET socket (should fail)
9. **Child uses passed socket** - Attempts to receive packets using the FD
10. **Reports results** - Success if at least 1 packet received

### Success Criteria

✅ **Pass** if:
- FD passes successfully via SCM_RIGHTS
- Child can drop to `nobody:nobody` (UID/GID 65534)
- Child cannot create new AF_PACKET sockets (privilege verification)
- Child can receive at least 1 packet using the passed socket FD

❌ **Fail** if:
- FD passing fails
- Child retains root privileges after drop attempt
- Passed socket FD doesn't work for packet reception
- Any permission denied errors when using passed socket

## How to Run

This experiment requires `sudo` privileges.

```bash
cd experiments/poc_fd_passing_privdrop
sudo ./run_test.sh
```

The test script will:
1. Build the experiment
2. Create isolated network namespace
3. Set up veth pair
4. Run the experiment
5. Report results

### Expected Output (if successful)

```text
=== File Descriptor Passing with Privilege Drop Experiment ===

Configuration:
  Interface: veth-fdpass
  Running as: root (UID 0)

[Parent/Privileged] Creating AF_PACKET socket...
  ✓ AF_PACKET socket created (FD: 3)
  ✓ Socket has CAP_NET_RAW privileges

[Parent/Privileged] Creating Unix domain socketpair for FD passing...
  ✓ Socketpair created for IPC

[Parent/Privileged] Forking child process...
  ✓ Forked child process (PID: 12345)

[Parent/Privileged] Passing AF_PACKET socket FD to child...
  ✓ FD passed to child via SCM_RIGHTS

[Child/Privileged] Child process started
  Current UID: 0
  Current GID: 0

[Child/Privileged] Receiving AF_PACKET socket FD from parent...
  ✓ Received FD: 3

[Child/Privileged] Dropping all privileges...
  ✓ Privileges dropped!
  New UID: 65534 (unprivileged)
  New GID: 65534 (unprivileged)

[Child/Unprivileged] Verifying CAP_NET_RAW is gone...
  ✓ Cannot create new AF_PACKET sockets (CAP_NET_RAW dropped)

[Child/Unprivileged] Attempting to receive packets using passed socket...
  Waiting for 5 packets...

  [1] Received packet: 90 bytes
      → IPv6
  [2] Received packet: 54 bytes
      → IPv4 (protocol: 2)
  ...

[Child/Unprivileged] Test Results:
  Packets received: 5/5

✓ SUCCESS: File descriptor passing works!
  - AF_PACKET socket created with CAP_NET_RAW
  - Socket FD passed via SCM_RIGHTS
  - Unprivileged child can use the socket
  - Received 5 packet(s) without privileges

✓ Core assumption validated: D24 (Privilege Separation) is viable
```

## Architectural Impact

### If Successful (Expected)

✅ **Validates:** Design decision D24

The security architecture can proceed as designed:
- Supervisor creates sockets with privileges
- Workers receive pre-created sockets via FD passing
- Workers run as unprivileged users (minimal attack surface)
- Socket capabilities survive the privilege boundary

### If Failed (Unexpected)

❌ **Invalidates:** Privilege separation model

Would require major redesign:

**Option 1:** Keep workers privileged
- Larger attack surface
- Violates security best practices
- Not acceptable for production

**Option 2:** Use different socket type
- Try standard `AF_INET` sockets (but requires solving RPF problem)
- Reduced performance (kernel processing overhead)

**Option 3:** Use kernel bypass (XDP/DPDK)
- Entirely different architecture
- Higher complexity, different trade-offs

## Key Learnings

**✅ Experiment Status: SUCCESSFUL** (2025-11-07)

### What We Validated

1. **AF_PACKET Socket Capabilities Survive Privilege Drop** ✅
   - Socket created with `CAP_NET_RAW` continues to function after being passed to an unprivileged process
   - Unprivileged process (UID/GID 65534 - nobody:nobody) successfully received 5/5 test packets
   - Socket remains bound to interface and continues capturing packets

2. **FD Passing via SCM_RIGHTS Works Correctly** ✅
   - Unix domain socketpair successfully transfers AF_PACKET socket file descriptor
   - Parent process (privileged) → Child process (unprivileged) communication verified
   - FD numbering changes across processes (FD 3 in parent → FD 4 in child) as expected

3. **Privilege Drop is Complete and Irreversible** ✅
   - Child process successfully drops from UID 0 → UID 65534
   - Child process successfully drops from GID 0 → GID 65534
   - After privilege drop, child cannot create new AF_PACKET sockets
   - Verification test confirmed `CAP_NET_RAW` is completely gone

4. **Security Pattern Works as Designed** ✅
   - Privileged supervisor creates sockets requiring capabilities
   - Workers receive pre-created sockets via FD passing
   - Workers run without any elevated privileges
   - Attack surface minimized to unprivileged worker processes

### Implementation Details

**nix 0.30 API Usage:**
- `sendmsg()`/`recvmsg()` accept raw `i32` file descriptors (not `BorrowedFd`)
- `ControlMessage::ScmRights(&[i32])` for sending FDs
- `msg.cmsgs()` returns `Result<CmsgIterator>` requiring `.context()?` handling
- Iterator pattern: `let mut cmsgs = msg.cmsgs()?; while let Some(cmsg) = cmsgs.next() { ... }`

**Fork Safety:**
- Parent must close child's socket, child must close parent's socket
- Proper cleanup required in both processes
- Parent can wait for child completion via socketpair communication

**Network Namespace Testing:**
- Test harness creates isolated network environment
- veth pair simulates real network interface
- IPv6 neighbor discovery provides test traffic

### Architectural Impact

#### ✅ Design Decision D24 (Privilege Separation) is VALIDATED

This confirms the core security architecture can proceed as designed:
- **Phase 2**: Supervisor process creates AF_PACKET sockets with `CAP_NET_RAW`
- **Phase 3**: Supervisor passes socket FDs to worker processes via SCM_RIGHTS
- **Phase 3**: Worker processes drop all privileges immediately after receiving FDs
- **Phase 4**: Workers process packets without any elevated privileges

**Security Benefits Confirmed:**
- Workers run as unprivileged users (e.g., `mcrelay:mcrelay`)
- Even if a worker is compromised, attacker gains no special capabilities
- Cannot create new privileged sockets
- Cannot regain elevated privileges
- Attack surface limited to standard user capabilities

### Related Validations

- ✅ **D24**: Privilege separation pattern validated
- ✅ **D1**: AF_PACKET sockets work as expected in this pattern
- ✅ **D18**: Supervisor pattern confirmed viable
- 🔄 **D7**: Still need to validate io_uring operations with passed FDs (Experiment #3)

## Related Design Decisions

- **D24 (Privilege Separation):** The core security pattern being tested
- **D1 (AF_PACKET):** Socket type that requires privileges
- **D7 (io_uring):** Will also need to validate io_uring with passed FDs (future test)
- **D18 (Supervisor Pattern):** Supervisor manages privileged operations

## Related Documents

- `ARCHITECTURE.md` - Design decisions D24, D1, D7
- `experiments/README.md` - Experiments index

## Next Steps

After validating this pattern:

1. Document findings in `DEVLOG.md`
2. If successful, proceed with supervisor implementation
3. If failed, convene design review to reassess security architecture
4. Consider additional test: FD passing with `io_uring` operations
