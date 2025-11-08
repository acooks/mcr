# Integration Test Implementation Guide

This guide provides step-by-step instructions for implementing the supervisor resilience integration tests.

## Overview

The supervisor resilience tests in `supervisor_resilience.rs` validate the core promise of the multicast relay system: that the supervisor can detect worker failures, restart them, and resynchronize their state.

These tests are currently stubbed with `#[ignore]` attributes and need implementation.

## Prerequisites

Before implementing these tests, you need:

1. ✅ `list-workers` command implemented (DONE in commit b12611d)
2. ✅ Rule dispatcher implemented (DONE in commit f34b64d)
3. ✅ `tests/lib.rs` with UUID-based socket helpers (DONE in commit 918b90f)
4. Understanding of supervisor worker lifecycle (see `src/supervisor.rs`)

## Implementation Order

Implement in this order to build complexity gradually:

### 1. Helper Functions (30-60 minutes)

Start by implementing the 3 helper functions at the top of `supervisor_resilience.rs`:

#### `async fn start_supervisor() -> Result<(Child, PathBuf)>`

**Purpose**: Spawn a supervisor process for testing

**Implementation steps**:
```rust
async fn start_supervisor() -> Result<(Child, PathBuf)> {
    // 1. Generate unique socket paths
    let control_socket = unique_socket_path_with_prefix("supervisor_control");
    let relay_socket = unique_socket_path_with_prefix("supervisor_relay");

    // 2. Clean up any existing sockets
    cleanup_socket(&control_socket);
    cleanup_socket(&relay_socket);

    // 3. Get path to the multicast_relay binary
    let binary = env!("CARGO_BIN_EXE_multicast_relay");

    // 4. Spawn supervisor process
    let supervisor = Command::new(binary)
        .arg("supervisor")
        .arg("--control-socket-path").arg(&control_socket)
        .arg("--relay-command-socket-path").arg(&relay_socket)
        .spawn()?;

    // 5. Wait for socket to be created (with timeout)
    for _ in 0..30 {  // 3 second timeout
        if control_socket.exists() {
            sleep(Duration::from_millis(100)).await;  // Give it a moment to stabilize
            return Ok((supervisor, control_socket));
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("Supervisor did not create socket within timeout")
}
```

**Testing**: After implementing, test it in isolation:
```bash
cargo test --test supervisor_resilience start_supervisor -- --exact --nocapture
```

#### `async fn kill_worker(pid: u32) -> Result<()>`

**Purpose**: Forcibly kill a worker process to simulate crash

**Implementation steps**:
```rust
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

async fn kill_worker(pid: u32) -> Result<()> {
    // Send SIGKILL to the process
    kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
        .context(format!("Failed to kill worker {}", pid))?;

    // Give the OS a moment to process the signal
    sleep(Duration::from_millis(50)).await;

    Ok(())
}
```

**Note**: Add `nix = { version = "0.27", features = ["signal"] }` to `dev-dependencies` if not already present.

#### `fn is_process_running(pid: u32) -> bool`

**Purpose**: Check if a process exists

**Implementation**:
```rust
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

fn is_process_running(pid: u32) -> bool {
    // Sending signal 0 doesn't actually send a signal,
    // but checks if we have permission to send one
    // (i.e., if the process exists)
    kill(Pid::from_raw(pid as i32), Signal::from_c_int(0).unwrap()).is_ok()
}
```

### 2. Test 1: `test_supervisor_restarts_control_plane_worker()` (1-2 hours)

**Purpose**: Verify supervisor detects and restarts crashed control plane worker

**Implementation strategy**:

```rust
#[tokio::test]
async fn test_supervisor_restarts_control_plane_worker() -> Result<()> {
    // Step 1: Start supervisor
    let (mut supervisor, socket_path) = start_supervisor().await?;

    // Step 2: Get control plane worker PID
    // Use the list-workers command (implemented in commit b12611d)
    let client = /* create control client connected to socket_path */;
    let workers = client.list_workers().await?;
    let cp_worker = workers.iter()
        .find(|w| w.worker_type == "ControlPlane")
        .ok_or_else(|| anyhow::anyhow!("No control plane worker found"))?;
    let original_pid = cp_worker.pid;

    println!("[TEST] Control plane worker PID: {}", original_pid);

    // Step 3: Kill the worker
    kill_worker(original_pid).await?;

    // Verify it's actually dead
    sleep(Duration::from_millis(200)).await;
    assert!(!is_process_running(original_pid), "Worker should be dead");

    // Step 4-5: Wait for supervisor to detect and restart
    // Poll for up to 5 seconds
    let mut new_pid = None;
    for i in 0..50 {
        sleep(Duration::from_millis(100)).await;

        if let Ok(workers) = client.list_workers().await {
            if let Some(cp) = workers.iter().find(|w| w.worker_type == "ControlPlane") {
                if cp.pid != original_pid && is_process_running(cp.pid) {
                    new_pid = Some(cp.pid);
                    println!("[TEST] Worker restarted with PID: {}", cp.pid);
                    break;
                }
            }
        }
    }

    // Step 6: Verify restart succeeded
    assert!(new_pid.is_some(), "Supervisor should have restarted worker");
    let new_pid = new_pid.unwrap();
    assert_ne!(new_pid, original_pid, "New worker should have different PID");
    assert!(is_process_running(new_pid), "New worker should be running");

    // Cleanup
    supervisor.kill().await?;
    cleanup_socket(&socket_path);

    Ok(())
}
```

**Debugging tips**:
- If test hangs, check supervisor output with `--nocapture`
- Verify socket paths are unique
- Check that `list-workers` command works correctly

### 3. Test 2: `test_supervisor_resyncs_rules_on_restart()` (1-2 hours)

**Purpose**: Verify workers receive all active rules after restart (D23)

**Key difference**: This test adds rules before killing the worker, then verifies the new worker receives them.

**Implementation outline**:
```rust
#[tokio::test]
async fn test_supervisor_resyncs_rules_on_restart() -> Result<()> {
    // 1. Start supervisor
    let (mut supervisor, socket_path) = start_supervisor().await?;
    let client = /* control client */;

    // 2. Add several forwarding rules
    let rule1 = ForwardingRule { /* ... */ };
    let rule2 = ForwardingRule { /* ... */ };
    client.add_rule(rule1).await?;
    client.add_rule(rule2).await?;

    // Give rules time to propagate
    sleep(Duration::from_millis(200)).await;

    // 3. Kill a data plane worker
    let workers = client.list_workers().await?;
    let dp_worker = workers.iter()
        .find(|w| w.worker_type == "DataPlane")
        .ok_or_else(|| anyhow::anyhow!("No data plane worker found"))?;

    kill_worker(dp_worker.pid).await?;

    // 4. Wait for restart (use same polling pattern as test 1)
    // ...

    // 5. Verify the new worker received the rules
    // This is the tricky part - you need a way to verify worker state
    // Options:
    // a) Send test traffic and verify it's forwarded (requires traffic generator)
    // b) Add a debug endpoint to workers to query their rules (recommended)
    // c) Parse worker logs for "Received AddRule" messages

    // For now, verify the supervisor still reports the rules as active:
    let rules = client.list_rules().await?;
    assert_eq!(rules.len(), 2);

    // Cleanup
    supervisor.kill().await?;
    cleanup_socket(&socket_path);
    Ok(())
}
```

**Note**: Verifying that rules were actually sent to the worker is challenging without adding debugging infrastructure. Consider:
- Adding a `--debug-worker-state` flag that dumps worker state
- Using traffic-based verification (more complex but more realistic)

### 4. Test 3: `test_supervisor_applies_exponential_backoff()` (2-3 hours)

**Purpose**: Verify restart delays increase exponentially on repeated failures

**Challenge**: This test is more complex because you need to measure timing.

**Implementation outline**:
```rust
#[tokio::test]
async fn test_supervisor_applies_exponential_backoff() -> Result<()> {
    // This test requires either:
    // 1. A way to make a worker fail immediately on startup (e.g., --fail-fast flag)
    // 2. A way to observe the supervisor's internal backoff state

    // Recommended approach: Add a test-only mode to supervisor that
    // allows forcing worker failure via environment variable

    // Alternative: Observe restart timings by killing worker repeatedly
    // and measuring time between death and restart

    todo!("Complex test - implement after simpler tests work")
}
```

### 5. Tests 4-5: Multiple failures and namespace tests

These are lower priority and can be implemented after the core resilience tests work.

## Common Issues and Solutions

### Issue: "Supervisor did not create socket"
- **Cause**: Supervisor crashed or socket path is wrong
- **Debug**: Run supervisor manually to see error messages
- **Fix**: Check logs, verify paths, ensure permissions

### Issue: "Worker not found in list-workers"
- **Cause**: Worker hasn't started yet or crashed immediately
- **Debug**: Add sleeps, check supervisor logs
- **Fix**: Increase wait time, verify worker spawn logic

### Issue: Test hangs
- **Cause**: Deadlock in control client or supervisor
- **Debug**: Use `--nocapture` and add debug prints
- **Fix**: Add timeouts to all blocking operations

### Issue: "Process still running after kill"
- **Cause**: Zombie process or PID reuse
- **Debug**: Check `ps aux` for actual process state
- **Fix**: Use `waitpid()` to reap zombie, increase wait time

## Testing Your Implementation

Run tests individually as you implement them:

```bash
# Test helpers only
cargo test --test supervisor_resilience start_supervisor -- --exact --nocapture

# Test 1
cargo test --test supervisor_resilience test_supervisor_restarts_control_plane_worker -- --exact --nocapture

# Test 2
cargo test --test supervisor_resilience test_supervisor_resyncs_rules_on_restart -- --exact --nocapture

# All tests (sequential)
cargo test --test supervisor_resilience -- --test-threads=1 --nocapture
```

## Success Criteria

When complete, you should have:
- ✅ All 5 tests passing without `#[ignore]`
- ✅ Tests run reliably in CI
- ✅ Tests validate core resilience promise (D18, D23)
- ✅ Tests complete in <10 seconds each
- ✅ Clear failure messages when tests fail

## Next Steps

After implementing these tests:
1. Remove all `#[ignore]` attributes
2. Update TESTING_PLAN.md Phase 3 to mark these as complete
3. Run full test suite to ensure no regressions
4. Consider adding more edge case tests (e.g., supervisor restart, multiple failures)
