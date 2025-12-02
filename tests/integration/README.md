# Integration Tests

This directory contains integration tests for the multicast relay that test the full system in isolated network namespaces.

## Structure

```text
integration/
├── common/              # Shared test utilities
│   ├── mod.rs          # Module exports
│   ├── mcr.rs          # McrInstance wrapper for managing MCR processes
│   ├── network.rs      # Network namespace and veth pair management
│   └── stats.rs        # Stats parsing from log files
├── test_basic.rs       # Basic forwarding tests (10, 1000 packets)
├── test_scaling.rs     # Scaling tests (1k, 10k, 1M packets)
├── test_topologies.rs  # Multi-hop and fanout topologies (2-hop, 3-hop, 1:3 fanout)
└── README.md           # This file
```

## Requirements

**These tests require root privileges** because they create network namespaces and veth interfaces.

## Running Tests

### Step 1: Build as regular user (important!)

```bash
cargo build --release --bins
cargo test --test integration --no-run
```

This ensures:

- All binaries are owned by your user, not root
- No permission issues with cargo cache/target directory
- Tests are compiled but not run yet

### Step 2: Run tests with sudo

```bash
# Run all network integration tests
sudo -E cargo test --test integration test_basic -- --ignored --test-threads=1
sudo -E cargo test --test integration test_scaling -- --ignored --test-threads=1
sudo -E cargo test --test integration test_topologies -- --ignored --test-threads=1

# Run a specific test
sudo -E cargo test --test integration test_minimal_10_packets -- --ignored --test-threads=1

# Run with verbose output
sudo -E cargo test --test integration test_basic -- --ignored --test-threads=1 --nocapture
```

**Note:** The `-E` flag preserves your environment variables, ensuring cargo uses the correct toolchain.

**If you run without sudo:**
Tests will gracefully skip with a message explaining they need root privileges.

### Why `--test-threads=1`?

Network namespace tests must run serially because:

- They modify global network state
- Parallel namespace creation can cause resource conflicts
- Test isolation is critical

### Why `--ignored`?

Network tests are marked `#[ignore]` because:

- They require root privileges
- They're slower than unit tests
- They shouldn't run in normal `cargo test`

## Test Utilities

### McrInstance

Manages an MCR process:

```rust
let mut mcr = McrInstance::start("veth0p", Some(0))?; // Start on core 0
mcr.add_rule("239.1.1.1:5001", vec!["239.2.2.2:5002:lo"])?;
let stats = mcr.shutdown_and_get_stats()?;
```

Features:

- Automatic process cleanup on drop
- Captures stdout/stderr to log file
- Waits for control socket to be ready
- Graceful shutdown with SIGTERM

### NetworkNamespace

Creates an isolated network namespace:

```rust
let _ns = NetworkNamespace::enter()?;
_ns.enable_loopback().await?;
// All network operations now isolated
// Namespace destroyed when _ns is dropped
```

### VethPair

Creates virtual ethernet pairs:

```rust
let _veth = VethPair::create("veth0", "veth0p")
    .await?
    .set_addr("veth0", "10.0.0.1/24").await?
    .set_addr("veth0p", "10.0.0.2/24").await?
    .up().await?;
```

Features:

- Fluent builder API
- Automatic cleanup on drop
- IP address configuration
- Link state management

### Stats

Parses statistics from MCR log files:

```rust
let stats = Stats::from_log_file("/tmp/mcr.log")?;
println!("Matched: {}", stats.ingress.matched);
println!("Sent: {}", stats.egress.sent);
```

Features:

- Prefers `STATS:Ingress FINAL` for accuracy
- Falls back to last periodic stat if needed
- Structured data (no string parsing in tests)

## Writing New Tests

1. **Add test function to appropriate module** (or create new module)
2. **Mark test as `#[ignore]`** if it requires root
3. **Use `#[tokio::test]`** for async operations (network setup)
4. **Follow the pattern:**

   ```rust
   #[tokio::test]
   #[ignore]
   async fn test_my_feature() -> Result<()> {
       // Setup namespace
       let _ns = NetworkNamespace::enter()?;
       _ns.enable_loopback().await?;

       // Setup network
       let _veth = VethPair::create(...).await?.set_addr(...).await?.up().await?;

       // Start MCR
       let mut mcr = McrInstance::start(...)?;
       mcr.add_rule(...)?;

       // Generate traffic
       send_packets(...)?;

       // Shutdown and validate
       let stats = mcr.shutdown_and_get_stats()?;
       assert_eq!(stats.ingress.matched, expected);

       Ok(())
   }
   ```

5. **Add module to `tests/integration.rs`**

## Known Issues

### AF_PACKET on veth interfaces

AF_PACKET sockets see both RX and TX packets on veth interfaces. This means:

- Traffic generator sends 1000 packets
- MCR ingress receives ~500 (kernel filters out TX)
- This is expected behavior, not a bug

Tests should validate proportional forwarding, not absolute packet counts.

### Graceful Shutdown Timing

The `McrInstance::shutdown_and_get_stats()` method:

1. Sends SIGTERM
2. Waits 5 seconds for clean exit
3. Force kills if still running
4. Waits 500ms for logs to flush

If tests show missing FINAL stats, increase the flush delay.

## Debugging Failed Tests

1. **Check log files:** Tests write to `/tmp/test_mcr_<pid>.log`
2. **Verify binaries:** Ensure `cargo build --release --bins` succeeded
3. **Check permissions:** Tests require root
4. **Single-threaded:** Always use `--test-threads=1`
5. **Inspect test output:** Remove `-q` flag for verbose output

## Future Work

- Multi-hop topology tests
- Performance tests (high packet rates)
- Failure injection tests
