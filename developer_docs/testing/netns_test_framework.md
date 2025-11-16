# Network Namespace Test Framework

## The Real Requirement

Tests must run in **isolated network namespaces** to:
1. Avoid interfering with host networking
2. Allow parallel test execution
3. Ensure clean, reproducible test environments
4. Test actual network behavior without affecting production

## The Solution: Wrapper Script Pattern

### Design: Two-Phase Execution

```
User space (as user)          Network namespace (as root)
─────────────────────────────────────────────────────────
cargo test --no-run     ───>  Create netns
                              Copy test binary into netns
                              Run tests in isolation
                              Cleanup netns
```

### Implementation

#### 1. Justfile Targets

```justfile
# Build test binaries (as user)
build-test:
    cargo test --no-run --all-targets
    cargo build --release --bins

# Run unit tests (no netns needed)
test-unit:
    cargo test --lib
    cargo test --bins

# Run integration tests in network namespace
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail

    # Build first
    cargo test --no-run --test integration

    # Find test binary
    TEST_BINARY=$(find target/debug/deps -name 'integration-*' -type f -executable | head -1)

    if [ -z "$TEST_BINARY" ]; then
        echo "Error: Test binary not found"
        exit 1
    fi

    # Run in netns wrapper
    sudo ./scripts/run-tests-in-netns.sh "$TEST_BINARY" --ignored --test-threads=1

# Run E2E tests (already use netns)
test-e2e:
    sudo bash tests/data_plane_e2e.sh

# All tests
test-all: build-test test-unit test-integration test-e2e

# Coverage (unit tests only, fast)
coverage:
    cargo tarpaulin --out html --output-dir coverage --lib
```

#### 2. Network Namespace Wrapper Script

Create `scripts/run-tests-in-netns.sh`:

```bash
#!/usr/bin/env bash
# Run tests in isolated network namespace

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <test-binary> [test-args...]"
    exit 1
fi

TEST_BINARY="$1"
shift
TEST_ARGS="$@"

# Generate unique namespace name
NETNS_NAME="mcr-test-$$"

# Cleanup function
cleanup() {
    echo "Cleaning up namespace $NETNS_NAME"
    ip netns del "$NETNS_NAME" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

echo "Creating network namespace: $NETNS_NAME"
ip netns add "$NETNS_NAME"

# Set up loopback in the namespace
ip netns exec "$NETNS_NAME" ip link set lo up

# Optional: Set up veth pair for tests that need external connectivity
# ip link add veth0 type veth peer name veth1
# ip link set veth1 netns "$NETNS_NAME"
# ip addr add 10.200.0.1/24 dev veth0
# ip link set veth0 up
# ip netns exec "$NETNS_NAME" ip addr add 10.200.0.2/24 dev veth1
# ip netns exec "$NETNS_NAME" ip link set veth1 up

echo "Running tests in namespace: $NETNS_NAME"
echo "Test binary: $TEST_BINARY"
echo "Test args: $TEST_ARGS"

# Run the test binary inside the namespace
# Preserve environment variables with -E flag
sudo -E ip netns exec "$NETNS_NAME" "$TEST_BINARY" $TEST_ARGS

EXIT_CODE=$?

echo "Tests completed with exit code: $EXIT_CODE"
exit $EXIT_CODE
```

#### 3. Per-Test Namespace Isolation (Optional)

For even better isolation, each test can create its own namespace:

```rust
// tests/integration/helpers.rs

use std::process::Command;

pub struct TestNamespace {
    name: String,
}

impl TestNamespace {
    pub fn new(test_name: &str) -> Result<Self, std::io::Error> {
        let name = format!("mcr-{}-{}", test_name, std::process::id());

        // Create namespace
        Command::new("ip")
            .args(&["netns", "add", &name])
            .status()?;

        // Set up loopback
        Command::new("ip")
            .args(&["netns", "exec", &name, "ip", "link", "set", "lo", "up"])
            .status()?;

        Ok(TestNamespace { name })
    }

    pub fn exec(&self, cmd: &str, args: &[&str]) -> Result<std::process::Output, std::io::Error> {
        let mut full_args = vec!["netns", "exec", &self.name, cmd];
        full_args.extend_from_slice(args);

        Command::new("ip")
            .args(&full_args)
            .output()
    }
}

impl Drop for TestNamespace {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(&["netns", "del", &self.name])
            .status();
    }
}

// Usage in tests:
#[test]
#[ignore = "requires root"]
fn test_supervisor_in_netns() {
    let netns = TestNamespace::new("supervisor").unwrap();

    // Start supervisor in the namespace
    let output = netns.exec(
        "./target/release/multicast_relay",
        &["supervisor", "--interface", "lo"]
    ).unwrap();

    assert!(output.status.success());
}
```

#### 4. GitHub Actions Integration

```yaml
name: Test

on: [push, pull_request]

jobs:
  test-unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --lib

  test-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable

      # Build test binary as regular user
      - run: cargo test --no-run --test integration

      # Run in network namespace
      - name: Run integration tests in netns
        run: |
          sudo chmod +x scripts/run-tests-in-netns.sh
          TEST_BINARY=$(find target/debug/deps -name 'integration-*' -type f -executable | head -1)
          sudo -E ./scripts/run-tests-in-netns.sh "$TEST_BINARY" --ignored --test-threads=1
```

## Benefits of This Approach

1. **Isolation**: Each test run gets a clean network namespace
2. **No host interference**: Tests can't accidentally affect host networking
3. **Repeatable**: Same environment every time
4. **Parallel-safe**: Different namespaces = no conflicts
5. **CI-friendly**: Works in GitHub Actions with sudo
6. **Same toolchain**: Build as user, run in netns as root

## Alternative: Systemd-nspawn Container

For even more isolation:

```bash
#!/usr/bin/env bash
# Run tests in systemd-nspawn container with private network

CONTAINER_NAME="mcr-test-$$"

systemd-nspawn \
    --private-network \
    --bind-ro="$TEST_BINARY:/test-binary" \
    --pipe \
    /test-binary $TEST_ARGS
```

**Pros**: Complete filesystem isolation
**Cons**: More complex setup, slower

## Recommendation

Start with the **network namespace wrapper script** approach:
1. Simple and fast
2. Provides necessary isolation
3. Works in CI
4. Easy to debug (can exec into namespace)

## Testing the Wrapper

```bash
# Build test binary
cargo test --no-run --test integration

# Find it
TEST_BINARY=$(find target/debug/deps -name 'integration-*' -type f -executable | head -1)

# Run in namespace
sudo ./scripts/run-tests-in-netns.sh "$TEST_BINARY" --ignored --test-threads=1

# Check namespace was cleaned up
ip netns list | grep mcr-test || echo "Clean!"
```

## Next Steps

1. Create `scripts/run-tests-in-netns.sh`
2. Make it executable: `chmod +x scripts/run-tests-in-netns.sh`
3. Test it with current integration tests
4. Add justfile targets
5. Update CI workflow
6. Document in README
