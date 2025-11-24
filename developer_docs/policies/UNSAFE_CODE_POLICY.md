# Unsafe Code Policy

## Overview

This document defines the policy for using `unsafe` code in the multicast_relay project and describes the automated checks that enforce this policy.

## Policy

### General Principles

1. **Minimize Unsafe**: Unsafe code should be avoided unless absolutely necessary
2. **Justify All Usage**: Every use of unsafe must be justified by one of the allowed reasons below
3. **Document Safety**: All unsafe functions must have a `# Safety` section explaining invariants
4. **Isolate Unsafe**: Unsafe code should be isolated in small, well-tested modules
5. **Track Growth**: Unsafe code usage is tracked and must not exceed defined limits

### Allowed Reasons for Unsafe Code

Unsafe code is permitted only for:

1. **FFI (Foreign Function Interface)**: Calling libc or kernel interfaces
2. **Performance**: Zero-copy operations, io_uring, high-performance networking
3. **Security**: Privilege separation, capability dropping, raw socket operations
4. **Low-level Operations**: File descriptor passing, raw memory management

### Current Limits

- **Maximum unsafe blocks in src/**: 20 blocks
- **Maximum unsafe percentage**: 0.5% of total codebase
- **Baseline tracking**: Changes in unsafe usage are flagged for review

## Automated Checks

### 1. Daily Unsafe Check (`just unsafe-check`)

Runs as part of `just check` and verifies:

- ✅ Unsafe block count is within limits
- ✅ Unsafe code percentage is acceptable
- ⚠️  Safety documentation exists for unsafe functions
- ⚠️  No dangerous patterns (excessive transmute, raw pointers)
- 📊 Tracks changes from baseline

**Usage**:

```bash
just unsafe-check         # Quick check (fails if limits exceeded)
just unsafe-report        # Detailed cargo-geiger report
```

**Output Example**:

```text
🔒 Checking unsafe code usage...

Current Unsafe Usage:
  Unsafe blocks:     17
  Unsafe lines:      20
  Total lines:       5768
  Unsafe percentage: 0.3467%

✅ Unsafe usage unchanged from baseline (17 blocks)
✅ Unsafe code check PASSED
```

### 2. Clippy Lint Configuration

The `.clippy.toml` file configures Clippy to:

- Warn on missing safety documentation (`warn-on-missing-safety-doc = true`)
- Catch common unsafe pitfalls during regular linting

**Usage**:

```bash
just clippy   # Runs as part of quality checks
```

### 3. cargo-geiger Dependency Audit

Generates comprehensive reports on unsafe usage in dependencies.

**Usage**:

```bash
just unsafe-report   # Generates target/geiger-report.txt
```

**Sample Output**:

```text
Functions  Expressions  Impls  Traits  Methods  Dependency
327/697    29568/43304  466/568 52/55  825/1120  multicast_relay
0/90       34/687       0/2    0/0     8/92     ├── libc 0.2.177
8/8        506/540      2/2    0/0     20/20    ├── io-uring 0.6.4
21/25      2275/2761    110/114 3/3    108/117  └── tokio 1.48.0
```

## Current Unsafe Usage Inventory

### Main Codebase (src/)

**Total**: 17 unsafe blocks (0.35% of codebase)

| File | Count | Purpose | Status |
|------|-------|---------|--------|
| `worker/ingress.rs` | 6 | io_uring, AF_PACKET sockets, FFI | ✅ Justified |
| `worker/egress.rs` | 4 | io_uring send operations, FD conversion | ✅ Justified |
| `worker/mod.rs` | 4 | Privilege checks, Unix stream conversion | ✅ Justified |
| `worker/data_plane.rs` | 2 | Socket ownership transfer | ✅ Justified |
| `worker/buffer_pool.rs` | 1 | Zero-copy buffer management | ⚠️ Needs doc |
| `packet_parser.rs` | 0 | (Future optimization candidate) | N/A |

### Dependencies with Heavy Unsafe

Expected for systems programming:

- **io-uring** (94% unsafe): Kernel async I/O interface - no safe alternative
- **tokio** (82% unsafe): Runtime requires unsafe for performance
- **socket2** (81% unsafe): Low-level socket operations
- **libc** (5% unsafe): FFI bindings by definition

Zero unsafe (safe abstractions):

- anyhow, clap, thiserror, serde, serde_json, uuid

## Recommendations for Developers

### When Adding Unsafe Code

1. **Justify the need**: Document why unsafe is necessary
2. **Add safety documentation**: Every unsafe function needs `# Safety` section
3. **Keep it minimal**: Extract unsafe into smallest possible scope
4. **Test thoroughly**: Unsafe code requires comprehensive testing
5. **Update baseline**: Run `echo <new_count> > .unsafe_baseline` if increase is justified

### Safety Documentation Template

```rust
/// Brief description of what this does
///
/// # Safety
///
/// This function is unsafe because [explain invariant that must be upheld].
/// Caller must ensure that:
/// - [specific requirement 1]
/// - [specific requirement 2]
///
/// # Examples
///
/// ```rust,no_run
/// // Safe usage example
/// ```
pub unsafe fn dangerous_operation() {
    // ...
}
```

### Code Review Checklist

When reviewing PRs with unsafe code:

- [ ] Is unsafe necessary? Could this be done safely?
- [ ] Is there a `# Safety` doc comment explaining invariants?
- [ ] Is the unsafe scope as small as possible?
- [ ] Are all invariants actually upheld by the code?
- [ ] Is there test coverage for the unsafe code path?
- [ ] Does it pass `just unsafe-check`?

## CI Integration

The unsafe check is integrated into CI as part of `just check`:

```yaml
# .github/workflows/ci.yml (example)
- name: Run Quality Checks
  run: just check  # Includes unsafe-check
```

## Monitoring and Trends

Track unsafe code growth over time:

```bash
# View historical trend (if using git)
git log --all --oneline -- .unsafe_baseline

# Current vs baseline
./scripts/check_unsafe.sh
```

## Related Tools

- **cargo-geiger**: Unsafe usage in dependency tree
- **cargo-audit**: Security vulnerabilities in dependencies
- **cargo-deny**: Ban specific unsafe dependencies if needed
- **miri**: Detect undefined behavior (for future integration)

## References

- [Rust Unsafe Code Guidelines](https://rust-lang.github.io/unsafe-code-guidelines/)
- [Rustonomicon](https://doc.rust-lang.org/nomicon/)
- [cargo-geiger](https://github.com/geiger-rs/cargo-geiger)

---

**Last Updated**: 2025-11-08
**Policy Version**: 1.0
**Current Baseline**: 17 unsafe blocks
