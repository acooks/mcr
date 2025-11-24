# Justfile Quick Reference

**Updated:** 2025-11-18
**Status:** New build-once workflow integrated

---

## TL;DR - What You Should Use

### For Regular Development

```bash
just           # or: just dev
```

Fast loop: format → lint → build release → run fast tests (~2-3 min)

### Before Committing

```bash
just check
```

Quality gates: format → lint → build → fast tests (~2-3 min)

### Full Test Suite

```bash
just check                       # Fast quality checks
sudo -E just test-privileged     # Privileged Rust tests
sudo just test-performance       # Performance validation
```

---

## New Workflow (Build Once, Test Many)

### Development Loop

#### Option 1: Default (Recommended)

```bash
just           # Runs 'dev' by default
```

- ✅ Formats code
- ✅ Runs linter
- ✅ Builds release binaries
- ✅ Runs fast tests (unit + unprivileged integration)
- ⏱️ Time: ~2-3 minutes

#### Option 2: Explicit Dev

```bash
just dev       # Same as default
```

#### Option 3: Even Faster (Skip Build)

```bash
just test-fast # Just run fast tests (assumes binaries built)
```

### Pre-Commit Checks

#### Fast Quality Check

```bash
just check
```

Same as `just dev` but emphasizes it's a quality gate.

**Full CI Pipeline** (slow)

```bash
just check-full
```

Includes coverage report (adds ~5-10 minutes).

### Testing Levels

#### Level 1: Fast Tests (No Root)

```bash
just test-fast        # Unit + unprivileged integration
just test-unit        # Unit tests only
just test-integration-light  # Unprivileged integration only
```

#### Level 2: All Unprivileged Tests

```bash
just test-all         # Builds test binaries, runs all unprivileged
```

#### Level 3: Privileged Tests (Requires Root)

```bash
sudo -E just test-integration-privileged  # Rust integration tests
sudo just test-e2e-bash                   # Bash E2E tests
```

#### Level 4: Performance Tests (Requires Root)

```bash
sudo just test-performance   # Full 10M packet test
sudo just test-perf-quick    # Quick 10 packet test
```

### Building

**Build Release Binaries** (Production)

```bash
just build-release
```

Uses `scripts/build_all.sh`, shows checksums.

**Build Test Binaries** (For Rust integration tests)

```bash
just build-test
```

Builds debug test binaries.

---

## Old Workflow (Deprecated)

### What Changed

**OLD:**

```bash
just check    # Rebuilt 3+ times, took 10+ minutes
```

**NEW:**

```bash
just check    # Builds once, takes 2-3 minutes
just check-full  # Full CI pipeline (if you really need it)
```

### Migration

If you were using:

- `just check` → Now faster! Still works but doesn't include coverage
- `just test` → Use `just test-fast` (same behavior, clearer name)
- Want coverage? → Use `just check-full` or `just coverage`

---

## Common Workflows

### Daily Development

```bash
# 1. Make changes to code

# 2. Quick feedback
just           # Format, lint, build, test

# 3. If tests pass, commit
git add .
git commit -m "your message"
```

### Before Pull Request

```bash
# 1. Run quality checks
just check

# 2. Run privileged tests
sudo -E just test-integration-privileged

# 3. Run performance validation
sudo just test-performance

# 4. All good? Push!
git push
```

### Performance Testing Only

```bash
# 1. Build once
just build-release

# 2. Run performance test
sudo just test-performance

# 3. Results in stdout
```

### After Pulling Changes

```bash
# Rebuild everything
just build-release
just build-test

# Run full test suite
just test-all
sudo -E just test-privileged
```

---

## Complete Command Reference

### Building

| Command              | What It Does                        | Time   |
| -------------------- | ----------------------------------- | ------ |
| `just build-release` | Build release binaries (production) | ~2 min |
| `just build-test`    | Build test binaries (debug)         | ~2 min |
| `just build`         | Build all targets (debug)           | ~2 min |

### Testing (No Root)

| Command                       | What It Does                    | Time    |
| ----------------------------- | ------------------------------- | ------- |
| `just test-fast`              | Unit + unprivileged integration | ~30 sec |
| `just test-unit`              | Unit tests only                 | ~10 sec |
| `just test-integration-light` | Unprivileged integration        | ~20 sec |
| `just test-all`               | All unprivileged tests          | ~1 min  |

### Testing (Requires Root)

| Command                        | What It Does          | Time    |
| ------------------------------ | --------------------- | ------- |
| `sudo -E just test-privileged` | Privileged Rust tests | ~1 min  |
| `sudo just test-e2e-bash`      | Bash E2E tests        | ~1 min  |
| `sudo just test-performance`   | Full performance test | ~15 sec |
| `sudo just test-perf-quick`    | Quick 10 packet test  | ~5 sec  |

### Quality Checks

| Command             | What It Does      | Time    |
| ------------------- | ----------------- | ------- |
| `just fmt`          | Format check      | ~5 sec  |
| `just clippy`       | Linter check      | ~30 sec |
| `just audit`        | Security audit    | ~10 sec |
| `just unsafe-check` | Unsafe code check | ~5 sec  |

### Meta Commands

| Command              | What It Does             | Time     |
| -------------------- | ------------------------ | -------- |
| `just` or `just dev` | Default development loop | ~2-3 min |
| `just check`         | Fast quality checks      | ~2-3 min |
| `just check-full`    | Full CI pipeline         | ~10+ min |

### Utilities

| Command             | What It Does                |
| ------------------- | --------------------------- |
| `just setup-kernel` | Setup kernel tuning         |
| `just clean`        | Clean build artifacts       |
| `just outdated`     | Check outdated dependencies |
| `just coverage`     | Generate coverage report    |

---

## Environment Setup

### One-Time Setup

**For Performance Testing:**

```bash
sudo just setup-kernel
```

Sets kernel network buffer limits. Persists until reboot.

**To Make Permanent:**

```bash
sudo just setup-kernel
# Then manually add to /etc/sysctl.conf (shown in output)
```

---

## Troubleshooting

### "Binary not found" Error

**Problem:**

```text
ERROR: Binary not found: target/release/multicast_relay
```

**Solution:**

```bash
just build-release
```

### Tests Rebuild Everything

**Problem:** Tests keep rebuilding binaries.

**Solution:** You're using old workflow. Use:

```bash
just build-release   # Build once
just test-fast       # Test many times
```

### Performance Test Fails with "Cannot set SO_SNDBUF"

**Problem:** Kernel limits too low.

**Solution:**

```bash
sudo just setup-kernel
```

### Want Old Behavior

**Problem:** Want coverage and all checks like old `just check`.

**Solution:**

```bash
just check-full      # Includes coverage, audit, etc.
```

---

## FAQ

**Q: What's the difference between `just` and `just check`?**
A: They're the same now. `just` runs `dev` which does the same as `check`.

**Q: Do I need to run `just build-release` every time?**
A: No, `just dev` and `just check` do it automatically.

**Q: What happened to the old `just check`?**
A: Renamed to `just check-full`. New `just check` is faster (no coverage).

**Q: How do I run all tests?**
A: `just test-all && sudo -E just test-privileged && sudo just test-performance`

**Q: Why use `sudo -E` for some tests?**
A: The `-E` preserves environment variables needed by Rust tests.

**Q: Can I skip kernel setup for performance tests?**
A: No, it's required. But it's fast and only needed once per boot.

**Q: What if I just want to check formatting?**
A: `just fmt` (5 seconds)

**Q: What's the fastest way to test after a small change?**
A: `just test-fast` (30 seconds, assumes binaries already built)

---

## Visual Workflow

```text
Daily Development:
  Code → just → [fmt → clippy → build → test-fast] → ✅ or ❌

Before Commit:
  Code → just check → ✅
       → sudo -E just test-privileged → ✅
       → sudo just test-performance → ✅
       → git commit

After Pull:
  git pull → just build-release → just test-all → ✅

Performance Only:
  just build-release → sudo just test-performance → 📊 Results
```

---

## Summary

### Use This Workflow ✅

```bash
# Regular development
just                              # Fast loop

# Before commit
just check                        # Quality checks
sudo -E just test-privileged      # Privileged tests
sudo just test-performance        # Performance validation
```

### Don't Use This ❌

```bash
# Don't manually build before testing
cargo build --release
cargo test

# Use instead:
just dev    # Does both correctly
```

---

## More Information

- **Testing guide:** [`testing/PRACTICAL_TESTING_GUIDE.md`](testing/PRACTICAL_TESTING_GUIDE.md)
- **Build consistency:** [`BUILD_CONSISTENCY.md`](BUILD_CONSISTENCY.md)
- **Quick test guide:** [`QUICK_TEST.md`](../user_docs/QUICK_TEST.md)

---

**Last Updated:** 2025-11-18
**Workflow:** Build once, test many
**Performance:** 2-3 min (was 10+ min)
