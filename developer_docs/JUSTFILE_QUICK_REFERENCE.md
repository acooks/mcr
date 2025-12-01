# Justfile Quick Reference

**Updated:** 2025-12-01

## TL;DR

```bash
just dev   # Fast development loop (no root needed)
just test  # Full test suite with coverage (handles sudo internally)
```

## Main Commands

| Command | What It Does | Root? |
|---------|--------------|-------|
| `just` or `just dev` | Format, lint, build, unit tests | No |
| `just test` | All tests with coverage report | Handled internally |

## Development Workflow

### Regular Development

```bash
just dev
```

This runs:

1. `cargo fmt --check` - Format check
2. `cargo clippy` - Linter
3. Build release binaries
4. Unit tests

No root required. Fast feedback loop.

### Full Test Suite

```bash
just test
```

This runs **everything**:

1. Unit tests (145 tests)
2. Integration tests (18 tests, network namespaces)
3. All topology tests (baseline, edge cases, payload integrity, etc.)
4. Coverage report generation

The command handles `sudo` internally - you don't need to think about privileges.

Coverage report: `target/coverage/html/index.html`

## Other Useful Commands

### Code Quality

| Command | Description |
|---------|-------------|
| `just fmt` | Check formatting |
| `just clippy` | Run linter |
| `just lint-docs` | Lint markdown files |
| `just check` | Full quality check (format + lint + docs + build + unit tests) |

### Testing

| Command | Description |
|---------|-------------|
| `just test-unit` | Unit tests only (fast, no root) |
| `just test-integration` | Integration tests only (calls sudo) |
| `just test-topologies` | Topology shell script tests (calls sudo) |
| `just test-topology NAME` | Run specific topology test |
| `just test-performance` | Performance benchmarks (calls sudo) |

### Coverage

| Command | Description |
|---------|-------------|
| `just coverage` | Full coverage (same as `just test`) |
| `just coverage-quick` | Unit test coverage only (no root) |

### Building

| Command | Description |
|---------|-------------|
| `just build` | Debug build |
| `just build-release` | Release build |

### Security & Maintenance

| Command | Description |
|---------|-------------|
| `just audit` | Security audit |
| `just outdated` | Check for outdated dependencies |
| `just unsafe-check` | Check unsafe code usage |
| `just clean` | Clean build artifacts |

### Setup

| Command | Description |
|---------|-------------|
| `just setup-hooks` | Install git pre-commit hook |
| `just setup-kernel` | Tune kernel for performance testing |

## Typical Workflows

### Daily Development

```bash
# Make changes
just dev          # Quick feedback
# Repeat until happy
just test         # Full verification before commit
git commit
```

### Before Pull Request

```bash
just test         # Runs everything with coverage
git push
```

### Performance Testing

```bash
just test-performance
```

### After Pulling Changes

```bash
just test         # Full test suite verifies everything works
```

## FAQ

**Q: Do I need to use sudo?**
A: No. Commands that need root call `sudo` internally.

**Q: How do I get coverage?**
A: `just test` generates coverage. Report at `target/coverage/html/index.html`.

**Q: What's the fastest test command?**
A: `just test-unit` runs only unit tests (~1 second).

**Q: How do I run a specific topology test?**
A: `just test-topology baseline_test` (without `.sh` extension).

## More Information

- **Contributing guide:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md)
