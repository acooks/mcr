# MCR: A High-Performance Userspace Multicast Relay

[![Build Status](https://github.com/acooks/mcr/actions/workflows/rust.yml/badge.svg)](https://github.com/acooks/mcr/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/acooks/mcr/graph/badge.svg)](https://codecov.io/gh/acooks/mcr)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](./licenses.html)

**MCR** is a specialized, high-performance multicast relay for Linux, designed to forward multicast traffic between network segments where conventional routing is impossible or inefficient.

It is built for engineers who face challenges with kernel-level multicast forwarding, such as the Reverse Path Forwarding (RPF) check, and require a flexible, scalable, and extremely fast userspace solution.

---

## The Problem MCR Solves

In many modern network environments—such as broadcast media facilities, financial data centers, or complex cloud VPCs—multicast traffic needs to traverse network boundaries that are not cleanly routable. Attempting to forward this traffic with standard routers often fails due to the kernel's strict RPF check, which drops packets that arrive on an interface other than the one the kernel would use to route back to the source.

**MCR is the solution for this exact problem.** By operating at Layer 2 and using raw `AF_PACKET` sockets, it can receive multicast packets from one network interface and re-transmit them on another, completely bypassing the kernel's IP-layer routing and RPF enforcement.

### Who is MCR for?

- **Network Architects & Cloud Engineers:** Bridge multicast traffic (e.g., discovery protocols, service announcements) between different VPCs, subnets, or physical network segments without complex routing changes.
- **Broadcast & Media Engineers:** Reliably transport high-bitrate media streams (e.g., SMPTE 2110) across network boundaries in production and lab environments.
- **Financial Services Developers:** Distribute real-time market data feeds across multiple isolated networks with minimal and predictable latency.

---

## Architecture: Performance by Design

MCR is architected from the ground up for maximum throughput and minimal latency. The design combines several modern Linux technologies to achieve near line-rate speeds.

- **Userspace Operation:** Provides maximum flexibility and control, avoiding the limitations and overhead of kernel-level forwarding.
- **`io_uring` for Asynchronous I/O:** Utilizes Linux's most advanced I/O interface to dramatically reduce syscall overhead and minimize kernel-userspace context switching.
- **`AF_PACKET` for Raw Sockets:** Reads and writes raw Ethernet frames, allowing for efficient processing and bypassing the kernel's IP stack.
- **Single-Threaded, Unified Event Loop:** A single thread handles ingress, processing, and egress within one `io_uring` instance, eliminating cross-thread communication overhead and maximizing cache efficiency.
- **Zero-Copy Fan-Out:** A single ingress packet can be efficiently replicated to multiple egress destinations using a zero-copy `Arc<[u8]>` based architecture.

This combination of technologies allows MCR to operate at speeds approaching line-rate, typically limited only by the underlying hardware.

---

## Quick Start

### 1. Prerequisites

**Required:**

- **Linux kernel 5.6+** (minimum for `io_uring` socket operations)
  - 5.6+: `IORING_OP_RECV`/`IORING_OP_SEND` support
  - 3.1+: `PACKET_FANOUT_CPU` for multi-worker scaling
  - **Recommended: 5.10+** (LTS kernel with stable io_uring)
- Rust toolchain (latest stable)

```bash
# On Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential

# Check your kernel version
uname -r
```

**Optional (Recommended):**

- `cargo-nextest` - Faster, more robust test execution
- `just` - Simplified build and test workflows

```bash
cargo install cargo-nextest just
```

### 2. Build

Build all necessary binaries in release mode.

```bash
./scripts/build_all.sh
```

### 3. Configure Kernel for High Performance

For optimal performance, tune the kernel's network buffer limits. This script increases the allowed send/receive buffer sizes.

```bash
# This is required once per boot
sudo ./scripts/setup_kernel_tuning.sh
```

### 4. Run & Configure the Relay

A full usage guide is available in the [User Guide](./user_docs/USAGE.md).

---

## Documentation

This project provides separate documentation for users and developers.

### For Users

- **[USAGE.md](./user_docs/USAGE.md):** A quick-start guide to get MCR up and running.
- **[CONFIGURATION.md](./user_docs/CONFIGURATION.md):** The complete guide to configuring MCR, including kernel tuning, environment variables, and control plane commands.
- **[WHY_USE_MCR.md](./user_docs/WHY_USE_MCR.md):** Explains the core problem MCR solves and compares it to other tools like `socat`.

### For Developers

- **[DEVELOPER_DOCS](./developer_docs/README.md):** The main entry point for all developer-focused documentation, including architecture, testing, and contribution guidelines.

---

## License

This project is dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

---

## Contributing

We welcome contributions! Please see the [Contributing Guide](./developer_docs/CONTRIBUTING.md) for details on how to get started.
