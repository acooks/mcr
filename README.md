# Multicast Relay (MCR)

**Note: MCR is currently under active development.**

MCR is a high-performance, userspace multicast relay for Linux. It is a purpose-built tool for network architects, broadcast/media engineers, and financial services developers who need to reliably bridge multicast traffic between isolated or unroutable network segments.

If you have ever been blocked by the kernel's Reverse Path Forwarding (RPF) check when trying to forward multicast traffic across network boundaries, MCR is the tool for you. It uses a low-level `AF_PACKET` and `io_uring` architecture to bypass these limitations and achieve millions of packets per second of throughput.

---

## Getting Started

This project provides separate documentation for the two primary audiences:

*   **For Users (`user_docs/`):** If you want to understand *why* you might need MCR, build it, or run it, start here.
    *   [**Why Use MCR?**](./user_docs/WHY_USE_MCR.md) - Explains the core problem MCR solves.
    *   [**Usage Guide**](./user_docs/USAGE.md) - A comprehensive guide to installing, configuring, and operating MCR.

*   **For Developers (`developer_docs/`):** If you want to contribute to the project, understand its architecture, or learn about the testing strategy, start with the [**Developer Documentation**](./developer_docs/README.md).