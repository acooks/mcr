# Multicast Relay

This project provides a high-performance, dynamically configurable multicast relay application written in Rust. It is designed to receive UDP multicast streams and retransmit them to one or more destination multicast groups, leveraging modern Linux kernel features for efficiency and control.

## Features

- **High-Performance Architecture:** Utilizes Linux's `io_uring` for asynchronous I/O and `AF_PACKET` for raw socket access, minimizing kernel-userspace overhead and enabling high throughput.
- **Dynamic Reconfiguration:** Add, remove, and list forwarding rules at runtime without restarting the application via a UNIX socket-based control plane.
- **Multi-Output (Fan-Out):** A single input stream can be efficiently replicated to multiple output multicast groups.
- **Real-time Monitoring:** Built-in monitoring for packet rates, byte rates, and errors, available via console output.
- **Standalone Tools:** Includes a high-performance traffic generator for load testing and a control client for interacting with the relay.

## Basic Concepts

MCR operates on a few core concepts:

- **Supervisor:** This is the main process that you launch when you run `multicast_relay`. It is responsible for managing the high-performance workers and handling runtime configuration commands. It does not process any multicast traffic itself.

- **Worker:** These are the high-performance processes that do the actual work of receiving, processing, and re-transmitting multicast packets. The supervisor spawns one or more workers, typically pinning each to a specific CPU core to maximize performance.

- **Forwarding Rule:** A forwarding rule is a configuration object that tells a worker what to do. Each rule defines a specific input stream (based on multicast group and port) and a list of one or more outputs where that stream should be re-transmitted. You can manage these rules at runtime using the `control_client`.

## Installation

### Prerequisites

This application is designed for and requires a **Linux** operating system due to its use of modern kernel APIs like `io_uring` and `AF_PACKET`.

You will also need to have the official **Rust toolchain** installed. You can install it from [rustup.rs](https://rustup.rs/).

### Building from Source

To build all components (the relay, the traffic generator, and the control client), run the following command from the project root:

```bash
./scripts/build_all.sh
```

The compiled binaries will be available in the `target/release/` directory. You may wish to copy them to a location in your system's `PATH` (e.g., `/usr/local/bin/`) for easier access.

## Configuration

For detailed information on kernel tuning, environment variables for performance tuning, and the full command-line reference for all utilities, please see the **[MCR Configuration Guide](./CONFIGURATION.md)**.

## Running the Relay

To run the main relay application, which will start the supervisor and its workers:

```bash
sudo ./target/release/multicast_relay
```

All forwarding rules and runtime operations are managed via the `control_client`.

## Basic `control_client` Examples

Here are some common examples of how to use the `control_client` to manage the relay.

**Add a 1-to-1 Forwarding Rule:**

```bash
./target/release/control_client add-rule \
    --input-interface eth0 \
    --input-group 239.10.1.2 \
    --input-port 8001 \
    --output-interface eth1 \
    --output-group 239.20.3.4 \
    --output-port 9002
```

**Add a 1-to-2 Fan-Out Rule:**

```bash
./target/release/control_client add-rule \
    --input-interface eth0 \
    --input-group 239.10.1.2 \
    --input-port 8001 \
    --output-interface eth1 \
    --output-group 239.30.1.1 \
    --output-port 7001 \
    --output-interface eth1 \
    --output-group 239.30.1.2 \
    --output-port 7002
```

**List Active Rules:**

```bash
./target/release/control_client list
```

**Remove a Rule:**

```bash
./target/release/control_client remove \
    --rule-id <rule_id>
```

**Note:** Use `./target/release/control_client list` to see all rules and their IDs.

**View Statistics:**

```bash
./target/release/control_client stats
```

**List Workers:**

```bash
./target/release/control_client list-workers
```

**Health Check:**

```bash
./target/release/control_client ping
```

For a complete command reference and advanced configuration options, see **[CONFIGURATION.md](./CONFIGURATION.md)**.

## Basic `traffic_generator` Example

The `traffic_generator` can be used to send multicast traffic for testing purposes.

```bash
./target/release/traffic_generator \
    --group 239.1.1.1 \
    --port 5000 \
    --interface 10.0.0.1 \
    --rate 100000 \
    --size 1200
```

## Running Tests

The project uses `cargo-nextest` for a more robust test execution experience and `just` to simplify the workflow.

### 1. Build All Binaries

Before running tests, build the release-optimized binaries.

```bash
just build-release
```

### 2. Run Test Suites

#### Unprivileged Tests

Run all unit tests and integration tests that do not require root privileges. This is the most common command needed during development.

```bash
just test-fast
```

#### Privileged Tests (Requires Sudo)

Run the integration tests that require root for network namespace manipulation.

```bash
sudo -E just test-integration-privileged
```
