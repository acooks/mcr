# Multicast Relay

This project provides a high-performance, dynamically configurable multicast relay application written in Rust. It is designed to receive UDP multicast streams and retransmit them to one or more destination multicast groups, with options for head-end replication.

The application is built for performance, using an asynchronous, parallel architecture with `tokio` to handle many concurrent flows efficiently. It also includes a control plane for runtime configuration and a suite of tools for testing and monitoring.

## Features

- **High-Performance:** Asynchronous, multi-threaded design capable of handling millions of packets per second.
- **Dynamic Reconfiguration:** Add, remove, and list forwarding rules at runtime without restarting the application.
- **Head-End Replication:** A single input stream can be replicated to multiple output multicast groups.
- **Real-time Monitoring:** Built-in monitoring for packet rates, byte rates, CPU usage, and memory usage, available via console output and a Prometheus exporter.
- **Standalone Tools:** Includes a high-performance traffic generator for load testing and a control client for interacting with the relay.

## Basic Concepts

MCR operates on a few core concepts:

*   **Supervisor:** This is the main process that you launch when you run `multicast_relay`. It is responsible for managing the high-performance workers and handling runtime configuration commands. It does not process any multicast traffic itself.

*   **Worker (or Data Plane):** These are the high-performance processes that do the actual work of receiving, processing, and re-transmitting multicast packets. The supervisor spawns one or more workers, typically pinning each to a specific CPU core to maximize performance.

*   **Forwarding Rule:** A forwarding rule is a configuration object that tells a worker what to do. Each rule defines a specific input stream (based on multicast group and port) and a list of one or more outputs where that stream should be re-transmitted. You can manage these rules at runtime using the `control_client`.

## Installation

### Prerequisites

This application is designed for and requires a **Linux** operating system due to its use of modern kernel APIs like `io_uring` and `AF_PACKET`.

You will also need to have the official **Rust toolchain** installed. You can install it from [rustup.rs](https://rustup.rs/).

### Building from Source

To build all components (the relay, the traffic generator, and the control client), run the following command from the project root:

```bash
cargo build --release
```

The compiled binaries will be available in the `target/release/` directory. You may wish to copy them to a location in your system's `PATH` (e.g., `/usr/local/bin/`) for easier access.

## Running the Relay

To run the main relay application:

```bash
./target/release/multicast_relay [OPTIONS]
```

**Options:**

- `--input-group <IP>`: Set an initial input multicast group.
- `--input-port <PORT>`: Set an initial input port.
- `--output-group <IP>`: Set an initial output multicast group.
- `--output-port <PORT>`: Set an initial output port.
- `--output-interface <IP>`: Set the initial output interface.
- `--reporting-interval <SECONDS>`: The interval for printing monitoring reports to the console.
- `--prometheus-addr <IP:PORT>`: The address for the Prometheus metrics exporter.

## Using the Control Client

The `control_client` is used to manage forwarding rules and log levels at runtime.

**Add a Rule:**

```bash
./target/release/control_client add \
    --input-group 224.1.1.1 \
    --input-port 5000 \
    --outputs 225.1.1.1:5001:127.0.0.1 \
    --outputs 225.1.1.2:5002:127.0.0.1
```

**Remove a Rule:**

```bash
./target/release/control_client remove \
    --input-group 224.1.1.1 \
    --input-port 5000
```

**List Rules:**

```bash
./target/release/control_client list
```

**Get Statistics:**

```bash
./target/release/control_client stats
```

**Control Log Levels:**

```bash
# Get current log levels
./target/release/control_client log-level get

# Set global log level (affects all facilities)
./target/release/control_client log-level set --global info

# Set facility-specific log level (overrides global)
./target/release/control_client log-level set --facility Ingress --level debug
```

Available log levels: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, `debug`

Available facilities: `Supervisor`, `RuleDispatch`, `ControlSocket`, `ControlPlane`, `DataPlane`, `Ingress`, `Egress`, `BufferPool`, `PacketParser`, `Stats`, `Security`, `Network`, `Test`

## Examples / Cookbook

Here are some practical examples of how to use the control client to configure the relay.

### Example 1: Simple 1-to-1 Relay

**Goal:** Relay traffic from multicast group `239.10.1.2:8001` to `239.20.3.4:9002` using the network interface with the IP `10.1.5.25`.

```bash
./target/release/control_client add \
    --input-group 239.10.1.2 \
    --input-port 8001 \
    --outputs 239.20.3.4:9002:10.1.5.25
```

### Example 2: 1-to-2 Head-End Replication

**Goal:** Take a single input stream and replicate it to two different downstream groups.

```bash
./target/release/control_client add \
    --input-group 239.10.1.2 \
    --input-port 8001 \
    --outputs 239.30.1.1:7001:10.1.5.25 \
    --outputs 239.30.1.2:7002:10.1.5.25
```
Note that we just provide a second `--outputs` flag for the same input rule.

## Using the Traffic Generator

The `traffic_generator` can be used to send multicast traffic for testing purposes.

```bash
./target/release/traffic_generator \
    --group 224.1.1.1 \
    --port 5000 \
    --interface 127.0.0.1 \
    --rate 100000 \
    --size 1200
```

## Running Tests

### Unit and Integration Tests

To run the unit and integration tests:

```bash
cargo test
```

### Topology Tests (End-to-End)

To run comprehensive end-to-end tests with network namespace isolation:

```bash
# Run all topology tests
sudo just test-topologies

# Run specific topology
sudo tests/topologies/chain_3hop.sh
```

Available topologies:
- `chain_3hop.sh` - 3-hop serial forwarding pipeline
- `tree_fanout.sh` - Head-end replication (1:N amplification)

See [tests/topologies/README.md](tests/topologies/README.md) for details.
