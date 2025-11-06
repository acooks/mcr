# Multicast Relay

This project provides a high-performance, dynamically configurable multicast relay application written in Rust. It is designed to receive UDP multicast streams and retransmit them to one or more destination multicast groups, with options for head-end replication.

The application is built for performance, using an asynchronous, parallel architecture with `tokio` to handle many concurrent flows efficiently. It also includes a control plane for runtime configuration and a suite of tools for testing and monitoring.

## Features

- **High-Performance:** Asynchronous, multi-threaded design capable of handling millions of packets per second.
- **Dynamic Reconfiguration:** Add, remove, and list forwarding rules at runtime without restarting the application.
- **Head-End Replication:** A single input stream can be replicated to multiple output multicast groups.
- **Real-time Monitoring:** Built-in monitoring for packet rates, byte rates, CPU usage, and memory usage, available via console output and a Prometheus exporter.
- **Standalone Tools:** Includes a high-performance traffic generator for load testing and a control client for interacting with the relay.

## Project Documentation

This project maintains several key documents to guide development and understanding:

- **`README.md` (This file):** Provides a high-level overview of the project, its features, and instructions for building and running the application.
- **`ARCHITECTURE.md`:** The definitive, up-to-date guide to the system's design, components, and core technical decisions. This document describes *what* the system is.
- **`DEVLOG.md`:** A chronological, historical record of the project's evolution, including requirements, design discussions, and implementation progress. This document describes *how* the system came to be.
- **`CONTRIBUTING.md`:** The rulebook for all contributions, outlining the coding standards, testing requirements, and development principles that must be followed.
- **`IMPLEMENTATION_PLAN.md`:** The strategic roadmap for building the application. It breaks the work into sequential phases, defining the goals and exit criteria for each step.
- **`TESTING.md`:** Outlines the project's comprehensive, tiered testing philosophy and strategy, emphasizing unit, integration, and end-to-end testing, as well as the role of prototypes.

## Components

The project is composed of three binaries:

- `multicast_relay`: The main relay application.
- `traffic_generator`: A tool for generating high-rate multicast UDP traffic for testing.
- `control_client`: A command-line tool for interacting with the `multicast_relay`'s control plane.

## Building the Project

To build all components, run the following command from the project root:

```bash
car go build --release
```

The binaries will be available in the `target/release/` directory.

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

The `control_client` is used to manage forwarding rules at runtime.

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

To run the unit tests:

```bash
car go test
```

To run the high-load functional test script:

```bash
./test_high_load.sh
```