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

### Core Documentation (Start Here)

- **[README.md](README.md)** (This file) - Project overview, quickstart, and usage
- **[STATUS.md](STATUS.md)** - Current implementation state, performance results, and priorities
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design, technical decisions, and architecture
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development standards, testing requirements, and workflow

### Additional Documentation

- **[docs/plans/](docs/plans/)** - Active work items and implementation plans
  - [LOGGING_INTEGRATION_PLAN.md](docs/plans/LOGGING_INTEGRATION_PLAN.md) - Next priority (3.5 hours)

- **[docs/completed/](docs/completed/)** - Completed phase reports and session summaries
  - [PHASE4_COMPLETION.md](docs/completed/PHASE4_COMPLETION.md) - Performance validation results
  - [SESSION_RECAP_2025-11-11.md](docs/completed/SESSION_RECAP_2025-11-11.md) - Latest session summary

- **[docs/reference/](docs/reference/)** - Development guides and references
  - [DEVELOPER_GUIDE.md](docs/reference/DEVELOPER_GUIDE.md) - Development workflows
  - [TESTING.md](docs/reference/TESTING.md) - Testing strategy
  - [EXPERIMENT_CANDIDATES.md](docs/reference/EXPERIMENT_CANDIDATES.md) - Experiment tracking


## Components

The project is composed of three binaries:

- `multicast_relay`: The main relay application.
- `traffic_generator`: A tool for generating high-rate multicast UDP traffic for testing.
- `control_client`: A command-line tool for interacting with the `multicast_relay`'s control plane.

## Building the Project

To build all components, run the following command from the project root:

```bash
cargo build --release
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
