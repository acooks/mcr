# MCR Configuration Guide

**Status:** ✅ CURRENT
**Last Updated:** 2025-11-18

---

This document provides a central reference for configuring the Multicast Relay (MCR) application. Configuration is managed through a combination of kernel tuning, environment variables, and runtime commands.

## 1. Kernel Tuning (Required for High Performance)

For optimal performance, especially in high-throughput environments, the host system's kernel must be tuned to allow for larger network buffers.

A script is provided to apply these settings. It must be run as root and is required once per system boot.

```bash
sudo ./scripts/setup_kernel_tuning.sh
```

### Manual Kernel Parameters

The script sets the following `sysctl` parameters. To make them permanent, add them to `/etc/sysctl.conf`.

| Parameter | Recommended Value | Description |
| :--- | :--- | :--- |
| `net.core.wmem_max` | `16777216` (16 MB) | Maximum UDP send buffer size for a socket. |
| `net.core.wmem_default`| `4194304` (4 MB) | Default UDP send buffer size. |
| `net.core.rmem_max` | `16777216` (16 MB) | Maximum UDP receive buffer size for a socket. |
| `net.core.rmem_default`| `4194304` (4 MB) | Default UDP receive buffer size. |

---

## 2. Environment Variables (Advanced Tuning)

These environment variables can be used to fine-tune the data plane's performance characteristics. They are intended for advanced users who are diagnosing performance issues or optimizing for specific workloads.

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `MCR_SOCKET_SNDBUF` | `4194304` (4 MB) | Sets the `SO_SNDBUF` (send buffer) size in bytes for egress UDP sockets. |
| `MCR_IO_URING_DEPTH`| `1024` | The number of submission queue entries for `io_uring`. Higher values allow more operations to be in-flight. |
| `MCR_SEND_BATCH_SIZE`| `64` | The maximum number of packets to send in a single batch syscall. |
| `MCR_NUM_WORKERS` | `1` | The number of data plane worker threads to spawn. |
| `MCR_BUFFER_POOL_SMALL`| `1000` | Number of small buffers (up to 2KB) to pre-allocate. |
| `MCR_BUFFER_POOL_STANDARD`| `500` | Number of standard buffers (up to 4KB) to pre-allocate. |
| `MCR_BUFFER_POOL_JUMBO`| `200` | Number of jumbo buffers (up to 64KB) to pre-allocate. |
| `MCR_VERBOSE` | `0` | Set to `1` to enable verbose logging for debugging. |

**Example:**

```bash
# Run MCR with an 8 MB socket buffer and 4 worker threads
MCR_SOCKET_SNDBUF=8388608 MCR_NUM_WORKERS=4 sudo ./target/release/multicast_relay
```

---

## 3. `multicast_relay` Supervisor

The main `multicast_relay` application is the supervisor. It has minimal command-line configuration, as all forwarding rules are managed dynamically at runtime.

**Start the Supervisor:**

```bash
sudo ./target/release/multicast_relay
```

There are no command-line flags for adding rules or configuring workers; use the `control_client` for all runtime operations.

---

## 4. `control_client` Commands

The `control_client` is the command-line tool for managing the MCR supervisor at runtime.

### 4.1. Add a Forwarding Rule

Adds a new rule to forward an input stream to one or more outputs.

```bash
./target/release/control_client add-rule \
    --input-interface <iface> \
    --input-group <ip> \
    --input-port <port> \
    --output-interface <iface> \
    --output-group <ip> \
    --output-port <port>
```

**Arguments:**

| Argument | Description |
| :--- | :--- |
| `--input-interface` | Network interface for the input stream (e.g., `eth0`). |
| `--input-group` | Input multicast group IP address. |
| `--input-port` | Input multicast UDP port. |
| `--output-interface`| Network interface for the output stream. Can be specified multiple times for fan-out. |
| `--output-group` | Output multicast group IP address. |
| `--output-port` | Output multicast UDP port. |

### 4.2. Remove a Forwarding Rule

Removes an existing rule, identified by its input group and port.

```bash
./target/release/control_client remove-rule \
    --input-group <ip> \
    --input-port <port>
```

### 4.3. List Rules

Displays all currently active forwarding rules.

```bash
./target/release/control_client list
```

### 4.4. Get Statistics

Retrieves and displays performance statistics from the data plane.

```bash
./target/release/control_client stats
```

### 4.5. Manage Log Levels

Controls the verbosity of MCR's logging at runtime.

```bash
# Get current levels
./target/release/control_client log-level get

# Set a global level
./target/release/control_client log-level set --global <level>

# Set a facility-specific level
./target/release/control_client log-level set --facility <facility> --level <level>
```

- **Levels:** `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, `debug`
- **Facilities:** `Supervisor`, `DataPlane`, `Ingress`, `Egress`, `ControlPlane`, etc.

---

## 5. `traffic_generator`

A utility for sending test multicast traffic.

```bash
./target/release/traffic_generator \
    --interface <ip> \
    --group <ip> \
    --port <port> \
    --rate <pps> \
    --size <bytes>
```

**Arguments:**

| Argument | Description |
| :--- | :--- |
| `--interface` | The source IP address of the interface to send from. |
| `--group` | The destination multicast group IP address. |
| `--port` | The destination multicast UDP port. |
| `--rate` | The target send rate in packets per second. |
| `--size` | The size of the UDP payload in bytes. |
