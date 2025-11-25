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

| Parameter               | Recommended Value  | Description                                   |
| :---------------------- | :----------------- | :-------------------------------------------- |
| `net.core.wmem_max`     | `16777216` (16 MB) | Maximum UDP send buffer size for a socket.    |
| `net.core.wmem_default` | `4194304` (4 MB)   | Default UDP send buffer size.                 |
| `net.core.rmem_max`     | `16777216` (16 MB) | Maximum UDP receive buffer size for a socket. |
| `net.core.rmem_default` | `4194304` (4 MB)   | Default UDP receive buffer size.              |

---

## 2. Environment Variables (Advanced Tuning)

These environment variables can be used to fine-tune the data plane's performance characteristics. They are intended for advanced users who are diagnosing performance issues or optimizing for specific workloads.

| Variable                   | Default Value    | Description                                                              |
| :------------------------- | :--------------- | :----------------------------------------------------------------------- |
| `MCR_SOCKET_SNDBUF`        | `4194304` (4 MB) | Sets the `SO_SNDBUF` (send buffer) size in bytes for egress UDP sockets. |
| `MCR_BUFFER_POOL_SMALL`    | `1000`           | Number of small buffers (up to 2KB) to pre-allocate.                     |
| `MCR_BUFFER_POOL_STANDARD` | `500`            | Number of standard buffers (up to 4KB) to pre-allocate.                  |
| `MCR_BUFFER_POOL_JUMBO`    | `200`            | Number of jumbo buffers (9KB each) to pre-allocate.                      |

**Note:** The number of data plane workers is configured via the `--num-workers` flag on the supervisor command, not via an environment variable.

**⚠️ Known Limitation:** Jumbo buffers are currently 9KB (9216 bytes), which holds exactly one jumbo frame. This may limit batching efficiency for high-throughput scenarios. The original design specified 64KB buffers to enable multi-packet batching. This sizing should be re-evaluated for performance optimization.

**Example:**

```bash
# Run MCR with an 8 MB socket buffer and 4 worker threads
MCR_SOCKET_SNDBUF=8388608 sudo ./target/release/multicast_relay supervisor --num-workers 4
```

---

## 3. `multicast_relay` Supervisor

The main `multicast_relay` application is the supervisor. Start it with the `supervisor` subcommand:

```bash
sudo ./target/release/multicast_relay supervisor [OPTIONS]
```

### Supervisor Options

| Option                        | Default                                 | Description                                             |
| :---------------------------- | :-------------------------------------- | :------------------------------------------------------ |
| `--num-workers <N>`           | Number of CPU cores                     | Override the number of worker processes to spawn.       |
| `--user <USER>`               | `nobody`                                | User to run worker processes as (privilege separation). |
| `--group <GROUP>`             | `daemon`                                | Group to run worker processes as.                       |
| `--interface <IFACE>`         | `lo`                                    | Network interface for data plane workers (deprecated).  |
| `--control-socket-path <PATH>`| `/tmp/multicast_relay_control.sock`     | Unix socket path for control_client connections.        |
| `--relay-command-socket-path` | `/tmp/mcr_relay_commands.sock`          | Unix socket path for supervisor-to-worker commands.     |
| `--prometheus-addr <ADDR>`    | None (disabled)                         | Address for Prometheus metrics export (e.g., `0.0.0.0:9090`). |

**Note:** The `--interface` parameter is deprecated and will be removed. Per the architecture design, interfaces should be specified per-rule via `control_client add --input-interface`, not globally.

### Examples

```bash
# Basic start with defaults
sudo ./target/release/multicast_relay supervisor

# Custom worker count and user
sudo ./target/release/multicast_relay supervisor --num-workers 4 --user mcr --group mcr

# Enable Prometheus metrics
sudo ./target/release/multicast_relay supervisor --prometheus-addr 0.0.0.0:9090

# Custom socket paths (useful for testing)
sudo ./target/release/multicast_relay supervisor \
    --control-socket-path /var/run/mcr_control.sock \
    --relay-command-socket-path /var/run/mcr_relay.sock
```

All forwarding rules are managed dynamically at runtime via the `control_client`.

---

## 4. `control_client` Commands

The `control_client` is the command-line tool for managing the MCR supervisor at runtime.

### 4.1. Add a Forwarding Rule

Adds a new rule to forward an input stream to one or more outputs.

```bash
./target/release/control_client add \
    --input-interface <iface> \
    --input-group <ip> \
    --input-port <port> \
    --outputs <group>:<port>:<interface>[,<group>:<port>:<interface>...]
```

**Arguments:**

| Argument            | Description                                                                                     |
| :------------------ | :---------------------------------------------------------------------------------------------- |
| `--input-interface` | Network interface for the input stream (e.g., `eth0`).                                          |
| `--input-group`     | Input multicast group IP address.                                                               |
| `--input-port`      | Input multicast UDP port.                                                                       |
| `--outputs`         | Comma-separated list of outputs in format `group:port:interface[:dtls]`. DTLS defaults to false. |
| `--rule-id`         | (Optional) Custom rule ID. If omitted, a UUID will be auto-generated.                           |

**Examples:**

```bash
# Single output
control_client add --input-interface eth0 --input-group 239.1.1.1 \
    --input-port 5000 --outputs 239.2.2.2:6000:eth1

# Fan-out to multiple outputs
control_client add --input-interface eth0 --input-group 239.1.1.1 \
    --input-port 5000 --outputs 239.2.2.2:6000:eth1,239.3.3.3:7000:eth2

# With custom rule ID and DTLS
control_client add --rule-id my-stream --input-interface eth0 \
    --input-group 239.1.1.1 --input-port 5000 --outputs 239.2.2.2:6000:eth1:true
```

### 4.2. Remove a Forwarding Rule

Removes an existing rule, identified by its rule ID.

```bash
./target/release/control_client remove \
    --rule-id <rule_id>
```

**Note:** Use the `list` command to see all rules and their IDs.

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

| Argument      | Description                                          |
| :------------ | :--------------------------------------------------- |
| `--interface` | The source IP address of the interface to send from. |
| `--group`     | The destination multicast group IP address.          |
| `--port`      | The destination multicast UDP port.                  |
| `--rate`      | The target send rate in packets per second.          |
| `--size`      | The size of the UDP payload in bytes.                |
