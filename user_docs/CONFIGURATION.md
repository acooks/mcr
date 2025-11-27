# MCR Configuration Guide

**Status:** ✅ CURRENT
**Last Updated:** 2025-11-27

---

This document provides a central reference for configuring the Multicast Relay (MCR) application. Configuration is managed through a combination of kernel tuning, environment variables, and runtime commands.

## 1. Kernel Version Requirements

MCR relies on modern Linux kernel features for high-performance packet processing. Understanding these requirements helps ensure compatibility and optimal performance.

### Minimum Kernel Version

**Absolute minimum: Linux 5.6**
**Recommended: Linux 5.10+ (LTS kernel)**

### Feature Requirements by Kernel Version

| Kernel Version | Feature | MCR Usage | Impact if Missing |
| :------------- | :------ | :-------- | :---------------- |
| **5.6+** | `IORING_OP_RECV` / `IORING_OP_SEND` | Socket I/O operations in unified data plane | **MCR will not run** - core operations fail |
| **5.1+** | `io_uring` basic support | Asynchronous I/O foundation | **MCR will not run** - io_uring unavailable |
| **3.1+** | `PACKET_FANOUT_CPU` | Multi-worker packet distribution | Single-worker only - no multi-core scaling |

### Checking Your Kernel Version

```bash
# Check current kernel version
uname -r

# Example output:
# 6.17.7-200.fc42.x86_64   ✅ Fully compatible (6.x)
# 5.15.0-56-generic        ✅ Fully compatible (5.15 LTS)
# 5.10.0-21-amd64          ✅ Recommended minimum (5.10 LTS)
# 5.4.0-135-generic        ❌ Too old (missing IORING_OP_RECV/SEND)
```

### Kernel Version Details

#### io_uring Socket Operations (Required)

MCR's unified data plane (`src/worker/unified_loop.rs`) uses `io_uring` for zero-copy, event-driven I/O:

- **`IORING_OP_RECV`** (Linux 5.6+): Receive packets from AF_PACKET sockets
  - Used in: `src/worker/unified_loop.rs:832`
  - `opcode::Recv::new()`
- **`IORING_OP_SEND`** (Linux 5.6+): Send packets to UDP sockets
  - Used in: `src/worker/unified_loop.rs:883`
  - `opcode::Send::new()`

**Why it matters:** Without these opcodes, MCR cannot perform socket I/O asynchronously and will fail at runtime.

#### PACKET_FANOUT_CPU (Required for Multi-Core Scaling)

MCR uses `PACKET_FANOUT_CPU` to distribute incoming packets across multiple worker processes based on CPU affinity:

- **Feature**: `PACKET_FANOUT_CPU` socket option
- **Introduced**: Linux 3.1
- **Used in**: `src/worker/unified_loop.rs:210`
- **Configuration**: Set via `--num-workers` flag on supervisor

**How it works:**
1. NIC delivers packet to CPU via RSS/RPS
2. Kernel's `PACKET_FANOUT_CPU` delivers packet to worker bound to that CPU
3. Worker processes packet with hot CPU cache

**Why it matters:** Without `PACKET_FANOUT_CPU`, multi-worker mode will duplicate packets (each worker receives all packets), causing incorrect forwarding and statistics.

### Recommended Distributions

The following distributions ship with compatible kernels:

| Distribution | Kernel Version | MCR Compatible? |
| :----------- | :------------- | :-------------- |
| **Ubuntu 22.04 LTS** | 5.15 (HWE: 6.x) | ✅ Fully compatible |
| **Ubuntu 20.04 LTS** | 5.4 (HWE: 5.15) | ⚠️ Base kernel too old, HWE kernel OK |
| **Debian 12 (Bookworm)** | 6.1 | ✅ Fully compatible |
| **Debian 11 (Bullseye)** | 5.10 | ✅ Fully compatible |
| **Fedora 40+** | 6.x | ✅ Fully compatible |
| **RHEL 9** | 5.14 | ✅ Fully compatible |
| **RHEL 8** | 4.18 | ❌ Too old |

**Note:** Ubuntu LTS releases offer Hardware Enablement (HWE) kernels with newer versions. Use `apt install linux-generic-hwe-XX.04` to upgrade.

### Upgrading Your Kernel

If your kernel is too old:

```bash
# Ubuntu: Install HWE kernel
sudo apt update
sudo apt install linux-generic-hwe-$(lsb_release -rs)
sudo reboot

# Debian: Install backports kernel
echo "deb http://deb.debian.org/debian $(lsb_release -cs)-backports main" | \
  sudo tee /etc/apt/sources.list.d/backports.list
sudo apt update
sudo apt install -t $(lsb_release -cs)-backports linux-image-amd64
sudo reboot

# Fedora: Update to latest kernel (usually automatic)
sudo dnf upgrade kernel
sudo reboot
```

### Testing Kernel Compatibility

After verifying your kernel version, test MCR:

```bash
# Build MCR
./scripts/build_all.sh

# Run a simple forwarding test
sudo ./target/release/multicast_relay supervisor --interface lo --num-workers 1

# In another terminal
./target/release/control_client add \
  --input-interface lo --input-group 239.1.1.1 --input-port 5000 \
  --outputs 239.2.2.2:6000:lo
```

If MCR starts without errors and accepts rules, your kernel is compatible.

---

## 2. Kernel Tuning (Required for High Performance)

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

## 3. Environment Variables (Advanced Tuning)

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

## 4. `multicast_relay` Supervisor

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

## 5. `control_client` Commands

The `control_client` is the command-line tool for managing the MCR supervisor at runtime.

### 5.1. Add a Forwarding Rule

Adds a new rule to forward an input stream to one or more outputs.

```bash
./target/release/control_client add \
    --input-interface <iface> \
    --input-group <ip> \
    --input-port <port> \
    --outputs <group>:<port>:<interface>[,<group>:<port>:<interface>...]
```

**⚠️ Interface Configuration Warnings:**

- **Self-loops are rejected**: If `input-interface` and an output `interface` are the same, the rule will be rejected. This prevents packet feedback loops where transmitted packets are immediately received again, causing exponential packet multiplication and invalid statistics.

- **Loopback interface (`lo`) not recommended**: While allowed, using the loopback interface can cause packet reflection artifacts in testing. AF_PACKET sockets on loopback may receive their own transmitted packets, leading to inflated statistics. Use veth pairs or real network interfaces (eth0, eth1) for accurate testing and production use.

**Arguments:**

| Argument            | Description                                                                                     |
| :------------------ | :---------------------------------------------------------------------------------------------- |
| `--input-interface` | Network interface name for the input stream (e.g., `eth0`, `lo`).                               |
| `--input-group`     | Input multicast group IP address.                                                               |
| `--input-port`      | Input multicast UDP port.                                                                       |
| `--outputs`         | Comma-separated list in format `group:port:interface[:dtls]` where `interface` is a network interface name (e.g., `eth0`). DTLS defaults to false. |
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

---

## Rule ID Lifecycle

Every forwarding rule has a unique **rule ID** that identifies it throughout its lifecycle. Understanding how rule IDs work is essential for managing rules at runtime.

### How Rule IDs Are Generated

1. **Auto-Generated (Default):**
   - If you don't specify `--rule-id` when adding a rule, MCR automatically generates a UUID v4
   - Example: `a3f8c2b5-7d4e-4a1b-9c6f-2e8d5b1a7c3d`
   - Generated by `uuid::Uuid::new_v4()` in the supervisor

2. **Custom (User-Provided):**
   - You can provide a custom rule ID via the `--rule-id` flag
   - Must be unique across all active rules
   - Useful for predictable rule management in scripts or automation
   - Example: `--rule-id production-stream-1`

### Finding Rule IDs

Use the `list` command to see all active rules and their IDs:

```bash
./target/release/control_client list
```

**Example output:**
```json
{
  "Rules": [
    {
      "rule_id": "a3f8c2b5-7d4e-4a1b-9c6f-2e8d5b1a7c3d",
      "input_interface": "eth0",
      "input_group": "239.1.1.1",
      "input_port": 5000,
      "outputs": [...]
    }
  ]
}
```

### Rule ID Persistence

**Important:** Rule IDs are **not persistent** across supervisor restarts.

- Rule IDs exist only in the supervisor's in-memory state (`master_rules` HashMap)
- When the supervisor restarts, all rules are lost
- You must re-add rules after a restart (or use a configuration management tool)

**Implications:**
- Auto-generated UUIDs will be **different** after a restart
- If you use custom rule IDs, you can re-create rules with the same IDs
- For production deployments, consider using custom IDs in your automation scripts

### Best Practices

1. **For Manual Testing:**
   - Auto-generated UUIDs are fine
   - Use `list` to find the ID before removing

2. **For Automation/Scripts:**
   - Use custom rule IDs with meaningful names
   - Example: `--rule-id camera-01-to-studio`
   - Makes scripts more readable and debuggable

3. **For Production:**
   - Use custom rule IDs in infrastructure-as-code tools
   - Document your rule ID naming convention
   - Consider prefixing by function: `prod-`, `test-`, etc.

**Example with custom ID:**
```bash
# Add with custom ID
control_client add --rule-id my-stream \
    --input-interface eth0 --input-group 239.1.1.1 \
    --input-port 5000 --outputs 239.2.2.2:6000:eth1

# Remove using the same ID
control_client remove --rule-id my-stream
```

---

### 5.2. Remove a Forwarding Rule

Removes an existing rule, identified by its rule ID.

```bash
./target/release/control_client remove \
    --rule-id <rule_id>
```

**Note:** Use the `list` command to see all rules and their IDs (see "Rule ID Lifecycle" section above for details).

### 5.3. List Rules

Displays all currently active forwarding rules.

```bash
./target/release/control_client list
```

### 5.4. Get Statistics

Retrieves and displays aggregated performance statistics from all data plane workers.

```bash
./target/release/control_client stats
```

#### Output Format

The `stats` command returns JSON with performance metrics for each active flow:

```json
{
  "Stats": [
    {
      "input_group": "239.1.1.1",
      "input_port": 5000,
      "packets_relayed": 30000,
      "bytes_relayed": 30720000,
      "packets_per_second": 2903.5920589974367,
      "bits_per_second": 23786226.147307
    }
  ]
}
```

#### Field Descriptions

| Field                | Type   | Description                                                                 |
| :------------------- | :----- | :-------------------------------------------------------------------------- |
| `input_group`        | String | The multicast group IP address for this flow.                               |
| `input_port`         | Number | The UDP port for this flow.                                                 |
| `packets_relayed`    | Number | Total number of packets forwarded (aggregated across all workers).          |
| `bytes_relayed`      | Number | Total number of bytes forwarded (aggregated across all workers).            |
| `packets_per_second` | Number | Current packet rate (aggregated across all workers).                        |
| `bits_per_second`    | Number | Current throughput in bits per second (aggregated across all workers).      |

#### Multi-Worker Aggregation

When running with multiple data plane workers (`--num-workers`), the supervisor automatically aggregates statistics from all workers:

- **Counters** (`packets_relayed`, `bytes_relayed`): Summed across all workers
- **Rates** (`packets_per_second`, `bits_per_second`): Summed across all workers

**Example:** If Worker 1 reports 10,000 packets at 1000 pps and Worker 2 reports 20,000 packets at 2000 pps for the same flow, the aggregated stats will show 30,000 packets at 3000 pps.

#### Reporting Frequency

Statistics are reported from data plane workers every 10,000 packets processed. This threshold is intentional to minimize overhead on the high-performance data plane. As a result, `packets_relayed` values will typically be multiples of 10,000.

For flows with lower traffic rates, stats may not appear immediately until the 10,000-packet threshold is reached on at least one worker.

#### Empty Stats

If no traffic has been processed, or if no flows have reached the 10,000-packet reporting threshold, the command returns an empty array:

```json
{
  "Stats": []
}
```

### 5.5. Manage Log Levels

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

## 6. `traffic_generator`

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

**Note:** Unlike `control_client` which uses network interface names (e.g., `eth0`), the `traffic_generator` `--interface` parameter expects an IP address (e.g., `10.0.0.1`).
