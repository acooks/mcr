# MCR Reference Manual

This document provides the complete reference for configuring and operating MCR.

## Binaries

MCR provides three binaries:

| Binary | Purpose |
| :----- | :------ |
| `mcrd` | The daemon (supervisor + workers) |
| `mcrctl` | Control client for managing rules at runtime |
| `mcrgen` | Traffic generator for testing |

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
sudo ./target/release/mcrd supervisor --interface lo --num-workers 1

# In another terminal
./target/release/mcrctl add \
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
MCR_SOCKET_SNDBUF=8388608 sudo ./target/release/mcrd supervisor --num-workers 4
```

---

## 4. `mcrd` - The Daemon

Start the MCR daemon:

```bash
sudo mcrd supervisor [OPTIONS]
```

### Options

| Option | Default | Description |
| :----- | :------ | :---------- |
| `--config <PATH>` | None | Load rules from JSON5 configuration file at startup |
| `--num-workers <N>` | Number of CPU cores | Number of worker processes to spawn |
| `--interface <NAME>` | `lo` | Network interface for PACKET_FANOUT_CPU |
| `--control-socket-path <PATH>` | `/tmp/mcrd_control.sock` | Unix socket for mcrctl connections |

### Examples

```bash
# Basic start with defaults
sudo mcrd supervisor

# With configuration file
sudo mcrd supervisor --config /etc/mcr/rules.json5

# Custom worker count and interface
sudo mcrd supervisor --interface eth0 --num-workers 4
```

All forwarding rules are managed at runtime via `mcrctl`.

---

## 5. `mcrctl` - Control Client

The control client manages the MCR daemon at runtime.

### 5.1. Add a Forwarding Rule

```bash
mcrctl add \
    --input-interface <iface> \
    --input-group <ip> \
    --input-port <port> \
    --outputs <group>:<port>:<interface>[,...]
```

**Arguments:**

| Argument | Description |
| :------- | :---------- |
| `--input-interface` | Network interface for input (e.g., `eth0`) |
| `--input-group` | Input multicast group IP |
| `--input-port` | Input UDP port |
| `--outputs` | Output specs: `group:port:interface` (comma-separated for fan-out) |
| `--rule-id` | (Optional) Custom rule ID |

**Constraints:**

- Input and output interfaces must be different (self-loops rejected)
- Loopback (`lo`) is allowed but not recommended for production

**Examples:**

```bash
# Forward from eth0 to eth1
mcrctl add --input-interface eth0 --input-group 239.1.1.1 \
    --input-port 5000 --outputs 239.2.2.2:6000:eth1

# Fan-out to multiple destinations
mcrctl add --input-interface eth0 --input-group 239.1.1.1 \
    --input-port 5000 --outputs 239.2.2.2:6000:eth1,239.3.3.3:7000:eth2

# With custom rule ID
mcrctl add --rule-id my-stream --input-interface eth0 \
    --input-group 239.1.1.1 --input-port 5000 --outputs 239.2.2.2:6000:eth1
```

#### Flexible Address Support

MCR supports any combination of unicast and multicast addresses for both input and output:

| Scenario | Input | Output | Use Case |
| :------- | :---- | :----- | :------- |
| Standard relay | Multicast | Multicast | Bridge multicast across network segments |
| Multicast-to-unicast | Multicast | Unicast | Deliver to legacy systems or cloud VPCs |
| Unicast-to-multicast | Unicast | Multicast | Inject from unicast tunnel into multicast |
| Unicast-to-unicast | Unicast | Unicast | General packet forwarding |

**Multicast-to-Unicast Example:**

```bash
# Forward multicast 239.1.1.1:5000 to unicast host 10.0.0.100:6000
mcrctl add --input-interface eth0 --input-group 239.1.1.1 \
    --input-port 5000 --outputs 10.0.0.100:6000:eth1
```

**Unicast-to-Multicast Example (tunnel endpoint):**

```bash
# Receive unicast from tunnel and re-inject to multicast
mcrctl add --input-interface eth0 --input-group 10.0.0.50 \
    --input-port 5000 --outputs 239.1.1.1:5000:eth1
```

**Hybrid Fan-Out:**

```bash
# Fan-out to both multicast group and specific unicast host
mcrctl add --input-interface eth0 --input-group 239.1.1.1 \
    --input-port 5000 --outputs 239.2.2.2:6000:eth1,10.0.0.100:6000:eth1
```

This flexibility enables complete multicast tunneling chains:

```text
[Network A]              [Routed Network]           [Network B]
Multicast 239.x  ──→  Unicast tunnel  ──→  Multicast 239.x
    (MCR #1)             (IP routing)          (MCR #2)
```

### 5.2. Rule IDs

Every rule has a unique ID for management.

**Auto-generated (default):** A stable hash computed from (interface, group, port). The same input always produces the same ID, making rules stable across config reloads.

**Custom:** Use `--rule-id my-name` for predictable management in scripts.

```bash
# Find rule IDs
mcrctl list

# Remove by ID
mcrctl remove --rule-id <id>
```

### 5.3. Other Commands

```bash
mcrctl list              # List all rules
mcrctl list-workers      # List worker processes
mcrctl stats             # Get forwarding statistics
mcrctl ping              # Health check
mcrctl remove --rule-id <id>  # Remove a rule
```

### 5.4. Statistics

```bash
mcrctl stats
```

Returns JSON with per-flow metrics: `packets_relayed`, `bytes_relayed`, `packets_per_second`, `bits_per_second`.

Statistics are aggregated across all workers and reported every 10,000 packets.

### 5.5. Log Levels

```bash
mcrctl log-level get                              # Show current levels
mcrctl log-level set --global info                # Set global level
mcrctl log-level set --facility DataPlane --level debug  # Per-facility
```

Levels: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, `debug`

### 5.6. Configuration Management

MCR supports JSON5 configuration files for persistent rule sets.

```bash
mcrctl config show              # Show running config as JSON5
mcrctl config save <file>       # Save running config to file
mcrctl config load <file>       # Load rules from file (merges with running)
mcrctl config check <file>      # Validate file without loading
```

**Example JSON5 configuration:**

```json5
{
  // MCR configuration
  rules: [
    {
      name: "video-feed",  // Optional human-friendly name
      input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
      outputs: [
        { group: "239.2.2.2", port: 6000, interface: "eth1" }
      ]
    },
    {
      name: "audio-feed",
      input: { interface: "eth0", group: "239.1.1.2", port: 5001 },
      outputs: [
        { group: "239.2.2.3", port: 6001, interface: "eth1" },
        { group: "239.2.2.4", port: 6002, interface: "eth2" }  // Fan-out
      ]
    },
    {
      name: "legacy-unicast",  // Multicast-to-unicast conversion
      input: { interface: "eth0", group: "239.1.1.3", port: 5002 },
      outputs: [
        { group: "10.0.0.100", port: 6003, interface: "eth1" }  // Unicast output
      ]
    },
    {
      name: "tunnel-endpoint",  // Unicast-to-multicast (tunnel receiver)
      input: { interface: "eth1", group: "10.0.0.50", port: 5002 },  // Unicast input
      outputs: [
        { group: "239.1.1.3", port: 5002, interface: "eth0" }  // Re-inject to multicast
      ]
    }
  ],

  // Optional: Pin workers to specific CPU cores per interface
  pinning: {
    "eth0": [0, 1, 2, 3],  // 4 workers on cores 0-3
    "eth1": [4, 5]         // 2 workers on cores 4-5
  }
}
```

**Configuration fields:**

| Field | Required | Description |
| :---- | :------- | :---------- |
| `rules` | Yes | Array of forwarding rules |
| `rules[].name` | No | Human-friendly name for the rule (for display and `RemoveRuleByName`) |
| `rules[].input` | Yes | Input specification: `interface`, `group`, `port` |
| `rules[].outputs` | Yes | Array of output destinations |
| `pinning` | No | Map of interface name to CPU core list |

**Note:** The `pinning` configuration controls how many workers spawn per interface and which CPU cores they use. If not specified, workers use the `--num-workers` default.

---

## 6. `mcrgen` - Traffic Generator

Generate test multicast traffic:

```bash
mcrgen --interface <ip> --group <ip> --port <port> --rate <pps> --size <bytes>
```

| Argument | Description |
| :------- | :---------- |
| `--interface` | Source IP address to send from |
| `--group` | Destination multicast group |
| `--port` | Destination UDP port |
| `--rate` | Packets per second |
| `--size` | UDP payload size in bytes |

**Note:** `--interface` expects an IP address (e.g., `10.0.0.1`), not an interface name.
