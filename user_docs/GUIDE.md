# MCR User Guide

## Prerequisites

Before starting, ensure your system meets the following requirements:

- **Linux Kernel:** Version 5.6 or newer (5.10+ LTS recommended) is required for `io_uring` support.
- **Dependencies:** Rust toolchain (if building from source).
- **Root/Capabilities:** You need `sudo` access or `CAP_NET_RAW` capabilities to run the daemon.

## Quick Start

### 1. Build

```bash
cargo build --release
```

### 2. Start the Daemon

```bash
sudo ./target/release/mcrd supervisor
```

### 3. Add a Forwarding Rule

```bash
./target/release/mcrctl add \
    --input-interface eth0 \
    --input-group 239.1.1.1 \
    --input-port 5000 \
    --outputs 239.2.2.2:6000:eth1
```

### 4. Verify

```bash
./target/release/mcrctl list       # See active rules
./target/release/mcrctl stats      # See forwarding statistics
```

## Common Operations

### Add a Fan-Out Rule (1-to-many)

```bash
mcrctl add --input-interface eth0 --input-group 239.1.1.1 \
    --input-port 5000 --outputs 239.2.2.2:6000:eth1,239.3.3.3:7000:eth2
```

### Remove a Rule

```bash
mcrctl list                        # Find the rule ID
mcrctl remove --rule-id <id>
```

### Check Health

```bash
mcrctl ping
mcrctl list-workers
```

### Manage Logging

```bash
mcrctl log-level get
mcrctl log-level set --global debug
```

## Tunneling and VPNs

Because MCR uses standard kernel sockets for egress, it is fully compatible with Layer 3 VPNs like **WireGuard**, **OpenVPN**, and **Tailscale**.

**How it works:**
MCR "republishes" the multicast payload as a unicast UDP packet destined for the VPN endpoint. The Linux kernel handles the encryption and routing through the tunnel interface.

**Example: Multicast over WireGuard**
Relay a multicast stream from a physical LAN (`eth0`) to a remote peer (`10.100.0.2`) over a WireGuard interface (`wg0`).

```bash
mcrctl add \
    --input-interface eth0 \
    --input-group 239.1.1.1 \
    --input-port 5000 \
    --outputs 10.100.0.2:6000:wg0
```

## Deployment Options

Choose the deployment method that best fits your environment.

### 1. Production (Recommended): Systemd Service

For production deployments, use the provided systemd service. This method handles permissions automatically, starts MCR at boot, and restarts it on failure.

```bash
# Install the service files
sudo cp packaging/systemd/mcrd.service /etc/systemd/system/
sudo cp packaging/systemd/mcrd.sysusers /usr/lib/sysusers.d/mcrd.conf
sudo cp packaging/systemd/mcrd.tmpfiles /usr/lib/tmpfiles.d/mcrd.conf

# Create the 'mcr' user and runtime directories
sudo systemd-sysusers
sudo systemd-tmpfiles --create

# Enable and start
sudo systemctl enable --now mcrd
```

The service runs as the unprivileged `mcr` user with ambient capabilities (`CAP_NET_RAW`), ensuring secure operation without requiring root or file-level capabilities.

### 2. Manual / Development: Running without Root

If you are developing or running manually but want to maintain security, you can run MCR as a standard user by granting the binary specific capabilities.

**Required capabilities:**

- `CAP_NET_RAW`: Create `AF_PACKET` sockets for packet capture.
- `CAP_SETUID` / `CAP_SETGID`: Drop worker privileges (only needed if starting as root).

**One-time setup (requires root):**

```bash
# Grant capabilities to the binary
sudo setcap 'cap_net_raw,cap_setuid,cap_setgid=eip' /usr/local/bin/mcrd

# Verify
getcap /usr/local/bin/mcrd
```

**Running:**

```bash
# Start the supervisor (no sudo needed)
mcrd supervisor --config /etc/mcr/rules.json5
```

### 3. Quick Test: Running as Root

For initial testing or in trusted, ephemeral environments (like containers), you can run MCR directly as root.

```bash
sudo mcrd supervisor --config /etc/mcr/rules.json5
```

**⚠️ Warning:** This is not recommended for production as it provides no privilege separation. If the process is compromised, the attacker gains full root access.

## Testing with mcrgen

Generate test traffic:

```bash
./target/release/mcrgen \
    --interface 10.0.0.1 \
    --group 239.1.1.1 \
    --port 5000 \
    --rate 10000 \
    --size 1400
```

**Note:** `--interface` takes an IP address, not an interface name.

## Known Limitations

- **Rule names via CLI:** When adding rules via `mcrctl add`, the `--name` flag is not supported. Use configuration files to assign human-readable names to rules.
- **IPv6:** MCR currently only supports IPv4 multicast. IPv6 multicast is not implemented.
- **Hot interface changes:** If a network interface goes down or changes IP address, MCR does not automatically detect this. Restart the affected worker or the supervisor.

## More Information

- **[Reference Manual](./REFERENCE.md)** - Complete command reference and configuration options
- **[Operational Guide](./OPERATIONAL_GUIDE.md)** - Monitoring statistics
- **[Troubleshooting Guide](./TROUBLESHOOTING.md)** - Diagnose and fix common issues
- **[Security Model](./SECURITY.md)** - Privilege separation and capabilities
- **[Why MCR?](./WHY_USE_MCR.md)** - Problem MCR solves vs alternatives
