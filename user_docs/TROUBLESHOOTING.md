# MCR Troubleshooting Guide

This guide helps diagnose and resolve common issues with MCR (Multicast Relay).

## Table of Contents

- [Permission Errors](#permission-errors)
- [Buffer Exhaustion](#buffer-exhaustion)
- [Performance Tuning](#performance-tuning)
- [Connection Issues](#connection-issues)
- [Common Error Messages](#common-error-messages)

---

## Permission Errors

### "Permission denied" when starting mcrd

**Symptom:**

```text
Error: Permission denied (os error 13)
```

or

```text
Error: Operation not permitted (os error 1)
```

**Cause:** MCR requires `CAP_NET_RAW` capability to create AF_PACKET sockets for raw packet capture.

**Solutions:**

#### Option 1: Run with sudo (testing only)

```bash
sudo mcrd supervisor
```

#### Option 2: Set file capabilities (recommended for development)

```bash
# Grant capabilities to the binary (one-time setup)
sudo setcap 'cap_net_raw,cap_setuid,cap_setgid=eip' /path/to/mcrd

# Verify capabilities were set
getcap /path/to/mcrd
# Expected output: /path/to/mcrd cap_net_raw,cap_setgid,cap_setuid=eip
```

#### Option 3: Use systemd with ambient capabilities (recommended for production)

The provided systemd service file (`packaging/systemd/mcrd.service`) configures ambient capabilities automatically:

```bash
sudo cp packaging/systemd/mcrd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start mcrd
```

### "Cannot create control socket"

**Symptom:**

```text
Error: Failed to bind to /run/mcr/control.sock
```

**Cause:** The runtime directory doesn't exist or has incorrect permissions.

**Solution:**

```bash
# Create the runtime directory
sudo mkdir -p /run/mcr
sudo chown mcr:mcr /run/mcr
sudo chmod 750 /run/mcr
```

Or use the tmpfiles.d configuration:

```bash
sudo cp packaging/systemd/mcrd.tmpfiles /usr/lib/tmpfiles.d/mcrd.conf
sudo systemd-tmpfiles --create
```

### mcrctl "Connection refused"

**Symptom:**

```text
Error: Connection refused (os error 111)
```

**Cause:** The supervisor is not running, or the control socket path is incorrect.

**Solution:**

1. Check if mcrd is running: `pgrep -a mcrd`
2. Check the socket exists: `ls -la /run/mcr/control.sock`
3. Verify the socket path matches (default: `/run/mcr/control.sock`)

---

## Buffer Exhaustion

### Understanding buf_exhaust

The `buf_exhaust` counter in statistics output indicates how many packets were dropped because internal memory buffers were temporarily unavailable.

**Example stats line:**

```text
[STATS:Ingress] recv=1000000 matched=950000 ... buf_exhaust=50000
```

### When buf_exhaust > 0 is Normal

Buffer exhaustion is **expected and healthy** when:

- Traffic rate exceeds system capacity
- Brief traffic bursts occur
- The system is operating at maximum throughput

This indicates MCR's back-pressure mechanism is working correctly, protecting system stability by dropping excess packets at ingress.

### When buf_exhaust > 0 is a Problem

Buffer exhaustion indicates a problem when:

- It occurs at low traffic rates
- `errors > 0` in egress stats (downstream bottleneck)
- The ratio of `buf_exhaust / recv` is very high (>50%)

### Reducing Buffer Exhaustion

#### 1. Increase buffer pool sizes

```bash
# Set via environment variables before starting mcrd
export MCR_BUFFER_POOL_SMALL=2000    # Default: 1000 (for packets ≤2KB)
export MCR_BUFFER_POOL_STANDARD=1000 # Default: 500 (for packets ≤9KB)
export MCR_BUFFER_POOL_JUMBO=400     # Default: 200 (for jumbo frames)

mcrd supervisor
```

Or in systemd:

```ini
[Service]
Environment="MCR_BUFFER_POOL_SMALL=2000"
Environment="MCR_BUFFER_POOL_STANDARD=1000"
```

#### 2. Increase socket send buffer

```bash
export MCR_SOCKET_SNDBUF=8388608  # 8 MB (default: 4 MB)
mcrd supervisor
```

#### 3. Check for downstream bottlenecks

If `errors > 0` in egress stats, the problem is downstream (network switch, receiving host). Increasing buffers won't help - fix the downstream issue.

---

## Performance Tuning

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCR_BUFFER_POOL_SMALL` | 1000 | Number of small buffers (≤2KB packets) |
| `MCR_BUFFER_POOL_STANDARD` | 500 | Number of standard buffers (≤9KB packets) |
| `MCR_BUFFER_POOL_JUMBO` | 200 | Number of jumbo buffers (>9KB packets) |
| `MCR_SOCKET_SNDBUF` | 4194304 | Socket send buffer size in bytes (4 MB) |
| `MCR_NUM_RECV_BUFFERS` | 32 | Number of receive buffers for io_uring |
| `MCR_STATS_INTERVAL_MS` | 0 | Stats reporting interval (0 = packet-count based) |

### High-Throughput Configuration

For sustained high packet rates (>200k pps):

```bash
# Increase buffer pools
export MCR_BUFFER_POOL_SMALL=4000
export MCR_BUFFER_POOL_STANDARD=2000

# Increase socket buffer (8 MB)
export MCR_SOCKET_SNDBUF=8388608

# Start supervisor
mcrd supervisor
```

### System-Level Tuning

#### Increase kernel socket buffer limits

```bash
# Check current limits
sysctl net.core.rmem_max
sysctl net.core.wmem_max

# Increase limits (add to /etc/sysctl.conf for persistence)
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

#### CPU affinity (optional)

For consistent latency, pin MCR to specific CPU cores using taskset or the systemd `CPUAffinity=` directive.

---

## Connection Issues

### No packets being forwarded

**Symptom:** `matched=0` and `no_match` is increasing

**Diagnosis:**

```bash
# Check active rules
mcrctl list

# Check if traffic is arriving
mcrctl stats
```

**Common causes:**

1. **Wrong multicast group or port** - Verify the rule matches the source traffic
2. **Wrong input interface** - Traffic may arrive on a different interface
3. **Firewall blocking** - Check iptables/nftables rules
4. **IGMP snooping** - Switch may not be forwarding multicast to MCR's port

### Packets received but not sent

**Symptom:** `recv` and `matched` increasing, but `sent=0`

**Diagnosis:**

```bash
mcrctl stats
# Look for errors > 0 in egress stats
```

**Common causes:**

1. **Output interface down** - Check `ip link show <interface>`
2. **Routing issue** - Check `ip route` for the output destination
3. **ARP failure** - Check `ip neigh` for the next hop

### High send errors

**Symptom:** `errors > 0` in egress stats

**Common causes:**

1. **Network congestion** - Downstream switch or host is overwhelmed
2. **Interface down** - Output interface went down
3. **MTU mismatch** - Packet too large for output interface

---

## Common Error Messages

### "AF_PACKET socket creation failed"

**Cause:** Missing `CAP_NET_RAW` capability or interface doesn't exist.

**Solution:** See [Permission Errors](#permission-errors) section.

### "Interface not found: eth0"

**Cause:** The specified interface doesn't exist on the system.

**Solution:**

```bash
# List available interfaces
ip link show

# Use the correct interface name (e.g., enp0s3, ens192)
mcrctl add --input-interface enp0s3 ...
```

### "Address already in use"

**Cause:** Another instance of mcrd is already running, or the control socket wasn't cleaned up.

**Solution:**

```bash
# Check for running instances
pgrep -a mcrd

# If stale socket exists, remove it
sudo rm /run/mcr/control.sock
```

### "Rule already exists"

**Cause:** Attempting to add a rule that duplicates an existing rule's input tuple (interface + group + port).

**Solution:**

```bash
# List existing rules
mcrctl list

# Remove the existing rule first, or modify outputs
mcrctl remove --rule-id <existing-id>
```

### "Worker process exited unexpectedly"

**Cause:** A data plane worker crashed. The supervisor will automatically restart it.

**Diagnosis:**

```bash
# Check system logs for crash details
journalctl -u mcrd -n 100

# Check for kernel messages (OOM, segfault)
dmesg | tail -50
```

**Common causes:**

1. **Out of memory** - Increase system RAM or reduce buffer pool sizes
2. **io_uring issue** - Ensure kernel version is 5.10+ LTS
3. **Bug** - Report with reproduction steps

---

## Getting Help

If you can't resolve an issue:

1. **Check logs:** `journalctl -u mcrd -f` or stderr output
2. **Enable debug logging:** `mcrctl log-level set --global debug`
3. **Gather diagnostics:**

   ```bash
   mcrctl list
   mcrctl list-workers
   mcrctl stats
   uname -r  # kernel version
   ```

4. **Report issues:** Open an issue at the project repository with diagnostics
