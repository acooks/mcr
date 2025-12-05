# MCR User Guide

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

## More Information

- **[Reference Manual](./REFERENCE.md)** - Complete command reference and configuration options
- **[Operational Guide](./OPERATIONAL_GUIDE.md)** - Monitoring and troubleshooting
- **[Why MCR?](./WHY_USE_MCR.md)** - Problem MCR solves vs alternatives
