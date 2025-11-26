# RSS/RPS Configuration for Optimal Performance

## Overview

The multicast relay's PACKET_FANOUT_CPU architecture depends on the kernel distributing packets to the correct CPUs. This document explains:
- How RSS (hardware) and RPS (software) work
- How to configure them for optimal worker placement
- How to verify the configuration
- Troubleshooting packet distribution issues

## The Stack: NIC → RSS/RPS → CPU → PACKET_FANOUT → Worker

```
┌─────────────────────────────────────────────────────────────┐
│                  Physical NIC (eth0)                         │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         NIC Hardware RSS (if supported)              │  │
│  │  Computes hash(src_ip, dst_ip, src_port, dst_port)  │  │
│  └─────────┬─────────┬─────────┬─────────┬──────────────┘  │
└────────────┼─────────┼─────────┼─────────┼─────────────────┘
             │         │         │         │
       RX Queue 0  Queue 1  Queue 2  Queue 3  (Hardware queues)
             │         │         │         │
         IRQ to    IRQ to    IRQ to    IRQ to
         CPU 0     CPU 1     CPU 2     CPU 3  (Interrupt routing)
             │         │         │         │
             ▼         ▼         ▼         ▼
        ┌────────┐┌────────┐┌────────┐┌────────┐
        │Softirq ││Softirq ││Softirq ││Softirq │
        │ CPU 0  ││ CPU 1  ││ CPU 2  ││ CPU 3  │  (Kernel)
        └────┬───┘└────┬───┘└────┬───┘└────┬───┘
             │         │         │         │
             │    PACKET_FANOUT_CPU         │
             │    (fanout_group_id)         │
             ▼         ▼         ▼         ▼
        ┌────────┐┌────────┐┌────────┐┌────────┐
        │Worker 0││Worker 1││Worker 2││Worker 3│  (User space)
        │Pinned  ││Pinned  ││Pinned  ││Pinned  │
        │to CPU0 ││to CPU1 ││to CPU2 ││to CPU3 │
        └────────┘└────────┘└────────┘└────────┘
```

## RSS vs RPS: Hardware vs Software

### RSS (Receive-Side Scaling) - Hardware

**What it is:**
- NIC feature that distributes packets to multiple hardware RX queues
- Each queue has dedicated DMA ring buffer
- NIC computes hash and chooses queue
- Zero CPU overhead for distribution

**Pros:**
- ✅ Lowest latency (hardware acceleration)
- ✅ No CPU overhead for packet steering
- ✅ Works at line rate for high-speed NICs
- ✅ Better cache locality (fewer bounces)

**Cons:**
- ❌ Requires NIC support (not all NICs have it)
- ❌ Limited number of queues (typically 2-128)
- ❌ Configuration via ethtool (interface-specific)

**Check if your NIC supports RSS:**
```bash
ethtool -l eth0
```

Expected output for RSS-capable NIC:
```
Channel parameters for eth0:
Pre-set maximums:
RX:             16      # Maximum RSS queues
TX:             16
Other:          0
Combined:       16
Current hardware settings:
RX:             4       # Currently active queues
TX:             4
Other:          0
Combined:       4
```

### RPS (Receive Packet Steering) - Software

**What it is:**
- Kernel software that emulates RSS
- For NICs without hardware RSS support
- Packet distribution happens in softirq
- Configurable per-interface via sysfs

**Pros:**
- ✅ Works on any NIC (even without RSS)
- ✅ More flexible configuration
- ✅ Can handle unlimited CPUs

**Cons:**
- ❌ CPU overhead for packet steering
- ❌ Higher latency than hardware RSS
- ❌ Packets may bounce between CPUs

**When to use RPS:**
- NIC doesn't support RSS
- Need more queues than NIC supports
- Virtual NICs (often don't have RSS)

## Configuring RSS (Hardware)

### 1. Check Current Configuration

```bash
# View RSS queue count
ethtool -l eth0

# View RSS hash settings
ethtool -n eth0 rx-flow-hash udp4

# View RSS indirection table (maps hash → queue)
ethtool -x eth0
```

### 2. Set Number of RSS Queues

**Match queue count to worker count:**

```bash
# If you have 48 workers, set 48 RSS queues
sudo ethtool -L eth0 combined 48

# Verify
ethtool -l eth0
```

**Important:** Some NICs have a maximum queue count. If your NIC maxes out at 16 queues but you have 48 CPUs, you'll need to use RPS in addition to RSS, or accept that multiple workers share queues.

### 3. Configure RSS Hash Function

**Set which packet fields are used for hashing:**

```bash
# For multicast UDP (typical for multicast relay):
sudo ethtool -N eth0 rx-flow-hash udp4 sdfn

# Flags:
#   s = source IP
#   d = destination IP
#   f = source port
#   n = destination port
```

**Why this matters:**
- Multicast flows have same destination IP/port
- Need source IP/port for distribution
- Default may only use destination → all packets to one queue!

### 4. Configure RSS Indirection Table

**The indirection table maps hash values to specific queues/CPUs:**

```bash
# View current table
ethtool -x eth0

# Set custom table (advanced)
# This requires understanding NIC-specific format
# Usually auto-configured when setting queue count
```

### 5. Set IRQ Affinity

**Each RSS queue has an IRQ that should be pinned to the right CPU:**

```bash
# Find IRQs for eth0
grep eth0 /proc/interrupts

# Example output:
#  137:  eth0-TxRx-0
#  138:  eth0-TxRx-1
#  139:  eth0-TxRx-2
#  140:  eth0-TxRx-3

# Pin each IRQ to its CPU
echo 1 > /proc/irq/137/smp_affinity  # CPU 0 (bitmask 0001)
echo 2 > /proc/irq/138/smp_affinity  # CPU 1 (bitmask 0010)
echo 4 > /proc/irq/139/smp_affinity  # CPU 2 (bitmask 0100)
echo 8 > /proc/irq/140/smp_affinity  # CPU 3 (bitmask 1000)

# Or use irqbalance daemon (automatic)
sudo systemctl enable irqbalance
sudo systemctl start irqbalance
```

**Bitmask format:**
- Binary → Hex: CPU0=1, CPU1=2, CPU2=4, CPU3=8, etc.
- For CPU lists, use `/proc/irq/N/smp_affinity_list`:
  ```bash
  echo 0 > /proc/irq/137/smp_affinity_list  # CPU 0
  echo 1 > /proc/irq/138/smp_affinity_list  # CPU 1
  ```

## Configuring RPS (Software)

### When to Use RPS

1. **NIC lacks RSS support** - Check with `ethtool -l eth0`
2. **Need more queues than NIC provides** - e.g., 16 HW queues but 48 workers
3. **Virtual environment** - VM NICs often don't expose RSS
4. **Testing** - Software fallback when RSS misbehaves

### RPS Configuration

```bash
# Enable RPS on eth0 for CPUs 0-3 (hex bitmask)
# CPUs 0-3 = binary 1111 = hex F
echo f > /sys/class/net/eth0/queues/rx-0/rps_cpus

# For CPUs 0-7 (hex FF)
echo ff > /sys/class/net/eth0/queues/rx-0/rps_cpus

# For CPUs 0-47 (all 48 CPUs)
echo ffffffffffff > /sys/class/net/eth0/queues/rx-0/rps_cpus

# Verify
cat /sys/class/net/eth0/queues/rx-0/rps_cpus
```

### RPS Flow Count

**Tune the RPS flow table size:**

```bash
# Default is often too small for high packet rates
echo 32768 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt

# Global flow table size (sum of all queues)
echo 131072 > /proc/sys/net/core/rps_sock_flow_entries
```

## RFS (Receive Flow Steering)

**Advanced: Steers packets to the CPU where the application socket is located**

```bash
# Enable RFS globally
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries

# Enable per-queue
echo 2048 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt
echo 2048 > /sys/class/net/eth0/queues/rx-1/rps_flow_cnt
# ... repeat for all queues
```

**How RFS helps:**
- Kernel tracks which CPU a socket is on
- Tries to deliver packets to that CPU
- Improves cache locality if worker moves CPUs
- **May interfere with PACKET_FANOUT_CPU** if worker affinity isn't strict

## Multicast Relay Configuration Script

### Automated Setup Script

```bash
#!/bin/bash
# setup-rss.sh - Configure RSS/RPS for multicast relay

set -e

INTERFACE=${1:-eth0}
NUM_WORKERS=${2:-$(nproc)}

echo "Configuring $INTERFACE for $NUM_WORKERS workers"

# 1. Try to set RSS queues (hardware)
if ethtool -l "$INTERFACE" &>/dev/null; then
    MAX_QUEUES=$(ethtool -l "$INTERFACE" | grep -A4 "Pre-set maximums" | grep "Combined:" | awk '{print $2}')

    if [ "$MAX_QUEUES" -ge "$NUM_WORKERS" ]; then
        echo "Setting $NUM_WORKERS RSS queues (hardware)"
        sudo ethtool -L "$INTERFACE" combined "$NUM_WORKERS"
    else
        echo "NIC only supports $MAX_QUEUES queues, using all available"
        sudo ethtool -L "$INTERFACE" combined "$MAX_QUEUES"
        echo "Warning: $NUM_WORKERS workers > $MAX_QUEUES queues. Some workers will share queues."
    fi

    # Configure hash for multicast UDP
    echo "Configuring RSS hash for UDP multicast"
    sudo ethtool -N "$INTERFACE" rx-flow-hash udp4 sdfn || echo "Warning: Could not set UDP hash"
else
    echo "NIC doesn't support RSS, will use RPS (software)"
    MAX_QUEUES=1
fi

# 2. Set up RPS (software) if needed
if [ "$NUM_WORKERS" -gt "$MAX_QUEUES" ]; then
    echo "Enabling RPS for $NUM_WORKERS CPUs"

    # Calculate bitmask for CPUs 0 to NUM_WORKERS-1
    MASK=$(printf '%x' $((2**NUM_WORKERS - 1)))

    for queue in /sys/class/net/"$INTERFACE"/queues/rx-*; do
        echo "$MASK" | sudo tee "$queue/rps_cpus" > /dev/null
        echo "2048" | sudo tee "$queue/rps_flow_cnt" > /dev/null
    done

    echo "$((NUM_WORKERS * 2048))" | sudo tee /proc/sys/net/core/rps_sock_flow_entries > /dev/null
fi

# 3. IRQ affinity (if using RSS)
if [ "$MAX_QUEUES" -gt 1 ]; then
    echo "Configuring IRQ affinity"

    # Find IRQs for interface
    IRQS=$(grep "$INTERFACE" /proc/interrupts | cut -d: -f1 | tr -d ' ')

    CPU=0
    for IRQ in $IRQS; do
        if [ $CPU -lt "$NUM_WORKERS" ]; then
            echo "$CPU" | sudo tee /proc/irq/"$IRQ"/smp_affinity_list > /dev/null
            echo "  IRQ $IRQ → CPU $CPU"
            CPU=$((CPU + 1))
        fi
    done
fi

# 4. Disable irqbalance (it conflicts with manual pinning)
if systemctl is-active --quiet irqbalance; then
    echo "Stopping irqbalance (conflicts with manual IRQ pinning)"
    sudo systemctl stop irqbalance
    sudo systemctl disable irqbalance
fi

echo "RSS/RPS configuration complete for $INTERFACE"
```

### Usage

```bash
# Configure eth0 for 48 workers
sudo ./setup-rss.sh eth0 48

# Auto-detect CPU count
sudo ./setup-rss.sh eth0
```

## Verifying Configuration

### Check RSS Queue Distribution

```bash
# Watch per-queue packet counters
watch -n 1 'ethtool -S eth0 | grep rx_queue'
```

Expected output (packets distributed across queues):
```
     rx_queue_0_packets: 1234567
     rx_queue_1_packets: 1245678
     rx_queue_2_packets: 1256789
     rx_queue_3_packets: 1267890
```

If all packets go to `rx_queue_0`, RSS is not working!

### Check RPS Distribution

```bash
# Per-CPU softirq stats
watch -n 1 'grep "NET_RX" /proc/softirqs'
```

Expected output (NET_RX work distributed):
```
             CPU0       CPU1       CPU2       CPU3
NET_RX:    1234567    1245678    1256789    1267890
```

If all NET_RX is on CPU0, RPS is not configured correctly.

### Check IRQ Affinity

```bash
# Show which CPUs handle which IRQs
grep eth0 /proc/interrupts | while read line; do
    irq=$(echo "$line" | awk '{print $1}' | tr -d ':')
    affinity=$(cat /proc/irq/$irq/smp_affinity_list 2>/dev/null || echo "N/A")
    echo "IRQ $irq → CPU $affinity"
done
```

### Check Worker CPU Affinity

```bash
# Find multicast_relay worker PIDs
pgrep -f "multicast_relay worker" | while read pid; do
    affinity=$(taskset -pc "$pid" 2>/dev/null | awk '{print $NF}')
    echo "Worker PID $pid → CPU $affinity"
done
```

Expected: Each worker pinned to different CPU

## Common Issues and Solutions

### Issue 1: All Packets Go to Queue 0

**Symptom:**
```bash
ethtool -S eth0 | grep rx_queue
     rx_queue_0_packets: 999999999
     rx_queue_1_packets: 0
     rx_queue_2_packets: 0
```

**Cause:** RSS hash not configured for multicast flows

**Solution:**
```bash
# Configure UDP hash to include source IP/port
sudo ethtool -N eth0 rx-flow-hash udp4 sdfn
```

### Issue 2: Workers See Imbalanced Traffic

**Symptom:** Some workers process 10x more packets than others

**Possible causes:**
1. **Few multicast sources** - If only 1-2 sources, RSS may hash them to same queue
2. **IRQ affinity wrong** - IRQs not pinned to correct CPUs
3. **Worker CPU affinity wrong** - Workers not pinned to CPUs matching RSS queues

**Diagnosis:**
```bash
# Check if traffic is balanced at NIC level
ethtool -S eth0 | grep rx_queue_.*_packets

# If balanced at NIC but not at workers, check CPU affinity
pgrep -f "multicast_relay worker" | xargs -I {} taskset -cp {}
```

### Issue 3: High CPU Usage on CPU 0

**Symptom:** CPU 0 at 100%, others idle

**Cause:** All softirqs handled on CPU 0 (default without RSS/RPS)

**Solution:**
```bash
# Enable RPS for software distribution
echo f > /sys/class/net/eth0/queues/rx-0/rps_cpus  # CPUs 0-3
```

### Issue 4: irqbalance Interferes

**Symptom:** IRQ affinity keeps changing, breaking distribution

**Cause:** `irqbalance` daemon moving IRQs automatically

**Solution:**
```bash
# Disable irqbalance for manual control
sudo systemctl stop irqbalance
sudo systemctl disable irqbalance

# Or configure irqbalance to ignore eth0
echo "IRQBALANCE_BANNED_CPUS=0xFFFFFFFF" >> /etc/sysconfig/irqbalance
```

## Performance Tuning

### Ring Buffer Size

**Larger ring buffers reduce packet drops under load:**

```bash
# Check current size
ethtool -g eth0

# Increase to maximum
sudo ethtool -G eth0 rx 4096 tx 4096
```

### Interrupt Coalescing

**Reduce interrupt rate for high-throughput scenarios:**

```bash
# Check current settings
ethtool -c eth0

# Set adaptive coalescing (NIC adjusts automatically)
sudo ethtool -C eth0 adaptive-rx on adaptive-tx on

# Or set fixed values (microseconds)
sudo ethtool -C eth0 rx-usecs 50 tx-usecs 50
```

**Trade-off:**
- Lower values = lower latency, more CPU overhead (more interrupts)
- Higher values = higher latency, less CPU overhead (fewer interrupts)

### CPU Frequency Scaling

**Disable power saving for consistent performance:**

```bash
# Set CPUs to performance governor
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | sudo tee "$cpu"
done

# Verify
grep . /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Integration with Multicast Relay

### Supervisor Responsibilities

The multicast relay supervisor should:

1. **Detect CPU topology**
   ```rust
   let num_cpus = num_cpus::get();
   ```

2. **Configure RSS/RPS** before starting workers
   ```rust
   Command::new("./setup-rss.sh")
       .arg(&interface)
       .arg(&num_cpus.to_string())
       .status()?;
   ```

3. **Pin workers to CPUs**
   ```rust
   // Already done in spawn_data_plane_worker()
   unsafe {
       let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
       libc::CPU_SET(core_id as usize, &mut cpu_set);
       libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpu_set);
   }
   ```

4. **Use consistent fanout_group_id**
   ```rust
   // Already done: all workers share same fanout group
   let fanout_group_id = (std::process::id() & 0xFFFF) as u16;
   ```

### Worker Responsibilities

Workers should:

1. **Verify CPU affinity on startup**
   ```rust
   let cpu = unsafe {
       libc::sched_getcpu()
   };
   logger.info(Facility::DataPlane, &format!("Worker bound to CPU {}", cpu));
   ```

2. **Configure PACKET_FANOUT_CPU** (already implemented)
   ```rust
   let fanout_arg: u32 = (fanout_group_id as u32) | (libc::PACKET_FANOUT_CPU << 16);
   setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, ...);
   ```

3. **Report imbalance** if detected
   ```rust
   if packets_this_worker < (total_packets / num_workers * 0.5) {
       logger.warn(Facility::DataPlane, "Worker underutilized - check RSS config");
   }
   ```

## Recommended Deployment Checklist

- [ ] Check NIC RSS support: `ethtool -l eth0`
- [ ] Set RSS queue count = worker count: `ethtool -L eth0 combined N`
- [ ] Configure UDP multicast hash: `ethtool -N eth0 rx-flow-hash udp4 sdfn`
- [ ] Pin IRQs to CPUs: `/proc/irq/*/smp_affinity_list`
- [ ] Disable irqbalance: `systemctl stop irqbalance`
- [ ] Enable RPS if needed: `/sys/class/net/eth0/queues/rx-0/rps_cpus`
- [ ] Set CPU governor to performance: `/sys/devices/system/cpu/*/cpufreq/scaling_governor`
- [ ] Verify worker CPU affinity: `taskset -cp <PID>`
- [ ] Monitor queue distribution: `ethtool -S eth0 | grep rx_queue`
- [ ] Monitor softirq distribution: `grep NET_RX /proc/softirqs`
- [ ] Test with realistic traffic: measure per-worker packet rates

## References

- [Linux kernel RSS documentation](https://www.kernel.org/doc/Documentation/networking/scaling.txt)
- [Intel's RSS guide](https://www.intel.com/content/www/us/en/support/articles/000005811/network-and-i-o/ethernet-products.html)
- [ethtool man page](https://man7.org/linux/man-pages/man8/ethtool.8.html)
- [AF_PACKET PACKET_FANOUT](https://man7.org/linux/man-pages/man7/packet.7.html)
- [CPU affinity](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html)
