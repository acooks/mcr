# MCR Logging System - Interactive Demo Guide

## Overview

The MCR logging system provides structured, high-performance logging across all components:
- **Supervisor**: Async MPSC ring buffers
- **Control Plane Worker**: Async MPSC ring buffers
- **Data Plane Workers**: Lock-free shared memory ring buffers (per-core)

All logs go to stdout in a structured format: `[Severity] [Facility] message`

## 1. Basic Startup - See Logging in Action

Start the supervisor (requires root for CAP_NET_RAW):

```bash
# Start supervisor with 2 data plane workers
sudo ./target/release/multicast_relay supervisor \
  --user $USER \
  --group $USER \
  --interface lo \
  --num-workers 2

# You'll see structured logs like:
# [Info] [Supervisor] Spawning Control Plane worker
# [Info] [Supervisor] Spawning Data Plane worker for core 0
# [Info] [Supervisor] Spawning Data Plane worker for core 1
# [Info] [ControlPlane] Control plane worker started
# [Info] [DataPlane] Data plane worker started on core 0
# [Info] [DataPlane] Using Mutex Backend
```

## 2. Log Facilities

The system organizes logs by facility:

| Facility | Purpose | Used By |
|----------|---------|---------|
| Supervisor | Main supervisor process | Supervisor |
| ControlPlane | Control plane worker | CP Worker |
| DataPlane | Data plane orchestration | DP Workers |
| Ingress | Packet ingress processing | DP Workers |
| Egress | Packet egress processing | DP Workers |
| BufferPool | Memory pool management | DP Workers |
| Test | Unit tests | Tests |

## 3. Log Severity Levels

From most to least severe (RFC 5424 syslog standard):

```
Emergency - System unusable (supervisor crash, data plane fatal)
Alert     - Immediate action required (capability loss, socket failure)
Critical  - Critical conditions (worker restart, buffer exhaustion)
Error     - Error conditions (packet drop, rule dispatch failure)
Warning   - Warning conditions (high latency, approaching limits)
Notice    - Significant normal condition (worker startup, rule added)
Info      - Informational (packet forwarded, stats update)
Debug     - Debug-level messages (verbose packet traces)
```

## 4. Monitoring Logs During Operation

### Terminal 1: Start the system
```bash
sudo ./target/release/multicast_relay supervisor \
  --user $USER \
  --group $USER \
  --interface lo \
  --num-workers 2 2>&1 | tee /tmp/mcr_logs.txt
```

### Terminal 2: Watch specific facilities
```bash
# Watch only DataPlane logs
tail -f /tmp/mcr_logs.txt | grep "\[DataPlane\]"

# Watch errors from all facilities
tail -f /tmp/mcr_logs.txt | grep "\[Error\]"

# Watch supervisor decisions
tail -f /tmp/mcr_logs.txt | grep "\[Supervisor\]"
```

### Terminal 3: Interact via control client
```bash
# Add a forwarding rule (triggers ControlPlane logs)
./target/release/multicast_relay control \
  add-rule \
  --rule-id test-rule-1 \
  --input-group 239.1.1.1 \
  --input-port 5000 \
  --output-group 239.2.2.2 \
  --output-port 6000 \
  --output-interface lo

# List rules (ControlPlane processes this)
./target/release/multicast_relay control list-rules

# Get stats
./target/release/multicast_relay control get-stats
```

## 5. Log Format Examples

### Startup Sequence
```
[Info] [Supervisor] Starting MCR supervisor
[Info] [Supervisor] Spawning Control Plane worker
[Info] [Supervisor] Spawning Data Plane worker for core 0
[Info] [ControlPlane] Control plane worker started
[Info] [DataPlane] Data plane worker started on core 0
[Info] [DataPlane] Using Mutex Backend
```

### Command Processing (Debug Level)
```
[Debug] [DataPlane] Received command: AddRule { rule_id: "test-rule-1", ... }
[Debug] [DataPlane] Command sent to data plane thread successfully
[Debug] [DataPlane] Signaling eventfd
```

### Shutdown Sequence
```
[Info] [DataPlane] Supervisor stream closed, sending shutdown to data plane
[Info] [ControlPlane] Supervisor stream closed
[Info] [Supervisor] Shutting down...
```

### Error Examples
```
[Error] [DataPlane] FATAL: Failed to send command to data plane thread: ...
[Error] [ControlPlane] Failed to read from supervisor stream: ...
[Error] [Supervisor] Worker process exited unexpectedly
```

## 6. Shared Memory Inspection

Data plane workers use shared memory for zero-copy logging:

```bash
# See shared memory regions (while system running)
ls -lh /dev/shm/mcr_*

# Example output:
# -rw------- 1 user user 4.0M Nov 13 10:00 /dev/shm/mcr_dp_c0_dataplane
# -rw------- 1 user user 4.0M Nov 13 10:00 /dev/shm/mcr_dp_c0_ingress
# -rw------- 1 user user 4.0M Nov 13 10:00 /dev/shm/mcr_dp_c0_egress
# -rw------- 1 user user 4.0M Nov 13 10:00 /dev/shm/mcr_dp_c0_bufferpool

# Each data plane worker has its own set (one per core)
```

## 7. Performance Characteristics

### Data Plane (Lock-Free Shared Memory)
- **Write latency**: ~50ns (lock-free atomic operations)
- **No blocking**: Writers never block readers
- **Zero-copy**: Logs written directly to shared memory
- **Per-core isolation**: Each worker has dedicated ring buffers

### Control Plane & Supervisor (MPSC Ring Buffers)
- **Write latency**: ~100ns (MPSC channel + ring buffer)
- **Async-safe**: Integrates with tokio runtime
- **Buffered**: 16K entries default capacity

### Consumer (stdout)
- **Batch writes**: Processes all available entries before flushing
- **Adaptive polling**: 1ms sleep when no data
- **Separate thread**: Doesn't block log producers

## 8. Debugging Tips

### See all log activity
```bash
sudo ./target/release/multicast_relay supervisor \
  --user $USER --group $USER --interface lo --num-workers 2 \
  2>&1 | tee >(ts '[%Y-%m-%d %H:%M:%S]' > /tmp/mcr_timestamped.log)
```

### Filter by severity
```bash
# Only errors and warnings
tail -f /tmp/mcr_logs.txt | grep -E "\[Error\]|\[Warning\]"

# Info and above (exclude Debug)
tail -f /tmp/mcr_logs.txt | grep -v "\[Debug\]"
```

### Count logs by facility
```bash
grep -o "\[[A-Za-z]*\]" /tmp/mcr_logs.txt | sort | uniq -c
```

### Find specific events
```bash
# Worker startup events
grep "worker started" /tmp/mcr_logs.txt

# Command processing
grep "Received command" /tmp/mcr_logs.txt

# Errors only
grep "\[Error\]" /tmp/mcr_logs.txt
```

## 9. Log Rotation (Production)

For production deployments, pipe to a log rotation tool:

```bash
sudo ./target/release/multicast_relay supervisor ... \
  2>&1 | rotatelogs /var/log/mcr/mcr-%Y%m%d.log 86400
```

Or use systemd journal:

```bash
# In systemd unit file:
StandardOutput=journal
StandardError=journal

# Then query with:
journalctl -u multicast-relay -f
journalctl -u multicast-relay --since "1 hour ago" | grep "\[Error\]"
```

## 10. Future Enhancements

The logging system is designed to support (not yet implemented):

- **Runtime log level control**: `SetGlobalLogLevel`, `SetFacilityLogLevel` commands
- **Per-worker log filtering**: Control logs from specific workers
- **Structured metadata**: Key-value pairs in log entries
- **Multiple sinks**: File, syslog, network backends
- **Log aggregation**: Centralized logging for multi-node deployments

## Notes

- All worker logs automatically include facility context
- Logs are lock-free in the hot path (data plane)
- Shared memory is cleaned up on process exit
- Tests run with `--test-threads=1` to avoid shared memory conflicts
- Pre-logging initialization messages use eprintln! (documented in code)
