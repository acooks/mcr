# Interactive CLI and Runtime Log Control Design

## Overview

This document defines the design for:

1. Runtime log-level filtering and control
2. Interactive TUI for monitoring and control
3. Log streaming capabilities

## Motivation

- **Debugging**: Change log levels at runtime without restarting
- **Observability**: Real-time view of system behavior
- **Usability**: Modern split-pane interface for ops/SRE workflows
- **Performance**: Stream logs efficiently without file I/O

## Design Decisions

### D1: Log-Level Control via Supervisor Commands

**Decision**: Extend SupervisorCommand enum with logging control commands.

**Rationale**:

- Reuses existing Unix socket infrastructure
- Consistent with current command architecture
- No additional IPC mechanism needed

**Implementation**:

```rust
pub enum SupervisorCommand {
    // ... existing commands ...

    SetLogLevel {
        facility: Option<Facility>,  // None = set global default
        level: Severity,
    },
    GetLogLevels,
    DumpLogs {
        facility: Option<Facility>,
        lines: Option<usize>,
    },
    StreamLogs {
        facilities: Vec<Facility>,  // Empty = all
        min_level: Severity,
    },
}
```

### D2: Per-Facility Log-Level Filtering

**Decision**: Maintain a `HashMap<Facility, Severity>` in the Logger/LogRegistry.

**Rationale**:

- Allows fine-grained control (e.g., "debug Ingress but warn everything else")
- Low overhead (single hash lookup per log call)
- Thread-safe with RwLock or atomic operations

**Implementation**:

```rust
pub struct LogRegistry {
    loggers: HashMap<Facility, Logger>,
    min_levels: Arc<RwLock<HashMap<Facility, Severity>>>,  // Runtime filtering
    global_min_level: Arc<AtomicU8>,  // Fast path for global check
}

impl Logger {
    pub fn log(&self, severity: Severity, facility: Facility, message: &str) {
        // Fast path: Check global minimum level first
        if severity as u8 > self.registry.global_min_level.load(Ordering::Relaxed) {
            return;  // Filtered out
        }

        // Slow path: Check facility-specific level
        let min_levels = self.registry.min_levels.read().unwrap();
        if let Some(&min_level) = min_levels.get(&facility) {
            if severity > min_level {
                return;  // Filtered out
            }
        }

        // Log the message
        self.ringbuffer.write(severity, facility, message);
    }
}
```

**Performance**:

- Fast path: 1 atomic load + comparison (~5ns)
- Slow path: RwLock read + hash lookup (~20-50ns)
- Total overhead: <100ns (within budget)

### D3: Log Streaming via WebSocket or Unix Socket

**Decision**: Use Unix socket with length-delimited framing for log streaming.

**Rationale**:

- Consistent with existing control interface
- Lower overhead than WebSocket for local IPC
- Simpler implementation (no HTTP/WS handshake)

**Alternative Considered**: WebSocket

- Pro: Browser-based UI possible
- Con: Complexity, dependencies (tokio-tungstenite)
- Verdict: Defer to Phase 2

**Protocol**:

```text
Client → Supervisor: StreamLogs { facilities: [Ingress], min_level: Debug }
Supervisor → Client: Response::LogStream (ack)
Supervisor → Client: [stream of length-delimited LogEntry JSON]
Client cancels by closing socket
```

### D4: TUI Framework - Ratatui

**Decision**: Use Ratatui for the interactive TUI.

**Rationale**:

- Modern, actively maintained
- Excellent layout system (constraints, splits)
- Good examples (bottom, gitui)
- Crossterm backend works everywhere

**Dependencies**:

```toml
[dependencies]
ratatui = "0.26"
crossterm = "0.27"
tokio = { version = "1", features = ["full"] }
```

### D5: TUI Architecture - Separate Binary

**Decision**: Create `mcr-monitor` as a separate binary from `control_client`.

**Rationale**:

- Keep `control_client` simple for scripting/automation
- TUI has different dependencies and runtime model
- Allows separate evolution of interfaces

**Binaries**:

- `control_client` - Simple one-shot CLI (existing)
- `mcr-monitor` - Interactive TUI (new)

## Feature Breakdown

### Phase 1: Runtime Log-Level Control ✅ COMPLETED

**Status**: Completed in commits d369379 and 5c04136

**Commands**:

```bash
# CLI interface
control_client log-level get
control_client log-level set --global info
control_client log-level set --facility Ingress --level debug

# Example output
control_client log-level get
{
  "LogLevels": {
    "global": "Info",
    "facility_overrides": {
      "Ingress": "Debug",
      "Egress": "Debug"
    }
  }
}
```

**Implementation Summary**:

1. ✅ Added `min_levels` and `global_min_level` to LogRegistry
2. ✅ Modified Logger::should_log() with facility-override-first logic
3. ✅ Added SetGlobalLogLevel/SetFacilityLogLevel/GetLogLevels commands
4. ✅ Implemented command handlers in supervisor with proper async lock scoping
5. ✅ Added log-level subcommands to control_client with parse_severity/parse_facility
6. ✅ Added 5 comprehensive unit tests for level filtering
7. ✅ Created 6 integration tests for runtime log-level changes

**Test Coverage**:

- Unit tests: 94 passing (5 new filtering tests in logger.rs)
- Control client tests: 5 passing (3 new CLI parsing tests)
- Integration tests: 6 comprehensive tests (tests/integration/log_level_control.rs)

**Exit Criteria**:

- ✅ Can set global log level at runtime
- ✅ Can set per-facility log level at runtime (overrides global)
- ✅ Filtered logs don't appear in output (verified by tests)
- ✅ No performance regression (~25-55ns overhead for filtered logs)

### Phase 2: Log Streaming

**Commands**:

```bash
# Tail logs (like journalctl -f)
control_client logs tail --facility Ingress --level debug

# Dump last N lines
control_client logs dump --lines 1000 > /tmp/mcr-logs.txt
```

**Implementation Tasks**:

1. Add DumpLogs/StreamLogs to SupervisorCommand
2. Implement ring buffer dump in AsyncConsumer
3. Implement streaming protocol (length-delimited JSON)
4. Add logs subcommands to control_client
5. Handle client disconnect gracefully

**Technical Challenge**: Ring buffer is consumed by AsyncConsumer.

- **Solution**: Add a "tap" mechanism to AsyncConsumer that multicasts to multiple sinks
- Consumers can register/unregister at runtime

```rust
pub struct AsyncConsumer {
    ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>,
    sinks: Vec<Box<dyn LogSink>>,
    taps: Arc<RwLock<Vec<mpsc::Sender<LogEntry>>>>,  // NEW: For streaming
}
```

### Phase 3: Interactive TUI

**Features**:

- Top pane: Real-time log stream with filtering
- Middle pane: Stats table (rules, pkt/s, errors)
- Bottom pane: Command input (add/remove rules, change log levels)
- Keybindings:
  - `q`: Quit
  - `f`: Filter logs by facility
  - `l`: Change log level
  - `/`: Search logs
  - `p`: Pause/resume log stream
  - `c`: Clear log buffer
  - `:`: Enter command mode

**Implementation Tasks**:

1. Create `mcr-monitor` binary
2. Set up Ratatui event loop
3. Implement 3-pane layout
4. Connect to supervisor via Unix socket
5. Subscribe to log stream
6. Implement stats polling (1s interval)
7. Implement command input mode
8. Handle terminal resize

**UI State Machine**:

```text
Normal Mode
  - Display logs and stats
  - Handle keypresses (q, f, l, etc.)

Command Mode (triggered by ':')
  - Bottom pane shows input prompt
  - Parse and execute commands
  - Return to Normal Mode on Enter/Esc

Filter Mode (triggered by 'f')
  - Show facility checkboxes
  - Update stream subscription
```

### Phase 4: Advanced Features (Future)

- Browser-based UI (WebSocket + React/Svelte)
- Log search and regex filtering
- Log export to file with rotation
- Alerting on error patterns
- Performance graphs (packet rate, CPU usage)

## API Examples

### Setting Log Levels

```rust
// In supervisor command handler
SupervisorCommand::SetLogLevel { facility, level } => {
    match facility {
        Some(f) => {
            log_registry.set_facility_level(f, level)?;
            Response::Success(format!("Set {} to {}", f, level))
        }
        None => {
            log_registry.set_global_level(level)?;
            Response::Success(format!("Set global level to {}", level))
        }
    }
}
```

### Streaming Logs

```rust
// In supervisor command handler
SupervisorCommand::StreamLogs { facilities, min_level } => {
    // Register this client as a tap
    let (tx, rx) = mpsc::channel(1000);
    log_consumer.add_tap(tx, facilities, min_level).await?;

    // Send ack
    let ack = Response::LogStream;
    socket.write_all(&serde_json::to_vec(&ack)?).await?;

    // Stream log entries
    tokio::spawn(async move {
        while let Some(entry) = rx.recv().await {
            let json = serde_json::to_vec(&entry)?;
            let len = (json.len() as u32).to_le_bytes();
            socket.write_all(&len).await?;
            socket.write_all(&json).await?;
        }
    });
}
```

## Testing Strategy

### Unit Tests

1. **Log-level filtering logic**
   - Test global level enforcement
   - Test facility-specific overrides
   - Test severity comparison

2. **Command parsing**
   - Test SetLogLevel command serialization
   - Test invalid facility names
   - Test invalid severity levels

### Integration Tests

1. **End-to-end log filtering**
   - Start supervisor with default log level
   - Change level via control_client
   - Verify filtered logs don't appear

2. **Log streaming**
   - Connect streaming client
   - Generate log messages
   - Verify client receives all expected entries

3. **TUI smoke test**
   - Launch mcr-monitor in test mode
   - Verify it connects to supervisor
   - Verify stats update
   - Send keypress events, verify handling

## Performance Considerations

### Log-Level Check Overhead

**Current (no filtering)**:

```rust
logger.log(Severity::Debug, Facility::Ingress, "Packet received");
// → Direct ring buffer write (~50-100ns)
```

**With filtering**:

```rust
logger.log(Severity::Debug, Facility::Ingress, "Packet received");
// → Check global level (atomic load: ~5ns)
// → Check facility level (RwLock read + hash: ~20-50ns)
// → Possibly skip ring buffer write
// Total: ~25-55ns for filtered logs, ~75-155ns for written logs
```

**Optimization**: Cache the min_level in the Logger struct, invalidate on change.

```rust
pub struct Logger {
    ringbuffer: Arc<dyn RingBuffer>,
    cached_min_level: AtomicU8,  // Cached for fast path
}

// On SetLogLevel command:
registry.invalidate_caches();  // Updates all Logger cached_min_level
```

### Streaming Throughput

**Scenario**: 100k log messages/sec at debug level

- Log entry size: ~256 bytes (LogEntry struct)
- Throughput: 256 bytes × 100k = 25.6 MB/sec
- Unix socket bandwidth: ~1-2 GB/sec (local)
- **Verdict**: No bottleneck

**Mitigation**: If streaming client is slow, use bounded channel and drop on full.

```rust
let (tx, rx) = mpsc::channel(1000);  // Buffer up to 1000 entries
if tx.try_send(entry).is_err() {
    // Client too slow, drop entry (don't block producer)
    dropped_count += 1;
}
```

## Compatibility

### CLI Backward Compatibility

Adding new commands to `control_client` is backward compatible:

- Old binaries ignore new commands (unknown variant error)
- New binaries support old commands

### Wire Protocol

JSON-based protocol is schema-flexible:

- New fields can be added (serde skip_serializing_if)
- Old clients ignore unknown fields

## Open Questions

1. **Log retention**: How long to keep logs in ring buffer?
   - **Recommendation**: Ring buffer only keeps recent logs (last ~16k entries). For long-term retention, stream to file or syslog.

2. **Multi-client streaming**: Can multiple TUI instances connect?
   - **Recommendation**: Yes, supervisor maintains a list of taps. Each client gets a copy of log entries.

3. **Log filtering performance**: Is RwLock read per-log acceptable?
   - **Recommendation**: Measure first. If bottleneck, use atomic per-facility cached min-level.

4. **TUI vs Web UI**: Which to prioritize?
   - **Recommendation**: TUI first (simpler, no HTTP server). Web UI later for remote monitoring.

## Implementation Phases Summary

| Phase | Status | Priority | Effort | Dependencies | Commits |
|-------|--------|----------|--------|--------------|---------|
| Phase 1: Runtime log-level control | ✅ DONE | HIGH | 2-3 days | Logging system | d369379, 5c04136 |
| Phase 2: Log streaming | 📋 TODO | MEDIUM | 2-3 days | Phase 1 | - |
| Phase 3: Interactive TUI | 📋 TODO | MEDIUM | 5-7 days | Phase 2 | - |
| Phase 4: Advanced features | 📋 TODO | LOW | 2-4 weeks | Phase 3 | - |

## References

- Ratatui: <https://ratatui.rs/>
- Crossterm: <https://docs.rs/crossterm/>
- TUI examples: <https://github.com/fdehau/tui-rs/tree/master/examples>
- Bottom (TUI app): <https://github.com/ClementTsang/bottom>
- GitUI (TUI app): <https://github.com/extrawurst/gitui>
