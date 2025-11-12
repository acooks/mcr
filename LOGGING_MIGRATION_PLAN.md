# Logging Migration Plan: Eliminate println! for Production Logging

## Current Status Analysis

### What Exists ✅
1. **Complete logging infrastructure** (Phases 1-4 from LOGGING_DESIGN.md):
   - Lock-free SPSC/MPSC ring buffers (cache-optimized, 256-byte entries)
   - LogEntry with severity/facility/structured KV pairs
   - Logger API with severity helpers
   - LogRegistry for managing per-facility buffers
   - Logging macros (`log_info!`, `log_error!`, `log_debug!`, etc.)
   - AsyncConsumer and BlockingConsumer tasks
   - Pluggable output sinks (stdout, stderr, custom)
   - Runtime log level filtering (global + per-facility)
   - Control client commands for log management

2. **Limited integration**:
   - Supervisor has some logging calls (16 uses total across codebase)
   - Control client has Facility/Severity imports
   - Most of codebase still uses `println!`/`eprintln!` (96 occurrences)

### The Problem

**Current situation:**
```bash
$ grep -r "println!" src --include="*.rs" | wc -l
96
```

**Files with heavy println! usage:**
- `src/worker/ingress.rs` - ~20+ calls (stats, debug, errors)
- `src/worker/egress.rs` - ~15+ calls (stats, debug)
- `src/worker/data_plane_integrated.rs` - ~10+ calls
- `src/worker/mod.rs` - Worker lifecycle messages
- `src/supervisor.rs` - Process management messages
- `src/main.rs` - Startup messages

**Categories of println! usage:**

1. **Stats/Metrics** (~30%):
   ```rust
   println!("[STATS:Ingress] recv={} matched={} ...", ...);
   println!("[STATS:Egress] sent={} ...", ...);
   ```

2. **Lifecycle Events** (~25%):
   ```rust
   println!("[Ingress] Adding rule: {:?}", key);
   println!("[DataPlane] Starting integrated data plane");
   ```

3. **Debug/Trace** (~30%):
   ```rust
   // println!("Buffer allocation successful");  // Commented out
   // println!("Processing output: {:?}", output);
   ```

4. **Errors** (~15%):
   ```rust
   eprintln!("[Ingress] Error receiving packet: {}", err);
   eprintln!("[DataPlane] Failed to reap completions: {}", e);
   ```

### Why This Is Bad

1. **No Filtering**: Can't turn off debug output without recompiling
2. **No Structure**: Hard to parse/analyze programmatically
3. **Performance**: println! blocks on stdout mutex (bad for data plane)
4. **No Control**: Can't query or change log levels at runtime
5. **No Storage**: Logs vanish if not redirected
6. **Testing Pain**: println! pollutes test output
7. **No Correlation**: Can't track related events across workers

---

## Three Options for Improvement

### Option 1: Minimal Integration (Quick Fix)

**Goal:** Replace println! with logging macros, use existing infrastructure

**Approach:**
1. Keep all existing logging infrastructure as-is
2. Create LogRegistry in main.rs and pass to supervisor/workers
3. Start AsyncConsumer task in supervisor (stdout sink)
4. Replace all println!/eprintln! with appropriate log_*! macros
5. Workers use logging system but don't start their own consumers

**Architecture:**
```
┌─────────────┐
│ Supervisor  │
│ (main.rs)   │
│             │
│ LogRegistry │◄──── All facilities use shared MPSC buffers
│ (MPSC)      │
│             │
│ AsyncConsumer ◄─── Single consumer task outputs to stdout
│ (stdout)    │
└─────────────┘
       ▲
       │ Logs flow through shared ring buffers
       │
  ┌────┴────┬──────────┬──────────┐
  │ Worker1 │ Worker2  │ Worker3  │
  │ (DP)    │ (CP)     │ (DP)     │
  └─────────┴──────────┴──────────┘
```

**Pros:**
- ✅ Simple: Minimal code changes
- ✅ Fast: ~1 week implementation
- ✅ Unified: All logs go through one consumer
- ✅ Testable: Can redirect to test sink

**Cons:**
- ❌ Shared buffers: MPSC for everyone (some contention)
- ❌ No per-worker isolation: Worker crash could lose logs
- ❌ No streaming: Logs only visible via stdout redirect
- ❌ Limited filtering: Can't filter per-worker

**Effort:** 1 week

---

### Option 2: Worker Ring Buffers with Central Consumer (Balanced)

**Goal:** Per-worker SPSC ring buffers, supervisor reads from all

**Approach:**
1. Each data plane worker creates its own SPSC LogRegistry (lock-free)
2. Supervisor creates MPSC LogRegistry for async components
3. Workers pass ring buffer Arc references to supervisor at startup
4. Supervisor runs single AsyncConsumer reading from ALL buffers
5. Optional: Add Unix domain socket for external monitoring tool

**Architecture:**
```
┌─────────────────────────────────────────┐
│ Supervisor (main.rs)                    │
│                                         │
│  LogRegistry (MPSC) ◄───── Supervisor  │
│  │                          logs        │
│  │                                      │
│  AsyncConsumer (stdout/file/socket)    │
│  │                                      │
│  │ Reads from:                          │
│  ├─► Supervisor MPSC buffers           │
│  ├─► Worker1 SPSC buffers (DataPlane)  │
│  ├─► Worker2 MPSC buffers (ControlPlane)│
│  └─► Worker3 SPSC buffers (DataPlane)  │
└─────────────────────────────────────────┘
           │
           │ Optional: Unix socket
           ▼
    ┌─────────────┐
    │  Monitoring │
    │  Client     │
    │  (mcr-logs) │
    └─────────────┘

Data Plane Workers:
┌──────────┐  ┌──────────┐
│ Worker1  │  │ Worker3  │
│ (core 0) │  │ (core 1) │
│          │  │          │
│ SPSC RB  │  │ SPSC RB  │
│ Ingress  │  │ Ingress  │
│ Egress   │  │ Egress   │
│ (lock-   │  │ (lock-   │
│  free)   │  │  free)   │
└──────────┘  └──────────┘
```

**Implementation Steps:**

1. **Worker Initialization:**
   ```rust
   // In worker thread
   let log_registry = LogRegistry::new_spsc(core_id);
   let logger = log_registry.get_logger(Facility::Ingress).unwrap();

   // Pass ring buffers back to supervisor via channel
   let ringbuffers = log_registry.export_ringbuffers();
   supervisor_tx.send(WorkerReady { ringbuffers, ... });
   ```

2. **Supervisor Consumer:**
   ```rust
   // In supervisor
   let mut all_ringbuffers = vec![];
   all_ringbuffers.extend(supervisor_registry.export_ringbuffers());

   for worker in workers {
       all_ringbuffers.extend(worker.ringbuffers);
   }

   tokio::spawn(async move {
       AsyncConsumer::stdout(all_ringbuffers).run().await;
   });
   ```

3. **Optional Monitoring Socket:**
   ```rust
   // In supervisor
   let monitor_socket = "/tmp/mcr-logs.sock";
   tokio::spawn(async move {
       stream_logs_to_socket(monitor_socket, ringbuffer_refs).await;
   });
   ```

**Pros:**
- ✅ Lock-free: Data plane workers use SPSC (zero contention)
- ✅ Isolated: Each worker has its own buffers
- ✅ Flexible: Can add monitoring socket later
- ✅ Performance: Optimal for data plane hot path

**Cons:**
- ❌ Complexity: Need to pass ring buffer references
- ❌ Consumer load: Single consumer reads from N buffers
- ❌ Monitoring: Need separate tool to view logs live

**Effort:** 2-3 weeks

---

### Option 3: Distributed Consumers with Monitor Server (Full Solution)

**Goal:** Each worker has its own consumer, supervisor aggregates via socket

**Approach:**
1. Each worker (DP and CP) creates its own LogRegistry + Consumer
2. Workers run their own BlockingConsumer or AsyncConsumer
3. Supervisor runs a "log server" on Unix domain socket
4. Workers connect to supervisor's log server and stream logs
5. Supervisor merges streams and outputs to stdout/file/syslog
6. External monitoring tool (`mcr-logs`) can also connect to socket

**Architecture:**
```
┌────────────────────────────────────────────┐
│ Supervisor (main.rs)                       │
│                                            │
│  LogRegistry (MPSC) ◄──── Supervisor logs │
│  │                                         │
│  Log Aggregator Server                     │
│  │ (Unix socket: /tmp/mcr.sock)           │
│  │                                         │
│  │ Accepts connections from:               │
│  ├─ Worker1 (streams logs)                │
│  ├─ Worker2 (streams logs)                │
│  ├─ Worker3 (streams logs)                │
│  └─ mcr-logs client (monitoring)          │
│                                            │
│  AsyncConsumer (stdout/file/syslog)       │
│  └─ Outputs merged log stream             │
└────────────────────────────────────────────┘
           ▲                    ▲
           │                    │
           │                    │
    ┌──────┴──────┐      ┌─────┴──────┐
    │ Worker1 (DP)│      │ mcr-logs   │
    │             │      │ (monitor)  │
    │ LogRegistry │      │            │
    │ (SPSC)      │      │ Live tail  │
    │             │      │ Filtering  │
    │ Blocking    │      └────────────┘
    │ Consumer    │
    │ │           │
    │ └─► Socket  │
    └─────────────┘
```

**Implementation Steps:**

1. **Supervisor Log Server:**
   ```rust
   // src/logging/aggregator.rs
   pub struct LogAggregator {
       socket_path: String,
       clients: Vec<TcpStream>,
       output_sink: Box<dyn LogSink>,
   }

   impl LogAggregator {
       pub async fn run(&mut self) {
           let listener = UnixListener::bind(&self.socket_path)?;
           loop {
               tokio::select! {
                   Ok((stream, _)) = listener.accept() => {
                       self.clients.push(stream);
                   }
                   Some(log_entry) = self.read_from_clients() => {
                       self.output_sink.write_entry(&log_entry);
                   }
               }
           }
       }
   }
   ```

2. **Worker Log Streaming:**
   ```rust
   // In worker
   let log_registry = LogRegistry::new_spsc(core_id);
   let logger = log_registry.get_logger(Facility::Ingress).unwrap();

   // Start consumer that streams to supervisor
   let ringbuffers = log_registry.export_ringbuffers();
   std::thread::spawn(move || {
       let socket = UnixStream::connect("/tmp/mcr.sock")?;
       let sink = SocketSink::new(socket);
       BlockingConsumer::new(ringbuffers, Box::new(sink)).run();
   });
   ```

3. **Monitoring Client:**
   ```bash
   # mcr-logs: Live log viewer
   mcr-logs tail                    # Tail all logs
   mcr-logs tail -f Ingress         # Filter by facility
   mcr-logs tail -l debug           # Filter by severity
   mcr-logs dump /tmp/debug.log     # Save to file
   ```

**Pros:**
- ✅ Distributed: Each worker manages its own logs
- ✅ Isolated: Worker crash doesn't lose supervisor logs
- ✅ Monitoring: External tools can tap into log stream
- ✅ Flexible: Can add filtering/routing logic in aggregator
- ✅ Production-Ready: Mimics syslog/journal architecture

**Cons:**
- ❌ Complexity: Significant new code (aggregator, socket protocol)
- ❌ Overhead: Socket I/O for every log batch
- ❌ Ordering: Logs from different workers may be interleaved
- ❌ Failure: Need to handle worker reconnection

**Effort:** 4-5 weeks

---

## Comparison Matrix

| Feature | Option 1 (Minimal) | Option 2 (Balanced) | Option 3 (Full) |
|---------|-------------------|---------------------|-----------------|
| **Implementation Time** | 1 week | 2-3 weeks | 4-5 weeks |
| **Code Complexity** | Low | Medium | High |
| **Data Plane Performance** | Medium (MPSC) | High (SPSC) | High (SPSC) |
| **Worker Isolation** | ❌ Shared buffers | ✅ Per-worker buffers | ✅ Per-worker + consumer |
| **External Monitoring** | ❌ No | ⚠️ Optional socket | ✅ Full monitoring API |
| **Production Readiness** | ⚠️ MVP | ✅ Production | ✅ Enterprise |
| **Testing Complexity** | Low | Medium | High |
| **Memory Overhead** | Low (~10 MB) | Medium (~15 MB) | Medium (~20 MB) |

---

## Recommendation

**Start with Option 2 (Balanced)**, then optionally add Option 3 features later.

**Rationale:**
1. **Performance:** SPSC for data plane is critical (no contention)
2. **Simplicity:** No socket protocol to implement/maintain
3. **Extensibility:** Can add monitoring socket incrementally
4. **Timeline:** 2-3 weeks is reasonable for production deployment

**Implementation Phases:**

### Phase 1 (Week 1): Core Integration
- Create LogRegistry in main.rs
- Pass loggers to supervisor and workers
- Start AsyncConsumer in supervisor
- Replace println! in supervisor and main.rs

### Phase 2 (Week 2): Worker Integration
- Integrate SPSC logging in data plane workers
- Pass ring buffer references to supervisor
- Replace println! in ingress/egress/data_plane
- Handle stats logging separately (see below)

### Phase 3 (Week 3): Polish
- Add compile-time log level filtering
- Performance testing (ensure <100ns overhead)
- Documentation and examples
- Optional: Add monitoring socket

---

## Special Considerations

### Stats Logging

Current stats are printed every second:
```rust
println!("[STATS:Ingress] recv={} matched={} ...", ...);
```

**Options:**
1. **Keep as println!**: Stats stay on stdout for monitoring
2. **Use Facility::Stats**: Send through logging system
3. **Separate channel**: Stats go to dedicated metrics endpoint

**Recommendation:** Use `Facility::Stats` with `Severity::Info`, but add optional prometheus/metrics export later.

### Debug Output

Many debug println! are commented out:
```rust
// println!("Buffer allocation successful");
```

**Recommendation:**
- Delete commented-out debug prints
- Add proper `log_debug!()` calls where needed
- Use compile-time feature flags to strip in release

### Error Handling

Currently:
```rust
eprintln!("[Ingress] Error: {}", err);
```

**Recommendation:**
- Use `log_error!()` for all errors
- Add structured logging for error context:
  ```rust
  log_kv!(logger, Severity::Error, Facility::Ingress,
      "Socket error",
      "errno" => error_code,
      "interface" => "eth0"
  );
  ```

---

## Migration Checklist

- [ ] Create LogRegistry infrastructure in main.rs
- [ ] Start AsyncConsumer task in supervisor
- [ ] Replace supervisor println!/eprintln! (~20 calls)
- [ ] Replace main.rs println! (~5 calls)
- [ ] Integrate SPSC logging in data plane workers
- [ ] Replace worker println! in ingress.rs (~20 calls)
- [ ] Replace worker println! in egress.rs (~15 calls)
- [ ] Replace worker println! in data_plane_integrated.rs (~10 calls)
- [ ] Replace worker println! in mod.rs (~10 calls)
- [ ] Update tests to use logging (capture output)
- [ ] Add log level CLI flags
- [ ] Add log output configuration (stdout/file/syslog)
- [ ] Performance benchmarks (<100ns target)
- [ ] Documentation updates

**Total println! to replace:** 96 calls

---

## Testing Strategy

1. **Unit Tests:** Verify logging macros compile and work
2. **Integration Tests:** Check log output in E2E tests
3. **Performance Tests:** Benchmark logging overhead
4. **Stress Tests:** High-frequency logging under load

**Example test:**
```rust
#[test]
fn test_logging_integration() {
    let (registry, consumer_rx) = test_registry();
    let logger = registry.get_logger(Facility::Test).unwrap();

    log_info!(logger, Facility::Test, "Test message");

    let entry = consumer_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(entry.severity, Severity::Info);
    assert!(entry.message().contains("Test message"));
}
```

---

## Next Steps

1. Review this plan with team
2. Choose implementation option (recommend Option 2)
3. Create GitHub issues for each migration checklist item
4. Start with Phase 1 (Core Integration)
5. Iteratively replace println! calls facility-by-facility
