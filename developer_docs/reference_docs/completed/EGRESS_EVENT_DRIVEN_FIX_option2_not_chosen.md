# Egress Event-Driven Architecture Fix (Option 2)

**Date:** 2025-11-17
**Status:** PLANNED
**Priority:** CRITICAL
**Related:** EGRESS_REGRESSION_ANALYSIS_2025-11-16.md, PERFORMANCE_FIX_2025-11-16.md

---

## Problem Statement

Egress performance regressed from 307k pps (PHASE4, commit 2d5e8ef) to 96k pps (current) due to commit e3fbf90 breaking the buffer pool feedback loop.

**Root Cause:**

- Commit e3fbf90 changed `send_batch()` from synchronous (submit + reap) to async (just prepare)
- Buffers stay in "in_flight" state longer
- Ingress can't allocate buffers → 86% buffer exhaustion
- Egress bottlenecked at ~96k pps

**Failed Fix Attempts:**

1. **Synchronous revert:** Blocked event loop → 71k pps (worse)
2. **Timeout-based waiting:** Added 1ms delays → 96k pps (no improvement)
3. **Current async:** Original problem persists → 96k pps

---

## Solution: Event-Driven io_uring (Option 2)

Use io_uring's `PollAdd` to monitor multiple event sources simultaneously:

1. **Eventfd** - Packet arrivals from ingress
2. **Send completions** - UDP packets sent to network

This creates a truly event-driven loop that wakes on ANY event.

---

## Architecture

```text
┌─────────────────────────────────────────────┐
│          Egress Event Loop                  │
│                                             │
│  io_uring.submit_and_wait(1)                │
│         │                                   │
│         ▼                                   │
│  ┌─────────────────────┐                   │
│  │  Wake on ANY event: │                   │
│  │  1. Eventfd fired   │                   │
│  │  2. Send completion │                   │
│  │  3. Shutdown signal │                   │
│  └─────────────────────┘                   │
│         │                                   │
│         ▼                                   │
│  Process all CQE completions:               │
│  ┌────────────────────────────────┐        │
│  │ PACKET_ARRIVAL_USER_DATA:      │        │
│  │   → Drain packet queue         │        │
│  │   → Submit sends (non-blocking)│        │
│  │   → Re-arm eventfd poll        │        │
│  ├────────────────────────────────┤        │
│  │ Send completion:               │        │
│  │   → Free buffer immediately    │        │
│  │   → Return to pool             │        │
│  └────────────────────────────────┘        │
└─────────────────────────────────────────────┘
```

---

## Implementation Steps

### Step 1: Extract eventfd from WakeupStrategy

**File:** `src/worker/egress.rs`

Add to `EgressLoop` struct:

```rust
pub struct EgressLoop<B, P> {
    // ... existing fields ...
    wakeup_fd: Option<Arc<OwnedFd>>,  // Eventfd for packet arrivals
}
```

In constructor, extract fd from wakeup_strategy if it's EventfdWakeup or HybridWakeup.

---

### Step 2: Add user_data constant

**File:** `src/worker/egress.rs`

```rust
const SHUTDOWN_USER_DATA: u64 = u64::MAX;
const COMMAND_USER_DATA: u64 = u64::MAX - 1;
const TIMEOUT_USER_DATA: u64 = u64::MAX - 2;  // Remove this
const PACKET_ARRIVAL_USER_DATA: u64 = u64::MAX - 3;  // Add this
```

---

### Step 3: Submit persistent PollAdd in run()

**File:** `src/worker/egress.rs`, in `run()` function

```rust
pub fn run(&mut self, packet_rx: &crossbeam_queue::SegQueue<EgressWorkItem>) -> Result<()> {
    // If we have an eventfd, set up persistent polling
    let poll_op = if let Some(ref wakeup_fd) = self.wakeup_fd {
        let op = opcode::PollAdd::new(wakeup_fd.as_raw_fd(), libc::POLLIN)
            .build()
            .user_data(PACKET_ARRIVAL_USER_DATA);
        Some(op)
    } else {
        None
    };

    // Submit initial poll if we have one
    if let Some(ref op) = poll_op {
        unsafe {
            self.ring.submission().push(op).context("Failed to add poll")?;
        }
        self.ring.submit()?;
    }

    // Main event loop...
```

---

### Step 4: Rewrite event loop

**File:** `src/worker/egress.rs`, replace entire `run()` function

```rust
pub fn run(&mut self, packet_rx: &crossbeam_queue::SegQueue<EgressWorkItem>) -> Result<()> {
    // Set up persistent eventfd polling (from Step 3)
    let poll_op = if let Some(ref wakeup_fd) = self.wakeup_fd {
        let op = opcode::PollAdd::new(wakeup_fd.as_raw_fd(), libc::POLLIN)
            .build()
            .user_data(PACKET_ARRIVAL_USER_DATA);
        Some(op)
    } else {
        None
    };

    if let Some(ref op) = poll_op {
        unsafe {
            self.ring.submission().push(op).context("Failed to add poll")?;
        }
        self.ring.submit()?;
    }

    // Main event loop
    loop {
        // Check shutdown first
        if self.shutdown_requested() {
            // Drain remaining packets
            while let Some(packet) = packet_rx.pop() {
                if self.config.track_stats {
                    self.stats.packets_received += 1;
                }
                self.add_destination(&packet.interface_name, packet.dest_addr)?;
                self.queue_packet(packet);
            }

            // Send all queued packets
            while !self.is_queue_empty() {
                self.send_batch_nonblocking()?;
            }

            // Submit and wait for all in-flight to complete
            self.ring.submit()?;
            while !self.in_flight.is_empty() {
                self.ring.submit_and_wait(1)?;
                self.process_cqe_batch()?;
            }

            break;
        }

        // Wait for ANY event (packet arrival OR send completion OR shutdown)
        self.ring.submit_and_wait(1)?;

        // Collect all completions
        let mut completions = Vec::new();
        for cqe in self.ring.completion() {
            completions.push((cqe.user_data(), cqe.result()));
        }

        // Process completions
        for (user_data, result) in completions {
            match user_data {
                PACKET_ARRIVAL_USER_DATA => {
                    // Eventfd fired - new packets available

                    // 1. Consume eventfd value to reset it
                    if let Some(ref wakeup_fd) = self.wakeup_fd {
                        let mut buf = [0u8; 8];
                        unsafe {
                            libc::read(
                                wakeup_fd.as_raw_fd(),
                                buf.as_mut_ptr() as *mut libc::c_void,
                                8,
                            );
                        }
                    }

                    // 2. Drain all packets from queue
                    while let Some(packet) = packet_rx.pop() {
                        if self.config.track_stats {
                            self.stats.packets_received += 1;
                        }
                        self.add_destination(&packet.interface_name, packet.dest_addr)?;
                        self.queue_packet(packet);
                    }

                    // 3. Send queued packets (non-blocking)
                    if !self.is_queue_empty() {
                        self.send_batch_nonblocking()?;
                    }

                    // 4. Re-arm eventfd poll for next notification
                    if let Some(ref op) = poll_op {
                        unsafe {
                            self.ring
                                .submission()
                                .push(op)
                                .context("Failed to re-arm poll")?;
                        }
                    }
                },

                SHUTDOWN_USER_DATA => {
                    // Shutdown event - will be handled in next iteration
                    self.shutdown_requested = true;
                },

                COMMAND_USER_DATA => {
                    // Command processing (existing code)
                    if result > 0 {
                        if self.process_commands_from_buffer(result as usize)? {
                            continue;
                        }
                        self.submit_command_read()?;
                    } else if result == 0 {
                        self.logger.info(Facility::Egress, "Command stream closed");
                        self.shutdown_requested = true;
                    } else {
                        self.logger.error(
                            Facility::Egress,
                            &format!("Command read error: {}",
                                std::io::Error::from_raw_os_error(-result)),
                        );
                    }
                },

                _ => {
                    // Send completion - free buffer immediately
                    let _buffer_item = self
                        .in_flight
                        .remove(&user_data)
                        .context("Unknown user_data")?;

                    if result < 0 {
                        if self.config.track_stats {
                            self.stats.send_errors += 1;
                        }
                        if self.stats.send_errors % 100 == 1 {
                            self.logger.error(
                                Facility::Egress,
                                &format!("Send error: errno={} (total: {})",
                                    -result, self.stats.send_errors),
                            );
                        }
                    } else {
                        if self.config.track_stats {
                            self.stats.packets_sent += 1;
                            self.stats.bytes_sent += result as u64;
                        }

                        // Periodic stats logging
                        if self.stats.packets_sent.is_multiple_of(10000) {
                            self.logger.info(
                                Facility::Egress,
                                &format!(
                                    "[STATS:Egress] total: sent={} submitted={} ch_recv={} errors={} bytes={}",
                                    self.stats.packets_sent,
                                    self.stats.packets_submitted,
                                    self.stats.packets_received,
                                    self.stats.send_errors,
                                    self.stats.bytes_sent
                                ),
                            );
                        }
                    }

                    // Buffer automatically freed by Drop (ManagedBuffer RAII)
                }
            }
        }
    }

    self.print_final_stats();
    Ok(())
}
```

---

### Step 5: Create send_batch_nonblocking()

**File:** `src/worker/egress.rs`

```rust
/// Send queued packets without blocking on completions
fn send_batch_nonblocking(&mut self) -> Result<usize> {
    if self.egress_queue.is_empty() {
        return Ok(0);
    }

    let batch_size = self.egress_queue.len().min(self.config.batch_size);

    // Submit send operations for each packet in the batch
    for _ in 0..batch_size {
        let packet = self.egress_queue.remove(0);
        self.submit_send(packet)?;
    }

    // Submit to io_uring but DON'T wait for completions
    // Completions will be processed in the main event loop
    self.ring.submit().context("Failed to submit send operations")?;

    Ok(batch_size)
}
```

---

### Step 6: Remove obsolete code

**Remove:**

- `reap_completions_blocking()` function (no longer needed)
- `TIMEOUT_USER_DATA` constant (no longer needed)
- Timeout handling in `process_cqe_batch()` (no longer needed)

---

## Expected Performance

**Target:** Match or exceed PHASE4 performance

- Egress: 307k pps (currently 96k pps)
- Buffer exhaustion: <40% (currently 86%)
- Ingress: Maintain current 689k pps

**Why this will work:**

1. **Immediate buffer return:** Completions processed in same loop iteration
2. **No artificial delays:** No timeouts or blocking on specific operations
3. **Continuous processing:** Eventfd wakes us immediately when packets arrive
4. **Optimal io_uring usage:** Batch submit, async complete, event-driven wait

---

## Testing Plan

1. Build with changes
2. Run `tests/data_plane_pipeline_veth.sh`
3. Verify metrics:
   - Egress ≥ 300k pps
   - Buffer exhaustion < 40%
   - Ingress maintained at ~690k pps
4. Compare with PHASE4 baseline

---

## Fallback Plan

If Option 2 doesn't achieve target performance:

- Revert to commit 2d5e8ef entirely
- Re-apply only critical fixes (logging removal)
- Accept PHASE4 architecture as-is

---

## Files to Modify

- `src/worker/egress.rs` - Complete event loop rewrite
- Possibly `src/worker/data_plane_integrated.rs` - If eventfd passing needs changes

---

## Risk Assessment

**Low Risk:**

- Architecture is well-understood (standard io_uring pattern)
- Eventfd infrastructure already exists
- Can revert if needed

**Testing Required:**

- Performance regression testing
- Shutdown behavior validation
- Buffer pool leak detection

---

## References

- Original proposal: Option 2 in conversation
- PHASE4 baseline: commit 2d5e8ef (2025-11-10)
- Regression introduced: commit e3fbf90 (2025-11-14)
