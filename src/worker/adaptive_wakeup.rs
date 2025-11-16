//! Adaptive Wakeup Strategies for Egress Thread
//!
//! This module provides different strategies for waking up the egress thread
//! when packets arrive, with runtime adaptation based on traffic patterns.
//!
//! ## Strategies
//!
//! - **SpinWakeup**: Pure spin, no syscalls (high performance, high CPU)
//! - **EventfdWakeup**: Block on eventfd (power efficient, lower throughput)
//! - **HybridWakeup**: Automatically switches between strategies based on packet rate
//!
//! ## Hybrid Strategy
//!
//! - **< 20k pps**: Use eventfd (save CPU, latency acceptable)
//! - **> 20k pps**: Switch to spin (avoid sleep overhead causing packet loss)
//!
//! The adaptation happens every 100ms based on observed packet rate.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ============================================================================
// Core Trait
// ============================================================================

/// Defines a strategy for waking up the egress thread when new packets arrive.
pub trait WakeupStrategy: Send + Sync {
    /// Called by the ingress thread after pushing a packet to the queue.
    fn signal(&self);

    /// Called by the egress thread when idle to wait for work.
    fn wait(&self);

    /// Returns true if this strategy uses io_uring blocking (eventfd).
    ///
    /// When true, EgressLoop should use submit_and_wait() to block.
    /// When false, EgressLoop should use submit() and rely on wait() for idle handling.
    fn uses_io_uring_blocking(&self) -> bool;
}

// ============================================================================
// Spin Strategy (High Performance)
// ============================================================================

/// Pure spin strategy for maximum throughput
///
/// Characteristics:
/// - Throughput: 100k+ pps
/// - CPU: ~100% even when idle
/// - Latency: <1μs response
pub struct SpinWakeup;

impl WakeupStrategy for SpinWakeup {
    fn signal(&self) {
        // NO-OP: Ingress just pushes to queue
    }

    fn wait(&self) {
        // Pure spin with CPU hint
        std::hint::spin_loop();
    }

    fn uses_io_uring_blocking(&self) -> bool {
        false
    }
}

// ============================================================================
// Eventfd Strategy (Power Saving)
// ============================================================================

/// Eventfd strategy for power efficiency
///
/// Characteristics:
/// - Throughput: ~20k pps max
/// - CPU: ~1% when idle
/// - Latency: ~10-50μs response
pub struct EventfdWakeup {
    wakeup_fd: Arc<OwnedFd>,
}

impl EventfdWakeup {
    pub fn new(wakeup_fd: Arc<OwnedFd>) -> Self {
        Self { wakeup_fd }
    }
}

impl WakeupStrategy for EventfdWakeup {
    fn signal(&self) {
        // Write to eventfd to wake egress
        let value: u64 = 1;
        let bytes = value.to_ne_bytes();
        let mut written = 0;

        while written < bytes.len() {
            match unsafe {
                libc::write(
                    self.wakeup_fd.as_raw_fd(),
                    bytes[written..].as_ptr() as *const libc::c_void,
                    bytes.len() - written,
                )
            } {
                n if n > 0 => written += n as usize,
                n if n == 0 => break,
                _ => {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::Interrupted {
                        eprintln!("EventfdWakeup::signal failed: {}", err);
                        break;
                    }
                }
            }
        }
    }

    fn wait(&self) {
        // Block by reading from eventfd (blocking fd)
        let mut buf = [0u8; 8];
        loop {
            match unsafe {
                libc::read(
                    self.wakeup_fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    8,
                )
            } {
                n if n > 0 => break, // Successfully read, wake up
                _ => {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::Interrupted {
                        eprintln!("EventfdWakeup::wait failed: {}", err);
                        break;
                    }
                    // Interrupted, retry
                }
            }
        }
    }

    fn uses_io_uring_blocking(&self) -> bool {
        false // No longer using io_uring blocking
    }
}

// ============================================================================
// Hybrid Strategy (Runtime Adaptive)
// ============================================================================

const STRATEGY_EVENTFD: usize = 0;
const STRATEGY_SPIN: usize = 1;
const ADAPTATION_THRESHOLD_PPS: u64 = 20_000;

/// Hybrid strategy that switches between eventfd and spin at runtime
///
/// Automatically adapts based on observed packet rate:
/// - < 20k pps: Use eventfd (save CPU)
/// - >= 20k pps: Switch to spin (avoid packet loss)
pub struct HybridWakeup {
    eventfd: EventfdWakeup,
    spin: SpinWakeup,

    /// Current active strategy: 0=eventfd, 1=spin
    current_strategy: AtomicUsize,

    /// Packet counter for rate measurement
    packet_count: AtomicU64,

    /// Last measurement timestamp
    last_measurement: Mutex<Instant>,

    /// Adaptation interval (how often to recalculate rate)
    adaptation_interval: Duration,
}

impl HybridWakeup {
    pub fn new(wakeup_fd: Arc<OwnedFd>) -> Self {
        Self {
            eventfd: EventfdWakeup::new(wakeup_fd),
            spin: SpinWakeup,
            current_strategy: AtomicUsize::new(STRATEGY_EVENTFD), // Start with eventfd
            packet_count: AtomicU64::new(0),
            last_measurement: Mutex::new(Instant::now()),
            adaptation_interval: Duration::from_millis(100),
        }
    }

    /// Maybe adapt strategy based on measured rate
    fn maybe_adapt(&self) {
        // Fast path: only check adaptation every 1024 packets to reduce lock contention
        let count = self.packet_count.fetch_add(1, Ordering::Relaxed);
        if count % 1024 != 0 {
            return;
        }

        let mut last = match self.last_measurement.try_lock() {
            Ok(guard) => guard,
            Err(_) => return, // Another thread is adapting, skip
        };

        let now = Instant::now();
        let elapsed = now.duration_since(*last);

        if elapsed < self.adaptation_interval {
            return; // Too soon
        }

        // Calculate rate
        let packets = self.packet_count.swap(0, Ordering::Relaxed);
        let elapsed_secs = elapsed.as_secs_f64();

        if elapsed_secs < 0.001 {
            return;
        }

        let rate_pps = (packets as f64 / elapsed_secs) as u64;

        // Determine target strategy
        let target_strategy = if rate_pps >= ADAPTATION_THRESHOLD_PPS {
            STRATEGY_SPIN
        } else {
            STRATEGY_EVENTFD
        };

        // Switch if needed
        let current = self.current_strategy.load(Ordering::Relaxed);
        if current != target_strategy {
            self.current_strategy
                .store(target_strategy, Ordering::Relaxed);
            eprintln!(
                "[HybridWakeup] Rate: {} pps, switching to {}",
                rate_pps,
                if target_strategy == STRATEGY_SPIN {
                    "SPIN"
                } else {
                    "EVENTFD"
                }
            );

            // If switching FROM eventfd TO spin, wake up any blocked reader
            if current == STRATEGY_EVENTFD && target_strategy == STRATEGY_SPIN {
                self.eventfd.signal();
            }
        }

        *last = now;
    }
}

impl WakeupStrategy for HybridWakeup {
    fn signal(&self) {
        // Track packets for rate measurement
        self.maybe_adapt();

        // Delegate to current strategy
        match self.current_strategy.load(Ordering::Relaxed) {
            STRATEGY_EVENTFD => self.eventfd.signal(),
            STRATEGY_SPIN => self.spin.signal(),
            _ => unreachable!(),
        }
    }

    fn wait(&self) {
        // Delegate to current strategy
        match self.current_strategy.load(Ordering::Relaxed) {
            STRATEGY_EVENTFD => self.eventfd.wait(),
            STRATEGY_SPIN => self.spin.wait(),
            _ => unreachable!(),
        }
    }

    fn uses_io_uring_blocking(&self) -> bool {
        // Return true if currently using eventfd
        self.current_strategy.load(Ordering::Relaxed) == STRATEGY_EVENTFD
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spin_is_noop_signal() {
        let spin = SpinWakeup;
        spin.signal(); // Should not panic
        assert!(!spin.uses_io_uring_blocking());
    }
}
