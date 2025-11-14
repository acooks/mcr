//! Adaptive Wakeup Strategy for Egress Thread
//!
//! This module implements an adaptive mechanism that adjusts eventfd signaling
//! based on measured packet rate to optimize the trade-off between latency
//! and throughput.
//!
//! ## Strategy
//!
//! - **Low rate (<1k pps)**: Signal every packet (latency-optimized)
//! - **Medium rate (1k-10k pps)**: Signal every 4-8 packets
//! - **High rate (10k-50k pps)**: Signal every 16-32 packets
//! - **Very high rate (>50k pps)**: Signal every 64 packets
//!
//! The adaptation happens every 100ms based on observed packet rate.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Adaptive wakeup configuration
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Minimum batch size (signal every N packets)
    pub min_batch: usize,
    /// Maximum batch size
    pub max_batch: usize,
    /// How often to recalculate rate and adjust threshold (milliseconds)
    pub adaptation_interval_ms: u64,
    /// Rate thresholds for different batch sizes (packets per second)
    pub rate_thresholds: Vec<(u64, usize)>, // (pps, batch_size)
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            min_batch: 1,     // Signal every packet at low rates
            max_batch: 64,    // Never batch more than 64 packets
            adaptation_interval_ms: 100,  // Adapt every 100ms
            rate_thresholds: vec![
                (0,      1),   // <1k pps: signal every packet
                (1_000,  4),   // 1k-10k pps: batch 4
                (10_000, 16),  // 10k-50k pps: batch 16
                (50_000, 32),  // 50k-100k pps: batch 32
                (100_000, 64), // >100k pps: batch 64
            ],
        }
    }
}

/// Adaptive wakeup state
pub struct AdaptiveWakeup {
    /// Lock-free packet queue
    queue: Arc<crossbeam_queue::SegQueue<crate::worker::egress::EgressWorkItem>>,

    /// Eventfd for waking egress
    wakeup_fd: i32,

    /// Current batch threshold (how many packets before signaling)
    current_threshold: AtomicUsize,

    /// Packets sent since last signal
    packets_since_signal: AtomicUsize,

    /// Total packets sent (for rate calculation)
    total_packets: AtomicU64,

    /// Last adaptation timestamp
    last_adaptation: Mutex<Instant>,

    /// Configuration
    config: AdaptiveConfig,
}

impl AdaptiveWakeup {
    pub fn new(
        queue: Arc<crossbeam_queue::SegQueue<crate::worker::egress::EgressWorkItem>>,
        wakeup_fd: i32,
        config: AdaptiveConfig,
    ) -> Self {
        Self {
            queue,
            wakeup_fd,
            current_threshold: AtomicUsize::new(config.min_batch),
            packets_since_signal: AtomicUsize::new(0),
            total_packets: AtomicU64::new(0),
            last_adaptation: Mutex::new(Instant::now()),
            config,
        }
    }

    /// Send a packet and adaptively signal egress
    pub fn send(&self, item: crate::worker::egress::EgressWorkItem) -> Result<(), ()> {
        // Push to lock-free queue
        self.queue.push(item);

        // Update counters (fast path: atomic operations only)
        let count = self.packets_since_signal.fetch_add(1, Ordering::Relaxed);
        let total = self.total_packets.fetch_add(1, Ordering::Relaxed);

        // Check if we should adapt (ONLY every 1024 packets to avoid mutex contention)
        // This means we check adaptation ~50 times/sec at 50k pps, which is plenty
        if total % 1024 == 0 {
            self.maybe_adapt();
        }

        // Check if we should signal
        let threshold = self.current_threshold.load(Ordering::Relaxed);

        // Signal on first packet or when reaching threshold
        if count == 0 || count >= threshold {
            self.signal_egress()?;
            self.packets_since_signal.store(0, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Signal egress thread via eventfd write
    fn signal_egress(&self) -> Result<(), ()> {
        let value: u64 = 1;
        loop {
            let ret = unsafe {
                libc::write(
                    self.wakeup_fd,
                    &value as *const u64 as *const libc::c_void,
                    8,
                )
            };
            if ret == 8 {
                return Ok(());
            }
            if ret < 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::EAGAIN)
                    || errno.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    // Buffer full, spin and retry
                    std::hint::spin_loop();
                    continue;
                }
                return Err(());
            }
        }
    }

    /// Check if we should adapt threshold based on elapsed time
    fn maybe_adapt(&self) {
        // Fast path: check if enough time has passed (no lock)
        let mut last = self.last_adaptation.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(*last);

        if elapsed < Duration::from_millis(self.config.adaptation_interval_ms) {
            return;
        }

        // Calculate current rate (packets per second)
        let total = self.total_packets.load(Ordering::Relaxed);
        let elapsed_secs = elapsed.as_secs_f64();

        if elapsed_secs < 0.001 {
            return; // Too soon to calculate meaningful rate
        }

        let rate = (total as f64) / elapsed_secs;

        // Find appropriate threshold based on rate
        let new_threshold = self.calculate_threshold(rate as u64);

        // Update threshold
        let old_threshold = self.current_threshold.swap(new_threshold, Ordering::Relaxed);

        // Debug logging (optional - could be behind a feature flag)
        if new_threshold != old_threshold {
            eprintln!(
                "[AdaptiveWakeup] Rate: {:.0} pps, threshold: {} -> {} packets",
                rate, old_threshold, new_threshold
            );
        }

        // Reset for next interval
        *last = now;
        self.total_packets.store(0, Ordering::Relaxed);
    }

    /// Calculate appropriate threshold based on packet rate
    fn calculate_threshold(&self, rate_pps: u64) -> usize {
        // Find the highest threshold that applies
        let mut threshold = self.config.min_batch;

        for (rate_limit, batch_size) in &self.config.rate_thresholds {
            if rate_pps >= *rate_limit {
                threshold = *batch_size;
            } else {
                break;
            }
        }

        // Clamp to configured limits
        threshold.clamp(self.config.min_batch, self.config.max_batch)
    }

    /// Get current statistics (for monitoring)
    pub fn stats(&self) -> AdaptiveStats {
        AdaptiveStats {
            current_threshold: self.current_threshold.load(Ordering::Relaxed),
            total_packets: self.total_packets.load(Ordering::Relaxed),
            packets_since_signal: self.packets_since_signal.load(Ordering::Relaxed),
        }
    }
}

/// Statistics for monitoring adaptive behavior
#[derive(Debug, Clone)]
pub struct AdaptiveStats {
    pub current_threshold: usize,
    pub total_packets: u64,
    pub packets_since_signal: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_calculation() {
        let config = AdaptiveConfig::default();
        let queue = Arc::new(crossbeam_queue::SegQueue::new());
        let wakeup = AdaptiveWakeup::new(queue, -1, config);

        assert_eq!(wakeup.calculate_threshold(500), 1);      // <1k: batch 1
        assert_eq!(wakeup.calculate_threshold(5_000), 4);    // 1k-10k: batch 4
        assert_eq!(wakeup.calculate_threshold(25_000), 16);  // 10k-50k: batch 16
        assert_eq!(wakeup.calculate_threshold(75_000), 32);  // 50k-100k: batch 32
        assert_eq!(wakeup.calculate_threshold(150_000), 64); // >100k: batch 64
    }

    #[test]
    fn test_min_max_clamping() {
        let mut config = AdaptiveConfig::default();
        config.min_batch = 8;
        config.max_batch = 16;

        let queue = Arc::new(crossbeam_queue::SegQueue::new());
        let wakeup = AdaptiveWakeup::new(queue, -1, config);

        // Should clamp to min
        assert_eq!(wakeup.calculate_threshold(500), 8);

        // Should clamp to max
        assert_eq!(wakeup.calculate_threshold(150_000), 16);
    }
}
