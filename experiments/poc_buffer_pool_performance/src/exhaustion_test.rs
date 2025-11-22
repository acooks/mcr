// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exhaustion Behavior Test
//!
//! This test simulates burst traffic scenarios to validate how the buffer pool
//! handles exhaustion and recovery.

use crate::BufferPool;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ExhaustionTestResults {
    /// Time taken to exhaust the pool
    pub time_to_exhaustion: Duration,
    /// Number of successful allocations before exhaustion
    pub successful_allocations: usize,
    /// Number of failed allocations during burst
    pub failed_allocations: usize,
    /// Time taken to fully recover (all buffers available)
    pub recovery_time: Duration,
    /// Peak buffers in use
    pub peak_in_use: usize,
}

/// Run an exhaustion test with burst traffic
///
/// # Test Scenario
/// 1. Allocate at burst rate until pool exhausts
/// 2. Measure time to exhaustion
/// 3. Release some buffers to simulate egress
/// 4. Measure recovery time
///
/// # Arguments
/// * `pool_capacity` - Size of the test pool
/// * `burst_factor` - How many times the normal rate (e.g., 3x)
pub fn run_exhaustion_test(pool_capacity: usize, burst_factor: usize) -> ExhaustionTestResults {
    let mut pool = BufferPool::with_capacities(pool_capacity, pool_capacity / 2, pool_capacity / 5, true);

    let mut allocated_buffers = Vec::with_capacity(pool_capacity * burst_factor);
    let mut successful_allocations = 0;
    let mut failed_allocations = 0;
    let mut peak_in_use = 0;

    println!("\n=== Exhaustion Test ===");
    println!("Pool capacity: {} buffers", pool_capacity);
    println!("Burst factor: {}x", burst_factor);
    println!();

    // Phase 1: Burst allocation until exhaustion
    println!("[Phase 1] Allocating at {}x rate until exhaustion...", burst_factor);
    let start = Instant::now();

    loop {
        match pool.allocate(1000) {
            Some(buffer) => {
                successful_allocations += 1;
                allocated_buffers.push(buffer);

                let in_use = pool.pool(crate::BufferSize::Small).in_use();
                peak_in_use = peak_in_use.max(in_use);
            }
            None => {
                failed_allocations += 1;
                // Pool exhausted
                break;
            }
        }
    }

    let time_to_exhaustion = start.elapsed();

    println!("  Time to exhaustion: {:?}", time_to_exhaustion);
    println!("  Successful allocations: {}", successful_allocations);
    println!("  Pool exhausted after {} allocations", allocated_buffers.len());
    println!();

    // Phase 2: Simulate processing and deallocations
    println!("[Phase 2] Simulating egress processing...");

    // Hold some buffers "in flight", deallocate the rest
    let hold_count = allocated_buffers.len() / 2;
    let to_release = allocated_buffers.len() - hold_count;

    println!("  Holding {} buffers in flight", hold_count);
    println!("  Releasing {} buffers", to_release);

    for _ in 0..to_release {
        if let Some(buffer) = allocated_buffers.pop() {
            pool.deallocate(buffer);
        }
    }

    println!("  Available after release: {}", pool.pool(crate::BufferSize::Small).available());
    println!();

    // Phase 3: Continued burst (should get more failures)
    println!("[Phase 3] Continuing burst with partial availability...");
    let continued_burst = pool_capacity / 4;
    let mut additional_successes = 0;
    let mut additional_failures = 0;

    for _ in 0..continued_burst {
        match pool.allocate(1000) {
            Some(buffer) => {
                additional_successes += 1;
                allocated_buffers.push(buffer);
            }
            None => {
                additional_failures += 1;
            }
        }
    }

    successful_allocations += additional_successes;
    failed_allocations += additional_failures;

    println!("  Additional successful: {}", additional_successes);
    println!("  Additional failed: {}", additional_failures);
    println!();

    // Phase 4: Full recovery
    println!("[Phase 4] Releasing all buffers for recovery...");
    let recovery_start = Instant::now();

    for buffer in allocated_buffers {
        pool.deallocate(buffer);
    }

    let recovery_time = recovery_start.elapsed();

    println!("  Recovery time: {:?}", recovery_time);
    println!("  Final available: {}", pool.pool(crate::BufferSize::Small).available());
    println!();

    // Print final statistics
    let stats = pool.pool(crate::BufferSize::Small).stats();
    println!("=== Final Statistics ===");
    println!("  Total allocation attempts: {}", stats.allocations_total);
    println!("  Successful: {}", stats.allocations_success);
    println!("  Failed: {}", stats.allocations_failed);
    println!("  Success rate: {:.2}%", stats.success_rate() * 100.0);
    println!("  Peak in use: {}", peak_in_use);
    println!();

    ExhaustionTestResults {
        time_to_exhaustion,
        successful_allocations,
        failed_allocations,
        recovery_time,
        peak_in_use,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exhaustion_scenario() {
        let results = run_exhaustion_test(100, 3);

        // Validate results
        assert!(results.successful_allocations > 0, "Should have some successful allocations");
        assert!(results.failed_allocations > 0, "Should encounter exhaustion");
        assert!(results.time_to_exhaustion.as_nanos() > 0, "Should measure time to exhaustion");
        assert!(results.recovery_time.as_nanos() > 0, "Should measure recovery time");
        assert!(results.peak_in_use <= 100, "Peak should not exceed capacity");

        // Recovery should be very fast (< 100ms target)
        assert!(
            results.recovery_time < Duration::from_millis(100),
            "Recovery should be fast, got {:?}",
            results.recovery_time
        );
    }

    #[test]
    fn test_different_burst_factors() {
        for burst_factor in [2, 5, 10] {
            println!("\n--- Testing burst factor: {}x ---", burst_factor);
            let results = run_exhaustion_test(50, burst_factor);

            // All tests should complete without panicking
            assert!(results.successful_allocations > 0);
        }
    }
}
