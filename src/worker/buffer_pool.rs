//! Buffer Pool for Data Plane
//!
//! High-performance, lock-free buffer pool for packet processing.
//!
//! This module implements the buffer pool strategy validated in
//! experiments/poc_buffer_pool_performance/ (Experiment #3).
//!
//! **Design decisions validated:**
//! - D15: Core-Local Buffer Pools
//! - D16: Buffer Pool Observability
//!
//! **Key findings from Experiment #3:**
//! - Pool allocation: 26.7 ns (1.79x faster than Vec::with_capacity)
//! - Throughput: 37.6M ops/sec (120x headroom over target)
//! - Recommended config: 1000/500/200 buffers per core (5.3 MB/core)
//! - Metrics overhead: 0.12% (negligible)
//!
//! **Performance characteristics:**
//! - Lock-free: Single-threaded per core, no contention
//! - Pre-allocated: No dynamic allocation on hot path
//! - Size-classified: Optimal for mixed packet sizes
//! - Observable: Optional per-pool statistics

use std::collections::VecDeque;

/// Size classes for buffer pools
///
/// Based on common packet sizes in multicast networks:
/// - Small: Ethernet MTU (1500 bytes)
/// - Standard: Common jumbo frame (4096 bytes)
/// - Jumbo: Large jumbo frame (9000 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BufferSize {
    /// Small buffers: 1500 bytes (typical Ethernet MTU)
    Small = 1500,
    /// Standard buffers: 4096 bytes (common jumbo frame size)
    Standard = 4096,
    /// Jumbo buffers: 9000 bytes (large jumbo frames)
    Jumbo = 9000,
}

impl BufferSize {
    /// Get the size in bytes
    pub const fn size(self) -> usize {
        self as usize
    }

    /// Select the appropriate buffer size for a given payload length
    pub fn for_payload(payload_len: usize) -> Option<Self> {
        if payload_len <= Self::Small.size() {
            Some(Self::Small)
        } else if payload_len <= Self::Standard.size() {
            Some(Self::Standard)
        } else if payload_len <= Self::Jumbo.size() {
            Some(Self::Jumbo)
        } else {
            None // Packet too large
        }
    }
}

/// A single buffer from the pool
pub struct Buffer {
    data: Vec<u8>,
    size_class: BufferSize,
}

impl Buffer {
    /// Get the buffer's data as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the buffer's data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Clone the buffer data (creates a new Buffer with copied data)
    ///
    /// This is used when a packet needs to be sent to multiple outputs.
    /// The new buffer will have the same size class and data as the original.
    pub fn clone_data(&self) -> Buffer {
        Buffer {
            data: self.data.clone(),
            size_class: self.size_class,
        }
    }

    /// Get the buffer's size class
    pub fn size_class(&self) -> BufferSize {
        self.size_class
    }

    /// Get the buffer's capacity
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Get the current length of valid data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Set the length of valid data (unsafe - caller must ensure data is initialized)
    ///
    /// # Safety
    /// Caller must ensure that `len` bytes of the buffer are initialized.
    pub unsafe fn set_len(&mut self, len: usize) {
        self.data.set_len(len);
    }
}

/// Statistics for a single buffer pool
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total number of allocations requested
    pub allocations_total: u64,
    /// Number of successful allocations
    pub allocations_success: u64,
    /// Number of allocation failures (pool exhausted)
    pub allocations_failed: u64,
    /// Total number of deallocations
    pub deallocations_total: u64,
}

impl PoolStats {
    /// Calculate current utilization (buffers in use)
    pub fn buffers_in_use(&self, pool_capacity: usize) -> usize {
        let net_allocs = self
            .allocations_success
            .saturating_sub(self.deallocations_total);
        net_allocs.min(pool_capacity as u64) as usize
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.allocations_total == 0 {
            return 1.0;
        }
        self.allocations_success as f64 / self.allocations_total as f64
    }
}

/// A buffer pool for a specific size class
pub struct SizeClassPool {
    size_class: BufferSize,
    free_list: VecDeque<Vec<u8>>,
    capacity: usize,
    stats: PoolStats,
    track_metrics: bool,
}

impl SizeClassPool {
    /// Create a new pool with the specified capacity
    ///
    /// # Arguments
    /// * `size_class` - The buffer size for this pool
    /// * `capacity` - Number of buffers to pre-allocate
    /// * `track_metrics` - Whether to track per-operation statistics
    pub fn new(size_class: BufferSize, capacity: usize, track_metrics: bool) -> Self {
        let mut free_list = VecDeque::with_capacity(capacity);

        // Pre-allocate all buffers for this pool
        for _ in 0..capacity {
            free_list.push_back(vec![0; size_class.size()]);
        }

        Self {
            size_class,
            free_list,
            capacity,
            stats: PoolStats::default(),
            track_metrics,
        }
    }

    /// Allocate a buffer from the pool
    ///
    /// Returns `None` if the pool is exhausted.
    pub fn allocate(&mut self) -> Option<Buffer> {
        if self.track_metrics {
            self.stats.allocations_total += 1;
        }

        match self.free_list.pop_front() {
            Some(data) => {
                if self.track_metrics {
                    self.stats.allocations_success += 1;
                }
                Some(Buffer {
                    data,
                    size_class: self.size_class,
                })
            }
            None => {
                if self.track_metrics {
                    self.stats.allocations_failed += 1;
                }
                None
            }
        }
    }

    /// Deallocate a buffer back to the pool
    ///
    /// # Panics
    /// Panics if the buffer's size class doesn't match this pool.
    pub fn deallocate(&mut self, mut buffer: Buffer) {
        assert_eq!(
            buffer.size_class, self.size_class,
            "Buffer size class mismatch: expected {:?}, got {:?}",
            self.size_class, buffer.size_class
        );

        if self.track_metrics {
            self.stats.deallocations_total += 1;
        }

        // Clear the buffer (optional, for security/consistency)
        buffer.data.clear();
        buffer.data.resize(buffer.size_class.size(), 0);

        self.free_list.push_back(buffer.data);
    }

    /// Get the number of available (free) buffers
    pub fn available(&self) -> usize {
        self.free_list.len()
    }

    /// Get the total capacity of this pool
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the number of buffers currently in use
    pub fn in_use(&self) -> usize {
        self.capacity - self.available()
    }

    /// Get a reference to the pool's statistics
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Reset the pool's statistics
    pub fn reset_stats(&mut self) {
        self.stats = PoolStats::default();
    }
}

/// Core-local buffer pool with multiple size classes
///
/// Each worker thread maintains its own BufferPool instance.
/// No synchronization is required as pools are never shared.
pub struct BufferPool {
    small_pool: SizeClassPool,
    standard_pool: SizeClassPool,
    jumbo_pool: SizeClassPool,
}

impl BufferPool {
    /// Create a new buffer pool with default configuration
    ///
    /// Default configuration (from Experiment #3):
    /// - Small: 1000 buffers × 1500B = 1.5 MB
    /// - Standard: 500 buffers × 4096B = 2.0 MB
    /// - Jumbo: 200 buffers × 9000B = 1.8 MB
    /// - Total: ~5.3 MB per core
    ///
    /// This configuration is validated for:
    /// - 312.5k packets/second/core ingress
    /// - Burst tolerance (98-99% success under 2-10x bursts)
    /// - Sub-microsecond recovery time
    pub fn new(track_metrics: bool) -> Self {
        Self::with_capacities(1000, 500, 200, track_metrics)
    }

    /// Create a new buffer pool with custom capacities
    pub fn with_capacities(
        small_capacity: usize,
        standard_capacity: usize,
        jumbo_capacity: usize,
        track_metrics: bool,
    ) -> Self {
        Self {
            small_pool: SizeClassPool::new(BufferSize::Small, small_capacity, track_metrics),
            standard_pool: SizeClassPool::new(
                BufferSize::Standard,
                standard_capacity,
                track_metrics,
            ),
            jumbo_pool: SizeClassPool::new(BufferSize::Jumbo, jumbo_capacity, track_metrics),
        }
    }

    /// Allocate a buffer of the appropriate size for the given payload
    ///
    /// Returns `None` if no buffer of sufficient size is available.
    pub fn allocate(&mut self, required_size: usize) -> Option<Buffer> {
        if required_size <= BufferSize::Small.size() {
            self.small_pool.allocate()
        } else if required_size <= BufferSize::Standard.size() {
            self.standard_pool.allocate()
        } else if required_size <= BufferSize::Jumbo.size() {
            self.jumbo_pool.allocate()
        } else {
            // Packet too large for any pool
            None
        }
    }

    /// Allocate a buffer of a specific size class
    pub fn allocate_exact(&mut self, size_class: BufferSize) -> Option<Buffer> {
        match size_class {
            BufferSize::Small => self.small_pool.allocate(),
            BufferSize::Standard => self.standard_pool.allocate(),
            BufferSize::Jumbo => self.jumbo_pool.allocate(),
        }
    }

    /// Deallocate a buffer back to its pool
    pub fn deallocate(&mut self, buffer: Buffer) {
        match buffer.size_class {
            BufferSize::Small => self.small_pool.deallocate(buffer),
            BufferSize::Standard => self.standard_pool.deallocate(buffer),
            BufferSize::Jumbo => self.jumbo_pool.deallocate(buffer),
        }
    }

    /// Get a reference to a specific size class pool
    pub fn pool(&self, size_class: BufferSize) -> &SizeClassPool {
        match size_class {
            BufferSize::Small => &self.small_pool,
            BufferSize::Standard => &self.standard_pool,
            BufferSize::Jumbo => &self.jumbo_pool,
        }
    }

    /// Get a mutable reference to a specific size class pool
    pub fn pool_mut(&mut self, size_class: BufferSize) -> &mut SizeClassPool {
        match size_class {
            BufferSize::Small => &mut self.small_pool,
            BufferSize::Standard => &mut self.standard_pool,
            BufferSize::Jumbo => &mut self.jumbo_pool,
        }
    }

    /// Get total memory footprint in bytes
    pub fn memory_footprint(&self) -> usize {
        (self.small_pool.capacity() * BufferSize::Small.size())
            + (self.standard_pool.capacity() * BufferSize::Standard.size())
            + (self.jumbo_pool.capacity() * BufferSize::Jumbo.size())
    }

    /// Get aggregate statistics across all pools
    pub fn aggregate_stats(&self) -> AggregateStats {
        AggregateStats {
            small: self.small_pool.stats().clone(),
            standard: self.standard_pool.stats().clone(),
            jumbo: self.jumbo_pool.stats().clone(),
        }
    }
}

/// Aggregate statistics across all buffer pools
#[derive(Debug, Clone)]
pub struct AggregateStats {
    pub small: PoolStats,
    pub standard: PoolStats,
    pub jumbo: PoolStats,
}

impl AggregateStats {
    /// Get total allocations across all pools
    pub fn total_allocations(&self) -> u64 {
        self.small.allocations_total
            + self.standard.allocations_total
            + self.jumbo.allocations_total
    }

    /// Get total successful allocations across all pools
    pub fn total_allocations_success(&self) -> u64 {
        self.small.allocations_success
            + self.standard.allocations_success
            + self.jumbo.allocations_success
    }

    /// Get total failed allocations across all pools
    pub fn total_allocations_failed(&self) -> u64 {
        self.small.allocations_failed
            + self.standard.allocations_failed
            + self.jumbo.allocations_failed
    }

    /// Get overall success rate across all pools
    pub fn overall_success_rate(&self) -> f64 {
        let total = self.total_allocations();
        if total == 0 {
            return 1.0;
        }
        self.total_allocations_success() as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_creation() {
        let pool = BufferPool::new(false);
        assert_eq!(pool.small_pool.capacity(), 1000);
        assert_eq!(pool.standard_pool.capacity(), 500);
        assert_eq!(pool.jumbo_pool.capacity(), 200);
    }

    #[test]
    fn test_buffer_allocation_deallocation() {
        let mut pool = BufferPool::new(false);

        // Allocate small buffer
        let buffer = pool.allocate(1000).expect("Should allocate small buffer");
        assert_eq!(buffer.size_class(), BufferSize::Small);
        assert_eq!(pool.small_pool.available(), 999);

        // Deallocate
        pool.deallocate(buffer);
        assert_eq!(pool.small_pool.available(), 1000);
    }

    #[test]
    fn test_size_class_selection() {
        let mut pool = BufferPool::new(false);

        let small = pool.allocate(1000).unwrap();
        assert_eq!(small.size_class(), BufferSize::Small);

        let standard = pool.allocate(2000).unwrap();
        assert_eq!(standard.size_class(), BufferSize::Standard);

        let jumbo = pool.allocate(5000).unwrap();
        assert_eq!(jumbo.size_class(), BufferSize::Jumbo);

        pool.deallocate(small);
        pool.deallocate(standard);
        pool.deallocate(jumbo);
    }

    #[test]
    fn test_pool_exhaustion() {
        let mut pool = BufferPool::with_capacities(2, 2, 2, true);

        // Exhaust small pool
        let b1 = pool.allocate(100).expect("First allocation");
        let b2 = pool.allocate(100).expect("Second allocation");
        let b3 = pool.allocate(100); // Should fail
        assert!(b3.is_none());

        // Check stats
        assert_eq!(pool.small_pool.stats().allocations_total, 3);
        assert_eq!(pool.small_pool.stats().allocations_success, 2);
        assert_eq!(pool.small_pool.stats().allocations_failed, 1);

        // Deallocate and try again
        pool.deallocate(b1);
        let b4 = pool.allocate(100).expect("Should succeed after dealloc");

        pool.deallocate(b2);
        pool.deallocate(b4);
    }

    #[test]
    fn test_metrics_tracking() {
        let mut pool = BufferPool::with_capacities(10, 10, 10, true);

        // Perform operations
        let buffers: Vec<_> = (0..5).map(|_| pool.allocate(1000).unwrap()).collect();

        for buffer in buffers {
            pool.deallocate(buffer);
        }

        let stats = pool.small_pool.stats();
        assert_eq!(stats.allocations_total, 5);
        assert_eq!(stats.allocations_success, 5);
        assert_eq!(stats.deallocations_total, 5);
        assert_eq!(stats.success_rate(), 1.0);
    }

    #[test]
    fn test_memory_footprint() {
        let pool = BufferPool::new(false);

        let expected = (1000 * 1500) + (500 * 4096) + (200 * 9000);
        assert_eq!(pool.memory_footprint(), expected);
    }

    #[test]
    #[should_panic(expected = "Buffer size class mismatch")]
    #[cfg(not(tarpaulin))]
    fn test_wrong_pool_deallocation() {
        let mut pool = BufferPool::new(false);

        let buffer = pool.allocate_exact(BufferSize::Small).unwrap();
        // Try to deallocate to wrong pool
        pool.standard_pool.deallocate(buffer);
    }

    #[test]
    fn test_buffer_size_selection() {
        assert_eq!(BufferSize::for_payload(1000), Some(BufferSize::Small));
        assert_eq!(BufferSize::for_payload(2000), Some(BufferSize::Standard));
        assert_eq!(BufferSize::for_payload(5000), Some(BufferSize::Jumbo));
        assert_eq!(BufferSize::for_payload(10000), None);
    }

    #[test]
    fn test_aggregate_stats() {
        let mut pool = BufferPool::with_capacities(10, 10, 10, true);

        // Allocate from different pools
        let small = pool.allocate(1000).unwrap();
        let standard = pool.allocate(2000).unwrap();
        let jumbo = pool.allocate(5000).unwrap();

        pool.deallocate(small);
        pool.deallocate(standard);
        pool.deallocate(jumbo);

        let stats = pool.aggregate_stats();
        assert_eq!(stats.total_allocations(), 3);
        assert_eq!(stats.total_allocations_success(), 3);
        assert_eq!(stats.total_allocations_failed(), 0);
        assert_eq!(stats.overall_success_rate(), 1.0);
    }
}
