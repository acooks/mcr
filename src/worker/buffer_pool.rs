//! Buffer Pool for Data Plane
//!
//! This module provides two implementations for the buffer pool, controlled by the
//! `lock_free_buffer_pool` feature flag.
//!
//! 1.  **Default (Mutex-based):** A simple, single-threaded buffer pool design.
//!     This is the original implementation, suitable for scenarios where the data plane
//!     runs in a single thread or where contention is not a primary concern.
//!
//! 2.  **`lock_free_buffer_pool` feature:** A high-performance, lock-free buffer pool
//!     designed for a multi-threaded data plane. It uses `crossbeam-queue` to allow
//!     contention-free access between ingress and egress threads.

// =================================================================================
// Implementation 1: Original Mutex-based Buffer Pool
// =================================================================================

#[cfg(not(feature = "lock_free_buffer_pool"))]
mod mutex_pool {
    use std::collections::VecDeque;

    /// Size classes for buffer pools
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum BufferSize {
        Small = 1500,
        Standard = 4096,
        Jumbo = 9000,
    }

    impl BufferSize {
        pub const fn size(self) -> usize {
            self as usize
        }
        pub fn for_payload(payload_len: usize) -> Option<Self> {
            if payload_len <= Self::Small.size() {
                Some(Self::Small)
            } else if payload_len <= Self::Standard.size() {
                Some(Self::Standard)
            } else if payload_len <= Self::Jumbo.size() {
                Some(Self::Jumbo)
            } else {
                None
            }
        }
    }

    /// A single buffer from the pool
    pub struct Buffer {
        pub(crate) data: Vec<u8>,
        pub(crate) size_class: BufferSize,
    }

    impl Buffer {
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.data
        }
        pub fn as_slice(&self) -> &[u8] {
            &self.data
        }
        pub fn clone_data(&self) -> Buffer {
            Buffer {
                data: self.data.clone(),
                size_class: self.size_class,
            }
        }
        pub fn size_class(&self) -> BufferSize {
            self.size_class
        }
        pub fn capacity(&self) -> usize {
            self.data.capacity()
        }
        pub fn len(&self) -> usize {
            self.data.len()
        }
        pub fn is_empty(&self) -> bool {
            self.data.is_empty()
        }
        pub unsafe fn set_len(&mut self, len: usize) {
            self.data.set_len(len);
        }
    }

    impl std::ops::Deref for Buffer {
        type Target = [u8];
        fn deref(&self) -> &Self::Target {
            &self.data
        }
    }

    impl std::ops::DerefMut for Buffer {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.data
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct PoolStats {
        pub allocations_total: u64,
        pub allocations_success: u64,
        pub allocations_failed: u64,
        pub deallocations_total: u64,
    }

    pub struct SizeClassPool {
        size_class: BufferSize,
        free_list: VecDeque<Vec<u8>>,
        capacity: usize,
        stats: PoolStats,
        track_metrics: bool,
    }

    impl SizeClassPool {
        pub fn new(size_class: BufferSize, capacity: usize, track_metrics: bool) -> Self {
            let mut free_list = VecDeque::with_capacity(capacity);
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

        pub fn deallocate(&mut self, mut buffer: Buffer) {
            assert_eq!(
                buffer.size_class, self.size_class,
                "Buffer size class mismatch"
            );
            if self.track_metrics {
                self.stats.deallocations_total += 1;
            }
            buffer.data.clear();
            buffer.data.resize(buffer.size_class.size(), 0);
            self.free_list.push_back(buffer.data);
        }
    }

    pub struct BufferPool {
        small_pool: SizeClassPool,
        standard_pool: SizeClassPool,
        jumbo_pool: SizeClassPool,
    }

    impl BufferPool {
        pub fn new(track_metrics: bool) -> Self {
            Self::with_capacities(1000, 500, 200, track_metrics)
        }

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

        pub fn allocate(&mut self, required_size: usize) -> Option<Buffer> {
            if required_size <= BufferSize::Small.size() {
                self.small_pool.allocate()
            } else if required_size <= BufferSize::Standard.size() {
                self.standard_pool.allocate()
            } else if required_size <= BufferSize::Jumbo.size() {
                self.jumbo_pool.allocate()
            } else {
                None
            }
        }

        pub fn deallocate(&mut self, buffer: Buffer) {
            match buffer.size_class {
                BufferSize::Small => self.small_pool.deallocate(buffer),
                BufferSize::Standard => self.standard_pool.deallocate(buffer),
                BufferSize::Jumbo => self.jumbo_pool.deallocate(buffer),
            }
        }
    }
}

#[cfg(not(feature = "lock_free_buffer_pool"))]
pub use mutex_pool::*;

// =================================================================================
// Implementation 2: Lock-Free Buffer Pool
// =================================================================================

#[cfg(feature = "lock_free_buffer_pool")]
mod lock_free_pool {
    use crossbeam_queue::SegQueue;
    use std::ops::{Deref, DerefMut};
    use std::sync::Arc;

    const SMALL_BUFFER_SIZE: usize = 2048;
    const STANDARD_BUFFER_SIZE: usize = 4096;
    const JUMBO_BUFFER_SIZE: usize = 9216;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BufferSize {
        Small,
        Standard,
        Jumbo,
    }

    impl BufferSize {
        pub const fn size(self) -> usize {
            match self {
                BufferSize::Small => SMALL_BUFFER_SIZE,
                BufferSize::Standard => STANDARD_BUFFER_SIZE,
                BufferSize::Jumbo => JUMBO_BUFFER_SIZE,
            }
        }

        pub fn for_payload(payload_len: usize) -> Option<Self> {
            if payload_len <= SMALL_BUFFER_SIZE {
                Some(Self::Small)
            } else if payload_len <= STANDARD_BUFFER_SIZE {
                Some(Self::Standard)
            } else if payload_len <= JUMBO_BUFFER_SIZE {
                Some(Self::Jumbo)
            } else {
                None
            }
        }
    }

    /// A "smart buffer" that automatically returns itself to its pool when dropped.
    pub struct ManagedBuffer {
        buffer: Box<[u8]>,
        size_category: BufferSize,
        pool: Arc<BufferPool>,
    }

    impl ManagedBuffer {
        /// Get the buffer's size category.
        pub fn size_category(&self) -> BufferSize {
            self.size_category
        }
    }

    impl Drop for ManagedBuffer {
        fn drop(&mut self) {
            // Move the buffer out and replace it with an empty one to satisfy the borrow checker.
            let fresh_buffer = std::mem::replace(&mut self.buffer, Box::new([]));
            self.pool.release(fresh_buffer, self.size_category);
        }
    }

    impl Deref for ManagedBuffer {
        type Target = [u8];
        fn deref(&self) -> &Self::Target {
            &self.buffer
        }
    }

    impl DerefMut for ManagedBuffer {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.buffer
        }
    }

    /// The lock-free pool manager. It is cheap to clone as it only contains Arcs.
    pub struct BufferPool {
        free_small: SegQueue<Box<[u8]>>,
        free_standard: SegQueue<Box<[u8]>>,
        free_jumbo: SegQueue<Box<[u8]>>,
    }

    impl BufferPool {
        /// Creates a new `BufferPool` and pre-allocates all buffers.
        /// Returns an `Arc` so it can be shared between threads.
        pub fn new(small_count: usize, std_count: usize, jumbo_count: usize) -> Arc<Self> {
            let pool = Arc::new(Self {
                free_small: SegQueue::new(),
                free_standard: SegQueue::new(),
                free_jumbo: SegQueue::new(),
            });

            for _ in 0..small_count {
                pool.free_small
                    .push(vec![0u8; SMALL_BUFFER_SIZE].into_boxed_slice());
            }
            for _ in 0..std_count {
                pool.free_standard
                    .push(vec![0u8; STANDARD_BUFFER_SIZE].into_boxed_slice());
            }
            for _ in 0..jumbo_count {
                pool.free_jumbo
                    .push(vec![0u8; JUMBO_BUFFER_SIZE].into_boxed_slice());
            }

            pool
        }

        /// Acquires a buffer from the appropriate free pool.
        /// Returns `None` if the pool for the requested size is empty.
        pub fn acquire(self: &Arc<Self>, size: BufferSize) -> Option<ManagedBuffer> {
            let queue = match size {
                BufferSize::Small => &self.free_small,
                BufferSize::Standard => &self.free_standard,
                BufferSize::Jumbo => &self.free_jumbo,
            };

            queue.pop().map(|buffer| ManagedBuffer {
                buffer,
                size_category: size,
                pool: self.clone(),
            })
        }

        /// Releases a buffer back to its corresponding free pool.
        /// This is called by the `Drop` implementation of `ManagedBuffer`.
        fn release(&self, buffer: Box<[u8]>, size: BufferSize) {
            let queue = match size {
                BufferSize::Small => &self.free_small,
                BufferSize::Standard => &self.free_standard,
                BufferSize::Jumbo => &self.free_jumbo,
            };
            queue.push(buffer);
        }

        /// Returns the number of available buffers in a specific pool.
        pub fn available(&self, size: BufferSize) -> usize {
            match size {
                BufferSize::Small => self.free_small.len(),
                BufferSize::Standard => self.free_standard.len(),
                BufferSize::Jumbo => self.free_jumbo.len(),
            }
        }
    }
}

#[cfg(feature = "lock_free_buffer_pool")]
pub use lock_free_pool::*;
