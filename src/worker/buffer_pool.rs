//! Buffer Pool for Data Plane
//!
//! This module provides a high-performance, lock-free buffer pool designed for a
//! multi-threaded data plane. It uses `crossbeam-queue` to allow contention-free
//! access between ingress and egress threads.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_size_constants() {
        assert_eq!(BufferSize::Small.size(), 2048);
        assert_eq!(BufferSize::Standard.size(), 4096);
        assert_eq!(BufferSize::Jumbo.size(), 9216);
    }

    #[test]
    fn test_buffer_size_for_payload() {
        // Small buffer
        assert_eq!(BufferSize::for_payload(0), Some(BufferSize::Small));
        assert_eq!(BufferSize::for_payload(1024), Some(BufferSize::Small));
        assert_eq!(BufferSize::for_payload(2048), Some(BufferSize::Small));

        // Standard buffer
        assert_eq!(BufferSize::for_payload(2049), Some(BufferSize::Standard));
        assert_eq!(BufferSize::for_payload(3000), Some(BufferSize::Standard));
        assert_eq!(BufferSize::for_payload(4096), Some(BufferSize::Standard));

        // Jumbo buffer
        assert_eq!(BufferSize::for_payload(4097), Some(BufferSize::Jumbo));
        assert_eq!(BufferSize::for_payload(8000), Some(BufferSize::Jumbo));
        assert_eq!(BufferSize::for_payload(9216), Some(BufferSize::Jumbo));

        // Too large
        assert_eq!(BufferSize::for_payload(9217), None);
        assert_eq!(BufferSize::for_payload(10000), None);
    }

    #[test]
    fn test_pool_creation_and_initial_counts() {
        let pool = BufferPool::new(10, 20, 5);

        assert_eq!(pool.available(BufferSize::Small), 10);
        assert_eq!(pool.available(BufferSize::Standard), 20);
        assert_eq!(pool.available(BufferSize::Jumbo), 5);
    }

    #[test]
    fn test_acquire_and_release_small() {
        let pool = BufferPool::new(5, 0, 0);
        assert_eq!(pool.available(BufferSize::Small), 5);

        // Acquire a buffer
        let buffer = pool.acquire(BufferSize::Small).expect("Should acquire");
        assert_eq!(pool.available(BufferSize::Small), 4);
        assert_eq!(buffer.len(), 2048);
        assert_eq!(buffer.size_category(), BufferSize::Small);

        // Release by dropping
        drop(buffer);
        assert_eq!(pool.available(BufferSize::Small), 5);
    }

    #[test]
    fn test_acquire_and_release_standard() {
        let pool = BufferPool::new(0, 3, 0);
        assert_eq!(pool.available(BufferSize::Standard), 3);

        let buffer = pool.acquire(BufferSize::Standard).expect("Should acquire");
        assert_eq!(pool.available(BufferSize::Standard), 2);
        assert_eq!(buffer.len(), 4096);
        assert_eq!(buffer.size_category(), BufferSize::Standard);

        drop(buffer);
        assert_eq!(pool.available(BufferSize::Standard), 3);
    }

    #[test]
    fn test_acquire_and_release_jumbo() {
        let pool = BufferPool::new(0, 0, 2);
        assert_eq!(pool.available(BufferSize::Jumbo), 2);

        let buffer = pool.acquire(BufferSize::Jumbo).expect("Should acquire");
        assert_eq!(pool.available(BufferSize::Jumbo), 1);
        assert_eq!(buffer.len(), 9216);
        assert_eq!(buffer.size_category(), BufferSize::Jumbo);

        drop(buffer);
        assert_eq!(pool.available(BufferSize::Jumbo), 2);
    }

    #[test]
    fn test_pool_exhaustion() {
        let pool = BufferPool::new(2, 0, 0);

        // Acquire all buffers
        let _buf1 = pool.acquire(BufferSize::Small).expect("Should get buffer 1");
        let _buf2 = pool.acquire(BufferSize::Small).expect("Should get buffer 2");
        assert_eq!(pool.available(BufferSize::Small), 0);

        // Try to acquire when exhausted
        let buf3 = pool.acquire(BufferSize::Small);
        assert!(buf3.is_none(), "Should return None when pool exhausted");

        // Release one and try again
        drop(_buf1);
        assert_eq!(pool.available(BufferSize::Small), 1);

        let buf4 = pool.acquire(BufferSize::Small);
        assert!(buf4.is_some(), "Should succeed after release");
    }

    #[test]
    fn test_multiple_acquire_release_cycles() {
        let pool = BufferPool::new(3, 0, 0);

        // Multiple cycles
        for _ in 0..10 {
            let buf = pool.acquire(BufferSize::Small).expect("Should acquire");
            assert_eq!(buf.len(), 2048);
            drop(buf);
        }

        // Pool should still have all buffers
        assert_eq!(pool.available(BufferSize::Small), 3);
    }

    #[test]
    fn test_buffer_deref() {
        let pool = BufferPool::new(1, 0, 0);
        let mut buffer = pool.acquire(BufferSize::Small).expect("Should acquire");

        // Test Deref
        assert_eq!(buffer.len(), 2048);

        // Test DerefMut - write to buffer
        buffer[0] = 42;
        buffer[100] = 99;
        assert_eq!(buffer[0], 42);
        assert_eq!(buffer[100], 99);
    }

    #[test]
    fn test_buffer_isolation() {
        let pool = BufferPool::new(2, 0, 0);

        let mut buf1 = pool.acquire(BufferSize::Small).expect("Should acquire buf1");
        let mut buf2 = pool.acquire(BufferSize::Small).expect("Should acquire buf2");

        // Write different data to each buffer
        buf1[0] = 1;
        buf2[0] = 2;

        // Verify isolation
        assert_eq!(buf1[0], 1);
        assert_eq!(buf2[0], 2);
    }

    #[test]
    fn test_mixed_size_operations() {
        let pool = BufferPool::new(2, 3, 1);

        // Acquire different sizes
        let _small = pool.acquire(BufferSize::Small).expect("Should get small");
        let _std = pool.acquire(BufferSize::Standard).expect("Should get standard");
        let _jumbo = pool.acquire(BufferSize::Jumbo).expect("Should get jumbo");

        // Check counts
        assert_eq!(pool.available(BufferSize::Small), 1);
        assert_eq!(pool.available(BufferSize::Standard), 2);
        assert_eq!(pool.available(BufferSize::Jumbo), 0);

        // Release all
        drop(_small);
        drop(_std);
        drop(_jumbo);

        // Verify all returned
        assert_eq!(pool.available(BufferSize::Small), 2);
        assert_eq!(pool.available(BufferSize::Standard), 3);
        assert_eq!(pool.available(BufferSize::Jumbo), 1);
    }

    #[test]
    fn test_zero_capacity_pool() {
        let pool = BufferPool::new(0, 0, 0);

        assert_eq!(pool.available(BufferSize::Small), 0);
        assert_eq!(pool.available(BufferSize::Standard), 0);
        assert_eq!(pool.available(BufferSize::Jumbo), 0);

        // All acquisitions should fail
        assert!(pool.acquire(BufferSize::Small).is_none());
        assert!(pool.acquire(BufferSize::Standard).is_none());
        assert!(pool.acquire(BufferSize::Jumbo).is_none());
    }

    #[test]
    fn test_arc_cloning() {
        let pool = BufferPool::new(5, 0, 0);
        let pool_clone = pool.clone();

        // Both should see same availability
        assert_eq!(pool.available(BufferSize::Small), 5);
        assert_eq!(pool_clone.available(BufferSize::Small), 5);

        // Acquire from original
        let _buf = pool.acquire(BufferSize::Small).expect("Should acquire");

        // Clone should see the change
        assert_eq!(pool_clone.available(BufferSize::Small), 4);

        // Release via drop
        drop(_buf);

        // Both should see buffer returned
        assert_eq!(pool.available(BufferSize::Small), 5);
        assert_eq!(pool_clone.available(BufferSize::Small), 5);
    }

    #[test]
    fn test_concurrent_acquire_release_simulation() {
        // Simulate multiple "threads" using the same pool
        let pool = BufferPool::new(10, 0, 0);

        // Acquire buffers in a "concurrent" pattern
        let mut buffers = Vec::new();
        for _ in 0..10 {
            buffers.push(pool.acquire(BufferSize::Small).expect("Should acquire"));
        }

        assert_eq!(pool.available(BufferSize::Small), 0);

        // Release in different order
        buffers.swap(0, 9);
        buffers.swap(3, 7);
        drop(buffers);

        // All should be returned
        assert_eq!(pool.available(BufferSize::Small), 10);
    }

    #[test]
    fn test_buffer_size_copy_clone() {
        let size = BufferSize::Standard;
        let size_copy = size;
        let size_clone = size.clone();

        assert_eq!(size, size_copy);
        assert_eq!(size, size_clone);
        assert_eq!(size.size(), size_copy.size());
    }
}
