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
