// SPDX-License-Identifier: Apache-2.0 OR MIT
// Lock-free ring buffers for logging
//
// Based on analysis of Linux printk_ringbuffer and FreeBSD msgbuf designs.
// See design/archive/RINGBUFFER_IMPLEMENTATION.md for details.

use super::entry::{LogEntry, EMPTY, READY, WRITING};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cache-aligned wrapper to prevent false sharing
#[repr(align(64))]
struct CacheAligned<T>(T);

// ============================================================================
// MPSC Ring Buffer (Multiple Producers, Single Consumer)
// ============================================================================

/// Lock-free multiple-producer single-consumer ring buffer
///
/// Designed for control plane and supervisor where multiple async tasks
/// may log concurrently. Uses CAS (compare-and-swap) to coordinate writers.
pub struct MPSCRingBuffer {
    entries: Box<[UnsafeCell<LogEntry>]>,
    capacity: usize,
    write_seq: CacheAligned<AtomicU64>,
    read_seq: CacheAligned<AtomicU64>,
    overruns: AtomicU64,
    cas_failures: AtomicU64,
}

// SAFETY: MPSCRingBuffer is Sync because:
// - Multiple writers coordinate via CAS on write_seq
// - Only one reader (guaranteed by consumer task)
// - State machine prevents concurrent access to same entry
unsafe impl Sync for MPSCRingBuffer {}

impl MPSCRingBuffer {
    /// Create a new MPSC ring buffer
    ///
    /// # Arguments
    /// * `capacity` - Number of entries (must be power of 2)
    ///
    /// # Panics
    /// Panics if capacity is not a power of 2
    pub fn new(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two(), "Capacity must be power of 2");

        let entries: Vec<UnsafeCell<LogEntry>> = (0..capacity)
            .map(|_| UnsafeCell::new(LogEntry::default()))
            .collect();

        Self {
            entries: entries.into_boxed_slice(),
            capacity,
            write_seq: CacheAligned(AtomicU64::new(0)),
            read_seq: CacheAligned(AtomicU64::new(0)),
            overruns: AtomicU64::new(0),
            cas_failures: AtomicU64::new(0),
        }
    }

    /// Write entry to ring buffer (lock-free via CAS, multiple producers)
    ///
    /// Never blocks - drops old messages on overflow.
    pub fn write(&self, mut entry: LogEntry) {
        // 1. Reserve sequence number via CAS (contention possible)
        let seq = loop {
            let current = self.write_seq.0.load(Ordering::Relaxed);

            match self.write_seq.0.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,  // Success: acquire current, release new
                Ordering::Relaxed, // Failure: retry
            ) {
                Ok(_) => break current, // Reserved slot
                Err(_) => {
                    self.cas_failures.fetch_add(1, Ordering::Relaxed);
                    std::hint::spin_loop(); // Brief pause before retry
                }
            }
        };

        let pos = (seq as usize) & (self.capacity - 1);

        // 2. Check for overrun
        let read_seq = self.read_seq.0.load(Ordering::Acquire);
        if seq >= read_seq + self.capacity as u64 {
            self.overruns.fetch_add(1, Ordering::Relaxed);
        }

        // 3. Mark entry as WRITING
        unsafe {
            (*self.entries[pos].get())
                .state
                .store(WRITING, Ordering::Release);
        }

        // 4. Fill entry fields
        entry.sequence = seq;

        // Copy data field-by-field (safe: we own this slot via state machine)
        unsafe {
            let slot = &mut *self.entries[pos].get();
            slot.timestamp_ns = entry.timestamp_ns;
            slot.sequence = entry.sequence;
            slot.severity = entry.severity;
            slot.facility = entry.facility;
            slot.core_id = entry.core_id;
            slot.process_id = entry.process_id;
            slot.thread_id = entry.thread_id;
            slot.message_len = entry.message_len;
            slot.message_start = entry.message_start;
            slot.message_cont = entry.message_cont;
            slot.kv_count = entry.kv_count;
            slot.kvs = entry.kvs;
        }

        // 5. Mark entry as READY
        unsafe {
            (*self.entries[pos].get())
                .state
                .store(READY, Ordering::Release);
        }
    }

    /// Read entry from ring buffer (single consumer)
    pub fn read(&self) -> Option<LogEntry> {
        let read_seq = self.read_seq.0.load(Ordering::Relaxed);
        let write_seq = self.write_seq.0.load(Ordering::Acquire);

        if read_seq >= write_seq {
            return None;
        }

        let pos = (read_seq as usize) & (self.capacity - 1);

        let mut spins = 0;
        loop {
            let state = unsafe { (*self.entries[pos].get()).state.load(Ordering::Acquire) };
            if state == READY {
                break;
            }
            if spins > 1000 {
                return None;
            }
            spins += 1;
            std::hint::spin_loop();
        }

        let entry = unsafe { (*self.entries[pos].get()).clone() };

        unsafe {
            (*self.entries[pos].get())
                .state
                .store(EMPTY, Ordering::Release);
        }
        self.read_seq.0.fetch_add(1, Ordering::Release);

        Some(entry)
    }

    /// Get number of overruns (messages dropped due to overflow)
    pub fn overruns(&self) -> u64 {
        self.overruns.load(Ordering::Relaxed)
    }

    /// Get number of CAS failures (contention metric)
    pub fn cas_failures(&self) -> u64 {
        self.cas_failures.load(Ordering::Relaxed)
    }

    /// Get number of entries currently in buffer
    pub fn len(&self) -> usize {
        let write_seq = self.write_seq.0.load(Ordering::Relaxed);
        let read_seq = self.read_seq.0.load(Ordering::Relaxed);
        (write_seq.saturating_sub(read_seq) as usize).min(self.capacity)
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{Facility, Severity};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_mpsc_basic() {
        let buffer = MPSCRingBuffer::new(4);

        let entry1 = LogEntry::new(Severity::Info, Facility::Test, "test1");
        let entry2 = LogEntry::new(Severity::Info, Facility::Test, "test2");

        buffer.write(entry1);
        buffer.write(entry2);

        assert_eq!(buffer.len(), 2);

        let read1 = buffer.read().unwrap();
        assert_eq!(read1.get_message(), "test1");

        let read2 = buffer.read().unwrap();
        assert_eq!(read2.get_message(), "test2");

        assert!(buffer.is_empty());
    }

    #[test]
    fn test_mpsc_concurrent() {
        let buffer = Arc::new(MPSCRingBuffer::new(1024));
        let mut handles = vec![];

        // Spawn 4 writers
        for i in 0..4 {
            let buffer_clone = buffer.clone();
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let entry =
                        LogEntry::new(Severity::Info, Facility::Test, &format!("t{}m{}", i, j));
                    buffer_clone.write(entry);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Read all messages
        let mut count = 0;
        while buffer.read().is_some() {
            count += 1;
        }

        assert_eq!(count, 400);
    }
}
