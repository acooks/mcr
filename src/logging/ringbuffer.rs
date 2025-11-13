// Lock-free ring buffers for logging
//
// Based on analysis of Linux printk_ringbuffer and FreeBSD msgbuf designs.
// See design/RINGBUFFER_IMPLEMENTATION.md for details.

use super::entry::{LogEntry, EMPTY, READY, WRITING};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cache-aligned wrapper to prevent false sharing
#[repr(align(64))]
struct CacheAligned<T>(T);

// ============================================================================
// SPSC Ring Buffer (Single Producer, Single Consumer)
// ============================================================================

/// Lock-free single-producer single-consumer ring buffer
///
/// Designed for data plane workers where each io_uring thread has its own
/// dedicated buffer. No locks required because there's only one writer and
/// one reader.
pub struct SPSCRingBuffer {
    entries: Box<[UnsafeCell<LogEntry>]>,
    capacity: usize,
    write_seq: CacheAligned<AtomicU64>,
    read_seq: CacheAligned<AtomicU64>,
    overruns: AtomicU64,
    core_id: u8,
}

// SAFETY: SPSCRingBuffer is Sync because:
// - Only one thread writes (guaranteed by architecture)
// - Only one thread reads (guaranteed by consumer task)
// - State machine prevents concurrent access to same entry
unsafe impl Sync for SPSCRingBuffer {}

impl SPSCRingBuffer {
    /// Create a new SPSC ring buffer
    ///
    /// # Arguments
    /// * `capacity` - Number of entries (must be power of 2)
    /// * `core_id` - CPU core ID for this buffer (0-254, 255=unknown)
    ///
    /// # Panics
    /// Panics if capacity is not a power of 2
    pub fn new(capacity: usize, core_id: u8) -> Self {
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
            core_id,
        }
    }

    /// Write entry to ring buffer (lock-free, single producer)
    ///
    /// Never blocks - drops old messages on overflow.
    pub fn write(&self, mut entry: LogEntry) {
        // 1. Reserve sequence number (no contention, use Relaxed)
        let seq = self.write_seq.0.fetch_add(1, Ordering::Relaxed);
        let pos = (seq as usize) & (self.capacity - 1); // Fast modulo for power of 2

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
        entry.core_id = self.core_id;

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

        // 5. Mark entry as READY (all data visible to reader)
        unsafe {
            (*self.entries[pos].get())
                .state
                .store(READY, Ordering::Release);
        }
    }

    /// Read entry from ring buffer (lock-free, single consumer)
    ///
    /// Returns Some(entry) if data available, None if buffer empty.
    pub fn read(&self) -> Option<LogEntry> {
        // 1. Check if data available
        let read_seq = self.read_seq.0.load(Ordering::Relaxed);
        let write_seq = self.write_seq.0.load(Ordering::Acquire);

        if read_seq >= write_seq {
            return None; // Buffer empty
        }

        let pos = (read_seq as usize) & (self.capacity - 1);

        // 2. Wait for entry to be READY (rare: writer might be mid-write)
        let mut spins = 0;
        loop {
            let state = unsafe { (*self.entries[pos].get()).state.load(Ordering::Acquire) };
            if state == READY {
                break;
            }
            if spins > 1000 {
                // Writer stalled? Shouldn't happen, but don't hang forever
                return None;
            }
            spins += 1;
            std::hint::spin_loop();
        }

        // 3. Read entry (safe: state == READY guarantees complete write)
        let entry = unsafe { (*self.entries[pos].get()).clone() };

        // 4. Mark as consumed
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

    /// Read entry from ring buffer (same as SPSC - single consumer)
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
    fn test_spsc_basic() {
        let buffer = SPSCRingBuffer::new(4, 0);

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
    fn test_spsc_wraparound() {
        let buffer = SPSCRingBuffer::new(4, 0);

        // Fill buffer
        for i in 0..4 {
            let entry = LogEntry::new(Severity::Info, Facility::Test, &format!("msg{}", i));
            buffer.write(entry);
        }

        // Read all
        for i in 0..4 {
            let entry = buffer.read().unwrap();
            assert_eq!(entry.get_message(), format!("msg{}", i));
        }

        // Write again (should wrap around)
        let entry = LogEntry::new(Severity::Info, Facility::Test, "wrap");
        buffer.write(entry);

        let read = buffer.read().unwrap();
        assert_eq!(read.get_message(), "wrap");
    }

    #[test]
    fn test_spsc_overrun() {
        let buffer = SPSCRingBuffer::new(4, 0);

        // Overfill buffer (write 8, capacity 4)
        for i in 0..8 {
            let entry = LogEntry::new(Severity::Info, Facility::Test, &format!("msg{}", i));
            buffer.write(entry);
        }

        assert_eq!(buffer.overruns(), 4);
    }

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

// ============================================================================
// Shared Memory SPSC Ring Buffer (Cross-Process)
// ============================================================================

use nix::fcntl::OFlag;
use nix::sys::mman::{mmap, munmap, shm_open, shm_unlink, MapFlags, ProtFlags};
use nix::sys::stat::Mode;
use nix::unistd::ftruncate;
use std::os::fd::OwnedFd;

/// Generate shared memory ID for a data plane worker's ring buffer
///
/// Format: `/mcr_dp_c{core_id}_{facility_code}`
/// Example: `/mcr_dp_c0_ingress` for core 0's ingress facility
pub fn shm_id_for_facility(core_id: u8, facility: crate::logging::Facility) -> String {
    format!("/mcr_dp_c{}_{}", core_id, facility.as_str().to_lowercase())
}

/// Header structure stored at the beginning of shared memory
#[repr(C, align(64))]
struct SharedRingBufferHeader {
    write_seq: AtomicU64,
    _pad1: [u8; 56], // Cache line padding
    read_seq: AtomicU64,
    _pad2: [u8; 56], // Cache line padding
    overruns: AtomicU64,
    capacity: usize,
    core_id: u8,
    _pad3: [u8; 47], // Align to cache line
}

/// Calculate total shared memory size needed
fn calc_shm_size(capacity: usize) -> usize {
    use std::mem::{align_of, size_of};
    let header_size = size_of::<SharedRingBufferHeader>();
    let entry_size = size_of::<LogEntry>();
    let entry_align = align_of::<LogEntry>();

    // Round up header to entry alignment
    let aligned_header = (header_size + entry_align - 1) & !(entry_align - 1);
    aligned_header + (capacity * entry_size)
}

/// Lock-free SPSC ring buffer in shared memory
///
/// This can be used across process boundaries. The supervisor creates
/// the shared memory region, and workers attach to it.
pub struct SharedSPSCRingBuffer {
    shm_name: String,
    _shm_fd: OwnedFd, // Keep fd alive, will auto-close on drop
    mapped_addr: *mut u8,
    mapped_size: usize,
    header: *mut SharedRingBufferHeader,
    entries: *mut UnsafeCell<LogEntry>,
    capacity: usize,
    is_owner: bool, // True if this process created the shm
}

// SAFETY: Same as SPSCRingBuffer - atomics + state machine guarantee safety
unsafe impl Send for SharedSPSCRingBuffer {}
unsafe impl Sync for SharedSPSCRingBuffer {}

impl SharedSPSCRingBuffer {
    /// Create a new shared memory ring buffer (supervisor side)
    ///
    /// # Arguments
    /// * `shm_id` - Shared memory ID (e.g., "/mcr_log_dp0")
    /// * `capacity` - Number of entries (must be power of 2)
    /// * `core_id` - CPU core ID for this buffer
    pub fn create(shm_id: &str, capacity: usize, core_id: u8) -> Result<Self, nix::Error> {
        assert!(capacity.is_power_of_two(), "Capacity must be power of 2");

        let size = calc_shm_size(capacity);

        // Remove any stale shared memory object from previous crashed instances
        // Ignore ENOENT (file doesn't exist) - that's the expected case
        let _ = shm_unlink(shm_id);

        // Create shared memory object
        let fd = shm_open(
            shm_id,
            OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?;

        // Set size
        ftruncate(&fd, size as i64)?;

        // Map into memory
        let addr = unsafe {
            mmap(
                None,
                std::num::NonZeroUsize::new(size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )?
        };

        unsafe {
            let mapped_addr = addr.as_ptr() as *mut u8;

            // Initialize header
            let header = mapped_addr as *mut SharedRingBufferHeader;
            std::ptr::write(&mut (*header).write_seq, AtomicU64::new(0));
            std::ptr::write(&mut (*header).read_seq, AtomicU64::new(0));
            std::ptr::write(&mut (*header).overruns, AtomicU64::new(0));
            (*header).capacity = capacity;
            (*header).core_id = core_id;

            // Calculate entries pointer (after aligned header)
            use std::mem::{align_of, size_of};
            let header_size = size_of::<SharedRingBufferHeader>();
            let entry_align = align_of::<LogEntry>();
            let aligned_header = (header_size + entry_align - 1) & !(entry_align - 1);
            let entries = (mapped_addr as usize + aligned_header) as *mut UnsafeCell<LogEntry>;

            // Initialize all entries to EMPTY
            for i in 0..capacity {
                let entry = &mut *entries.add(i).cast::<LogEntry>();
                *entry = LogEntry::default();
            }

            Ok(Self {
                shm_name: shm_id.to_string(),
                _shm_fd: fd,
                mapped_addr,
                mapped_size: size,
                header,
                entries,
                capacity,
                is_owner: true,
            })
        }
    }

    /// Attach to existing shared memory ring buffer (worker side)
    ///
    /// # Arguments
    /// * `shm_id` - Shared memory ID to attach to
    pub fn attach(shm_id: &str) -> Result<Self, nix::Error> {
        // Open existing shared memory
        let fd = shm_open(shm_id, OFlag::O_RDWR, Mode::empty())?;

        // First, map just the header to read the capacity
        let header_size = std::mem::size_of::<SharedRingBufferHeader>();
        let temp_addr = unsafe {
            mmap(
                None,
                std::num::NonZeroUsize::new(header_size).unwrap(),
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )?
        };

        let capacity = unsafe {
            let header = temp_addr.as_ptr() as *const SharedRingBufferHeader;
            (*header).capacity
        };

        // Unmap temporary mapping
        unsafe {
            munmap(temp_addr, header_size)?;
        }

        // Now map the full size
        let size = calc_shm_size(capacity);
        unsafe {
            let addr = mmap(
                None,
                std::num::NonZeroUsize::new(size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )?;

            let mapped_addr = addr.as_ptr() as *mut u8;
            let header = mapped_addr as *mut SharedRingBufferHeader;

            // Calculate entries pointer
            use std::mem::{align_of, size_of};
            let header_size = size_of::<SharedRingBufferHeader>();
            let entry_align = align_of::<LogEntry>();
            let aligned_header = (header_size + entry_align - 1) & !(entry_align - 1);
            let entries = (mapped_addr as usize + aligned_header) as *mut UnsafeCell<LogEntry>;

            Ok(Self {
                shm_name: shm_id.to_string(),
                _shm_fd: fd,
                mapped_addr,
                mapped_size: size,
                header,
                entries,
                capacity,
                is_owner: false,
            })
        }
    }

    /// Write an entry (MPSC-safe with fetch_add reserve-then-write)
    ///
    /// This uses atomic fetch_add to reserve a slot before writing, making it
    /// safe for multiple producers (MPSC) without locks.
    pub fn write(&self, mut entry: LogEntry) {
        unsafe {
            // STEP 1: Atomically reserve a slot
            // fetch_add returns the PREVIOUS value, giving us exclusive ownership
            // of this sequence number. The counter is incremented atomically,
            // so the next thread gets a different, unique sequence number.
            let write_seq = (*self.header).write_seq.fetch_add(1, Ordering::Relaxed);
            let pos = (write_seq as usize) & (self.capacity - 1);

            // STEP 2: Wait for slot to be free (buffer might be full)
            // If we've lapped the consumer (write_seq >= read_seq + capacity),
            // we must wait for the consumer to advance.
            const MAX_SPIN_ITERATIONS: u32 = 10_000;
            let mut spin_count = 0;

            loop {
                let read_seq = (*self.header).read_seq.load(Ordering::Acquire);

                // Check if the slot we reserved is available
                if write_seq < read_seq + self.capacity as u64 {
                    break; // Slot is free, proceed
                }

                // Buffer is full - implement spin timeout to prevent DoS
                spin_count += 1;
                if spin_count > MAX_SPIN_ITERATIONS {
                    // Drop the log message instead of blocking forever
                    (*self.header).overruns.fetch_add(1, Ordering::Relaxed);
                    return;
                }

                std::hint::spin_loop();
            }

            // STEP 3: Fill entry metadata
            entry.sequence = write_seq;
            entry.core_id = (*self.header).core_id;
            entry.state.store(WRITING, Ordering::Relaxed);

            // STEP 4: Write entry to our reserved slot
            std::ptr::write(self.entries.add(pos).cast::<LogEntry>(), entry);

            // STEP 5: Signal completion with Release ordering
            // This ensures all data writes above are visible to the consumer
            // before it sees the READY state.
            (*self.entries.add(pos).cast::<LogEntry>())
                .state
                .store(READY, Ordering::Release);
        }
    }

    /// Read an entry (consumer side of MPSC ringbuffer)
    ///
    /// This method is safe for a single consumer thread reading from multiple
    /// producer threads. It uses proper Acquire ordering to synchronize with
    /// the producers' Release stores.
    pub fn read(&self) -> Option<LogEntry> {
        unsafe {
            let read_seq = (*self.header).read_seq.load(Ordering::Relaxed);
            let write_seq = (*self.header).write_seq.load(Ordering::Acquire);

            // Check if there are any entries to read
            if read_seq >= write_seq {
                return None;
            }

            let pos = (read_seq as usize) & (self.capacity - 1);

            // Wait for READY state with timeout to prevent DoS
            // A producer may have reserved this slot (via fetch_add) but not yet
            // marked it READY. We must wait, but with a timeout to prevent blocking forever.
            const MAX_SPIN_ITERATIONS: u32 = 10_000;
            let mut spin_count = 0;

            loop {
                let state = (*self.entries.add(pos).cast::<LogEntry>())
                    .state
                    .load(Ordering::Acquire);

                if state == READY {
                    break; // Entry is ready to read
                }

                // Implement spin timeout to prevent DoS
                spin_count += 1;
                if spin_count > MAX_SPIN_ITERATIONS {
                    // Producer took too long to write - treat as empty
                    // This shouldn't happen in normal operation but prevents
                    // a malicious or buggy producer from blocking the consumer forever
                    return None;
                }

                std::hint::spin_loop();
            }

            // Read entry with proper synchronization
            let entry = std::ptr::read(self.entries.add(pos).cast::<LogEntry>());

            // Mark as consumed with Release ordering
            // This ensures the consumer's read is complete before the slot
            // can be reused by producers
            (*self.entries.add(pos).cast::<LogEntry>())
                .state
                .store(EMPTY, Ordering::Release);

            (*self.header).read_seq.fetch_add(1, Ordering::Release);

            Some(entry)
        }
    }

    /// Get number of overruns
    pub fn overruns(&self) -> u64 {
        unsafe { (*self.header).overruns.load(Ordering::Relaxed) }
    }

    /// Get shared memory ID for passing to workers
    pub fn shm_id(&self) -> &str {
        &self.shm_name
    }

    /// Get the core ID associated with this ring buffer
    pub fn core_id(&self) -> u8 {
        unsafe { (*self.header).core_id }
    }
}

impl Drop for SharedSPSCRingBuffer {
    fn drop(&mut self) {
        unsafe {
            // Unmap memory
            let _ = munmap(
                std::ptr::NonNull::new(self.mapped_addr as *mut libc::c_void).unwrap(),
                self.mapped_size,
            );

            // OwnedFd will automatically close the file descriptor

            // Only the owner (supervisor) unlinks the shared memory
            // Workers just detach when they drop
            if self.is_owner {
                let _ = shm_unlink(self.shm_name.as_str());
            }
        }
    }
}

#[cfg(test)]
mod shared_tests {
    use super::*;
    use crate::logging::{Facility, Severity};

    #[test]
    fn test_shared_ringbuffer_basic() {
        let shm_id = "/mcr_test_basic";
        let capacity = 16;
        let core_id = 0;

        // Create shared memory ring buffer (supervisor side)
        let ring = SharedSPSCRingBuffer::create(shm_id, capacity, core_id)
            .expect("Failed to create shared ring buffer");

        // Write an entry
        let mut entry = LogEntry::default();
        entry.facility = Facility::DataPlane;
        entry.severity = Severity::Info;
        ring.write(entry);

        // Read it back
        let read_entry = ring.read().expect("Failed to read entry");
        assert_eq!(read_entry.facility, Facility::DataPlane);
        assert_eq!(read_entry.severity, Severity::Info);
        assert_eq!(read_entry.core_id, core_id);

        // Clean up happens automatically on drop
    }

    #[test]
    fn test_shm_id_generation() {
        let id = shm_id_for_facility(0, Facility::Ingress);
        assert_eq!(id, "/mcr_dp_c0_ingress");

        let id = shm_id_for_facility(7, Facility::Egress);
        assert_eq!(id, "/mcr_dp_c7_egress");
    }
}
