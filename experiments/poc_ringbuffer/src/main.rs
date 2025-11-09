// Ring Buffer Proof of Concept
// Demonstrates lockless SPSC and MPSC ring buffers for logging system

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Data Structures
// ============================================================================

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;

/// Cache-aligned wrapper to prevent false sharing
#[repr(align(64))]
struct CacheAligned<T>(T);

/// Simplified log entry for PoC (512 bytes)
#[repr(C, align(64))]
struct LogEntry {
    state: AtomicU8,
    _pad1: [u8; 7],
    timestamp_ns: u64,
    sequence: u64,
    core_id: u8,
    severity: u8,
    _pad2: [u8; 6],
    message_len: u16,
    _pad3: [u8; 6],
    message: [u8; 256],
    _pad4: [u8; 200], // Padding to reach 512 bytes
}

impl Clone for LogEntry {
    fn clone(&self) -> Self {
        Self {
            state: AtomicU8::new(self.state.load(Ordering::Relaxed)),
            _pad1: self._pad1,
            timestamp_ns: self.timestamp_ns,
            sequence: self.sequence,
            core_id: self.core_id,
            severity: self.severity,
            _pad2: self._pad2,
            message_len: self.message_len,
            _pad3: self._pad3,
            message: self.message,
            _pad4: self._pad4,
        }
    }
}

impl Default for LogEntry {
    fn default() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            _pad1: [0; 7],
            timestamp_ns: 0,
            sequence: 0,
            core_id: 0,
            severity: 0,
            _pad2: [0; 6],
            message_len: 0,
            _pad3: [0; 6],
            message: [0; 256],
            _pad4: [0; 200],
        }
    }
}

impl LogEntry {
    fn new(sequence: u64, core_id: u8, message: &str) -> Self {
        let mut entry = Self::default();
        entry.timestamp_ns = monotonic_nanos();
        entry.sequence = sequence;
        entry.core_id = core_id;
        entry.message_len = message.len().min(256) as u16;
        entry.message[..entry.message_len as usize]
            .copy_from_slice(&message.as_bytes()[..entry.message_len as usize]);
        entry.state = AtomicU8::new(READY);
        entry
    }

    fn get_message(&self) -> &str {
        std::str::from_utf8(&self.message[..self.message_len as usize]).unwrap_or("")
    }
}

// ============================================================================
// SPSC Ring Buffer (Single Producer, Single Consumer)
// ============================================================================

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

    /// Write entry (lock-free, single producer)
    pub fn write(&self, mut entry: LogEntry) -> Result<(), ()> {
        // 1. Reserve sequence number (no contention, use Relaxed)
        let seq = self.write_seq.0.fetch_add(1, Ordering::Relaxed);
        let pos = (seq as usize) & (self.capacity - 1); // Fast modulo

        // 2. Check for overrun
        let read_seq = self.read_seq.0.load(Ordering::Acquire);
        if seq >= read_seq + self.capacity as u64 {
            self.overruns.fetch_add(1, Ordering::Relaxed);
        }

        // 3. Mark entry as WRITING
        unsafe {
            (*self.entries[pos].get()).state.store(WRITING, Ordering::Release);
        }

        // 4. Fill entry fields
        entry.sequence = seq;
        entry.core_id = self.core_id;

        // Copy data field-by-field (safe: we own this slot via state machine)
        unsafe {
            let slot = &mut *self.entries[pos].get();
            slot.timestamp_ns = entry.timestamp_ns;
            slot.sequence = entry.sequence;
            slot.core_id = entry.core_id;
            slot.severity = entry.severity;
            slot.message_len = entry.message_len;
            slot.message = entry.message;
        }

        // 5. Mark entry as READY (all data visible to reader)
        unsafe {
            (*self.entries[pos].get()).state.store(READY, Ordering::Release);
        }

        Ok(())
    }

    /// Read entry (lock-free, single consumer)
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
                // Writer stalled? Shouldn't happen
                println!("SPSC: Reader waited {} spins, state={}", spins, state);
                return None;
            }
            spins += 1;
            std::hint::spin_loop();
        }

        // 3. Read entry (safe: state == READY guarantees complete write)
        let entry = unsafe { (*self.entries[pos].get()).clone() };

        // 4. Mark as consumed
        unsafe {
            (*self.entries[pos].get()).state.store(EMPTY, Ordering::Release);
        }
        self.read_seq.0.fetch_add(1, Ordering::Release);

        Some(entry)
    }

    pub fn overruns(&self) -> u64 {
        self.overruns.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        let write_seq = self.write_seq.0.load(Ordering::Relaxed);
        let read_seq = self.read_seq.0.load(Ordering::Relaxed);
        (write_seq.saturating_sub(read_seq) as usize).min(self.capacity)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// MPSC Ring Buffer (Multiple Producers, Single Consumer)
// ============================================================================

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

    /// Write entry (lock-free via CAS, multiple producers)
    pub fn write(&self, mut entry: LogEntry) -> Result<(), ()> {
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
            (*self.entries[pos].get()).state.store(WRITING, Ordering::Release);
        }

        // 4. Fill entry fields
        entry.sequence = seq;

        // Copy data field-by-field (safe: we own this slot via state machine)
        unsafe {
            let slot = &mut *self.entries[pos].get();
            slot.timestamp_ns = entry.timestamp_ns;
            slot.sequence = entry.sequence;
            slot.core_id = entry.core_id;
            slot.severity = entry.severity;
            slot.message_len = entry.message_len;
            slot.message = entry.message;
        }

        // 5. Mark entry as READY
        unsafe {
            (*self.entries[pos].get()).state.store(READY, Ordering::Release);
        }

        Ok(())
    }

    /// Read entry (same as SPSC - single consumer)
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
                println!("MPSC: Reader waited {} spins, state={}", spins, state);
                return None;
            }
            spins += 1;
            std::hint::spin_loop();
        }

        let entry = unsafe { (*self.entries[pos].get()).clone() };

        unsafe {
            (*self.entries[pos].get()).state.store(EMPTY, Ordering::Release);
        }
        self.read_seq.0.fetch_add(1, Ordering::Release);

        Some(entry)
    }

    pub fn overruns(&self) -> u64 {
        self.overruns.load(Ordering::Relaxed)
    }

    pub fn cas_failures(&self) -> u64 {
        self.cas_failures.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        let write_seq = self.write_seq.0.load(Ordering::Relaxed);
        let read_seq = self.read_seq.0.load(Ordering::Relaxed);
        (write_seq.saturating_sub(read_seq) as usize).min(self.capacity)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Utilities
// ============================================================================

fn monotonic_nanos() -> u64 {
    let t = std::time::Instant::now();
    t.elapsed().as_nanos() as u64
}

// ============================================================================
// Demos and Tests
// ============================================================================

fn demo_spsc() {
    println!("\n=== SPSC Ring Buffer Demo ===");

    let buffer = Arc::new(SPSCRingBuffer::new(16, 0));
    let buffer_clone = buffer.clone();

    // Writer thread
    let writer = thread::spawn(move || {
        for i in 0..10 {
            let entry = LogEntry::new(0, 0, &format!("Message {}", i));
            buffer_clone.write(entry).unwrap();
            thread::sleep(Duration::from_millis(50));
        }
        println!("Writer: Sent 10 messages");
    });

    // Reader thread
    let reader = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100)); // Let some messages queue
        let mut count = 0;
        loop {
            if let Some(entry) = buffer.read() {
                println!(
                    "Reader: seq={}, msg='{}'",
                    entry.sequence,
                    entry.get_message()
                );
                count += 1;
            } else {
                thread::sleep(Duration::from_millis(10));
            }

            if count >= 10 {
                break;
            }
        }
        println!("Reader: Received {} messages", count);
        println!("Overruns: {}", buffer.overruns());
    });

    writer.join().unwrap();
    reader.join().unwrap();
}

fn demo_mpsc() {
    println!("\n=== MPSC Ring Buffer Demo ===");

    let buffer = Arc::new(MPSCRingBuffer::new(16));

    // Multiple writer threads
    let mut writers = vec![];
    for core in 0..4 {
        let buffer_clone = buffer.clone();
        let writer = thread::spawn(move || {
            for i in 0..5 {
                let entry = LogEntry::new(0, core, &format!("Core {} msg {}", core, i));
                buffer_clone.write(entry).unwrap();
                thread::sleep(Duration::from_millis(10));
            }
        });
        writers.push(writer);
    }

    // Single reader thread
    let buffer_clone = buffer.clone();
    let reader = thread::spawn(move || {
        let mut count = 0;
        let mut by_core = [0u32; 4];
        loop {
            if let Some(entry) = buffer_clone.read() {
                println!(
                    "Reader: seq={}, core={}, msg='{}'",
                    entry.sequence,
                    entry.core_id,
                    entry.get_message()
                );
                by_core[entry.core_id as usize] += 1;
                count += 1;
            } else {
                thread::sleep(Duration::from_millis(5));
            }

            if count >= 20 {
                break;
            }
        }
        println!("Reader: Received {} messages", count);
        println!("By core: {:?}", by_core);
        println!("CAS failures: {}", buffer_clone.cas_failures());
        println!("Overruns: {}", buffer_clone.overruns());
    });

    for writer in writers {
        writer.join().unwrap();
    }
    reader.join().unwrap();
}

fn bench_spsc() {
    println!("\n=== SPSC Benchmark ===");

    let buffer = Arc::new(SPSCRingBuffer::new(65536, 0));
    let buffer_clone = buffer.clone();

    let ops = 1_000_000;

    // Writer thread
    let writer = thread::spawn(move || {
        let start = Instant::now();
        for _ in 0..ops {
            let entry = LogEntry::new(0, 0, "Benchmark message");
            buffer_clone.write(entry).unwrap();
        }
        let elapsed = start.elapsed();
        let throughput = ops as f64 / elapsed.as_secs_f64();
        println!("Writer: {} ops in {:?}", ops, elapsed);
        println!("Writer: {:.2} Mops/sec", throughput / 1_000_000.0);
        println!(
            "Writer: {:.0} ns/op",
            elapsed.as_nanos() as f64 / ops as f64
        );
    });

    // Reader thread
    let reader = thread::spawn(move || {
        let start = Instant::now();
        let mut count = 0;
        while count < ops {
            if let Some(_entry) = buffer.read() {
                count += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        let elapsed = start.elapsed();
        let throughput = ops as f64 / elapsed.as_secs_f64();
        println!("Reader: {} ops in {:?}", count, elapsed);
        println!("Reader: {:.2} Mops/sec", throughput / 1_000_000.0);
        println!(
            "Reader: {:.0} ns/op",
            elapsed.as_nanos() as f64 / ops as f64
        );
        println!("Overruns: {}", buffer.overruns());
    });

    writer.join().unwrap();
    reader.join().unwrap();
}

fn bench_mpsc() {
    println!("\n=== MPSC Benchmark (4 writers) ===");

    let buffer = Arc::new(MPSCRingBuffer::new(65536));
    let ops_per_writer = 250_000;
    let num_writers = 4;
    let total_ops = ops_per_writer * num_writers;

    // Writer threads
    let mut writers = vec![];
    for core in 0..num_writers {
        let buffer_clone = buffer.clone();
        let writer = thread::spawn(move || {
            let start = Instant::now();
            for _i in 0..ops_per_writer {
                let entry = LogEntry::new(0, core as u8, "Benchmark message");
                buffer_clone.write(entry).unwrap();
            }
            let elapsed = start.elapsed();
            println!("Writer {}: {} ops in {:?}", core, ops_per_writer, elapsed);
        });
        writers.push(writer);
    }

    // Reader thread
    let buffer_clone = buffer.clone();
    let reader = thread::spawn(move || {
        let start = Instant::now();
        let mut count = 0;
        while count < total_ops {
            if let Some(_entry) = buffer_clone.read() {
                count += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        let elapsed = start.elapsed();
        let throughput = total_ops as f64 / elapsed.as_secs_f64();
        println!("\nReader: {} ops in {:?}", count, elapsed);
        println!("Reader: {:.2} Mops/sec", throughput / 1_000_000.0);
        println!(
            "Reader: {:.0} ns/op",
            elapsed.as_nanos() as f64 / count as f64
        );
        println!("CAS failures: {}", buffer_clone.cas_failures());
        println!("Overruns: {}", buffer_clone.overruns());
    });

    for writer in writers {
        writer.join().unwrap();
    }
    reader.join().unwrap();
}

fn main() {
    println!("Ring Buffer Proof of Concept");
    println!("Entry size: {} bytes", std::mem::size_of::<LogEntry>());

    demo_spsc();
    demo_mpsc();
    bench_spsc();
    bench_mpsc();

    println!("\n=== All tests complete ===");
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spsc_basic() {
        let buffer = SPSCRingBuffer::new(4, 0);

        // Write and read
        buffer
            .write(LogEntry::new(0, 0, "test1"))
            .unwrap();
        buffer
            .write(LogEntry::new(0, 0, "test2"))
            .unwrap();

        assert_eq!(buffer.len(), 2);

        let entry1 = buffer.read().unwrap();
        assert_eq!(entry1.get_message(), "test1");

        let entry2 = buffer.read().unwrap();
        assert_eq!(entry2.get_message(), "test2");

        assert!(buffer.is_empty());
    }

    #[test]
    fn test_spsc_wraparound() {
        let buffer = SPSCRingBuffer::new(4, 0);

        // Fill buffer
        for i in 0..4 {
            buffer
                .write(LogEntry::new(0, 0, &format!("msg{}", i)))
                .unwrap();
        }

        // Read all
        for i in 0..4 {
            let entry = buffer.read().unwrap();
            assert_eq!(entry.get_message(), format!("msg{}", i));
        }

        // Write again (should wrap around)
        buffer
            .write(LogEntry::new(0, 0, "wrap"))
            .unwrap();
        let entry = buffer.read().unwrap();
        assert_eq!(entry.get_message(), "wrap");
    }

    #[test]
    fn test_spsc_overrun() {
        let buffer = SPSCRingBuffer::new(4, 0);

        // Overfill buffer (write 8, capacity 4)
        for i in 0..8 {
            buffer
                .write(LogEntry::new(0, 0, &format!("msg{}", i)))
                .unwrap();
        }

        assert_eq!(buffer.overruns(), 4); // 4 messages overwritten
    }

    #[test]
    fn test_mpsc_basic() {
        let buffer = MPSCRingBuffer::new(4);

        buffer.write(LogEntry::new(0, 0, "test1")).unwrap();
        buffer.write(LogEntry::new(0, 0, "test2")).unwrap();

        assert_eq!(buffer.len(), 2);

        let entry1 = buffer.read().unwrap();
        assert_eq!(entry1.get_message(), "test1");

        let entry2 = buffer.read().unwrap();
        assert_eq!(entry2.get_message(), "test2");

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
                    buffer_clone
                        .write(LogEntry::new(0, i, &format!("t{}m{}", i, j)))
                        .unwrap();
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
