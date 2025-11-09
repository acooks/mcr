// Criterion benchmarks for ring buffer

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::sync::Arc;
use std::thread;

// Re-export the ring buffer implementations
// Note: In real implementation, these would be in a library crate
// For PoC, we'll just include the needed code here

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;

#[repr(align(64))]
struct CacheAligned<T>(T);

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
    _pad4: [u8; 200],
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
        entry.sequence = sequence;
        entry.core_id = core_id;
        entry.message_len = message.len().min(256) as u16;
        entry.message[..entry.message_len as usize]
            .copy_from_slice(&message.as_bytes()[..entry.message_len as usize]);
        entry.state = AtomicU8::new(READY);
        entry
    }
}

pub struct SPSCRingBuffer {
    entries: Box<[LogEntry]>,
    capacity: usize,
    write_seq: CacheAligned<AtomicU64>,
    read_seq: CacheAligned<AtomicU64>,
    overruns: AtomicU64,
    core_id: u8,
}

impl SPSCRingBuffer {
    pub fn new(capacity: usize, core_id: u8) -> Self {
        assert!(capacity.is_power_of_two());
        let entries = vec![LogEntry::default(); capacity].into_boxed_slice();
        Self {
            entries,
            capacity,
            write_seq: CacheAligned(AtomicU64::new(0)),
            read_seq: CacheAligned(AtomicU64::new(0)),
            overruns: AtomicU64::new(0),
            core_id,
        }
    }

    pub fn write(&self, mut entry: LogEntry) -> Result<(), ()> {
        let seq = self.write_seq.0.fetch_add(1, Ordering::Relaxed);
        let pos = (seq as usize) & (self.capacity - 1);

        let read_seq = self.read_seq.0.load(Ordering::Acquire);
        if seq >= read_seq + self.capacity as u64 {
            self.overruns.fetch_add(1, Ordering::Relaxed);
        }

        self.entries[pos].state.store(WRITING, Ordering::Release);
        entry.sequence = seq;
        entry.core_id = self.core_id;

        // Copy data field-by-field
        self.entries[pos].timestamp_ns = entry.timestamp_ns;
        self.entries[pos].sequence = entry.sequence;
        self.entries[pos].core_id = entry.core_id;
        self.entries[pos].severity = entry.severity;
        self.entries[pos].message_len = entry.message_len;
        self.entries[pos].message = entry.message;

        self.entries[pos].state.store(READY, Ordering::Release);
        Ok(())
    }

    pub fn read(&self) -> Option<LogEntry> {
        let read_seq = self.read_seq.0.load(Ordering::Relaxed);
        let write_seq = self.write_seq.0.load(Ordering::Acquire);

        if read_seq >= write_seq {
            return None;
        }

        let pos = (read_seq as usize) & (self.capacity - 1);

        loop {
            let state = self.entries[pos].state.load(Ordering::Acquire);
            if state == READY {
                break;
            }
            std::hint::spin_loop();
        }

        let entry = self.entries[pos].clone();
        self.entries[pos].state.store(EMPTY, Ordering::Release);
        self.read_seq.0.fetch_add(1, Ordering::Release);

        Some(entry)
    }
}

fn bench_spsc_write(c: &mut Criterion) {
    let buffer = SPSCRingBuffer::new(65536, 0);
    let entry = LogEntry::new(0, 0, "Benchmark message for testing");

    c.bench_function("spsc_write", |b| {
        b.iter(|| {
            buffer.write(black_box(entry)).unwrap();
        });
    });
}

fn bench_spsc_read(c: &mut Criterion) {
    let buffer = SPSCRingBuffer::new(65536, 0);

    // Pre-fill buffer
    for _ in 0..10000 {
        buffer.write(LogEntry::new(0, 0, "Test message")).unwrap();
    }

    c.bench_function("spsc_read", |b| {
        b.iter(|| {
            buffer.read()
        });
    });
}

fn bench_spsc_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("spsc_roundtrip");

    for size in [1024, 4096, 16384, 65536].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let buffer = Arc::new(SPSCRingBuffer::new(size, 0));
            let buffer_clone = buffer.clone();

            // Spawn reader thread
            let reader = thread::spawn(move || {
                loop {
                    while buffer_clone.read().is_some() {}
                    if buffer_clone.write_seq.0.load(Ordering::Relaxed) >= 1000000 {
                        break;
                    }
                    std::hint::spin_loop();
                }
            });

            b.iter(|| {
                buffer.write(LogEntry::new(0, 0, "Test")).unwrap();
            });

            reader.join().unwrap();
        });
    }

    group.finish();
}

criterion_group!(benches, bench_spsc_write, bench_spsc_read, bench_spsc_roundtrip);
criterion_main!(benches);
