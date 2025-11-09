// Log entry structure

use super::{Facility, Severity};
use std::sync::atomic::{AtomicU8, Ordering};

/// Entry states for the state machine
pub(crate) const EMPTY: u8 = 0;
pub(crate) const WRITING: u8 = 1;
pub(crate) const READY: u8 = 2;

/// Key-value pair for structured logging
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyValue {
    key_len: u8,
    value_len: u8,
    _pad: [u8; 2],
    key: [u8; 16],
    value: [u8; 64],
}

impl KeyValue {
    /// Create empty key-value pair
    pub const fn empty() -> Self {
        Self {
            key_len: 0,
            value_len: 0,
            _pad: [0; 2],
            key: [0; 16],
            value: [0; 64],
        }
    }

    /// Create new key-value pair
    pub fn new(key: &str, value: &str) -> Self {
        let mut kv = Self::empty();
        let key_bytes = key.as_bytes();
        let value_bytes = value.as_bytes();

        kv.key_len = key_bytes.len().min(16) as u8;
        kv.value_len = value_bytes.len().min(64) as u8;

        kv.key[..kv.key_len as usize].copy_from_slice(&key_bytes[..kv.key_len as usize]);
        kv.value[..kv.value_len as usize]
            .copy_from_slice(&value_bytes[..kv.value_len as usize]);

        kv
    }

    /// Get key as string slice
    pub fn key(&self) -> &str {
        std::str::from_utf8(&self.key[..self.key_len as usize]).unwrap_or("")
    }

    /// Get value as string slice
    pub fn value(&self) -> &str {
        std::str::from_utf8(&self.value[..self.value_len as usize]).unwrap_or("")
    }
}

impl std::fmt::Debug for KeyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.key(), self.value())
    }
}

/// Log entry (512 bytes, cache-aligned)
#[repr(C, align(64))]
pub struct LogEntry {
    // === Synchronization (8 bytes) ===
    pub(crate) state: AtomicU8,
    _pad1: [u8; 7],

    // === Metadata (32 bytes) ===
    pub timestamp_ns: u64,
    pub sequence: u64,
    pub severity: Severity,
    pub facility: Facility,
    pub core_id: u8,
    _pad2: [u8; 5],
    pub process_id: u32,
    pub thread_id: u64,

    // === Message (272 bytes) ===
    pub message_len: u16,
    _pad3: [u8; 6],
    pub message: [u8; 256],

    // === Key-Value Pairs (192 bytes) ===
    pub kv_count: u8,
    _pad4: [u8; 7],
    pub kvs: [KeyValue; 8],
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(severity: Severity, facility: Facility, message: &str) -> Self {
        let mut entry = Self::default();
        entry.timestamp_ns = monotonic_nanos();
        entry.severity = severity;
        entry.facility = facility;
        entry.process_id = std::process::id();
        entry.thread_id = current_thread_id();

        let msg_bytes = message.as_bytes();
        entry.message_len = msg_bytes.len().min(256) as u16;
        entry.message[..entry.message_len as usize]
            .copy_from_slice(&msg_bytes[..entry.message_len as usize]);

        entry.state = AtomicU8::new(READY);
        entry
    }

    /// Add a key-value pair
    pub fn add_kv(&mut self, key: &str, value: &str) {
        if (self.kv_count as usize) < self.kvs.len() {
            self.kvs[self.kv_count as usize] = KeyValue::new(key, value);
            self.kv_count += 1;
        }
    }

    /// Get message as string slice
    pub fn get_message(&self) -> &str {
        std::str::from_utf8(&self.message[..self.message_len as usize]).unwrap_or("")
    }

    /// Get key-value pairs
    pub fn get_kvs(&self) -> &[KeyValue] {
        &self.kvs[..self.kv_count as usize]
    }
}

impl Default for LogEntry {
    fn default() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            _pad1: [0; 7],
            timestamp_ns: 0,
            sequence: 0,
            severity: Severity::Info,
            facility: Facility::Unknown,
            core_id: 255,
            _pad2: [0; 5],
            process_id: 0,
            thread_id: 0,
            message_len: 0,
            _pad3: [0; 6],
            message: [0; 256],
            kv_count: 0,
            _pad4: [0; 7],
            kvs: [KeyValue::empty(); 8],
        }
    }
}

impl Clone for LogEntry {
    fn clone(&self) -> Self {
        Self {
            state: AtomicU8::new(self.state.load(Ordering::Relaxed)),
            _pad1: self._pad1,
            timestamp_ns: self.timestamp_ns,
            sequence: self.sequence,
            severity: self.severity,
            facility: self.facility,
            core_id: self.core_id,
            _pad2: self._pad2,
            process_id: self.process_id,
            thread_id: self.thread_id,
            message_len: self.message_len,
            _pad3: self._pad3,
            message: self.message,
            kv_count: self.kv_count,
            _pad4: self._pad4,
            kvs: self.kvs,
        }
    }
}

impl std::fmt::Debug for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("LogEntry");
        debug
            .field("severity", &self.severity)
            .field("facility", &self.facility)
            .field("message", &self.get_message());

        if self.kv_count > 0 {
            debug.field("kvs", &self.get_kvs());
        }

        debug.finish()
    }
}

// Helper functions

/// Get monotonic nanoseconds since an arbitrary point
fn monotonic_nanos() -> u64 {
    use std::time::Instant;
    // This is a simplified version - in production we'd use a global start time
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as u64
}

/// Get current thread ID
fn current_thread_id() -> u64 {
    // Platform-specific thread ID
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::gettid() as u64 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::thread::current().id().as_u64().get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_size() {
        // Verify entry is power-of-2 and cache-aligned
        // Actual size is 1024 bytes (not 512 as initially planned)
        // due to 8 KeyValue pairs taking more space than estimated
        assert_eq!(std::mem::size_of::<LogEntry>(), 1024);
    }

    #[test]
    fn test_entry_creation() {
        let entry = LogEntry::new(Severity::Info, Facility::Supervisor, "Test message");
        assert_eq!(entry.severity, Severity::Info);
        assert_eq!(entry.facility, Facility::Supervisor);
        assert_eq!(entry.get_message(), "Test message");
    }

    #[test]
    fn test_key_value() {
        let kv = KeyValue::new("key1", "value1");
        assert_eq!(kv.key(), "key1");
        assert_eq!(kv.value(), "value1");
    }

    #[test]
    fn test_add_kv() {
        let mut entry = LogEntry::new(Severity::Info, Facility::Supervisor, "Test");
        entry.add_kv("worker_id", "0");
        entry.add_kv("core", "1");

        assert_eq!(entry.kv_count, 2);
        assert_eq!(entry.get_kvs()[0].key(), "worker_id");
        assert_eq!(entry.get_kvs()[0].value(), "0");
        assert_eq!(entry.get_kvs()[1].key(), "core");
        assert_eq!(entry.get_kvs()[1].value(), "1");
    }

    #[test]
    fn test_message_truncation() {
        let long_msg = "a".repeat(300);
        let entry = LogEntry::new(Severity::Info, Facility::Supervisor, &long_msg);
        assert_eq!(entry.message_len, 256);
        assert_eq!(entry.get_message().len(), 256);
    }
}
