// SPDX-License-Identifier: Apache-2.0 OR MIT
// Log entry structure with cache-line optimized layout

use super::{Facility, Severity};
use std::sync::atomic::{AtomicU8, Ordering};

/// Entry states for the state machine
pub(crate) const EMPTY: u8 = 0;
pub(crate) const WRITING: u8 = 1;
pub(crate) const READY: u8 = 2;

/// Key-value pair for structured logging (32 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyValue {
    key_len: u8,
    value_len: u8,
    _pad: [u8; 2],
    key: [u8; 8],    // Short keys: "worker", "core", "port"
    value: [u8; 20], // Values: "eth0", "10.0.0.1", "5555"
}

impl KeyValue {
    /// Create empty key-value pair
    pub const fn empty() -> Self {
        Self {
            key_len: 0,
            value_len: 0,
            _pad: [0; 2],
            key: [0; 8],
            value: [0; 20],
        }
    }

    /// Create new key-value pair
    pub fn new(key: &str, value: &str) -> Self {
        let mut kv = Self::empty();
        let key_bytes = key.as_bytes();
        let value_bytes = value.as_bytes();

        kv.key_len = key_bytes.len().min(8) as u8;
        kv.value_len = value_bytes.len().min(20) as u8;

        kv.key[..kv.key_len as usize].copy_from_slice(&key_bytes[..kv.key_len as usize]);
        kv.value[..kv.value_len as usize].copy_from_slice(&value_bytes[..kv.value_len as usize]);

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

/// Log entry - 256 bytes, cache-line optimized
///
/// Layout (4 cache lines of 64 bytes each):
/// - Cache Line 0: Hot fields (state, metadata, first 32 bytes of message)
/// - Cache Lines 1-2: Rest of message (128 bytes)
/// - Cache Line 3: Key-value pairs (64 bytes)
#[repr(C, align(64))]
pub struct LogEntry {
    // === Cache Line 0 (bytes 0-63): HOTTEST ===
    /// State for lock-free synchronization (checked on every read)
    pub(crate) state: AtomicU8,
    pub severity: Severity,
    pub facility: Facility,
    pub message_len: u8,
    pub kv_count: u8,
    pub core_id: u8,
    _pad1: [u8; 2],

    pub timestamp_ns: u64,
    pub sequence: u64,
    pub process_id: u32,
    pub thread_id: u32, // Truncated from full thread ID

    /// First 32 bytes of message (fills cache line 0)
    pub(crate) message_start: [u8; 32],

    // === Cache Lines 1-2 (bytes 64-191): HOT ===
    /// Continuation of message (128 bytes)
    pub(crate) message_cont: [u8; 128],

    // === Cache Line 3 (bytes 192-255): WARM ===
    /// Structured logging: up to 2 key-value pairs
    pub kvs: [KeyValue; 2],
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(severity: Severity, facility: Facility, message: &str) -> Self {
        let mut entry = Self {
            timestamp_ns: monotonic_nanos(),
            severity,
            facility,
            process_id: std::process::id(),
            thread_id: current_thread_id(),
            state: AtomicU8::new(READY),
            ..Default::default()
        };

        entry.set_message(message);
        entry
    }

    /// Set message, handling split across message_start and message_cont
    fn set_message(&mut self, message: &str) {
        let msg_bytes = message.as_bytes();
        let total_len = msg_bytes.len().min(160); // Max 160 bytes
        self.message_len = total_len as u8;

        if total_len <= 32 {
            // Short message: fits in cache line 0
            self.message_start[..total_len].copy_from_slice(&msg_bytes[..total_len]);
        } else {
            // Long message: spans cache lines
            self.message_start.copy_from_slice(&msg_bytes[..32]);
            let cont_len = total_len - 32;
            self.message_cont[..cont_len].copy_from_slice(&msg_bytes[32..total_len]);
        }
    }

    /// Get message as string slice
    pub fn get_message(&self) -> &str {
        let len = self.message_len as usize;
        if len <= 32 {
            // Short message: only in message_start
            std::str::from_utf8(&self.message_start[..len]).unwrap_or("")
        } else {
            // Need to reconstruct from both parts
            // This is safe because we know the layout
            unsafe {
                let ptr = &self.message_start as *const u8;
                let slice = std::slice::from_raw_parts(ptr, len);
                std::str::from_utf8(slice).unwrap_or("")
            }
        }
    }

    /// Add a key-value pair (max 2 pairs)
    pub fn add_kv(&mut self, key: &str, value: &str) {
        if (self.kv_count as usize) < self.kvs.len() {
            self.kvs[self.kv_count as usize] = KeyValue::new(key, value);
            self.kv_count += 1;
        }
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
            severity: Severity::Info,
            facility: Facility::Unknown,
            message_len: 0,
            kv_count: 0,
            core_id: 255,
            _pad1: [0; 2],
            timestamp_ns: 0,
            sequence: 0,
            process_id: 0,
            thread_id: 0,
            message_start: [0; 32],
            message_cont: [0; 128],
            kvs: [KeyValue::empty(); 2],
        }
    }
}

impl Clone for LogEntry {
    fn clone(&self) -> Self {
        Self {
            state: AtomicU8::new(self.state.load(Ordering::Relaxed)),
            severity: self.severity,
            facility: self.facility,
            message_len: self.message_len,
            kv_count: self.kv_count,
            core_id: self.core_id,
            _pad1: self._pad1,
            timestamp_ns: self.timestamp_ns,
            sequence: self.sequence,
            process_id: self.process_id,
            thread_id: self.thread_id,
            message_start: self.message_start,
            message_cont: self.message_cont,
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
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as u64
}

/// Get current thread ID (truncated to u32)
fn current_thread_id() -> u32 {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::gettid() as u32 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Fall back to truncating the Rust thread ID
        std::thread::current().id().as_u64().get() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_size() {
        // Verify entry is 256 bytes (4 cache lines)
        assert_eq!(std::mem::size_of::<LogEntry>(), 256);

        // Verify cache line alignment
        assert_eq!(std::mem::align_of::<LogEntry>(), 64);
    }

    #[test]
    fn test_keyvalue_size() {
        // Each KeyValue should be 32 bytes
        assert_eq!(std::mem::size_of::<KeyValue>(), 32);
    }

    #[test]
    fn test_entry_creation() {
        let entry = LogEntry::new(Severity::Info, Facility::Supervisor, "Test message");
        assert_eq!(entry.severity, Severity::Info);
        assert_eq!(entry.facility, Facility::Supervisor);
        assert_eq!(entry.get_message(), "Test message");
    }

    #[test]
    fn test_short_message() {
        // Short messages fit in cache line 0
        let entry = LogEntry::new(Severity::Info, Facility::Supervisor, "Short");
        assert_eq!(entry.get_message(), "Short");
        assert_eq!(entry.message_len, 5);
    }

    #[test]
    fn test_long_message() {
        // Long messages span cache lines
        let long_msg = "This is a longer message that will span across the message_start and message_cont fields to test the cache line split";
        let entry = LogEntry::new(Severity::Info, Facility::Supervisor, long_msg);
        assert_eq!(entry.get_message(), long_msg);
    }

    #[test]
    fn test_message_truncation() {
        let very_long = "a".repeat(200);
        let entry = LogEntry::new(Severity::Info, Facility::Supervisor, &very_long);
        assert_eq!(entry.message_len, 160); // Max length
        assert_eq!(entry.get_message().len(), 160);
    }

    #[test]
    fn test_key_value() {
        let kv = KeyValue::new("worker", "dp-0");
        assert_eq!(kv.key(), "worker");
        assert_eq!(kv.value(), "dp-0");
    }

    #[test]
    fn test_kv_truncation() {
        let kv = KeyValue::new("very_long_key", "very_long_value_that_exceeds_limit");
        assert_eq!(kv.key(), "very_lon"); // Truncated to 8 bytes
        assert_eq!(kv.value(), "very_long_value_that"); // Truncated to 20 bytes
    }

    #[test]
    fn test_add_kv() {
        let mut entry = LogEntry::new(Severity::Info, Facility::Supervisor, "Test");
        entry.add_kv("worker", "0");
        entry.add_kv("core", "1");

        assert_eq!(entry.kv_count, 2);
        assert_eq!(entry.get_kvs()[0].key(), "worker");
        assert_eq!(entry.get_kvs()[0].value(), "0");
        assert_eq!(entry.get_kvs()[1].key(), "core");
        assert_eq!(entry.get_kvs()[1].value(), "1");
    }

    #[test]
    fn test_max_kvs() {
        let mut entry = LogEntry::new(Severity::Info, Facility::Supervisor, "Test");
        entry.add_kv("k1", "v1");
        entry.add_kv("k2", "v2");
        entry.add_kv("k3", "v3"); // Should be ignored (max 2)

        assert_eq!(entry.kv_count, 2);
    }

    #[test]
    fn test_cache_line_layout() {
        // Verify hot fields are in first cache line
        let entry = LogEntry::default();
        let entry_ptr = &entry as *const LogEntry as usize;

        // State should be at offset 0 (first byte)
        let state_offset = &entry.state as *const _ as usize - entry_ptr;
        assert_eq!(state_offset, 0);

        // All metadata should be in first 64 bytes
        let timestamp_offset = &entry.timestamp_ns as *const _ as usize - entry_ptr;
        assert!(timestamp_offset < 64);
    }
}
