// SPDX-License-Identifier: Apache-2.0 OR MIT
// Logger and LogRegistry for managing ring buffers

use super::entry::LogEntry;
use super::ringbuffer::MPSCRingBuffer;
use super::{Facility, Severity};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};

/// Logger handle for writing log entries
///
/// This is a lightweight handle that can be cloned and passed around.
/// The actual ring buffer is shared via Arc.
pub struct Logger {
    ringbuffer: Arc<dyn RingBuffer>,
    /// Global minimum log level (default: Info)
    global_min_level: Arc<AtomicU8>,
    /// Per-facility minimum log levels
    facility_min_levels: Arc<RwLock<std::collections::HashMap<Facility, Severity>>>,
}

/// Trait to abstract over different ring buffer types
pub trait RingBuffer: Send + Sync {
    fn write(&self, entry: LogEntry);
}

impl RingBuffer for MPSCRingBuffer {
    fn write(&self, entry: LogEntry) {
        MPSCRingBuffer::write(self, entry);
    }
}

/// Simple stderr JSON logger (no ring buffer, direct output)
pub struct StderrJsonLogger;

impl RingBuffer for StderrJsonLogger {
    fn write(&self, entry: LogEntry) {
        let log_msg = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "level": format!("{:?}", entry.severity),
            "facility": format!("{:?}", entry.facility),
            "message": entry.get_message(),
        });
        eprintln!("{}", log_msg);
        // No flush() - let stderr buffer naturally for better performance
    }
}

impl Logger {
    /// Create a new logger from an MPSC ring buffer
    pub fn from_mpsc(
        ringbuffer: Arc<MPSCRingBuffer>,
        global_min_level: Arc<AtomicU8>,
        facility_min_levels: Arc<RwLock<std::collections::HashMap<Facility, Severity>>>,
    ) -> Self {
        Self {
            ringbuffer: ringbuffer as Arc<dyn RingBuffer>,
            global_min_level,
            facility_min_levels,
        }
    }

    /// Create a logger that writes JSON directly to stderr
    ///
    /// This is used for pipe-based logging where the supervisor reads
    /// worker stderr through a pipe. All messages are written (no filtering).
    pub fn stderr_json() -> Self {
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));

        Self {
            ringbuffer: Arc::new(StderrJsonLogger) as Arc<dyn RingBuffer>,
            global_min_level,
            facility_min_levels,
        }
    }

    /// Check if a log message should be written based on severity filtering
    #[inline]
    fn should_log(&self, severity: Severity, facility: Facility) -> bool {
        // Check facility-specific level first (if set, it overrides global)
        let levels = self.facility_min_levels.read().unwrap();
        if let Some(&min_level) = levels.get(&facility) {
            // Facility-specific level is set - use it
            return severity <= min_level;
        }
        drop(levels); // Release lock before atomic load

        // No facility-specific level - use global minimum level
        let global_min = self.global_min_level.load(Ordering::Relaxed);
        (severity as u8) <= global_min
    }

    /// Write a log entry
    #[inline]
    pub fn log(&self, severity: Severity, facility: Facility, message: &str) {
        // Check if this log should be written based on configured levels
        if !self.should_log(severity, facility) {
            return;
        }

        let entry = LogEntry::new(severity, facility, message);
        self.ringbuffer.write(entry);
    }

    /// Write a log entry with key-value pairs
    #[inline]
    pub fn log_kv(
        &self,
        severity: Severity,
        facility: Facility,
        message: &str,
        kvs: &[(&str, &str)],
    ) {
        // Check if this log should be written based on configured levels
        if !self.should_log(severity, facility) {
            return;
        }

        let mut entry = LogEntry::new(severity, facility, message);
        for (key, value) in kvs.iter().take(2) {
            entry.add_kv(key, value);
        }
        self.ringbuffer.write(entry);
    }

    /// Log with emergency severity
    #[inline]
    pub fn emergency(&self, facility: Facility, message: &str) {
        self.log(Severity::Emergency, facility, message);
    }

    /// Log with alert severity
    #[inline]
    pub fn alert(&self, facility: Facility, message: &str) {
        self.log(Severity::Alert, facility, message);
    }

    /// Log with critical severity
    #[inline]
    pub fn critical(&self, facility: Facility, message: &str) {
        self.log(Severity::Critical, facility, message);
    }

    /// Log with error severity
    #[inline]
    pub fn error(&self, facility: Facility, message: &str) {
        self.log(Severity::Error, facility, message);
    }

    /// Log with warning severity
    #[inline]
    pub fn warning(&self, facility: Facility, message: &str) {
        self.log(Severity::Warning, facility, message);
    }

    /// Log with notice severity
    #[inline]
    pub fn notice(&self, facility: Facility, message: &str) {
        self.log(Severity::Notice, facility, message);
    }

    /// Log with info severity
    #[inline]
    pub fn info(&self, facility: Facility, message: &str) {
        self.log(Severity::Info, facility, message);
    }

    /// Log with debug severity
    #[inline]
    pub fn debug(&self, facility: Facility, message: &str) {
        self.log(Severity::Debug, facility, message);
    }

    /// Log with trace severity
    #[inline]
    pub fn trace(&self, facility: Facility, message: &str) {
        self.log(Severity::Trace, facility, message);
    }

    /// Set the global minimum log level
    pub fn set_global_level(&self, level: Severity) {
        self.global_min_level.store(level as u8, Ordering::Relaxed);
    }

    /// Set the minimum log level for a specific facility
    pub fn set_facility_level(&self, facility: Facility, level: Severity) {
        self.facility_min_levels
            .write()
            .unwrap()
            .insert(facility, level);
    }

    /// Clear the facility-specific log level (fall back to global)
    pub fn clear_facility_level(&self, facility: Facility) {
        self.facility_min_levels.write().unwrap().remove(&facility);
    }
}

impl Clone for Logger {
    fn clone(&self) -> Self {
        Self {
            ringbuffer: Arc::clone(&self.ringbuffer),
            global_min_level: Arc::clone(&self.global_min_level),
            facility_min_levels: Arc::clone(&self.facility_min_levels),
        }
    }
}

/// Registry for creating and managing loggers
///
/// The registry creates ring buffers with appropriate sizes for each facility
/// and provides Logger handles to write to them.
pub struct LogRegistry {
    loggers: std::collections::HashMap<Facility, Logger>,
    /// Global minimum log level (default: Info = 6)
    global_min_level: Arc<AtomicU8>,
    /// Per-facility minimum log levels (overrides global)
    facility_min_levels: Arc<RwLock<std::collections::HashMap<Facility, Severity>>>,
    /// MPSC ring buffers (stored separately for export)
    mpsc_ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>,
}

impl LogRegistry {
    /// Create a new LogRegistry with MPSC ring buffers for all facilities
    ///
    /// Use this for supervisor and control plane (async, multiple writers)
    pub fn new_mpsc() -> Self {
        let mut loggers = std::collections::HashMap::new();
        let mut mpsc_ringbuffers = Vec::new();

        // Initialize shared filtering state (default: Info level = 6)
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Create MPSC ring buffers for each facility
        for facility in [
            Facility::Supervisor,
            Facility::RuleDispatch,
            Facility::ControlSocket,
            Facility::DataPlane,
            Facility::Ingress,
            Facility::Egress,
            Facility::BufferPool,
            Facility::PacketParser,
            Facility::Stats,
            Facility::Security,
            Facility::Network,
            Facility::Test,
        ] {
            let capacity = facility.buffer_size();
            let ringbuffer = Arc::new(MPSCRingBuffer::new(capacity));
            let logger = Logger::from_mpsc(
                Arc::clone(&ringbuffer),
                Arc::clone(&global_min_level),
                Arc::clone(&facility_min_levels),
            );
            loggers.insert(facility, logger);
            mpsc_ringbuffers.push((facility, ringbuffer));
        }

        Self {
            loggers,
            global_min_level,
            facility_min_levels,
            mpsc_ringbuffers,
        }
    }

    /// Get a logger for a specific facility
    pub fn get(&self, facility: Facility) -> Option<&Logger> {
        self.loggers.get(&facility)
    }

    /// Get a cloned logger for a specific facility
    pub fn get_logger(&self, facility: Facility) -> Option<Logger> {
        self.loggers.get(&facility).cloned()
    }

    /// Get all ring buffers for consumer task
    ///
    /// Returns facility -> ringbuffer mapping for consumption
    pub fn get_ringbuffers(&self) -> Vec<(Facility, Arc<dyn RingBuffer>)> {
        self.loggers
            .iter()
            .map(|(facility, logger)| (*facility, Arc::clone(&logger.ringbuffer)))
            .collect()
    }

    /// Set the global minimum log level
    ///
    /// This affects all facilities unless overridden by facility-specific levels.
    pub fn set_global_level(&self, level: Severity) {
        self.global_min_level.store(level as u8, Ordering::Relaxed);
    }

    /// Get the global minimum log level
    pub fn get_global_level(&self) -> Severity {
        let level = self.global_min_level.load(Ordering::Relaxed);
        Severity::from_u8(level).unwrap_or(Severity::Info)
    }

    /// Set the minimum log level for a specific facility
    ///
    /// This overrides the global level for this facility.
    pub fn set_facility_level(&self, facility: Facility, level: Severity) {
        let mut levels = self.facility_min_levels.write().unwrap();
        levels.insert(facility, level);
    }

    /// Clear the facility-specific log level (fall back to global)
    pub fn clear_facility_level(&self, facility: Facility) {
        let mut levels = self.facility_min_levels.write().unwrap();
        levels.remove(&facility);
    }

    /// Get the minimum log level for a specific facility
    ///
    /// Returns the facility-specific level if set, otherwise the global level.
    pub fn get_facility_level(&self, facility: Facility) -> Severity {
        let levels = self.facility_min_levels.read().unwrap();
        levels
            .get(&facility)
            .copied()
            .unwrap_or_else(|| self.get_global_level())
    }

    /// Get all facility-specific log level overrides
    pub fn get_all_facility_levels(&self) -> std::collections::HashMap<Facility, Severity> {
        let levels = self.facility_min_levels.read().unwrap();
        levels.clone()
    }

    /// Export MPSC ring buffers for AsyncConsumer
    ///
    /// This is used by supervisor and control plane workers to get
    /// ring buffers in the concrete MPSC type required by AsyncConsumer.
    ///
    /// # Returns
    /// Vector of (Facility, Arc<MPSCRingBuffer>) pairs for consumption.
    pub fn export_mpsc_ringbuffers(&self) -> Vec<(Facility, Arc<MPSCRingBuffer>)> {
        self.mpsc_ringbuffers
            .iter()
            .map(|(facility, rb)| (*facility, Arc::clone(rb)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_logger_simple() -> Logger {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));
        Logger::from_mpsc(ringbuffer, global_min_level, facility_min_levels)
    }

    #[test]
    fn test_logger_basic() {
        let logger = create_test_logger_simple();
        logger.info(Facility::Test, "Test message");
        logger.error(Facility::Test, "Error message");
    }

    #[test]
    fn test_logger_with_kvs() {
        let logger = create_test_logger_simple();
        logger.log_kv(
            Severity::Info,
            Facility::Test,
            "Test with context",
            &[("worker", "0"), ("core", "1")],
        );
    }

    #[test]
    fn test_logger_clone() {
        let logger1 = create_test_logger_simple();
        let logger2 = logger1.clone();

        logger1.info(Facility::Test, "From logger1");
        logger2.info(Facility::Test, "From logger2");
    }

    #[test]
    fn test_log_registry_mpsc() {
        let registry = LogRegistry::new_mpsc();

        let logger = registry.get(Facility::Supervisor).unwrap();
        logger.info(Facility::Supervisor, "Supervisor message");

        let logger = registry.get(Facility::Ingress).unwrap();
        logger.debug(Facility::Ingress, "Ingress debug");
    }

    #[test]
    fn test_severity_helpers() {
        let logger = create_test_logger_simple();

        logger.emergency(Facility::Test, "Emergency");
        logger.alert(Facility::Test, "Alert");
        logger.critical(Facility::Test, "Critical");
        logger.error(Facility::Test, "Error");
        logger.warning(Facility::Test, "Warning");
        logger.notice(Facility::Test, "Notice");
        logger.info(Facility::Test, "Info");
        logger.debug(Facility::Test, "Debug");
        logger.trace(Facility::Test, "Trace");
    }

    #[test]
    fn test_global_log_level_filtering() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Warning as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let logger = Logger::from_mpsc(
            Arc::clone(&ringbuffer),
            global_min_level,
            facility_min_levels,
        );

        // These should be written (Warning and above)
        logger.emergency(Facility::Test, "Emergency");
        logger.alert(Facility::Test, "Alert");
        logger.critical(Facility::Test, "Critical");
        logger.error(Facility::Test, "Error");
        logger.warning(Facility::Test, "Warning");

        // These should be filtered out (below Warning)
        logger.notice(Facility::Test, "Notice");
        logger.info(Facility::Test, "Info");
        logger.debug(Facility::Test, "Debug");

        // Read all entries from the ring buffer
        let mut count = 0;
        while ringbuffer.read().is_some() {
            count += 1;
        }

        // Should have exactly 5 entries (Emergency through Warning)
        assert_eq!(count, 5, "Expected 5 log entries to pass the filter");
    }

    #[test]
    fn test_facility_specific_log_level() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Warning as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Set facility-specific level for Test facility to Debug
        {
            let mut levels = facility_min_levels.write().unwrap();
            levels.insert(Facility::Test, Severity::Debug);
        }

        let logger = Logger::from_mpsc(
            Arc::clone(&ringbuffer),
            global_min_level,
            facility_min_levels,
        );

        // All of these should be written because Test facility allows Debug and above
        logger.emergency(Facility::Test, "Emergency");
        logger.alert(Facility::Test, "Alert");
        logger.critical(Facility::Test, "Critical");
        logger.error(Facility::Test, "Error");
        logger.warning(Facility::Test, "Warning");
        logger.notice(Facility::Test, "Notice");
        logger.info(Facility::Test, "Info");
        logger.debug(Facility::Test, "Debug");

        // Count entries
        let mut count = 0;
        while ringbuffer.read().is_some() {
            count += 1;
        }

        // Should have all 8 entries
        assert_eq!(
            count, 8,
            "Expected all 8 log entries to pass with facility-specific Debug level"
        );
    }

    #[test]
    fn test_facility_level_overrides_global() {
        let ringbuffer_test = Arc::new(MPSCRingBuffer::new(16));
        let ringbuffer_supervisor = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Error as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Set Test facility to Info (more permissive than global Error)
        {
            let mut levels = facility_min_levels.write().unwrap();
            levels.insert(Facility::Test, Severity::Info);
        }

        let logger_test = Logger::from_mpsc(
            Arc::clone(&ringbuffer_test),
            Arc::clone(&global_min_level),
            Arc::clone(&facility_min_levels),
        );
        let logger_supervisor = Logger::from_mpsc(
            Arc::clone(&ringbuffer_supervisor),
            Arc::clone(&global_min_level),
            Arc::clone(&facility_min_levels),
        );

        // Test facility should allow Info
        logger_test.info(Facility::Test, "Info from Test");
        logger_test.warning(Facility::Test, "Warning from Test");
        logger_test.error(Facility::Test, "Error from Test");

        // Supervisor facility should use global level (Error)
        logger_supervisor.info(Facility::Supervisor, "Info from Supervisor");
        logger_supervisor.warning(Facility::Supervisor, "Warning from Supervisor");
        logger_supervisor.error(Facility::Supervisor, "Error from Supervisor");

        // Count Test facility entries (should have all 3)
        let mut test_count = 0;
        while ringbuffer_test.read().is_some() {
            test_count += 1;
        }
        assert_eq!(
            test_count, 3,
            "Test facility should have 3 entries with Info level"
        );

        // Count Supervisor facility entries (should have only 1 - Error)
        let mut supervisor_count = 0;
        while ringbuffer_supervisor.read().is_some() {
            supervisor_count += 1;
        }
        assert_eq!(
            supervisor_count, 1,
            "Supervisor facility should have 1 entry with global Error level"
        );
    }

    #[test]
    fn test_set_and_get_log_levels() {
        let registry = LogRegistry::new_mpsc();

        // Default global level should be Info
        assert_eq!(registry.get_global_level(), Severity::Info);

        // Set global level to Warning
        registry.set_global_level(Severity::Warning);
        assert_eq!(registry.get_global_level(), Severity::Warning);

        // Set facility-specific level
        registry.set_facility_level(Facility::Ingress, Severity::Debug);
        assert_eq!(
            registry.get_facility_level(Facility::Ingress),
            Severity::Debug
        );

        // Facility without override should return global level
        assert_eq!(
            registry.get_facility_level(Facility::Egress),
            Severity::Warning
        );

        // Clear facility level
        registry.clear_facility_level(Facility::Ingress);
        assert_eq!(
            registry.get_facility_level(Facility::Ingress),
            Severity::Warning
        );

        // Get all facility levels
        registry.set_facility_level(Facility::Ingress, Severity::Error);
        registry.set_facility_level(Facility::Egress, Severity::Critical);
        let all_levels = registry.get_all_facility_levels();
        assert_eq!(all_levels.len(), 2);
        assert_eq!(all_levels.get(&Facility::Ingress), Some(&Severity::Error));
        assert_eq!(all_levels.get(&Facility::Egress), Some(&Severity::Critical));
    }

    #[test]
    fn test_log_level_filtering_edge_cases() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let logger = Logger::from_mpsc(
            Arc::clone(&ringbuffer),
            global_min_level,
            facility_min_levels,
        );

        // Log exactly at the threshold (should be included)
        logger.info(Facility::Test, "Info at threshold");

        // Log just above threshold (should be included)
        logger.notice(Facility::Test, "Notice above threshold");

        // Log just below threshold (should be filtered)
        logger.debug(Facility::Test, "Debug below threshold");

        let mut count = 0;
        while ringbuffer.read().is_some() {
            count += 1;
        }

        // Should have 2 entries (Info and Notice, but not Debug)
        assert_eq!(count, 2, "Expected 2 log entries at and above Info level");
    }

    #[test]
    fn test_logger_set_global_level() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let logger = Logger::from_mpsc(
            Arc::clone(&ringbuffer),
            global_min_level,
            facility_min_levels,
        );

        // Initially Info level - debug should be filtered
        logger.debug(Facility::Test, "Debug before level change");

        // Change to Debug level
        logger.set_global_level(Severity::Debug);

        // Now debug should pass
        logger.debug(Facility::Test, "Debug after level change");

        let mut count = 0;
        while ringbuffer.read().is_some() {
            count += 1;
        }

        // Should have 1 entry (only the one after level change)
        assert_eq!(count, 1, "Expected 1 log entry after level change");
    }

    #[test]
    fn test_logger_set_facility_level() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let global_min_level = Arc::new(AtomicU8::new(Severity::Warning as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let logger = Logger::from_mpsc(
            Arc::clone(&ringbuffer),
            global_min_level,
            facility_min_levels,
        );

        // Global is Warning - Info should be filtered
        logger.info(Facility::Test, "Info before facility override");

        // Set Test facility to Debug
        logger.set_facility_level(Facility::Test, Severity::Debug);

        // Now Info should pass for Test facility
        logger.info(Facility::Test, "Info after facility override");

        // Clear facility level
        logger.clear_facility_level(Facility::Test);

        // Info should be filtered again
        logger.info(Facility::Test, "Info after clearing override");

        let mut count = 0;
        while ringbuffer.read().is_some() {
            count += 1;
        }

        // Should have 1 entry (only the one with facility override active)
        assert_eq!(
            count, 1,
            "Expected 1 log entry when facility override was active"
        );
    }
}
