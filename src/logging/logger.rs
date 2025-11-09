// Logger and LogRegistry for managing ring buffers

use super::entry::LogEntry;
use super::ringbuffer::{MPSCRingBuffer, SPSCRingBuffer};
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

/// Trait to abstract over SPSC and MPSC ring buffers
pub trait RingBuffer: Send + Sync {
    fn write(&self, entry: LogEntry);
}

impl RingBuffer for SPSCRingBuffer {
    fn write(&self, entry: LogEntry) {
        SPSCRingBuffer::write(self, entry);
    }
}

impl RingBuffer for MPSCRingBuffer {
    fn write(&self, entry: LogEntry) {
        MPSCRingBuffer::write(self, entry);
    }
}

impl Logger {
    /// Create a new logger from an SPSC ring buffer
    pub fn from_spsc(
        ringbuffer: Arc<SPSCRingBuffer>,
        global_min_level: Arc<AtomicU8>,
        facility_min_levels: Arc<RwLock<std::collections::HashMap<Facility, Severity>>>,
    ) -> Self {
        Self {
            ringbuffer: ringbuffer as Arc<dyn RingBuffer>,
            global_min_level,
            facility_min_levels,
        }
    }

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

    /// Check if a log message should be written based on severity filtering
    #[inline]
    fn should_log(&self, severity: Severity, facility: Facility) -> bool {
        // Fast path: Check global minimum level first (atomic load ~5ns)
        let global_min = self.global_min_level.load(Ordering::Relaxed);
        if (severity as u8) > global_min {
            return false; // Severity is lower priority than global minimum
        }

        // Slow path: Check facility-specific level (RwLock read + hash ~20-50ns)
        let levels = self.facility_min_levels.read().unwrap();
        if let Some(&min_level) = levels.get(&facility) {
            if severity > min_level {
                return false; // Severity is lower priority than facility minimum
            }
        }

        true
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
}

impl LogRegistry {
    /// Create a new LogRegistry with MPSC ring buffers for all facilities
    ///
    /// Use this for supervisor and control plane (async, multiple writers)
    pub fn new_mpsc() -> Self {
        let mut loggers = std::collections::HashMap::new();

        // Initialize shared filtering state (default: Info level = 6)
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Create MPSC ring buffers for each facility
        for facility in [
            Facility::Supervisor,
            Facility::RuleDispatch,
            Facility::ControlSocket,
            Facility::ControlPlane,
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
                ringbuffer,
                Arc::clone(&global_min_level),
                Arc::clone(&facility_min_levels),
            );
            loggers.insert(facility, logger);
        }

        Self {
            loggers,
            global_min_level,
            facility_min_levels,
        }
    }

    /// Create a new LogRegistry with SPSC ring buffers for data plane
    ///
    /// Use this for data plane workers (single thread, single writer)
    pub fn new_spsc(core_id: u8) -> Self {
        let mut loggers = std::collections::HashMap::new();

        // Initialize shared filtering state (default: Info level = 6)
        let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
        let facility_min_levels = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Create SPSC ring buffers for data plane facilities
        for facility in [
            Facility::DataPlane,
            Facility::Ingress,
            Facility::Egress,
            Facility::BufferPool,
            Facility::PacketParser,
            Facility::Stats,
            Facility::Network,
            Facility::Test,
        ] {
            let capacity = facility.buffer_size();
            let ringbuffer = Arc::new(SPSCRingBuffer::new(capacity, core_id));
            let logger = Logger::from_spsc(
                ringbuffer,
                Arc::clone(&global_min_level),
                Arc::clone(&facility_min_levels),
            );
            loggers.insert(facility, logger);
        }

        Self {
            loggers,
            global_min_level,
            facility_min_levels,
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
    fn test_log_registry_spsc() {
        let registry = LogRegistry::new_spsc(0);

        let logger = registry.get(Facility::DataPlane).unwrap();
        logger.info(Facility::DataPlane, "Data plane message");
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
    }
}
