// Logger and LogRegistry for managing ring buffers

use super::entry::LogEntry;
use super::ringbuffer::{MPSCRingBuffer, SPSCRingBuffer};
use super::{Facility, Severity};
use std::sync::Arc;

/// Logger handle for writing log entries
///
/// This is a lightweight handle that can be cloned and passed around.
/// The actual ring buffer is shared via Arc.
pub struct Logger {
    ringbuffer: Arc<dyn RingBuffer>,
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
    pub fn from_spsc(ringbuffer: Arc<SPSCRingBuffer>) -> Self {
        Self {
            ringbuffer: ringbuffer as Arc<dyn RingBuffer>,
        }
    }

    /// Create a new logger from an MPSC ring buffer
    pub fn from_mpsc(ringbuffer: Arc<MPSCRingBuffer>) -> Self {
        Self {
            ringbuffer: ringbuffer as Arc<dyn RingBuffer>,
        }
    }

    /// Write a log entry
    #[inline]
    pub fn log(&self, severity: Severity, facility: Facility, message: &str) {
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
        }
    }
}

/// Registry for creating and managing loggers
///
/// The registry creates ring buffers with appropriate sizes for each facility
/// and provides Logger handles to write to them.
pub struct LogRegistry {
    loggers: std::collections::HashMap<Facility, Logger>,
}

impl LogRegistry {
    /// Create a new LogRegistry with MPSC ring buffers for all facilities
    ///
    /// Use this for supervisor and control plane (async, multiple writers)
    pub fn new_mpsc() -> Self {
        let mut loggers = std::collections::HashMap::new();

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
            let logger = Logger::from_mpsc(ringbuffer);
            loggers.insert(facility, logger);
        }

        Self { loggers }
    }

    /// Create a new LogRegistry with SPSC ring buffers for data plane
    ///
    /// Use this for data plane workers (single thread, single writer)
    pub fn new_spsc(core_id: u8) -> Self {
        let mut loggers = std::collections::HashMap::new();

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
            let logger = Logger::from_spsc(ringbuffer);
            loggers.insert(facility, logger);
        }

        Self { loggers }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_basic() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let logger = Logger::from_mpsc(ringbuffer);

        logger.info(Facility::Test, "Test message");
        logger.error(Facility::Test, "Error message");
    }

    #[test]
    fn test_logger_with_kvs() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let logger = Logger::from_mpsc(ringbuffer);

        logger.log_kv(
            Severity::Info,
            Facility::Test,
            "Test with context",
            &[("worker", "0"), ("core", "1")],
        );
    }

    #[test]
    fn test_logger_clone() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let logger1 = Logger::from_mpsc(ringbuffer);
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
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let logger = Logger::from_mpsc(ringbuffer);

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
