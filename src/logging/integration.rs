//! Logging Integration Module
//!
//! This module provides helpers for integrating the logging system into
//! the supervisor and worker processes.

use crate::logging::{
    AsyncConsumer, Facility, LogRegistry, Logger, SPSCRingBuffer, StdoutSink,
};
use std::sync::{atomic::AtomicBool, Arc};

/// Logging system for the supervisor process
///
/// The supervisor uses MPSC ring buffers since multiple async tasks
/// may log concurrently (tokio runtime).
pub struct SupervisorLogging {
    registry: LogRegistry,
    consumer_handle: Option<tokio::task::JoinHandle<()>>,
    consumer_stop: Arc<AtomicBool>,
}

impl SupervisorLogging {
    /// Create a new supervisor logging system
    ///
    /// This creates MPSC ring buffers for all facilities and starts
    /// an async consumer task that outputs logs to stdout.
    pub fn new() -> Self {
        let registry = LogRegistry::new_mpsc();

        // Get MPSC ring buffers for the consumer
        let ringbuffers = registry.export_mpsc_ringbuffers();

        // Start async consumer task
        let consumer = AsyncConsumer::new(ringbuffers, Box::new(StdoutSink::new()));
        let consumer_stop = consumer.stop_handle();
        let consumer_handle = Some(tokio::spawn(async move {
            consumer.run().await;
        }));

        Self {
            registry,
            consumer_handle,
            consumer_stop,
        }
    }

    /// Get a logger for a specific facility
    pub fn logger(&self, facility: Facility) -> Option<Logger> {
        self.registry.get_logger(facility)
    }

    /// Get the log registry (for exporting ring buffers to workers)
    pub fn registry(&self) -> &LogRegistry {
        &self.registry
    }

    /// Shutdown the logging system
    pub async fn shutdown(mut self) {
        self.consumer_stop
            .store(false, std::sync::atomic::Ordering::Relaxed);

        if let Some(handle) = self.consumer_handle.take() {
            let _ = handle.await;
        }
    }
}

/// Logging system for data plane worker processes
///
/// Data plane workers use SPSC ring buffers for lock-free logging
/// (single producer = worker thread, single consumer = supervisor).
pub struct DataPlaneLogging {
    registry: LogRegistry,
    core_id: u8,
}

impl DataPlaneLogging {
    /// Create a new data plane logging system
    ///
    /// This creates SPSC ring buffers optimized for single-threaded
    /// data plane workers.
    pub fn new(core_id: u8) -> Self {
        let registry = LogRegistry::new_spsc(core_id);

        Self { registry, core_id }
    }

    /// Get a logger for a specific facility
    pub fn logger(&self, facility: Facility) -> Option<Logger> {
        self.registry.get_logger(facility)
    }

    /// Export ring buffers for the supervisor to consume
    ///
    /// The supervisor will collect these ring buffers from all workers
    /// and read from them in its central consumer task.
    pub fn export_ringbuffers(&self) -> Vec<(Facility, Arc<SPSCRingBuffer>)> {
        self.registry.export_spsc_ringbuffers()
    }

    /// Get core ID
    pub fn core_id(&self) -> u8 {
        self.core_id
    }
}

/// Logging system for control plane worker processes
///
/// Control plane workers use MPSC ring buffers since they run in
/// async tokio contexts with multiple concurrent tasks.
pub struct ControlPlaneLogging {
    registry: LogRegistry,
    consumer_handle: Option<tokio::task::JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl ControlPlaneLogging {
    /// Create a new control plane logging system
    ///
    /// This creates MPSC ring buffers and starts an async consumer.
    pub fn new() -> Self {
        let registry = LogRegistry::new_mpsc();

        // Get ring buffers for the consumer
        let ringbuffers = registry.export_mpsc_ringbuffers();

        // Start async consumer task
        let consumer = AsyncConsumer::new(ringbuffers, Box::new(StdoutSink::new()));
        let running = consumer.stop_handle();
        let consumer_handle = Some(tokio::spawn(async move {
            consumer.run().await;
        }));

        Self {
            registry,
            consumer_handle,
            running,
        }
    }

    /// Get a logger for a specific facility
    pub fn logger(&self, facility: Facility) -> Option<Logger> {
        self.registry.get_logger(facility)
    }

    /// Shutdown the logging system
    pub async fn shutdown(mut self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);

        if let Some(handle) = self.consumer_handle.take() {
            let _ = handle.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_supervisor_logging() {
        let logging = SupervisorLogging::new();
        let logger = logging.logger(Facility::Supervisor).unwrap();

        // Log a message
        logger.info(Facility::Supervisor, "Test supervisor message");

        // Give consumer time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        logging.shutdown().await;
    }

    #[test]
    fn test_data_plane_logging() {
        let logging = DataPlaneLogging::new(0);
        let logger = logging.logger(Facility::DataPlane).unwrap();

        // Log a message
        logger.info(Facility::DataPlane, "Test data plane message");

        // Export ring buffers (supervisor would collect these)
        let ringbuffers = logging.export_ringbuffers();
        assert!(!ringbuffers.is_empty());
    }

    #[tokio::test]
    async fn test_control_plane_logging() {
        let logging = ControlPlaneLogging::new();
        let logger = logging.logger(Facility::ControlPlane).unwrap();

        // Log a message
        logger.info(Facility::ControlPlane, "Test control plane message");

        // Give consumer time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        logging.shutdown().await;
    }
}
