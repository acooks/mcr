//! Logging Integration Module
//!
//! This module provides helpers for integrating the logging system into
//! the supervisor and worker processes.

use crate::logging::{
    shm_id_for_facility, AsyncConsumer, Facility, LogRegistry, Logger, SharedBlockingConsumer,
    SharedSPSCRingBuffer, StdoutSink,
};
use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, Arc};
use std::thread;

/// Logging system for the supervisor process
///
/// The supervisor uses MPSC ring buffers since multiple async tasks
/// may log concurrently (tokio runtime).
pub struct SupervisorLogging {
    registry: LogRegistry,
    consumer_handle: Option<tokio::task::JoinHandle<()>>,
    consumer_stop: Arc<AtomicBool>,
}

impl Default for SupervisorLogging {
    fn default() -> Self {
        Self::new()
    }
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

/// Manager for shared memory ring buffers used by data plane workers
///
/// The supervisor creates shared memory regions that workers attach to.
/// This allows lock-free cross-process logging.
pub struct SharedMemoryLogManager {
    /// Shared memory ring buffers created by supervisor (owned, will be cleaned up on drop)
    shared_buffers: HashMap<String, Arc<SharedSPSCRingBuffer>>,
    /// Consumer thread that reads from all shared buffers
    consumer_handle: Option<thread::JoinHandle<()>>,
    consumer_stop: Arc<AtomicBool>,
}

impl SharedMemoryLogManager {
    /// Create shared memory ring buffers for a data plane worker
    ///
    /// Creates SharedSPSCRingBuffer for each data plane facility.
    /// The worker will attach to these using the same shm_id.
    ///
    /// # Arguments
    /// * `supervisor_pid` - PID of the supervisor process (to create unique paths)
    /// * `core_id` - CPU core ID for this worker
    /// * `capacity` - Ring buffer capacity (must be power of 2)
    pub fn create_for_worker(supervisor_pid: u32, core_id: u8, capacity: usize) -> Result<Self, nix::Error> {
        let mut shared_buffers = HashMap::new();

        // Create shared memory ring buffers for data plane facilities
        let facilities = [
            Facility::DataPlane,
            Facility::Ingress,
            Facility::Egress,
            Facility::BufferPool,
        ];

        for facility in &facilities {
            let shm_id = shm_id_for_facility(supervisor_pid, core_id, *facility);
            let buffer = SharedSPSCRingBuffer::create(&shm_id, capacity, core_id)?;
            shared_buffers.insert(shm_id, Arc::new(buffer));
        }

        // Start consumer thread
        let buffers_for_consumer = shared_buffers.values().cloned().collect::<Vec<_>>();
        let consumer_stop = Arc::new(AtomicBool::new(true));
        let consumer_stop_clone = consumer_stop.clone();

        let consumer_handle = Some(thread::spawn(move || {
            use std::io::Write;
            eprintln!("[LogConsumer] Consumer thread started for data plane worker");
            std::io::stderr().flush().ok();

            let sink = Box::new(StdoutSink::new());
            let mut consumer = SharedBlockingConsumer::new(buffers_for_consumer, sink);

            let mut iterations = 0;
            while consumer_stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                consumer.process_once();
                thread::sleep(std::time::Duration::from_millis(10));

                iterations += 1;
                if iterations % 100 == 0 {
                    eprintln!("[LogConsumer] Still running... (iteration {})", iterations);
                    std::io::stderr().flush().ok();
                }
            }

            eprintln!("[LogConsumer] Consumer thread exiting");
            std::io::stderr().flush().ok();
        }));

        Ok(Self {
            shared_buffers,
            consumer_handle,
            consumer_stop,
        })
    }

    /// Get core ID from the first buffer
    pub fn core_id(&self) -> Option<u8> {
        self.shared_buffers.values().next().map(|b| b.core_id())
    }

    /// Shutdown the consumer and clean up shared memory
    pub fn shutdown(mut self) {
        self.consumer_stop
            .store(false, std::sync::atomic::Ordering::Relaxed);

        if let Some(handle) = self.consumer_handle.take() {
            let _ = handle.join();
        }

        // Shared buffers will be automatically cleaned up on drop
    }

    /// Clean up stale shared memory from previous instances
    ///
    /// This should be called at supervisor startup to remove any shared memory
    /// left behind by crashed or killed previous instances.
    ///
    /// # Arguments
    /// * `supervisor_pid` - PID of the supervisor process
    /// * `max_workers` - Maximum number of workers to clean up (defaults to 16)
    pub fn cleanup_stale_shared_memory(supervisor_pid: u32, max_workers: Option<u8>) {
        use nix::sys::mman::shm_unlink;

        let max_workers = max_workers.unwrap_or(16);
        let facilities = [
            Facility::DataPlane,
            Facility::Ingress,
            Facility::Egress,
            Facility::BufferPool,
        ];

        for core_id in 0..max_workers {
            for facility in &facilities {
                let shm_id = shm_id_for_facility(supervisor_pid, core_id, *facility);
                // Ignore errors - the shared memory may not exist
                let _ = shm_unlink(shm_id.as_str());
            }
        }
    }
}

/// Logging system for data plane worker processes
///
/// Data plane workers attach to shared memory ring buffers created by the supervisor
/// for lock-free cross-process logging.
pub struct DataPlaneLogging {
    shared_buffers: HashMap<Facility, Arc<SharedSPSCRingBuffer>>,
    core_id: u8,
}

impl DataPlaneLogging {
    /// Attach to existing shared memory ring buffers
    ///
    /// The supervisor must have already created these shared memory regions
    /// before the worker process starts.
    ///
    /// # Arguments
    /// * `supervisor_pid` - PID of the supervisor process
    /// * `core_id` - CPU core ID for this worker
    pub fn attach(supervisor_pid: u32, core_id: u8) -> Result<Self, nix::Error> {
        let mut shared_buffers = HashMap::new();

        // Attach to shared memory ring buffers for data plane facilities
        let facilities = [
            Facility::DataPlane,
            Facility::Ingress,
            Facility::Egress,
            Facility::BufferPool,
        ];

        for facility in &facilities {
            let shm_id = shm_id_for_facility(supervisor_pid, core_id, *facility);
            let buffer = SharedSPSCRingBuffer::attach(&shm_id)?;
            shared_buffers.insert(*facility, Arc::new(buffer));
        }

        Ok(Self {
            shared_buffers,
            core_id,
        })
    }

    /// Get a logger for a specific facility
    ///
    /// Creates a Logger that writes directly to the shared memory ring buffer.
    pub fn logger(&self, facility: Facility) -> Option<Logger> {
        self.shared_buffers
            .get(&facility)
            .map(|buffer| Logger::from_shared(buffer.clone()))
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

impl Default for ControlPlaneLogging {
    fn default() -> Self {
        Self::new()
    }
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
        // Use test PID for shared memory paths
        let test_pid = std::process::id();

        // Clean up any leftover shared memory from previous test runs
        // Use the centralized cleanup method to ensure consistency
        SharedMemoryLogManager::cleanup_stale_shared_memory(test_pid, Some(1));

        // Create shared memory (supervisor side)
        let manager = SharedMemoryLogManager::create_for_worker(test_pid, 0, 1024).unwrap();

        // Attach to shared memory (worker side)
        let logging = DataPlaneLogging::attach(test_pid, 0).unwrap();
        let logger = logging.logger(Facility::DataPlane).unwrap();

        // Log a message
        logger.info(Facility::DataPlane, "Test data plane message");

        // Verify core ID
        assert_eq!(logging.core_id(), 0);

        // Cleanup
        manager.shutdown();
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
