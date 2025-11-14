// High-performance logging system for MCR
//
// Uses pipe-based JSON logging for data plane workers,
// and MPSC ring buffers for control plane components.

mod consumer;
mod entry;
mod facility;
mod logger;
#[macro_use]
mod macros;
mod ringbuffer;
mod severity;

// Public exports
pub use consumer::{
    AsyncConsumer, BlockingConsumer, LogSink, SharedBlockingConsumer, StderrSink, StdoutSink,
};
pub use entry::{KeyValue, LogEntry};
pub use facility::Facility;
pub use logger::{LogRegistry, Logger};
pub use ringbuffer::{MPSCRingBuffer, SPSCRingBuffer};
pub use severity::Severity;

// Re-export ControlPlaneLogging for backward compatibility
// This is a simple wrapper around Logger with MPSC ring buffers
pub struct ControlPlaneLogging {
    registry: LogRegistry,
}

impl ControlPlaneLogging {
    pub fn new() -> Self {
        Self {
            registry: LogRegistry::new_mpsc(),
        }
    }

    pub fn logger(&self, facility: Facility) -> Option<Logger> {
        self.registry.get_logger(facility)
    }

    pub fn registry(&self) -> &LogRegistry {
        &self.registry
    }

    /// Shutdown logging system
    /// For MPSC ring buffers, this is a no-op since they're automatically cleaned up
    pub async fn shutdown(&self) {
        // MPSC ring buffers are automatically dropped when consumers exit
        // No explicit cleanup needed
    }
}

impl Default for ControlPlaneLogging {
    fn default() -> Self {
        Self::new()
    }
}
