// SPDX-License-Identifier: Apache-2.0 OR MIT
// High-performance logging system for MCR
//
// Uses pipe-based JSON logging for data plane workers,
// and MPSC ring buffers for testing.

mod consumer;
mod entry;
mod facility;
mod logger;
#[macro_use]
mod macros;
mod ringbuffer;
mod severity;

// Public exports
pub use consumer::{AsyncConsumer, LogSink, StderrSink, StdoutSink};
pub use entry::{KeyValue, LogEntry};
pub use facility::Facility;
pub use logger::{LogRegistry, Logger};
pub use ringbuffer::MPSCRingBuffer;
pub use severity::Severity;

/// Test logging system using MPSC ring buffers
/// Used only in test builds for data plane worker logging
#[cfg(feature = "testing")]
pub struct TestLogging {
    registry: LogRegistry,
}

#[cfg(feature = "testing")]
impl TestLogging {
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

#[cfg(feature = "testing")]
impl Default for TestLogging {
    fn default() -> Self {
        Self::new()
    }
}
