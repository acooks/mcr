// High-performance lockless logging system for MCR
//
// Documentation:
// - docs/LOGGING.md - User guide and quick start (START HERE)
// - design/LOGGING_DESIGN.md - Technical design details
// - design/RINGBUFFER_IMPLEMENTATION.md - Ring buffer implementation
// - design/KERNEL_RINGBUFFER_ANALYSIS.md - Linux/FreeBSD analysis

mod consumer;
mod entry;
mod facility;
pub mod integration;
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
pub use integration::{
    ControlPlaneLogging, DataPlaneLogging, SharedMemoryLogManager, SupervisorLogging,
};
pub use logger::{LogRegistry, Logger};
pub use ringbuffer::{shm_id_for_facility, MPSCRingBuffer, SPSCRingBuffer, SharedSPSCRingBuffer};
pub use severity::Severity;
