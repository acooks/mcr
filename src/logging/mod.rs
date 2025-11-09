// High-performance lockless logging system for MCR
//
// Design documentation:
// - design/LOGGING_DESIGN.md - Overall architecture
// - design/RINGBUFFER_IMPLEMENTATION.md - Ring buffer details
// - design/KERNEL_RINGBUFFER_ANALYSIS.md - Linux/FreeBSD analysis

mod entry;
mod facility;
mod ringbuffer;
mod severity;

// Public exports
pub use entry::{KeyValue, LogEntry};
pub use facility::Facility;
pub use ringbuffer::{MPSCRingBuffer, SPSCRingBuffer};
pub use severity::Severity;

// TODO: Add in future phases
// mod logger;      - Logger and LogRegistry
// mod macros;      - Logging macros
// mod consumer;    - Consumer task and output sinks
