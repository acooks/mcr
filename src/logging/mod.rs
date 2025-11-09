// High-performance lockless logging system for MCR
//
// Design documentation:
// - design/LOGGING_DESIGN.md - Overall architecture
// - design/RINGBUFFER_IMPLEMENTATION.md - Ring buffer details
// - design/KERNEL_RINGBUFFER_ANALYSIS.md - Linux/FreeBSD analysis

mod consumer;
mod entry;
mod facility;
mod logger;
#[macro_use]
mod macros;
mod ringbuffer;
mod severity;

// Public exports
pub use consumer::{AsyncConsumer, BlockingConsumer, LogSink, StderrSink, StdoutSink};
pub use entry::{KeyValue, LogEntry};
pub use facility::Facility;
pub use logger::{LogRegistry, Logger};
pub use ringbuffer::{MPSCRingBuffer, SPSCRingBuffer};
pub use severity::Severity;
