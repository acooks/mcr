// Log consumer task - drains ring buffers and outputs log entries

use super::entry::LogEntry;
use super::ringbuffer::{MPSCRingBuffer, SPSCRingBuffer, SharedSPSCRingBuffer};
use super::Facility;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Output sink for log entries
pub trait LogSink: Send {
    /// Write a log entry to the sink
    fn write_entry(&mut self, entry: &LogEntry);

    /// Flush any buffered output
    fn flush(&mut self);
}

/// Standard output sink (writes to stdout)
pub struct StdoutSink {
    stdout: std::io::Stdout,
}

impl StdoutSink {
    pub fn new() -> Self {
        Self {
            stdout: std::io::stdout(),
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl LogSink for StdoutSink {
    fn write_entry(&mut self, entry: &LogEntry) {
        // Format: [TIMESTAMP] [SEVERITY] [Facility] message key1=value1 key2=value2
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let kvs = entry.get_kvs();
        if kvs.is_empty() {
            let _ = writeln!(
                self.stdout,
                "[{}] [{:?}] [{}] {}",
                timestamp,
                entry.severity,
                entry.facility.as_str(),
                entry.get_message()
            );
        } else {
            let kv_str: Vec<String> = kvs.iter().map(|kv| format!("{:?}", kv)).collect();
            let _ = writeln!(
                self.stdout,
                "[{}] [{:?}] [{}] {} {}",
                timestamp,
                entry.severity,
                entry.facility.as_str(),
                entry.get_message(),
                kv_str.join(" ")
            );
        }
    }

    fn flush(&mut self) {
        let _ = self.stdout.flush();
    }
}

/// Standard error sink (writes to stderr)
pub struct StderrSink {
    stderr: std::io::Stderr,
}

impl StderrSink {
    pub fn new() -> Self {
        Self {
            stderr: std::io::stderr(),
        }
    }
}

impl Default for StderrSink {
    fn default() -> Self {
        Self::new()
    }
}

impl LogSink for StderrSink {
    fn write_entry(&mut self, entry: &LogEntry) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let kvs = entry.get_kvs();
        if kvs.is_empty() {
            let _ = writeln!(
                self.stderr,
                "[{}] [{:?}] [{}] {}",
                timestamp,
                entry.severity,
                entry.facility.as_str(),
                entry.get_message()
            );
        } else {
            let kv_str: Vec<String> = kvs.iter().map(|kv| format!("{:?}", kv)).collect();
            let _ = writeln!(
                self.stderr,
                "[{}] [{:?}] [{}] {} {}",
                timestamp,
                entry.severity,
                entry.facility.as_str(),
                entry.get_message(),
                kv_str.join(" ")
            );
        }
    }

    fn flush(&mut self) {
        let _ = self.stderr.flush();
    }
}

/// Consumer task for MPSC ring buffers (async/tokio)
pub struct AsyncConsumer {
    ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>,
    sink: Box<dyn LogSink>,
    running: Arc<AtomicBool>,
}

impl AsyncConsumer {
    /// Create a new async consumer with given ring buffers and sink
    pub fn new(ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>, sink: Box<dyn LogSink>) -> Self {
        Self {
            ringbuffers,
            sink,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Create a consumer that writes to stdout
    pub fn stdout(ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>) -> Self {
        Self::new(ringbuffers, Box::new(StdoutSink::new()))
    }

    /// Create a consumer that writes to stderr
    pub fn stderr(ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)>) -> Self {
        Self::new(ringbuffers, Box::new(StderrSink::new()))
    }

    /// Get a handle to stop the consumer
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Run the consumer task (blocks until stopped)
    pub async fn run(mut self) {
        while self.running.load(Ordering::Relaxed) {
            let mut any_read = false;

            // Poll all ring buffers
            for (_facility, ringbuffer) in &self.ringbuffers {
                while let Some(entry) = ringbuffer.read() {
                    self.sink.write_entry(&entry);
                    any_read = true;
                }
            }

            if any_read {
                self.sink.flush();
            } else {
                // No data available, sleep briefly
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        // Final flush
        self.sink.flush();
    }
}

/// Consumer task for SPSC ring buffers (blocking/thread)
pub struct BlockingConsumer {
    ringbuffers: Vec<(Facility, Arc<SPSCRingBuffer>)>,
    sink: Box<dyn LogSink>,
    running: Arc<AtomicBool>,
}

impl BlockingConsumer {
    /// Create a new blocking consumer with given ring buffers and sink
    pub fn new(ringbuffers: Vec<(Facility, Arc<SPSCRingBuffer>)>, sink: Box<dyn LogSink>) -> Self {
        Self {
            ringbuffers,
            sink,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Create a consumer that writes to stdout
    pub fn stdout(ringbuffers: Vec<(Facility, Arc<SPSCRingBuffer>)>) -> Self {
        Self::new(ringbuffers, Box::new(StdoutSink::new()))
    }

    /// Create a consumer that writes to stderr
    pub fn stderr(ringbuffers: Vec<(Facility, Arc<SPSCRingBuffer>)>) -> Self {
        Self::new(ringbuffers, Box::new(StderrSink::new()))
    }

    /// Get a handle to stop the consumer
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Run the consumer task (blocks until stopped)
    pub fn run(mut self) {
        while self.running.load(Ordering::Relaxed) {
            let mut any_read = false;

            // Poll all ring buffers
            for (_facility, ringbuffer) in &self.ringbuffers {
                while let Some(entry) = ringbuffer.read() {
                    self.sink.write_entry(&entry);
                    any_read = true;
                }
            }

            if any_read {
                self.sink.flush();
            } else {
                // No data available, sleep briefly
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        // Final flush
        self.sink.flush();
    }
}

/// Consumer task for SharedSPSCRingBuffer (cross-process logging)
pub struct SharedBlockingConsumer {
    ringbuffers: Vec<Arc<SharedSPSCRingBuffer>>,
    sink: Box<dyn LogSink>,
}

impl SharedBlockingConsumer {
    /// Create a new shared blocking consumer
    pub fn new(ringbuffers: Vec<Arc<SharedSPSCRingBuffer>>, sink: Box<dyn LogSink>) -> Self {
        Self { ringbuffers, sink }
    }

    /// Process once (read all available entries from all buffers)
    ///
    /// This is called repeatedly by the consumer thread.
    pub fn process_once(&mut self) {
        let mut any_read = false;

        // Poll all ring buffers
        for ringbuffer in &self.ringbuffers {
            while let Some(entry) = ringbuffer.read() {
                self.sink.write_entry(&entry);
                any_read = true;
            }
        }

        if any_read {
            self.sink.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{LogEntry, Severity};
    use std::sync::Mutex;

    // Test sink that captures entries
    struct TestSink {
        entries: Arc<Mutex<Vec<String>>>,
    }

    impl TestSink {
        fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
            let entries = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    entries: Arc::clone(&entries),
                },
                entries,
            )
        }
    }

    impl LogSink for TestSink {
        fn write_entry(&mut self, entry: &LogEntry) {
            let msg = format!(
                "[{:?}] [{}] {}",
                entry.severity,
                entry.facility.as_str(),
                entry.get_message()
            );
            self.entries.lock().unwrap().push(msg);
        }

        fn flush(&mut self) {}
    }

    #[tokio::test]
    async fn test_async_consumer() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));
        let (sink, entries) = TestSink::new();

        // Write some entries
        ringbuffer.write(LogEntry::new(Severity::Info, Facility::Test, "Message 1"));
        ringbuffer.write(LogEntry::new(Severity::Error, Facility::Test, "Message 2"));

        let consumer = AsyncConsumer::new(vec![(Facility::Test, ringbuffer)], Box::new(sink));
        let stop = consumer.stop_handle();

        // Run consumer in background
        let handle = tokio::spawn(async move {
            consumer.run().await;
        });

        // Give it time to consume
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Stop consumer
        stop.store(false, Ordering::Relaxed);
        handle.await.unwrap();

        // Check entries were consumed
        let entries = entries.lock().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].contains("Message 1"));
        assert!(entries[1].contains("Message 2"));
    }

    #[test]
    fn test_blocking_consumer() {
        let ringbuffer = Arc::new(SPSCRingBuffer::new(16, 0));
        let (sink, entries) = TestSink::new();

        // Write some entries
        ringbuffer.write(LogEntry::new(Severity::Info, Facility::Test, "Message 1"));
        ringbuffer.write(LogEntry::new(Severity::Error, Facility::Test, "Message 2"));

        let consumer = BlockingConsumer::new(vec![(Facility::Test, ringbuffer)], Box::new(sink));
        let stop = consumer.stop_handle();

        // Run consumer in background thread
        let handle = std::thread::spawn(move || {
            consumer.run();
        });

        // Give it time to consume
        std::thread::sleep(Duration::from_millis(10));

        // Stop consumer
        stop.store(false, Ordering::Relaxed);
        handle.join().unwrap();

        // Check entries were consumed
        let entries = entries.lock().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].contains("Message 1"));
        assert!(entries[1].contains("Message 2"));
    }

    #[test]
    fn test_shared_blocking_consumer() {
        // Create shared memory ring buffer
        let buffer = SharedSPSCRingBuffer::create("/test_shared_consumer", 16, 0).unwrap();
        let buffer = Arc::new(buffer);

        // Write some entries
        buffer.write(LogEntry::new(
            Severity::Info,
            Facility::Test,
            "Shared message 1",
        ));
        buffer.write(LogEntry::new(
            Severity::Error,
            Facility::Test,
            "Shared message 2",
        ));

        let (sink, entries) = TestSink::new();
        let mut consumer = SharedBlockingConsumer::new(vec![Arc::clone(&buffer)], Box::new(sink));

        // Process entries
        consumer.process_once();

        // Check entries were consumed
        let entries = entries.lock().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].contains("Shared message 1"));
        assert!(entries[1].contains("Shared message 2"));
    }

    #[test]
    fn test_stdout_sink() {
        let mut sink = StdoutSink::new();
        let entry = LogEntry::new(Severity::Info, Facility::Test, "Test stdout");

        // Just ensure it doesn't crash - we can't easily capture stdout in tests
        sink.write_entry(&entry);
        sink.flush();
    }

    #[test]
    fn test_stderr_sink() {
        let mut sink = StderrSink::new();
        let entry = LogEntry::new(Severity::Error, Facility::Test, "Test stderr");

        // Just ensure it doesn't crash - we can't easily capture stderr in tests
        sink.write_entry(&entry);
        sink.flush();
    }

    #[test]
    fn test_consumer_convenience_constructors() {
        let ringbuffer = Arc::new(SPSCRingBuffer::new(16, 0));

        // Test stdout constructor
        let _consumer = BlockingConsumer::stdout(vec![(Facility::Test, Arc::clone(&ringbuffer))]);

        // Test stderr constructor
        let _consumer = BlockingConsumer::stderr(vec![(Facility::Test, ringbuffer)]);
    }

    #[tokio::test]
    async fn test_async_consumer_constructors() {
        let ringbuffer = Arc::new(MPSCRingBuffer::new(16));

        // Test stdout constructor
        let _consumer = AsyncConsumer::stdout(vec![(Facility::Test, Arc::clone(&ringbuffer))]);

        // Test stderr constructor
        let _consumer = AsyncConsumer::stderr(vec![(Facility::Test, ringbuffer)]);
    }
}
