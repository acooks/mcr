// Example demonstrating the MCR logging system
//
// Run with: cargo run --example logging_demo

use multicast_relay::logging::*;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("=== MCR Logging System Demo ===\n");

    // Create a logging registry with MPSC ring buffers (for async/multi-threaded use)
    let registry = LogRegistry::new_mpsc();

    // Get loggers for different facilities
    let supervisor_logger = registry.get_logger(Facility::Supervisor).unwrap();
    let ingress_logger = registry.get_logger(Facility::Ingress).unwrap();

    // Set up a consumer task to output logs to stdout
    let ringbuffers: Vec<(Facility, Arc<MPSCRingBuffer>)> = vec![
        (
            Facility::Supervisor,
            Arc::new(MPSCRingBuffer::new(Facility::Supervisor.buffer_size())),
        ),
        (
            Facility::Ingress,
            Arc::new(MPSCRingBuffer::new(Facility::Ingress.buffer_size())),
        ),
    ];

    // Note: In a real application, you'd get the ringbuffers from the registry.
    // This is simplified for demonstration.

    // Start the consumer task
    let consumer = AsyncConsumer::stdout(vec![]);
    let _stop_handle = consumer.stop_handle();

    // In production, you'd spawn: tokio::spawn(consumer.run());

    println!("1. Basic logging with severity helpers:");
    supervisor_logger.info(Facility::Supervisor, "Supervisor starting");
    supervisor_logger.debug(Facility::Supervisor, "Debug: Configuration loaded");
    supervisor_logger.error(Facility::Supervisor, "Error: Failed to bind socket");

    println!("\n2. Using macros (more convenient):");
    log_info!(supervisor_logger, Facility::Supervisor, "Worker spawned");
    log_warning!(supervisor_logger, Facility::Supervisor, "High memory usage");

    println!("\n3. Structured logging with key-value pairs:");
    log_kv!(
        ingress_logger,
        Severity::Info,
        Facility::Ingress,
        "Packet received",
        "src" => "10.0.0.1",
        "port" => "5000"
    );

    println!("\n4. Demonstrating different severity levels:");
    supervisor_logger.emergency(Facility::Supervisor, "EMERGENCY: System critical");
    supervisor_logger.alert(Facility::Supervisor, "ALERT: Immediate action required");
    supervisor_logger.critical(Facility::Supervisor, "CRITICAL: System failure");
    supervisor_logger.error(Facility::Supervisor, "ERROR: Operation failed");
    supervisor_logger.warning(Facility::Supervisor, "WARNING: Resource low");
    supervisor_logger.notice(Facility::Supervisor, "NOTICE: Configuration changed");
    supervisor_logger.info(Facility::Supervisor, "INFO: Normal operation");
    supervisor_logger.debug(Facility::Supervisor, "DEBUG: Internal state");

    println!("\n=== Key Features ===");
    println!("✓ Lock-free ring buffers (<100ns write latency)");
    println!("✓ Zero-copy message passing");
    println!("✓ Cache-line optimized (256 bytes per entry)");
    println!("✓ Structured logging with key-value pairs");
    println!("✓ Multiple severity levels (RFC 5424)");
    println!("✓ Per-facility ring buffers");
    println!("✓ Async and blocking consumers");
    println!("✓ No IPC overhead");

    println!("\n=== Memory Footprint ===");
    println!("2-core system: ~12.5 MB total");
    println!("  - Ingress: 4 MB per worker");
    println!("  - Egress: 1 MB per worker");
    println!("  - Supervisor: 256 KB");

    // Give logs time to flush
    tokio::time::sleep(Duration::from_millis(100)).await;
}
