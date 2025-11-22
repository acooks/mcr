// SPDX-License-Identifier: Apache-2.0 OR MIT
// Example demonstrating the MCR logging system
//
// Run with: cargo run --example logging_demo

use multicast_relay::logging::*;
use multicast_relay::{log_info, log_kv, log_warning};
use std::collections::HashMap;
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("=== MCR Logging System Demo ===\n");

    // Create ring buffers for different facilities
    let supervisor_ringbuffer = Arc::new(MPSCRingBuffer::new(Facility::Supervisor.buffer_size()));
    let ingress_ringbuffer = Arc::new(MPSCRingBuffer::new(Facility::Ingress.buffer_size()));

    // Create log level filtering structures
    let global_min_level = Arc::new(AtomicU8::new(Severity::Info as u8));
    let facility_min_levels: Arc<RwLock<HashMap<Facility, Severity>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Create loggers from the ring buffers
    let supervisor_logger = Logger::from_mpsc(
        Arc::clone(&supervisor_ringbuffer),
        Arc::clone(&global_min_level),
        Arc::clone(&facility_min_levels),
    );
    let ingress_logger = Logger::from_mpsc(
        Arc::clone(&ingress_ringbuffer),
        Arc::clone(&global_min_level),
        Arc::clone(&facility_min_levels),
    );

    // Set up ring buffers for the consumer task
    let ringbuffers_for_consumer = vec![
        (Facility::Supervisor, Arc::clone(&supervisor_ringbuffer)),
        (Facility::Ingress, Arc::clone(&ingress_ringbuffer)),
    ];

    // Start the consumer task
    let consumer = AsyncConsumer::stdout(ringbuffers_for_consumer);
    let stop_handle = consumer.stop_handle();

    // Spawn consumer in background
    tokio::spawn(async move {
        consumer.run().await;
    });

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

    // Stop the consumer
    stop_handle.store(false, std::sync::atomic::Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(10)).await;
}
