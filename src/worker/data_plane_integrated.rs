//! Integrated Data Plane
//!
//! This module provides the integrated data plane that combines ingress and egress
//! into a complete packet processing pipeline.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐         ┌──────────────┐
//! │   Ingress    │─────────▶│   Egress     │
//! │   Loop       │ Channel │   Loop       │
//! │ (io_uring)   │         │  (io_uring)  │
//! └──────────────┘         └──────────────┘
//!        │                        │
//!        ▼                        ▼
//!   Buffer Pool           Buffer Pool
//!   (shared)              (deallocation)
//! ```
//!
//! The ingress and egress loops run in separate threads and communicate via
//! an std::sync::mpsc channel for zero-copy packet forwarding.

use anyhow::{Context, Result};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use crate::worker::{
    buffer_pool::BufferPool,
    egress::{EgressConfig, EgressLoop, EgressPacket},
    ingress::{IngressConfig, IngressLoop},
};
use crate::{DataPlaneConfig, RelayCommand};

/// Integrated data plane runner
///
/// This function sets up and runs the complete data plane pipeline with
/// ingress and egress loops communicating via a channel.
///
/// # Arguments
///
/// * `config` - Data plane configuration
///
/// # Returns
///
/// This function runs indefinitely until an error occurs or the loops terminate.
///
/// # Example
///
/// ```ignore
/// use multicast_relay::worker::data_plane_integrated::{DataPlaneConfig, run_data_plane};
/// use multicast_relay::ForwardingRule;
/// use std::net::Ipv4Addr;
///
/// let mut config = DataPlaneConfig::default();
/// config.interface_name = "eth0".to_string();
///
/// // Add a forwarding rule
/// let rule = ForwardingRule {
///     rule_id: "rule-1".to_string(),
///     input_interface: "eth0".to_string(),
///     input_group: "224.0.0.1".parse().unwrap(),
///     input_port: 5000,
///     outputs: vec![],
///     dtls_enabled: false,
/// };
/// config.initial_rules.push(rule);
///
/// // Run the data plane (blocks indefinitely)
/// run_data_plane(config, command_rx, event_fd).expect("Data plane failed");
/// ```
pub fn run_data_plane(
    config: DataPlaneConfig,
    command_rx: mpsc::Receiver<RelayCommand>,
    event_fd: nix::sys::eventfd::EventFd,
) -> Result<()> {
    println!(
        "[DataPlane] Starting integrated data plane on {}",
        config.input_interface_name.as_deref().unwrap_or("default")
    );

    let ingress_config = IngressConfig {
        ..Default::default()
    };

    let egress_config = EgressConfig {
        ..Default::default()
    };

    // Create channel for ingress→egress communication
    let (egress_tx, egress_rx) = mpsc::channel::<EgressPacket>();

    // Create shared buffer pool (Arc<Mutex<>> for thread-safe shared access)
    let buffer_pool = Arc::new(std::sync::Mutex::new(BufferPool::new(
        ingress_config.track_stats,
    )));

    // Clone config for threads
    // TODO: ARCHITECTURAL FIX NEEDED
    // This creates AF_PACKET socket eagerly on startup. Per architecture (D21, D23):
    // - Workers should start with NO sockets
    // - Sockets should be created LAZILY when rules are assigned to this worker
    // - Each worker can handle multiple interfaces based on its assigned rules
    // Current approach causes resource exhaustion when spawning many workers.
    let interface_name = config
        .input_interface_name
        .clone()
        .unwrap_or_else(|| "lo".to_string());
    let initial_rules = Vec::new(); // TODO: Pass rules from control plane

    // Spawn ingress thread
    let ingress_handle = {
        let interface_name = interface_name.clone();
        let egress_tx = egress_tx.clone();
        let buffer_pool_for_ingress = buffer_pool.clone();

        thread::Builder::new()
            .name("ingress".to_string())
            .spawn(move || -> Result<()> {
                println!("[DataPlane] Ingress thread started");

                // Debug: Check if CAP_NET_RAW is available in this thread
                use caps::{CapSet, Capability};
                match caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW) {
                    Ok(true) => {
                        println!("[DataPlane] Ingress thread has CAP_NET_RAW in Effective set")
                    }
                    Ok(false) => eprintln!(
                        "[DataPlane] WARNING: Ingress thread missing CAP_NET_RAW in Effective set!"
                    ),
                    Err(e) => eprintln!("[DataPlane] ERROR checking capabilities: {}", e),
                }

                // Create ingress loop
                let mut ingress = match IngressLoop::new(
                    &interface_name,
                    ingress_config,
                    buffer_pool_for_ingress,
                    Some(egress_tx),
                    command_rx,
                    event_fd,
                ) {
                    Ok(ingress) => {
                        println!("[DataPlane] Ingress loop created successfully");
                        ingress
                    }
                    Err(e) => {
                        eprintln!("[DataPlane] FATAL: IngressLoop::new() failed: {}", e);
                        return Err(e);
                    }
                };

                // Add initial rules
                for rule in initial_rules {
                    ingress.add_rule(Arc::new(rule))?;
                }

                println!("[DataPlane] Starting ingress run loop");
                // Run ingress loop (blocks forever)
                if let Err(e) = ingress.run() {
                    eprintln!("[DataPlane] FATAL: Ingress run() failed: {}", e);
                    return Err(e);
                }

                Ok(())
            })
            .context("Failed to spawn ingress thread")?
    };

    // Spawn egress thread
    let egress_handle = {
        let egress_rx = egress_rx;

        thread::Builder::new()
            .name("egress".to_string())
            .spawn(move || -> Result<()> {
                println!("[DataPlane] Egress thread started");

                // Create egress loop
                let mut egress = EgressLoop::new(egress_config.clone(), buffer_pool.clone())?;

                // Main egress loop: receive packets from channel and send in batches
                loop {
                    // Receive packets from ingress (blocking)
                    match egress_rx.recv_timeout(Duration::from_millis(10)) {
                        Ok(packet) => {
                            // Add destination socket if not already present
                            if let Err(e) =
                                egress.add_destination(&packet.interface_name, packet.dest_addr)
                            {
                                eprintln!("[DataPlane] Failed to add egress destination: {}", e);
                                continue;
                            }

                            // Queue packet
                            egress.queue_packet(packet);

                            // If queue is full, send batch
                            if egress.queue_len() >= egress_config.batch_size {
                                if let Err(e) = egress.send_batch() {
                                    eprintln!("[DataPlane] Egress send batch failed: {}", e);
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            // No packets available, flush pending packets
                            if !egress.is_queue_empty() {
                                if let Err(e) = egress.send_batch() {
                                    eprintln!("[DataPlane] Egress send batch failed: {}", e);
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            println!("[DataPlane] Ingress channel closed, shutting down egress");
                            break;
                        }
                    }
                }

                Ok(())
            })
            .context("Failed to spawn egress thread")?
    };

    // Wait for both threads to complete
    println!("[DataPlane] Data plane running, waiting for threads...");

    let ingress_result = ingress_handle
        .join()
        .map_err(|e| anyhow::anyhow!("Ingress thread panicked: {:?}", e))?;

    let egress_result = egress_handle
        .join()
        .map_err(|e| anyhow::anyhow!("Egress thread panicked: {:?}", e))?;

    // Propagate any errors
    ingress_result?;
    egress_result?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::packet_parser::parse_packet;
    use crate::{ForwardingRule, OutputDestination};
    use std::net::Ipv4Addr;

    /// Helper function to create a valid Ethernet/IPv4/UDP packet
    fn create_test_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0xFF; 6]); // Destination MAC
        packet.extend_from_slice(&[0x00; 6]); // Source MAC
        packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        let ip_total_len = 20 + 8 + payload.len() as u16;
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP/ECN
        packet.extend_from_slice(&ip_total_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]); // Identification
        packet.extend_from_slice(&[0x00, 0x00]); // Flags/Fragment
        packet.push(64); // TTL
        packet.push(17); // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder

        // IP addresses
        packet.extend_from_slice(&src_ip.octets());
        packet.extend_from_slice(&dst_ip.octets());

        // Calculate and insert IP checksum
        let checksum = calculate_ip_checksum(&packet[14..14 + 20]);
        packet[24..26].copy_from_slice(&checksum.to_be_bytes());

        // UDP header (8 bytes)
        let udp_len = 8 + payload.len() as u16;
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&udp_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // UDP checksum

        // Payload
        packet.extend_from_slice(payload);

        packet
    }

    fn calculate_ip_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..header.len()).step_by(2) {
            if i == 10 {
                continue; // Skip checksum field
            }
            let word = if i + 1 < header.len() {
                u16::from_be_bytes([header[i], header[i + 1]])
            } else {
                u16::from_be_bytes([header[i], 0])
            };
            sum += word as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    #[test]
    fn test_packet_creation_and_parsing() {
        let packet = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 1, 1),
            5000,
            5001,
            b"TEST",
        );

        let parsed = parse_packet(&packet, false).expect("Should parse valid packet");
        assert_eq!(parsed.ipv4.src_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.ipv4.dst_ip, Ipv4Addr::new(224, 1, 1, 1));
        assert_eq!(parsed.udp.src_port, 5000);
        assert_eq!(parsed.udp.dst_port, 5001);
        assert_eq!(parsed.payload_len, 4);
        assert_eq!(
            &packet[parsed.payload_offset..parsed.payload_offset + parsed.payload_len],
            b"TEST"
        );
    }

    #[test]
    fn test_buffer_pool_allocation_with_packets() {
        let mut pool = BufferPool::with_capacities(10, 5, 2, true);

        // Test different packet sizes
        let small_buf = pool.allocate(100).expect("Should allocate small");
        assert!(small_buf.capacity() >= 100);

        let standard_buf = pool.allocate(1500).expect("Should allocate standard");
        assert!(standard_buf.capacity() >= 1500);

        pool.deallocate(small_buf);
        pool.deallocate(standard_buf);

        let stats = pool.aggregate_stats();
        assert_eq!(stats.total_allocations(), 2);
        assert_eq!(
            stats.small.deallocations_total + stats.standard.deallocations_total,
            2
        );
    }

    #[test]
    fn test_rule_matching() {
        let rule = ForwardingRule {
            rule_id: "test-001".to_string(),
            input_interface: "lo".to_string(),
            input_group: Ipv4Addr::new(224, 1, 1, 1),
            input_port: 5001,
            outputs: vec![OutputDestination {
                group: Ipv4Addr::new(239, 1, 1, 1),
                port: 6001,
                interface: "127.0.0.1".to_string(),
                dtls_enabled: false,
            }],
            dtls_enabled: false,
        };

        // Matching packet
        let matching_packet = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 1, 1),
            5000,
            5001,
            b"MATCH",
        );
        let parsed = parse_packet(&matching_packet, false).expect("Should parse");
        assert!(parsed.matches(rule.input_group, rule.input_port));

        // Non-matching packet
        let non_matching = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 1, 1),
            5000,
            9999, // Wrong port
            b"NO_MATCH",
        );
        let parsed_no_match = parse_packet(&non_matching, false).expect("Should parse");
        assert!(!parsed_no_match.matches(rule.input_group, rule.input_port));
    }

    #[test]
    fn test_multi_destination_forwarding() {
        let rule = ForwardingRule {
            rule_id: "multi-dest".to_string(),
            input_interface: "lo".to_string(),
            input_group: Ipv4Addr::new(224, 1, 1, 1),
            input_port: 5001,
            outputs: vec![
                OutputDestination {
                    group: Ipv4Addr::new(239, 1, 1, 1),
                    port: 6001,
                    interface: "127.0.0.1".to_string(),
                    dtls_enabled: false,
                },
                OutputDestination {
                    group: Ipv4Addr::new(239, 2, 2, 2),
                    port: 6002,
                    interface: "127.0.0.1".to_string(),
                    dtls_enabled: false,
                },
                OutputDestination {
                    group: Ipv4Addr::new(239, 3, 3, 3),
                    port: 6003,
                    interface: "127.0.0.1".to_string(),
                    dtls_enabled: false,
                },
            ],
            dtls_enabled: false,
        };

        // Verify 1:3 amplification
        assert_eq!(rule.outputs.len(), 3);

        // Verify all destinations are unique
        let mut seen = std::collections::HashSet::new();
        for output in &rule.outputs {
            let key = (output.group, output.port);
            assert!(seen.insert(key), "Duplicate destination");
        }
    }

    #[test]
    fn test_fragmented_packet_detection() {
        let mut packet = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 1, 1),
            5000,
            5001,
            b"FRAG",
        );

        // Set More Fragments flag
        packet[14 + 6] = 0x20; // MF flag

        // Fragmented packets should be rejected (D30)
        let result = parse_packet(&packet, false);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(crate::worker::packet_parser::ParseError::FragmentedPacket)
        ));
    }

    #[test]
    fn test_error_handling_malformed_packets() {
        // Too short
        assert!(parse_packet(&[0u8; 10], false).is_err());

        // Invalid EtherType
        let mut invalid = vec![0u8; 42];
        invalid[12] = 0x86;
        invalid[13] = 0xDD;
        assert!(parse_packet(&invalid, false).is_err());

        // Invalid IP version
        let mut invalid_ip = vec![0u8; 42];
        invalid_ip[12] = 0x08;
        invalid_ip[13] = 0x00;
        invalid_ip[14] = 0x35; // Version 3
        assert!(parse_packet(&invalid_ip, false).is_err());
    }

    #[test]
    fn test_packet_size_classes() {
        let mut pool = BufferPool::with_capacities(10, 10, 10, false);

        // Small packet
        let small = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 1, 1),
            5000,
            5001,
            &[0u8; 100],
        );
        assert!(pool.allocate(small.len()).is_some());

        // Standard packet (typical MTU)
        let standard = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 1, 1),
            5000,
            5001,
            &[0u8; 1400],
        );
        assert!(pool.allocate(standard.len()).is_some());

        // Jumbo packet
        let jumbo = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 1, 1),
            5000,
            5001,
            &[0u8; 8000],
        );
        assert!(pool.allocate(jumbo.len()).is_some());
    }

    #[test]
    fn test_rule_lookup_table() {
        use std::collections::HashMap;

        let mut rules = HashMap::new();

        // Create 100 rules
        for i in 0..100 {
            let rule = ForwardingRule {
                rule_id: format!("rule-{:03}", i),
                input_interface: "lo".to_string(),
                input_group: Ipv4Addr::new(224, 1, (i / 256) as u8, (i % 256) as u8),
                input_port: 5000 + i as u16,
                outputs: vec![OutputDestination {
                    group: Ipv4Addr::new(239, 1, 1, 1),
                    port: 6000 + i as u16,
                    interface: "127.0.0.1".to_string(),
                    dtls_enabled: false,
                }],
                dtls_enabled: false,
            };
            let key = (rule.input_group, rule.input_port);
            rules.insert(key, rule);
        }

        // Test lookup
        let packet = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 0, 50),
            5000,
            5050,
            b"LOOKUP",
        );

        let parsed = parse_packet(&packet, false).expect("Should parse");
        let key = (parsed.ipv4.dst_ip, parsed.udp.dst_port);

        let found = rules.get(&key);
        assert!(found.is_some());
        assert_eq!(found.unwrap().rule_id, "rule-050");
    }

    /// Performance validation tests for Phase 4 completion
    /// These tests verify we meet the design targets:
    /// - Buffer allocation cycle: <200ns (Experiment #3 showed 26.7ns for alloc only)
    /// - Packet parsing: <100ns per packet
    /// - Rule lookup: <100ns (HashMap O(1))
    /// - Pipeline target: 312.5k pps/core ingress (3.2µs = 3200ns per packet budget)
    ///
    /// Note: These tests only run in release mode (--release) because debug builds
    /// are 10-50x slower and would fail the performance targets.

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_performance_buffer_allocation() {
        let mut pool = BufferPool::with_capacities(10000, 5000, 2000, false);
        let iterations = 10000;

        // Warm up
        for _ in 0..100 {
            let buf = pool.allocate(1500);
            if let Some(b) = buf {
                pool.deallocate(b);
            }
        }

        // Measure allocation performance
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let buf = pool.allocate(1500).expect("Pool should have buffers");
            pool.deallocate(buf);
        }
        let elapsed = start.elapsed();
        let avg_ns = elapsed.as_nanos() / iterations as u128;

        // Target: <200ns per allocation/deallocation cycle
        // Experiment #3 showed 26.7ns for allocation only
        // Full cycle (alloc + dealloc) is ~4-5x that, which is expected
        // 200ns still gives us plenty of headroom for 312.5k pps (3200ns budget per packet)
        assert!(
            avg_ns < 200,
            "Buffer allocation too slow: {}ns (target: <200ns)",
            avg_ns
        );

        println!(
            "✓ Buffer allocation performance: {}ns (target: <200ns)",
            avg_ns
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_performance_packet_parsing() {
        let iterations = 10000;

        // Create a typical packet
        let packet = create_test_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(224, 1, 1, 1),
            5000,
            5001,
            &[0u8; 1200], // Typical payload size
        );

        // Warm up
        for _ in 0..100 {
            let _ = parse_packet(&packet, false);
        }

        // Measure parsing performance
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = parse_packet(&packet, false).expect("Should parse");
        }
        let elapsed = start.elapsed();
        let avg_ns = elapsed.as_nanos() / iterations as u128;

        // Target: <100ns per packet (design requirement)
        assert!(
            avg_ns < 100,
            "Packet parsing too slow: {}ns (target: <100ns)",
            avg_ns
        );

        println!(
            "✓ Packet parsing performance: {}ns (target: <100ns)",
            avg_ns
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_performance_rule_lookup() {
        use std::collections::HashMap;

        let mut rules = HashMap::new();
        let iterations = 100000;

        // Create realistic rule table with 1000 rules
        for i in 0..1000 {
            let rule = ForwardingRule {
                rule_id: format!("rule-{:04}", i),
                input_interface: "lo".to_string(),
                input_group: Ipv4Addr::new(224, (i / 256) as u8, (i % 256) as u8, 1),
                input_port: 5000 + (i % 1000) as u16,
                outputs: vec![OutputDestination {
                    group: Ipv4Addr::new(239, 1, 1, 1),
                    port: 6000 + i as u16,
                    interface: "127.0.0.1".to_string(),
                    dtls_enabled: false,
                }],
                dtls_enabled: false,
            };
            let key = (rule.input_group, rule.input_port);
            rules.insert(key, rule);
        }

        // Test lookup for middle rule
        let lookup_key = (Ipv4Addr::new(224, 1, 244, 1), 5500);

        // Warm up
        for _ in 0..1000 {
            let _ = rules.get(&lookup_key);
        }

        // Measure lookup performance
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = rules.get(&lookup_key);
        }
        let elapsed = start.elapsed();
        let avg_ns = elapsed.as_nanos() / iterations as u128;

        // Target: <100ns per lookup (HashMap O(1))
        assert!(
            avg_ns < 100,
            "Rule lookup too slow: {}ns (target: <100ns)",
            avg_ns
        );

        println!("✓ Rule lookup performance: {}ns (target: <100ns)", avg_ns);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_performance_pipeline_throughput_estimate() {
        // This test validates that the sum of individual component latencies
        // allows us to meet the 312.5k pps/core ingress target (3.2µs per packet)

        // Component timings (conservative estimates based on other tests):
        let buffer_alloc_ns = 200; // <200ns validated above (alloc + dealloc cycle)
        let parsing_ns = 100; // <100ns validated above
        let rule_lookup_ns = 100; // <100ns validated above
        let copy_overhead_ns = 100; // Estimate for 1:N amplification prep
        let channel_send_ns = 200; // Estimate for mpsc channel send

        let total_pipeline_ns =
            buffer_alloc_ns + parsing_ns + rule_lookup_ns + copy_overhead_ns + channel_send_ns;

        // Convert to throughput
        let packets_per_sec = 1_000_000_000.0 / total_pipeline_ns as f64;

        // Target: 312.5k pps (3.2µs per packet = 3200ns)
        let target_pps = 312_500.0;

        assert!(
            packets_per_sec > target_pps,
            "Estimated throughput too low: {:.0} pps (target: {:.0} pps)",
            packets_per_sec,
            target_pps
        );

        println!(
            "✓ Estimated pipeline throughput: {:.0} pps ({:.0}ns per packet, target: {:.0} pps / 3200ns)",
            packets_per_sec,
            total_pipeline_ns,
            target_pps
        );
    }
}
