#!/usr/bin/env rust-script
//! Functional test for io_uring egress
//!
//! This test validates basic functionality:
//! 1. Socket creation and binding
//! 2. Sending packets via io_uring
//! 3. Receiving packets on the other end
//! 4. Source IP binding
//! 5. Basic error handling

use anyhow::{Context, Result};
use poc_io_uring_egress::{ConnectedEgressSender, EgressConfig};
use std::net::UdpSocket;
use std::time::Duration;

fn main() -> Result<()> {
    println!("=== io_uring Egress Functional Test ===\n");

    // Test 1: Basic send/receive
    println!("[Test 1] Basic send/receive");
    test_basic_send_receive()?;
    println!("✓ Basic send/receive passed\n");

    // Test 2: Batched send
    println!("[Test 2] Batched send");
    test_batched_send()?;
    println!("✓ Batched send passed\n");

    // Test 3: Source IP binding
    println!("[Test 3] Source IP binding");
    test_source_binding()?;
    println!("✓ Source IP binding passed\n");

    // Test 4: Statistics tracking
    println!("[Test 4] Statistics tracking");
    test_statistics()?;
    println!("✓ Statistics tracking passed\n");

    // Test 5: Different packet sizes
    println!("[Test 5] Different packet sizes");
    test_packet_sizes()?;
    println!("✓ Different packet sizes passed\n");

    println!("=== All Tests Passed ✓ ===");
    Ok(())
}

fn test_basic_send_receive() -> Result<()> {
    // Create receiver
    let receiver = UdpSocket::bind("127.0.0.1:18000")?;
    receiver.set_read_timeout(Some(Duration::from_secs(1)))?;

    // Create sender
    let config = EgressConfig::default();
    let mut sender =
        ConnectedEgressSender::new(config, "127.0.0.1:18000".parse().unwrap())?;

    // Send a packet
    let data = b"Hello, io_uring!";
    let packets = vec![data.as_slice()];
    let sent = sender.send_batch(&packets)?;

    assert_eq!(sent, 1, "Expected 1 packet sent");

    // Receive the packet
    let mut buf = vec![0u8; 1500];
    let (size, _src) = receiver.recv_from(&mut buf)?;

    assert_eq!(&buf[..size], data, "Received data doesn't match sent data");

    println!("  Sent: {} bytes", data.len());
    println!("  Received: {} bytes", size);

    Ok(())
}

fn test_batched_send() -> Result<()> {
    let receiver = UdpSocket::bind("127.0.0.1:18001")?;
    receiver.set_read_timeout(Some(Duration::from_secs(1)))?;

    let config = EgressConfig {
        queue_depth: 128,
        ..Default::default()
    };
    let mut sender =
        ConnectedEgressSender::new(config, "127.0.0.1:18001".parse().unwrap())?;

    // Send 10 packets in a batch
    let data = b"Batch packet";
    let packets: Vec<&[u8]> = (0..10).map(|_| data.as_slice()).collect();
    let sent = sender.send_batch(&packets)?;

    assert_eq!(sent, 10, "Expected 10 packets sent");

    // Receive all packets
    let mut buf = vec![0u8; 1500];
    for i in 0..10 {
        let (size, _src) = receiver
            .recv_from(&mut buf)
            .context(format!("Failed to receive packet {}", i))?;
        assert_eq!(&buf[..size], data);
    }

    println!("  Sent batch of: {} packets", sent);

    Ok(())
}

fn test_source_binding() -> Result<()> {
    let config = EgressConfig {
        source_addr: Some("127.0.0.1:18100".parse().unwrap()),
        ..Default::default()
    };

    let sender =
        ConnectedEgressSender::new(config, "127.0.0.1:18002".parse().unwrap())?;

    let local_addr = sender.local_addr()?;

    assert_eq!(local_addr.ip().to_string(), "127.0.0.1");
    assert_eq!(local_addr.port(), 18100);

    println!("  Bound to: {}", local_addr);

    Ok(())
}

fn test_statistics() -> Result<()> {
    let receiver = UdpSocket::bind("127.0.0.1:18003")?;
    receiver.set_read_timeout(Some(Duration::from_secs(1)))?;

    let config = EgressConfig {
        track_stats: true,
        ..Default::default()
    };
    let mut sender =
        ConnectedEgressSender::new(config, "127.0.0.1:18003".parse().unwrap())?;

    // Send 5 packets
    let data = b"Stats test packet";
    let packets: Vec<&[u8]> = (0..5).map(|_| data.as_slice()).collect();
    sender.send_batch(&packets)?;

    let stats = sender.stats();

    assert_eq!(stats.packets_submitted, 5);
    assert_eq!(stats.packets_sent, 5);
    assert_eq!(stats.send_errors, 0);

    println!("  Submitted: {}", stats.packets_submitted);
    println!("  Sent: {}", stats.packets_sent);
    println!("  Errors: {}", stats.send_errors);
    println!("  Success rate: {:.2}%", stats.success_rate() * 100.0);

    // Drain receiver
    let mut buf = vec![0u8; 1500];
    for _ in 0..5 {
        let _ = receiver.recv_from(&mut buf);
    }

    Ok(())
}

fn test_packet_sizes() -> Result<()> {
    let receiver = UdpSocket::bind("127.0.0.1:18004")?;
    receiver.set_read_timeout(Some(Duration::from_secs(1)))?;

    let config = EgressConfig::default();
    let mut sender =
        ConnectedEgressSender::new(config, "127.0.0.1:18004".parse().unwrap())?;

    let sizes = [100, 500, 1000, 1500, 4000, 8000];

    for &size in &sizes {
        let data = vec![0xAB; size];
        let packets = vec![data.as_slice()];
        let sent = sender.send_batch(&packets)?;

        assert_eq!(sent, 1);

        // Receive and verify size
        let mut buf = vec![0u8; 9000];
        let (recv_size, _src) = receiver.recv_from(&mut buf)?;

        assert_eq!(recv_size, size, "Size mismatch for {} byte packet", size);

        println!("  {} bytes: OK", size);
    }

    Ok(())
}
