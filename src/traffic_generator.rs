// SPDX-License-Identifier: Apache-2.0 OR MIT
use clap::Parser;
use std::net::Ipv4Addr;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Multicast group IP address to send to
    #[arg(long)]
    group: Ipv4Addr,

    /// Port to send to
    #[arg(long)]
    port: u16,

    /// Local interface IP address to send from
    #[arg(long)]
    interface: Ipv4Addr,

    /// Packet rate in packets per second
    #[arg(long, default_value_t = 1000)]
    rate: u64,

    /// Packet size in bytes
    #[arg(long, default_value_t = 1024)]
    size: usize,

    /// Number of packets to send (0 for infinite)
    #[arg(long, default_value_t = 0)]
    count: u64,

    /// Payload to send as a string
    #[arg(long)]
    payload: Option<String>,
}

/// Configuration for the traffic generator
#[derive(Debug, Clone)]
pub struct TrafficGeneratorConfig {
    pub group: Ipv4Addr,
    pub port: u16,
    pub interface: Ipv4Addr,
    pub rate: u64,
    pub size: usize,
    pub count: u64,
    pub payload: Option<String>,
}

/// Statistics returned after traffic generation completes
#[derive(Debug, Clone)]
pub struct TrafficGeneratorStats {
    pub packets_sent: u64,
    pub errors: u64,
    pub elapsed_secs: f64,
}

impl TrafficGeneratorStats {
    pub fn actual_pps(&self) -> f64 {
        self.packets_sent as f64 / self.elapsed_secs
    }

    pub fn actual_gbps(&self, packet_size: usize) -> f64 {
        (self.actual_pps() * packet_size as f64 * 8.0) / 1_000_000_000.0
    }
}

/// Core traffic generation logic - used by both CLI and tests
pub async fn run_traffic_generator(
    config: TrafficGeneratorConfig,
    verbose: bool,
) -> anyhow::Result<TrafficGeneratorStats> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddrV4;
    use tokio::net::UdpSocket;
    use tokio::time::{self, Duration};

    let dest_addr = SocketAddrV4::new(config.group, config.port);

    let sender_std_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    // Only set multicast interface if destination is a multicast address (224.0.0.0/4)
    if config.group.is_multicast() {
        sender_std_socket.set_multicast_if_v4(&config.interface)?;
    }

    sender_std_socket.bind(&SocketAddrV4::new(config.interface, 0).into())?;
    sender_std_socket.set_nonblocking(true)?;
    let sender_socket = UdpSocket::from_std(sender_std_socket.into())?;

    if verbose {
        println!(
            "Sending to {}:{} from interface {} at {} pps with size {}",
            config.group, config.port, config.interface, config.rate, config.size
        );
    }

    let packet = if let Some(payload_str) = config.payload {
        let mut p = payload_str.into_bytes();
        p.resize(config.size, 0);
        p
    } else {
        vec![0u8; config.size]
    };

    let interval = Duration::from_secs_f64(1.0 / config.rate as f64);
    let mut interval_timer = time::interval(interval);

    let mut packets_sent = 0;
    let mut errors = 0;
    let start_time = std::time::Instant::now();
    let mut last_report = start_time;
    let mut last_report_count = 0;

    loop {
        interval_timer.tick().await;
        if let Err(e) = sender_socket.send_to(&packet, dest_addr).await {
            errors += 1;
            if errors <= 10 {
                eprintln!("Error sending packet: {}", e);
            }
        }
        packets_sent += 1;

        // Progress reporting every second (only in verbose mode)
        if verbose {
            let now = std::time::Instant::now();
            if now.duration_since(last_report).as_secs() >= 1 {
                let interval_packets = packets_sent - last_report_count;
                let interval_duration = now.duration_since(last_report).as_secs_f64();
                let current_pps = interval_packets as f64 / interval_duration;
                let current_gbps = (current_pps * config.size as f64 * 8.0) / 1_000_000_000.0;
                println!(
                    "Progress: {} packets sent, current rate: {:.0} pps ({:.2} Gbps), errors: {}",
                    packets_sent, current_pps, current_gbps, errors
                );
                last_report = now;
                last_report_count = packets_sent;
            }
        }

        if config.count > 0 && packets_sent >= config.count {
            break;
        }
    }

    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();

    Ok(TrafficGeneratorStats {
        packets_sent,
        errors,
        elapsed_secs,
    })
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let config = TrafficGeneratorConfig {
        group: args.group,
        port: args.port,
        interface: args.interface,
        rate: args.rate,
        size: args.size,
        count: args.count,
        payload: args.payload,
    };

    let stats = run_traffic_generator(config.clone(), true).await?;

    // Final statistics
    println!("\n=== Traffic Generator Summary ===");
    println!("Total packets sent: {}", stats.packets_sent);
    println!("Total errors: {}", stats.errors);
    println!("Elapsed time: {:.2}s", stats.elapsed_secs);
    println!(
        "Actual packet rate: {:.0} pps (target: {} pps)",
        stats.actual_pps(),
        config.rate
    );
    println!(
        "Actual throughput: {:.2} Gbps",
        stats.actual_gbps(config.size)
    );
    println!("Packet size: {} bytes", config.size);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_traffic_generator_sends_packets() {
        // 1. Setup: Bind a UDP socket to a random port on localhost to act as the receiver.
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        // 2. Action: Run the traffic generator's core logic in a separate task.
        let config = TrafficGeneratorConfig {
            group: "127.0.0.1".parse().unwrap(),
            port: receiver_addr.port(),
            interface: "127.0.0.1".parse().unwrap(),
            rate: 100,
            size: 64,
            count: 0, // infinite
            payload: None,
        };

        let generator_task = tokio::spawn(run_traffic_generator(config, false));

        // 3. Verification: Try to receive a few packets.
        let mut packets_received = 0;
        let mut recv_buf = [0u8; 128];

        // We expect to receive ~10 packets in 100ms.
        let reception_timeout = Duration::from_millis(100);
        let start_time = tokio::time::Instant::now();

        while start_time.elapsed() < reception_timeout {
            match timeout(Duration::from_millis(10), receiver.recv_from(&mut recv_buf)).await {
                Ok(Ok((len, _))) => {
                    assert_eq!(len, 64);
                    packets_received += 1;
                }
                _ => {
                    // Timeout or error, continue loop
                }
            }
        }

        // 4. Cleanup: Abort the generator task.
        generator_task.abort();

        // Assert that we received a reasonable number of packets for the time window.
        assert!(
            packets_received > 5,
            "Expected to receive at least a few packets, but got {}",
            packets_received
        );
    }

    #[tokio::test]
    async fn test_traffic_generator_with_payload() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig {
            group: "127.0.0.1".parse().unwrap(),
            port: receiver_addr.port(),
            interface: "127.0.0.1".parse().unwrap(),
            rate: 100,
            size: 32,
            count: 5,
            payload: Some("TESTPAYLOAD".to_string()),
        };

        let generator_task = tokio::spawn(run_traffic_generator(config, false));

        // Receive packets and verify payload
        let mut recv_buf = [0u8; 64];
        let mut received_with_correct_payload = 0;

        for _ in 0..5 {
            match timeout(
                Duration::from_millis(500),
                receiver.recv_from(&mut recv_buf),
            )
            .await
            {
                Ok(Ok((len, _))) => {
                    assert_eq!(len, 32);
                    // Check that payload starts with "TESTPAYLOAD"
                    if &recv_buf[..11] == b"TESTPAYLOAD" {
                        received_with_correct_payload += 1;
                    }
                }
                _ => break,
            }
        }

        let _ = generator_task.await;

        assert!(
            received_with_correct_payload >= 3,
            "Expected at least 3 packets with correct payload, got {}",
            received_with_correct_payload
        );
    }

    #[tokio::test]
    async fn test_traffic_generator_stats() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig {
            group: "127.0.0.1".parse().unwrap(),
            port: receiver_addr.port(),
            interface: "127.0.0.1".parse().unwrap(),
            rate: 1000,
            size: 100,
            count: 10,
            payload: None,
        };

        let stats = run_traffic_generator(config, false).await.unwrap();

        assert_eq!(stats.packets_sent, 10);
        assert_eq!(stats.errors, 0);
        assert!(stats.elapsed_secs > 0.0);
        assert!(stats.actual_pps() > 0.0);
        assert!(stats.actual_gbps(100) > 0.0);
    }
}
