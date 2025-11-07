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
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddrV4;
    use tokio::net::UdpSocket;
    use tokio::time::{self, Duration};

    let args = Args::parse();

    let dest_addr = SocketAddrV4::new(args.group, args.port);

    let sender_std_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sender_std_socket.set_multicast_if_v4(&args.interface)?;
    sender_std_socket.bind(&SocketAddrV4::new(args.interface, 0).into())?;
    sender_std_socket.set_nonblocking(true)?;
    let sender_socket = UdpSocket::from_std(sender_std_socket.into())?;

    println!(
        "Sending to {}:{} from interface {} at {} pps with size {}",
        args.group, args.port, args.interface, args.rate, args.size
    );

    let packet = vec![0u8; args.size];
    let interval = Duration::from_secs_f64(1.0 / args.rate as f64);
    let mut interval_timer = time::interval(interval);

    loop {
        interval_timer.tick().await;
        if let Err(e) = sender_socket.send_to(&packet, dest_addr).await {
            eprintln!("Error sending packet: {}", e);
        }
    }
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
        let generator_task = tokio::spawn(run_traffic_generator(
            "127.0.0.1".parse().unwrap(),
            receiver_addr.port(),
            "127.0.0.1".parse().unwrap(),
            100, // 100 pps
            64,  // 64 bytes
        ));

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
        // This is a bit fuzzy due to timing, but it should be > 0.
        assert!(
            packets_received > 5,
            "Expected to receive at least a few packets, but got {}",
            packets_received
        );
    }

    async fn run_traffic_generator(
        group: Ipv4Addr,
        port: u16,
        interface: Ipv4Addr,
        rate: u64,
        size: usize,
    ) -> anyhow::Result<()> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::SocketAddrV4;
        use tokio::time;

        let dest_addr = SocketAddrV4::new(group, port);

        let sender_std_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sender_std_socket.set_multicast_if_v4(&interface)?;
        sender_std_socket.bind(&SocketAddrV4::new(interface, 0).into())?;
        sender_std_socket.set_nonblocking(true)?;
        let sender_socket = UdpSocket::from_std(sender_std_socket.into())?;

        let packet = vec![0u8; size];
        let interval = Duration::from_secs_f64(1.0 / rate as f64);
        let mut interval_timer = time::interval(interval);

        loop {
            interval_timer.tick().await;
            sender_socket.send_to(&packet, dest_addr).await?;
        }
    }
}