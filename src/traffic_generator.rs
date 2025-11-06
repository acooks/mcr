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
