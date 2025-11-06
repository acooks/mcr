use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub input_group: Option<Ipv4Addr>,
    #[arg(long)]
    pub input_port: Option<u16>,
    #[arg(long)]
    pub output_group: Option<Ipv4Addr>,
    #[arg(long)]
    pub output_port: Option<u16>,
    #[arg(long)]
    pub output_interface: Option<Ipv4Addr>,
    #[arg(long)]
    pub input_interface_name: Option<String>,
    #[arg(long, default_value_t = 5)]
    pub reporting_interval: u64,
    #[arg(long, default_value = "127.0.0.1:9090")]
    pub prometheus_addr: SocketAddr,
}
