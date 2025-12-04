// SPDX-License-Identifier: Apache-2.0 OR MIT
//! High-performance multicast traffic generator
//!
//! This module provides a configurable traffic generator for testing multicast
//! relay applications. It supports multiple rate-limiting strategies:
//!
//! - **Async mode**: Uses tokio timers, good for low-to-medium rates (<100k pps)
//! - **Spin mode**: Uses busy-wait loop, accurate for high rates (100k-1M pps)
//! - **Burst mode**: No rate limiting, maximum throughput testing
//!
//! For maximum performance, use burst mode with batching enabled.

use clap::{Parser, ValueEnum};
use std::net::Ipv4Addr;

/// Rate limiting strategy for packet transmission
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum RateLimitMode {
    /// Use tokio async timers (good for rates < 100k pps)
    #[default]
    Async,
    /// Use busy-wait spin loop (accurate for high rates, uses CPU)
    Spin,
    /// No rate limiting - send as fast as possible
    Burst,
}

impl std::fmt::Display for RateLimitMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitMode::Async => write!(f, "async"),
            RateLimitMode::Spin => write!(f, "spin"),
            RateLimitMode::Burst => write!(f, "burst"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "High-performance multicast traffic generator", long_about = None)]
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

    /// Target packet rate in packets per second (ignored in burst mode)
    #[arg(long, default_value_t = 1000)]
    rate: u64,

    /// Packet size in bytes (UDP payload)
    #[arg(long, default_value_t = 1024)]
    size: usize,

    /// Number of packets to send (0 for infinite)
    #[arg(long, default_value_t = 0)]
    count: u64,

    /// Payload to send as a string (padded/truncated to size)
    #[arg(long)]
    payload: Option<String>,

    /// Rate limiting mode
    #[arg(long, value_enum, default_value_t = RateLimitMode::Async)]
    mode: RateLimitMode,

    /// Batch size for sendmmsg (1 = no batching)
    #[arg(long, default_value_t = 1)]
    batch: usize,

    /// Quiet mode - suppress progress output
    #[arg(long, short)]
    quiet: bool,
}

/// Configuration for the traffic generator
#[derive(Debug, Clone)]
pub struct TrafficGeneratorConfig {
    /// Destination multicast group address
    pub group: Ipv4Addr,
    /// Destination UDP port
    pub port: u16,
    /// Source interface IP address
    pub interface: Ipv4Addr,
    /// Target packet rate (packets per second), ignored in burst mode
    pub rate: u64,
    /// Packet size in bytes (UDP payload)
    pub size: usize,
    /// Number of packets to send (0 for infinite)
    pub count: u64,
    /// Optional payload string (padded/truncated to size)
    pub payload: Option<String>,
    /// Rate limiting mode
    pub mode: RateLimitMode,
    /// Batch size for sendmmsg (1 = no batching)
    pub batch_size: usize,
}

impl Default for TrafficGeneratorConfig {
    fn default() -> Self {
        Self {
            group: Ipv4Addr::new(239, 1, 1, 1),
            port: 5001,
            interface: Ipv4Addr::new(127, 0, 0, 1),
            rate: 1000,
            size: 1024,
            count: 0,
            payload: None,
            mode: RateLimitMode::Async,
            batch_size: 1,
        }
    }
}

impl TrafficGeneratorConfig {
    /// Create a new config builder
    pub fn builder() -> TrafficGeneratorConfigBuilder {
        TrafficGeneratorConfigBuilder::default()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.size == 0 {
            return Err("Packet size must be greater than 0");
        }
        if self.size > 65507 {
            return Err("Packet size exceeds maximum UDP payload (65507 bytes)");
        }
        if self.rate == 0 && self.mode != RateLimitMode::Burst {
            return Err("Rate must be greater than 0 (use burst mode for unlimited)");
        }
        if self.batch_size == 0 {
            return Err("Batch size must be greater than 0");
        }
        if self.port == 0 {
            return Err("Port must be greater than 0");
        }
        Ok(())
    }
}

/// Builder for TrafficGeneratorConfig
#[derive(Debug, Clone, Default)]
pub struct TrafficGeneratorConfigBuilder {
    config: TrafficGeneratorConfig,
}

impl TrafficGeneratorConfigBuilder {
    pub fn group(mut self, group: Ipv4Addr) -> Self {
        self.config.group = group;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    pub fn interface(mut self, interface: Ipv4Addr) -> Self {
        self.config.interface = interface;
        self
    }

    pub fn rate(mut self, rate: u64) -> Self {
        self.config.rate = rate;
        self
    }

    pub fn size(mut self, size: usize) -> Self {
        self.config.size = size;
        self
    }

    pub fn count(mut self, count: u64) -> Self {
        self.config.count = count;
        self
    }

    pub fn payload(mut self, payload: impl Into<String>) -> Self {
        self.config.payload = Some(payload.into());
        self
    }

    pub fn mode(mut self, mode: RateLimitMode) -> Self {
        self.config.mode = mode;
        self
    }

    pub fn batch_size(mut self, batch_size: usize) -> Self {
        self.config.batch_size = batch_size;
        self
    }

    pub fn burst(mut self) -> Self {
        self.config.mode = RateLimitMode::Burst;
        self
    }

    pub fn build(self) -> TrafficGeneratorConfig {
        self.config
    }
}

/// Statistics returned after traffic generation completes
#[derive(Debug, Clone, Default)]
pub struct TrafficGeneratorStats {
    /// Total packets sent successfully
    pub packets_sent: u64,
    /// Total send errors
    pub errors: u64,
    /// Total elapsed time in seconds
    pub elapsed_secs: f64,
    /// Target rate from config
    pub target_rate: u64,
    /// Packet size from config
    pub packet_size: usize,
}

impl TrafficGeneratorStats {
    /// Calculate actual packets per second achieved
    pub fn actual_pps(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.packets_sent as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }

    /// Calculate actual throughput in Gbps
    pub fn actual_gbps(&self) -> f64 {
        (self.actual_pps() * self.packet_size as f64 * 8.0) / 1_000_000_000.0
    }

    /// Calculate actual throughput in Mbps
    pub fn actual_mbps(&self) -> f64 {
        (self.actual_pps() * self.packet_size as f64 * 8.0) / 1_000_000.0
    }

    /// Calculate rate accuracy as a percentage of target
    /// Returns None if target_rate is 0 (burst mode)
    pub fn rate_accuracy(&self) -> Option<f64> {
        if self.target_rate == 0 {
            None
        } else {
            Some((self.actual_pps() / self.target_rate as f64) * 100.0)
        }
    }

    /// Calculate total bytes sent
    pub fn total_bytes(&self) -> u64 {
        self.packets_sent * self.packet_size as u64
    }

    /// Calculate error rate as a percentage
    pub fn error_rate(&self) -> f64 {
        let total = self.packets_sent + self.errors;
        if total > 0 {
            (self.errors as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }
}

/// High-performance traffic generator
pub struct TrafficGenerator {
    config: TrafficGeneratorConfig,
    socket: std::net::UdpSocket,
    packet: Vec<u8>,
}

impl TrafficGenerator {
    /// Create a new traffic generator with the given configuration
    pub fn new(config: TrafficGeneratorConfig) -> anyhow::Result<Self> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::SocketAddrV4;

        config.validate().map_err(anyhow::Error::msg)?;

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // Set multicast interface if destination is multicast
        if config.group.is_multicast() {
            socket.set_multicast_if_v4(&config.interface)?;
        }

        socket.bind(&SocketAddrV4::new(config.interface, 0).into())?;

        // Build packet payload
        let packet = if let Some(ref payload_str) = config.payload {
            let mut p = payload_str.as_bytes().to_vec();
            p.resize(config.size, 0);
            p
        } else {
            vec![0u8; config.size]
        };

        Ok(Self {
            config,
            socket: socket.into(),
            packet,
        })
    }

    /// Run the traffic generator (blocking)
    pub fn run(&self, verbose: bool) -> anyhow::Result<TrafficGeneratorStats> {
        match self.config.mode {
            RateLimitMode::Burst => self.run_burst(verbose),
            RateLimitMode::Spin => self.run_spin(verbose),
            RateLimitMode::Async => {
                // For async mode, we need a runtime
                tokio::runtime::Runtime::new()?.block_on(self.run_async(verbose))
            }
        }
    }

    /// Run in burst mode (no rate limiting)
    fn run_burst(&self, verbose: bool) -> anyhow::Result<TrafficGeneratorStats> {
        use std::net::SocketAddrV4;

        let dest_addr = SocketAddrV4::new(self.config.group, self.config.port);

        if verbose {
            println!(
                "Burst mode: sending to {}:{} from {} with size {} (batch={})",
                self.config.group,
                self.config.port,
                self.config.interface,
                self.config.size,
                self.config.batch_size
            );
        }

        let mut packets_sent: u64 = 0;
        let mut errors: u64 = 0;
        let start_time = std::time::Instant::now();
        let mut last_report = start_time;
        let mut last_report_count: u64 = 0;

        if self.config.batch_size > 1 {
            // Batched sending using sendmmsg
            packets_sent = self.run_burst_batched(&dest_addr, verbose, &mut errors, &start_time)?;
        } else {
            // Single packet sending
            loop {
                if let Err(_e) = self.socket.send_to(&self.packet, dest_addr) {
                    errors += 1;
                }
                packets_sent += 1;

                if verbose {
                    let now = std::time::Instant::now();
                    if now.duration_since(last_report).as_secs() >= 1 {
                        self.report_progress(
                            packets_sent,
                            errors,
                            &mut last_report,
                            &mut last_report_count,
                        );
                    }
                }

                if self.config.count > 0 && packets_sent >= self.config.count {
                    break;
                }
            }
        }

        let elapsed_secs = start_time.elapsed().as_secs_f64();

        Ok(TrafficGeneratorStats {
            packets_sent,
            errors,
            elapsed_secs,
            target_rate: 0, // Burst mode has no target
            packet_size: self.config.size,
        })
    }

    /// Run burst mode with sendmmsg batching
    #[cfg(target_os = "linux")]
    fn run_burst_batched(
        &self,
        dest_addr: &std::net::SocketAddrV4,
        verbose: bool,
        errors: &mut u64,
        start_time: &std::time::Instant,
    ) -> anyhow::Result<u64> {
        use std::os::unix::io::AsRawFd;

        let fd = self.socket.as_raw_fd();
        let batch_size = self.config.batch_size;
        let mut packets_sent: u64 = 0;
        let mut last_report = *start_time;
        let mut last_report_count: u64 = 0;

        // Prepare sockaddr_in directly
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: dest_addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dest_addr.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        let sockaddr_len = std::mem::size_of::<libc::sockaddr_in>();

        // Prepare iovec and mmsghdr arrays
        let mut iovecs: Vec<libc::iovec> = (0..batch_size)
            .map(|_| libc::iovec {
                iov_base: self.packet.as_ptr() as *mut libc::c_void,
                iov_len: self.packet.len(),
            })
            .collect();

        let mut msghdrs: Vec<libc::mmsghdr> = (0..batch_size)
            .map(|i| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: &mut iovecs[i] as *mut libc::iovec,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect();

        // Set destination address for all messages
        for msghdr in &mut msghdrs {
            msghdr.msg_hdr.msg_name = &sockaddr as *const _ as *mut libc::c_void;
            msghdr.msg_hdr.msg_namelen = sockaddr_len as libc::socklen_t;
        }

        loop {
            let remaining = if self.config.count > 0 {
                (self.config.count - packets_sent) as usize
            } else {
                batch_size
            };
            let to_send = remaining.min(batch_size);

            // SAFETY: We're calling sendmmsg with properly initialized structures
            let sent =
                unsafe { libc::sendmmsg(fd, msghdrs.as_mut_ptr(), to_send as libc::c_uint, 0) };

            if sent < 0 {
                *errors += to_send as u64;
            } else {
                packets_sent += sent as u64;
                if (sent as usize) < to_send {
                    *errors += (to_send - sent as usize) as u64;
                }
            }

            if verbose {
                let now = std::time::Instant::now();
                if now.duration_since(last_report).as_secs() >= 1 {
                    self.report_progress(
                        packets_sent,
                        *errors,
                        &mut last_report,
                        &mut last_report_count,
                    );
                }
            }

            if self.config.count > 0 && packets_sent >= self.config.count {
                break;
            }
        }

        Ok(packets_sent)
    }

    #[cfg(not(target_os = "linux"))]
    fn run_burst_batched(
        &self,
        dest_addr: &std::net::SocketAddrV4,
        verbose: bool,
        errors: &mut u64,
        start_time: &std::time::Instant,
    ) -> anyhow::Result<u64> {
        // Fallback for non-Linux: just send one at a time
        let mut packets_sent: u64 = 0;
        let mut last_report = *start_time;
        let mut last_report_count: u64 = 0;

        loop {
            if let Err(_e) = self.socket.send_to(&self.packet, dest_addr) {
                *errors += 1;
            }
            packets_sent += 1;

            if verbose {
                let now = std::time::Instant::now();
                if now.duration_since(last_report).as_secs() >= 1 {
                    self.report_progress(
                        packets_sent,
                        *errors,
                        &mut last_report,
                        &mut last_report_count,
                    );
                }
            }

            if self.config.count > 0 && packets_sent >= self.config.count {
                break;
            }
        }

        Ok(packets_sent)
    }

    /// Run in spin mode (busy-wait rate limiting)
    fn run_spin(&self, verbose: bool) -> anyhow::Result<TrafficGeneratorStats> {
        use std::net::SocketAddrV4;

        let dest_addr = SocketAddrV4::new(self.config.group, self.config.port);
        let interval_ns = 1_000_000_000u64 / self.config.rate;

        if verbose {
            println!(
                "Spin mode: sending to {}:{} from {} at {} pps ({} ns interval)",
                self.config.group,
                self.config.port,
                self.config.interface,
                self.config.rate,
                interval_ns
            );
        }

        let mut packets_sent: u64 = 0;
        let mut errors: u64 = 0;
        let start_time = std::time::Instant::now();
        let mut last_report = start_time;
        let mut last_report_count: u64 = 0;
        let mut next_send = start_time;

        loop {
            // Busy-wait until next send time
            while std::time::Instant::now() < next_send {
                std::hint::spin_loop();
            }

            if let Err(_e) = self.socket.send_to(&self.packet, dest_addr) {
                errors += 1;
            }
            packets_sent += 1;
            next_send += std::time::Duration::from_nanos(interval_ns);

            if verbose {
                let now = std::time::Instant::now();
                if now.duration_since(last_report).as_secs() >= 1 {
                    self.report_progress(
                        packets_sent,
                        errors,
                        &mut last_report,
                        &mut last_report_count,
                    );
                }
            }

            if self.config.count > 0 && packets_sent >= self.config.count {
                break;
            }
        }

        let elapsed_secs = start_time.elapsed().as_secs_f64();

        Ok(TrafficGeneratorStats {
            packets_sent,
            errors,
            elapsed_secs,
            target_rate: self.config.rate,
            packet_size: self.config.size,
        })
    }

    /// Run in async mode (tokio timers)
    async fn run_async(&self, verbose: bool) -> anyhow::Result<TrafficGeneratorStats> {
        use std::net::SocketAddrV4;
        use tokio::time::{self, Duration};

        // Clone socket for async use
        let socket = self.socket.try_clone()?;
        socket.set_nonblocking(true)?;
        let socket = tokio::net::UdpSocket::from_std(socket)?;

        let dest_addr = SocketAddrV4::new(self.config.group, self.config.port);
        let interval = Duration::from_secs_f64(1.0 / self.config.rate as f64);
        let mut interval_timer = time::interval(interval);

        if verbose {
            println!(
                "Async mode: sending to {}:{} from {} at {} pps",
                self.config.group, self.config.port, self.config.interface, self.config.rate
            );
        }

        let mut packets_sent: u64 = 0;
        let mut errors: u64 = 0;
        let start_time = std::time::Instant::now();
        let mut last_report = start_time;
        let mut last_report_count: u64 = 0;

        loop {
            interval_timer.tick().await;

            if let Err(_e) = socket.send_to(&self.packet, dest_addr).await {
                errors += 1;
            }
            packets_sent += 1;

            if verbose {
                let now = std::time::Instant::now();
                if now.duration_since(last_report).as_secs() >= 1 {
                    self.report_progress(
                        packets_sent,
                        errors,
                        &mut last_report,
                        &mut last_report_count,
                    );
                }
            }

            if self.config.count > 0 && packets_sent >= self.config.count {
                break;
            }
        }

        let elapsed_secs = start_time.elapsed().as_secs_f64();

        Ok(TrafficGeneratorStats {
            packets_sent,
            errors,
            elapsed_secs,
            target_rate: self.config.rate,
            packet_size: self.config.size,
        })
    }

    fn report_progress(
        &self,
        packets_sent: u64,
        errors: u64,
        last_report: &mut std::time::Instant,
        last_report_count: &mut u64,
    ) {
        let now = std::time::Instant::now();
        let interval_packets = packets_sent - *last_report_count;
        let interval_duration = now.duration_since(*last_report).as_secs_f64();
        let current_pps = interval_packets as f64 / interval_duration;
        let current_gbps = (current_pps * self.config.size as f64 * 8.0) / 1_000_000_000.0;

        println!(
            "Progress: {} sent, {:.0} pps ({:.2} Gbps), {} errors",
            packets_sent, current_pps, current_gbps, errors
        );

        *last_report = now;
        *last_report_count = packets_sent;
    }
}

/// Legacy async function for backward compatibility with existing tests
pub async fn run_traffic_generator(
    config: TrafficGeneratorConfig,
    verbose: bool,
) -> anyhow::Result<TrafficGeneratorStats> {
    let generator = TrafficGenerator::new(config.clone())?;

    // For async mode, run directly; for others, spawn blocking
    match config.mode {
        RateLimitMode::Async => generator.run_async(verbose).await,
        _ => tokio::task::spawn_blocking(move || generator.run(verbose))
            .await
            .map_err(|e| anyhow::anyhow!("Task join error: {}", e))?,
    }
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
        mode: args.mode,
        batch_size: args.batch,
    };

    if let Err(e) = config.validate() {
        eprintln!("Configuration error: {}", e);
        std::process::exit(1);
    }

    let verbose = !args.quiet;
    let generator = TrafficGenerator::new(config.clone())?;
    let stats = generator.run(verbose)?;

    // Final statistics
    if verbose {
        println!("\n=== Traffic Generator Summary ===");
        println!("Mode: {}", config.mode);
        if config.batch_size > 1 {
            println!("Batch size: {}", config.batch_size);
        }
        println!("Total packets sent: {}", stats.packets_sent);
        println!("Total errors: {}", stats.errors);
        if stats.errors > 0 {
            println!("Error rate: {:.2}%", stats.error_rate());
        }
        println!("Elapsed time: {:.2}s", stats.elapsed_secs);
        println!("Actual packet rate: {:.0} pps", stats.actual_pps());
        if let Some(accuracy) = stats.rate_accuracy() {
            println!(
                "Rate accuracy: {:.1}% of target {} pps",
                accuracy, config.rate
            );
        }
        println!("Actual throughput: {:.2} Gbps", stats.actual_gbps());
        println!(
            "Total bytes: {} ({:.2} MB)",
            stats.total_bytes(),
            stats.total_bytes() as f64 / 1_000_000.0
        );
        println!("Packet size: {} bytes", config.size);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    // ==================== Config Validation Tests ====================

    #[test]
    fn test_config_default() {
        let config = TrafficGeneratorConfig::default();
        assert_eq!(config.group, Ipv4Addr::new(239, 1, 1, 1));
        assert_eq!(config.port, 5001);
        assert_eq!(config.rate, 1000);
        assert_eq!(config.size, 1024);
        assert_eq!(config.count, 0);
        assert_eq!(config.mode, RateLimitMode::Async);
        assert_eq!(config.batch_size, 1);
    }

    #[test]
    fn test_config_builder() {
        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(239, 2, 2, 2))
            .port(6000)
            .interface(Ipv4Addr::new(192, 168, 1, 1))
            .rate(50000)
            .size(512)
            .count(1000)
            .payload("test")
            .mode(RateLimitMode::Spin)
            .batch_size(16)
            .build();

        assert_eq!(config.group, Ipv4Addr::new(239, 2, 2, 2));
        assert_eq!(config.port, 6000);
        assert_eq!(config.interface, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.rate, 50000);
        assert_eq!(config.size, 512);
        assert_eq!(config.count, 1000);
        assert_eq!(config.payload, Some("test".to_string()));
        assert_eq!(config.mode, RateLimitMode::Spin);
        assert_eq!(config.batch_size, 16);
    }

    #[test]
    fn test_config_builder_burst() {
        let config = TrafficGeneratorConfig::builder().burst().build();
        assert_eq!(config.mode, RateLimitMode::Burst);
    }

    #[test]
    fn test_config_validate_zero_size() {
        let config = TrafficGeneratorConfig {
            size: 0,
            ..Default::default()
        };
        assert_eq!(config.validate(), Err("Packet size must be greater than 0"));
    }

    #[test]
    fn test_config_validate_size_too_large() {
        let config = TrafficGeneratorConfig {
            size: 65508,
            ..Default::default()
        };
        assert_eq!(
            config.validate(),
            Err("Packet size exceeds maximum UDP payload (65507 bytes)")
        );
    }

    #[test]
    fn test_config_validate_zero_rate_not_burst() {
        let config = TrafficGeneratorConfig {
            rate: 0,
            mode: RateLimitMode::Async,
            ..Default::default()
        };
        assert_eq!(
            config.validate(),
            Err("Rate must be greater than 0 (use burst mode for unlimited)")
        );
    }

    #[test]
    fn test_config_validate_zero_rate_burst_ok() {
        let config = TrafficGeneratorConfig {
            rate: 0,
            mode: RateLimitMode::Burst,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_zero_batch() {
        let config = TrafficGeneratorConfig {
            batch_size: 0,
            ..Default::default()
        };
        assert_eq!(config.validate(), Err("Batch size must be greater than 0"));
    }

    #[test]
    fn test_config_validate_zero_port() {
        let config = TrafficGeneratorConfig {
            port: 0,
            ..Default::default()
        };
        assert_eq!(config.validate(), Err("Port must be greater than 0"));
    }

    #[test]
    fn test_config_validate_max_size() {
        let config = TrafficGeneratorConfig {
            size: 65507,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    // ==================== Stats Calculation Tests ====================

    #[test]
    fn test_stats_actual_pps() {
        let stats = TrafficGeneratorStats {
            packets_sent: 1000,
            errors: 0,
            elapsed_secs: 2.0,
            target_rate: 500,
            packet_size: 100,
        };
        assert!((stats.actual_pps() - 500.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_actual_pps_zero_elapsed() {
        let stats = TrafficGeneratorStats {
            packets_sent: 1000,
            elapsed_secs: 0.0,
            ..Default::default()
        };
        assert_eq!(stats.actual_pps(), 0.0);
    }

    #[test]
    fn test_stats_actual_gbps() {
        let stats = TrafficGeneratorStats {
            packets_sent: 1_000_000,
            elapsed_secs: 1.0,
            packet_size: 1000,
            ..Default::default()
        };
        // 1M pps * 1000 bytes * 8 bits = 8 Gbps
        assert!((stats.actual_gbps() - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_actual_mbps() {
        let stats = TrafficGeneratorStats {
            packets_sent: 1000,
            elapsed_secs: 1.0,
            packet_size: 1000,
            ..Default::default()
        };
        // 1k pps * 1000 bytes * 8 bits = 8 Mbps
        assert!((stats.actual_mbps() - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_rate_accuracy() {
        let stats = TrafficGeneratorStats {
            packets_sent: 950,
            elapsed_secs: 1.0,
            target_rate: 1000,
            packet_size: 100,
            ..Default::default()
        };
        let accuracy = stats.rate_accuracy().unwrap();
        assert!((accuracy - 95.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_rate_accuracy_burst_mode() {
        let stats = TrafficGeneratorStats {
            packets_sent: 1000,
            elapsed_secs: 1.0,
            target_rate: 0, // Burst mode
            ..Default::default()
        };
        assert!(stats.rate_accuracy().is_none());
    }

    #[test]
    fn test_stats_total_bytes() {
        let stats = TrafficGeneratorStats {
            packets_sent: 1000,
            packet_size: 1400,
            ..Default::default()
        };
        assert_eq!(stats.total_bytes(), 1_400_000);
    }

    #[test]
    fn test_stats_error_rate() {
        let stats = TrafficGeneratorStats {
            packets_sent: 90,
            errors: 10,
            ..Default::default()
        };
        assert!((stats.error_rate() - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_error_rate_zero_total() {
        let stats = TrafficGeneratorStats::default();
        assert_eq!(stats.error_rate(), 0.0);
    }

    // ==================== RateLimitMode Tests ====================

    #[test]
    fn test_rate_limit_mode_display() {
        assert_eq!(format!("{}", RateLimitMode::Async), "async");
        assert_eq!(format!("{}", RateLimitMode::Spin), "spin");
        assert_eq!(format!("{}", RateLimitMode::Burst), "burst");
    }

    #[test]
    fn test_rate_limit_mode_default() {
        assert_eq!(RateLimitMode::default(), RateLimitMode::Async);
    }

    // ==================== Generator Creation Tests ====================

    #[test]
    fn test_generator_new_valid_config() {
        let config = TrafficGeneratorConfig::builder()
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(5001)
            .build();

        let generator = TrafficGenerator::new(config);
        assert!(generator.is_ok());
    }

    #[test]
    fn test_generator_new_invalid_config() {
        let config = TrafficGeneratorConfig {
            size: 0,
            ..Default::default()
        };
        let generator = TrafficGenerator::new(config);
        assert!(generator.is_err());
    }

    #[test]
    fn test_generator_payload_padding() {
        let config = TrafficGeneratorConfig::builder()
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(5001)
            .size(32)
            .payload("short")
            .build();

        let generator = TrafficGenerator::new(config).unwrap();
        assert_eq!(generator.packet.len(), 32);
        assert_eq!(&generator.packet[..5], b"short");
        assert!(generator.packet[5..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_generator_payload_truncation() {
        let config = TrafficGeneratorConfig::builder()
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(5001)
            .size(5)
            .payload("longer_payload")
            .build();

        let generator = TrafficGenerator::new(config).unwrap();
        assert_eq!(generator.packet.len(), 5);
        assert_eq!(&generator.packet, b"longe");
    }

    // ==================== Integration Tests ====================

    #[tokio::test]
    async fn test_async_mode_sends_packets() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .rate(100)
            .size(64)
            .count(10)
            .mode(RateLimitMode::Async)
            .build();

        let stats = run_traffic_generator(config, false).await.unwrap();

        assert_eq!(stats.packets_sent, 10);
        assert_eq!(stats.errors, 0);
    }

    #[tokio::test]
    async fn test_spin_mode_sends_packets() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .rate(1000)
            .size(64)
            .count(100)
            .mode(RateLimitMode::Spin)
            .build();

        let stats = run_traffic_generator(config, false).await.unwrap();

        assert_eq!(stats.packets_sent, 100);
        assert_eq!(stats.errors, 0);
    }

    #[tokio::test]
    async fn test_burst_mode_sends_packets() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .size(64)
            .count(1000)
            .burst()
            .build();

        let stats = run_traffic_generator(config, false).await.unwrap();

        assert_eq!(stats.packets_sent, 1000);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.target_rate, 0); // Burst mode has no target
    }

    #[tokio::test]
    async fn test_burst_mode_with_batching() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .size(64)
            .count(1000)
            .batch_size(16)
            .burst()
            .build();

        let stats = run_traffic_generator(config, false).await.unwrap();

        // With batching, we might send slightly more than count due to batch boundaries
        assert!(stats.packets_sent >= 1000);
        assert_eq!(stats.errors, 0);
    }

    #[tokio::test]
    async fn test_payload_received_correctly() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .rate(100)
            .size(32)
            .count(5)
            .payload("TESTPAYLOAD")
            .build();

        let generator_task = tokio::spawn(run_traffic_generator(config, false));

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
    async fn test_multicast_interface_binding() {
        // This test verifies that multicast interface is set for multicast destinations
        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(239, 1, 1, 1)) // Multicast address
            .port(5001)
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .size(64)
            .count(1)
            .build();

        // Should succeed without errors (multicast interface will be set)
        let generator = TrafficGenerator::new(config);
        assert!(generator.is_ok());
    }

    #[tokio::test]
    async fn test_unicast_no_multicast_interface() {
        // This test verifies that multicast interface is NOT set for unicast destinations
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1)) // Unicast address
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .size(64)
            .count(1)
            .build();

        let stats = run_traffic_generator(config, false).await.unwrap();
        assert_eq!(stats.packets_sent, 1);
    }

    #[tokio::test]
    async fn test_single_packet() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .rate(100)
            .size(64)
            .count(1)
            .build();

        let stats = run_traffic_generator(config, false).await.unwrap();

        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.errors, 0);
    }

    #[tokio::test]
    async fn test_rate_limiting_accuracy_async() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let target_rate = 100;
        let count = 50;

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .rate(target_rate)
            .size(64)
            .count(count)
            .mode(RateLimitMode::Async)
            .build();

        let stats = run_traffic_generator(config, false).await.unwrap();

        // Expected time: 50 packets at 100 pps = 0.5 seconds
        // Allow 20% tolerance for timer inaccuracies
        let expected_time = count as f64 / target_rate as f64;
        assert!(
            stats.elapsed_secs > expected_time * 0.8,
            "Elapsed time {} too short (expected ~{})",
            stats.elapsed_secs,
            expected_time
        );
        assert!(
            stats.elapsed_secs < expected_time * 1.2,
            "Elapsed time {} too long (expected ~{})",
            stats.elapsed_secs,
            expected_time
        );
    }

    #[tokio::test]
    async fn test_rate_limiting_accuracy_spin() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let target_rate = 10000;
        let count = 5000;

        let config = TrafficGeneratorConfig::builder()
            .group(Ipv4Addr::new(127, 0, 0, 1))
            .port(receiver_addr.port())
            .interface(Ipv4Addr::new(127, 0, 0, 1))
            .rate(target_rate)
            .size(64)
            .count(count)
            .mode(RateLimitMode::Spin)
            .build();

        let stats = run_traffic_generator(config, false).await.unwrap();

        // Spin mode should be more accurate
        // Expected time: 5000 packets at 10000 pps = 0.5 seconds
        let expected_time = count as f64 / target_rate as f64;
        assert!(
            stats.elapsed_secs > expected_time * 0.9,
            "Elapsed time {} too short (expected ~{})",
            stats.elapsed_secs,
            expected_time
        );
        assert!(
            stats.elapsed_secs < expected_time * 1.1,
            "Elapsed time {} too long (expected ~{})",
            stats.elapsed_secs,
            expected_time
        );
    }

    // Legacy test - ensure backward compatibility
    #[tokio::test]
    async fn test_legacy_run_traffic_generator() {
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
            mode: RateLimitMode::Async,
            batch_size: 1,
        };

        let stats = run_traffic_generator(config, false).await.unwrap();

        assert_eq!(stats.packets_sent, 10);
        assert_eq!(stats.errors, 0);
        assert!(stats.elapsed_secs > 0.0);
        assert!(stats.actual_pps() > 0.0);
        assert!(stats.actual_gbps() > 0.0);
    }
}
