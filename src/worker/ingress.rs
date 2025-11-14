//! Ingress I/O Loop
use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use crate::logging::{Facility, Logger};
use crate::worker::packet_parser::parse_packet;
use crate::{ForwardingRule, RelayCommand};

use crate::worker::buffer_pool::{BufferPool, ManagedBuffer};
use crate::worker::egress::EgressWorkItem;
use crossbeam_queue::SegQueue;

// --- Traits for abstracting over backend implementations ---

/// Trait for buffers that can be mutably accessed as byte slices
pub trait BufferTrait: Deref<Target = [u8]> + DerefMut {}

// Blanket implementation for any type that satisfies the bounds
impl<T: Deref<Target = [u8]> + DerefMut> BufferTrait for T {}

pub trait BufferPoolTrait {
    type Buffer: BufferTrait;
    fn allocate(&self, size: usize) -> Option<Self::Buffer>;
}

pub trait EgressChannel {
    type Item;
    fn send(&self, item: Self::Item) -> Result<(), ()>;
}

/// Factory trait for creating egress items from buffers
pub trait EgressItemFactory<B> {
    fn new(buffer: B, payload_len: usize, interface_name: String, dest_addr: SocketAddr) -> Self;
}

// --- Concrete implementations ---

use crate::worker::buffer_pool::BufferSize;

impl BufferPoolTrait for Arc<BufferPool> {
    type Buffer = ManagedBuffer;
    fn allocate(&self, size: usize) -> Option<Self::Buffer> {
        let size_cat = if size <= 2048 {
            BufferSize::Small
        } else if size <= 4096 {
            BufferSize::Standard
        } else {
            BufferSize::Jumbo
        };
        self.acquire(size_cat)
    }
}

/// Wrapper that combines a lock-free queue with adaptive eventfd wakeup
pub struct EgressQueueWithWakeup {
    adaptive: crate::worker::adaptive_wakeup::AdaptiveWakeup,
}

impl EgressQueueWithWakeup {
    pub fn new(queue: Arc<SegQueue<EgressWorkItem>>, wakeup_fd: i32) -> Self {
        let config = crate::worker::adaptive_wakeup::AdaptiveConfig::default();
        Self {
            adaptive: crate::worker::adaptive_wakeup::AdaptiveWakeup::new(
                queue,
                wakeup_fd,
                config,
            ),
        }
    }
}

impl EgressChannel for EgressQueueWithWakeup {
    type Item = EgressWorkItem;
    fn send(&self, item: Self::Item) -> Result<(), ()> {
        self.adaptive.send(item)
    }
}

impl EgressItemFactory<ManagedBuffer> for EgressWorkItem {
    fn new(
        buffer: ManagedBuffer,
        payload_len: usize,
        interface_name: String,
        dest_addr: SocketAddr,
    ) -> Self {
        Self {
            buffer,
            payload_len,
            interface_name,
            dest_addr,
        }
    }
}

// --- Generic IngressLoop and its implementation ---

pub struct IngressLoop<P, C> {
    af_packet_socket: OwnedFd,
    helper_sockets: HashMap<(String, Ipv4Addr), StdUdpSocket>,
    ring: IoUring,
    buffer_pool: P,
    rules: HashMap<(Ipv4Addr, u16), Arc<ForwardingRule>>,
    config: IngressConfig,
    stats: IngressStats,
    egress_tx: Option<C>,
    cmd_stream_fd: OwnedFd,
    cmd_reader: crate::worker::command_reader::CommandReader,
    logger: Logger,
    first_packet_logged: bool,
}

// Common implementation for both backends
impl<P, C> IngressLoop<P, C>
where
    P: BufferPoolTrait,
    C: EgressChannel,
    C::Item: EgressItemFactory<P::Buffer>,
{
    pub fn add_rule(&mut self, rule: Arc<ForwardingRule>) -> Result<()> {
        let key = (rule.input_group, rule.input_port);
        self.rules.insert(key, rule.clone());
        // Create helper socket to send IGMP joins for this multicast group.
        // This ensures switches/routers forward the multicast traffic to our interface.
        let helper_key = (rule.input_interface.clone(), rule.input_group);
        self.helper_sockets.entry(helper_key).or_insert_with(|| {
            setup_helper_socket(&rule.input_interface, rule.input_group).unwrap()
        });
        self.logger.info(
            Facility::Ingress,
            &format!(
                "Rule added: {}:{} -> {} outputs (total rules: {})",
                rule.input_group,
                rule.input_port,
                rule.outputs.len(),
                self.rules.len()
            ),
        );
        Ok(())
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> Result<()> {
        let before_count = self.rules.len();
        self.rules.retain(|_key, rule| rule.rule_id != rule_id);
        let removed = before_count - self.rules.len();
        if removed > 0 {
            self.logger.info(
                Facility::Ingress,
                &format!(
                    "Rule removed: {} (total rules: {})",
                    rule_id,
                    self.rules.len()
                ),
            );
        }
        Ok(())
    }

    fn submit_command_read(&mut self, buf: &mut [u8]) -> Result<()> {
        let read_op = opcode::Read::new(
            types::Fd(self.cmd_stream_fd.as_raw_fd()),
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
        .build()
        .user_data(COMMAND_NOTIFY);
        unsafe {
            self.ring
                .submission()
                .push(&read_op)
                .context("Failed to push command read")?;
        }
        Ok(())
    }

    /// Process a single command. Returns true if shutdown was requested.
    fn process_single_command(&mut self, command: RelayCommand) -> Result<bool> {
        match command {
            RelayCommand::AddRule(rule) => {
                self.add_rule(Arc::new(rule))?;
                Ok(false)
            }
            RelayCommand::RemoveRule { rule_id } => {
                self.remove_rule(&rule_id)?;
                Ok(false)
            }
            RelayCommand::Shutdown => {
                self.logger.info(Facility::Ingress, "Shutdown requested");
                Ok(true)
            }
        }
    }

    /// Process commands from command reader buffer
    /// Returns true if shutdown was requested.
    fn process_commands_from_buffer(&mut self, bytes_read: usize, cmd_buffer: &[u8]) -> Result<bool> {
        let commands = self.cmd_reader.process_bytes(&cmd_buffer[..bytes_read])
            .context("Failed to parse commands")?;

        for command in commands {
            if self.process_single_command(command)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn process_packet(&mut self, packet_data: &[u8]) -> Result<()> {
        self.stats.packets_received += 1;
        self.stats.bytes_received += packet_data.len() as u64;

        // Log first packet received
        if !self.first_packet_logged {
            self.logger.debug(Facility::Ingress, "First packet received");
            self.first_packet_logged = true;
        }

        // Periodic stats logging (every 10,000 packets)
        if self.stats.packets_received % 10000 == 0 {
            let msg = format!(
                "[STATS:Ingress] recv={} matched={} egr_sent={} filtered={} no_match={} buf_exhaust={}",
                self.stats.packets_received,
                self.stats.packets_matched,
                self.stats.egress_packets_sent,
                self.stats.filtered,
                self.stats.no_rule_match,
                self.stats.buffer_exhaustion
            );
            self.logger.info(Facility::Ingress, &msg);
        }

        let headers = match parse_packet(packet_data, false) {
            Ok(h) => h,
            Err(_) => {
                self.stats.filtered += 1;
                // Sample logging: log every 100th filtered packet
                if self.stats.filtered % 100 == 0 {
                    let msg = format!("Filtered packets (non-UDP): {}", self.stats.filtered);
                    self.logger.debug(Facility::Ingress, &msg);
                }
                return Ok(());
            }
        };

        self.logger.trace(
            Facility::Ingress,
            &format!(
                "Packet: dst={}:{} len={}",
                headers.ipv4.dst_ip, headers.udp.dst_port, packet_data.len()
            ),
        );

        let key = (headers.ipv4.dst_ip, headers.udp.dst_port);
        let rule = match self.rules.get(&key) {
            Some(r) => r.clone(),
            None => {
                self.stats.no_rule_match += 1;
                // Sample logging: log every 100th miss
                if self.stats.no_rule_match % 100 == 0 {
                    let msg = format!(
                        "No rule match for {}:{} (total misses: {})",
                        headers.ipv4.dst_ip, headers.udp.dst_port, self.stats.no_rule_match
                    );
                    self.logger.debug(Facility::Ingress, &msg);
                }
                return Ok(());
            }
        };
        if rule.outputs.is_empty() {
            return Ok(());
        }

        self.stats.packets_matched += 1;

        if let Some(ref tx) = self.egress_tx {
            for output in &rule.outputs {
                let mut buffer = match self.buffer_pool.allocate(headers.payload_len) {
                    Some(b) => b,
                    None => {
                        self.stats.buffer_exhaustion += 1;
                        self.logger.critical(
                            Facility::Ingress,
                            &format!(
                                "Buffer pool exhausted! Total exhaustions: {}",
                                self.stats.buffer_exhaustion
                            ),
                        );
                        return Ok(());
                    }
                };
                let payload_end = headers.payload_offset + headers.payload_len;
                buffer[..headers.payload_len]
                    .copy_from_slice(&packet_data[headers.payload_offset..payload_end]);
                let egress_item = C::Item::new(
                    buffer,
                    headers.payload_len,
                    output.interface.clone(),
                    SocketAddr::new(output.group.into(), output.port),
                );
                self.logger.trace(
                    Facility::Ingress,
                    &format!(
                        "Forwarding to {}:{} via {}",
                        output.group, output.port, output.interface
                    ),
                );
                self.stats.egress_packets_sent += 1;
                if tx.send(egress_item).is_err() {
                    self.stats.egress_channel_errors += 1;
                    self.logger.error(
                        Facility::Ingress,
                        &format!(
                            "Egress channel send failed! Total errors: {}",
                            self.stats.egress_channel_errors
                        ),
                    );
                }
            }
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        eprintln!("[ingress-run] ENTRY: run() method started");
        std::io::stderr().flush().ok();

        let mut recv_buffers: Vec<Vec<u8>> = (0..self.config.batch_size)
            .map(|_| vec![0u8; 9000])
            .collect();
        let mut command_buffer = vec![0u8; 4096];

        eprintln!("[ingress-run] Buffers allocated");
        std::io::stderr().flush().ok();

        // *** STARTUP SYNCHRONIZATION: Wait for initial configuration ***
        // Submit command read and wait for first command via io_uring.
        // This prevents a race condition where:
        // 1. Worker starts and enters io_uring submit_and_wait(1) for packets
        // 2. Test/supervisor sends AddRule command
        // 3. Worker is blocked on packets, can't process command
        // 4. Command would join multicast group, but never processed
        // 5. No packets arrive because group not joined -> DEADLOCK

        eprintln!("[ingress-run] About to log 'Waiting for initial configuration'");
        std::io::stderr().flush().ok();

        self.logger.info(Facility::Ingress, "Waiting for initial configuration...");

        eprintln!("[ingress-run] Submitting command read and waiting for initial configuration");
        std::io::stderr().flush().ok();

        // Submit command read and block until we get a command
        self.submit_command_read(&mut command_buffer)?;

        loop {
            self.ring.submit_and_wait(1)?;

            // Look for command completion
            let cqes: Vec<_> = self
                .ring
                .completion()
                .map(|cqe| (cqe.user_data(), cqe.result()))
                .collect();

            for (user_data, result) in cqes {
                if user_data == COMMAND_NOTIFY {
                    if result > 0 {
                        // Process commands from buffer
                        if self.process_commands_from_buffer(result as usize, &command_buffer)? {
                            self.logger.info(Facility::Ingress, "Shutdown during initialization");
                            return Ok(());
                        }

                        // If we have rules now, we're initialized
                        if !self.rules.is_empty() {
                            self.logger.info(Facility::Ingress, "Initial configuration complete, entering main loop");
                            // Re-submit command read for main loop
                            self.submit_command_read(&mut command_buffer)?;
                            break;
                        } else {
                            // No rules yet, keep waiting
                            self.submit_command_read(&mut command_buffer)?;
                        }
                    } else if result == 0 {
                        // Stream closed
                        return Err(anyhow::anyhow!("Command stream closed during initialization"));
                    } else {
                        // Error
                        return Err(anyhow::anyhow!("Command read error: {}", std::io::Error::from_raw_os_error(-result)));
                    }
                }
            }

            // Break out of init loop once we have rules
            if !self.rules.is_empty() {
                break;
            }
        }

        eprintln!("[ingress-run] Initial configuration complete, entering main loop");
        std::io::stderr().flush().ok();

        loop {
            let available_buffers = self.config.batch_size - self.ring.submission().len();
            for (i, buf) in recv_buffers.iter_mut().enumerate().take(available_buffers) {
                let recv_op = opcode::Recv::new(
                    types::Fd(self.af_packet_socket.as_raw_fd()),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                )
                .build()
                .user_data(PACKET_RECV_BASE + i as u64);
                unsafe {
                    self.ring
                        .submission()
                        .push(&recv_op)
                        .context("Failed to push recv op")?;
                }
            }

            self.ring.submit_and_wait(1)?;

            // Collect completion queue entries to avoid borrow checker issues
            let cqes: Vec<_> = self
                .ring
                .completion()
                .map(|cqe| (cqe.user_data(), cqe.result()))
                .collect();

            for (user_data, result) in cqes {
                match user_data {
                    COMMAND_NOTIFY => {
                        if result > 0 {
                            // Process commands from buffer
                            if self.process_commands_from_buffer(result as usize, &command_buffer)? {
                                self.logger.info(
                                    Facility::Ingress,
                                    "Exiting run loop due to shutdown command",
                                );
                                self.print_final_stats();
                                return Ok(());
                            }
                            // Re-submit command read
                            self.submit_command_read(&mut command_buffer)?;
                        } else if result == 0 {
                            // Stream closed - supervisor disconnected
                            self.logger.info(Facility::Ingress, "Command stream closed");
                            self.print_final_stats();
                            return Ok(());
                        } else {
                            // Error
                            self.logger.error(
                                Facility::Ingress,
                                &format!("Command read error: {}", std::io::Error::from_raw_os_error(-result))
                            );
                        }
                    }
                    ud if ud >= PACKET_RECV_BASE => {
                        let buffer_idx = (ud - PACKET_RECV_BASE) as usize;
                        let bytes_received = result;
                        if bytes_received >= 0 {
                            self.process_packet(
                                &recv_buffers[buffer_idx][..bytes_received as usize],
                            )?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn print_final_stats(&self) {
        // Print final stats in the format expected by integration tests
        let msg = format!(
            "[STATS:Ingress FINAL] total: recv={} matched={} egr_sent={} filtered={} no_match={} buf_exhaust={}",
            self.stats.packets_received,
            self.stats.packets_matched,
            self.stats.egress_packets_sent,
            self.stats.filtered,
            self.stats.no_rule_match,
            self.stats.buffer_exhaustion
        );
        self.logger.info(Facility::Ingress, &msg);
    }
}

// --- Backend-specific `new` implementation ---

impl IngressLoop<Arc<BufferPool>, EgressQueueWithWakeup> {
    pub fn new(
        interface_name: &str,
        config: IngressConfig,
        buffer_pool: Arc<BufferPool>,
        egress_tx: Option<EgressQueueWithWakeup>,
        cmd_stream_fd: OwnedFd,
        logger: Logger,
    ) -> Result<Self> {
        logger.info(Facility::Ingress, "Ingress loop starting");
        Ok(Self {
            af_packet_socket: setup_af_packet_socket(interface_name)?,
            ring: IoUring::new(config.queue_depth)?,
            helper_sockets: HashMap::new(),
            buffer_pool,
            rules: HashMap::new(),
            config,
            stats: IngressStats::default(),
            egress_tx,
            cmd_stream_fd,
            cmd_reader: crate::worker::command_reader::CommandReader::new(),
            logger,
            first_packet_logged: false,
        })
    }
}

// --- Unchanged structs and helper functions ---
#[derive(Debug, Clone, Default)]
pub struct IngressStats {
    pub packets_received: u64,
    pub packets_matched: u64,
    pub filtered: u64, // Non-UDP packets (ARP, IPv6, TCP, etc.) - not an error
    pub no_rule_match: u64,
    pub buffer_exhaustion: u64,
    pub egress_channel_errors: u64,
    pub bytes_received: u64,
    pub egress_packets_sent: u64,
}
#[derive(Debug, Clone)]
pub struct IngressConfig {
    pub queue_depth: u32,
    pub batch_size: usize,
    pub track_stats: bool,
    pub buffer_pool_small: usize,
    pub buffer_pool_standard: usize,
    pub buffer_pool_jumbo: usize,
}
impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            queue_depth: 64,
            batch_size: 32,
            track_stats: true,
            buffer_pool_small: 1000,
            buffer_pool_standard: 500,
            buffer_pool_jumbo: 200,
        }
    }
}
const COMMAND_NOTIFY: u64 = 0;
const PACKET_RECV_BASE: u64 = 1;

pub fn setup_af_packet_socket(interface_name: &str) -> Result<OwnedFd> {
    // Use ETH_P_ALL (0x0003) to receive all packets, including multicast
    // Using ETH_P_IP (0x0800) only receives unicast IPv4 packets
    let socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(libc::ETH_P_ALL as i32)))?;
    socket.set_recv_buffer_size(32 * 1024 * 1024)?;
    let iface_index = get_interface_index(interface_name)?;
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = iface_index;
    unsafe {
        if libc::bind(
            socket.as_raw_fd(),
            &addr as *const _ as *const _,
            std::mem::size_of::<libc::sockaddr_ll>() as _,
        ) < 0
        {
            return Err(anyhow::anyhow!("bind failed"));
        }
    }
    Ok(socket.into())
}

pub fn setup_helper_socket(
    interface_name: &str,
    multicast_group: Ipv4Addr,
) -> Result<StdUdpSocket> {
    // Use socket2 to join multicast group by interface index instead of IP address.
    // This works reliably in network namespaces where interface IPs may not be discoverable.
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.bind(&socket2::SockAddr::from(std::net::SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        0,
    )))?;

    let interface_index = get_interface_index(interface_name)?;
    socket.join_multicast_v4_n(
        &multicast_group,
        &socket2::InterfaceIndexOrAddress::Index(interface_index as u32),
    )?;

    Ok(socket.into())
}
fn get_interface_index(name: &str) -> Result<i32> {
    let c_name = std::ffi::CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        Err(anyhow::anyhow!("not found"))
    } else {
        Ok(index as i32)
    }
}
fn get_interface_ip(name: &str) -> Result<Ipv4Addr> {
    for iface in pnet::datalink::interfaces() {
        if iface.name == name {
            for ipnet in iface.ips {
                if let std::net::IpAddr::V4(ip) = ipnet.ip() {
                    return Ok(ip);
                }
            }
        }
    }
    Err(anyhow::anyhow!("no ip"))
}
