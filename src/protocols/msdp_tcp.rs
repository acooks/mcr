// SPDX-License-Identifier: Apache-2.0 OR MIT
//! MSDP TCP Connection Management
//!
//! This module handles TCP connections for MSDP (port 639).
//! It implements the active/passive connection model where the router
//! with the higher IP address initiates the connection.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use super::msdp::{MsdpHeader, MsdpKeepaliveBuilder, MsdpSaBuilder, MSDP_PORT};
use super::{PacketBuilder, ProtocolEvent, TimerRequest};

/// Maximum MSDP message size (64KB should be plenty)
const MAX_MESSAGE_SIZE: usize = 65535;

/// Buffer size for reading from TCP socket
const READ_BUFFER_SIZE: usize = 8192;

/// A single MSDP peer TCP connection
pub struct MsdpConnection {
    /// The peer's address
    pub peer_addr: Ipv4Addr,
    /// TCP stream
    pub stream: TcpStream,
    /// Read buffer for incomplete messages
    pub read_buffer: Vec<u8>,
    /// Whether we initiated this connection (active) or received it (passive)
    pub is_active: bool,
    /// When the connection was established
    pub established_at: Instant,
}

impl MsdpConnection {
    /// Create a new connection from an established TCP stream
    pub fn new(peer_addr: Ipv4Addr, stream: TcpStream, is_active: bool) -> Self {
        Self {
            peer_addr,
            stream,
            read_buffer: Vec::with_capacity(READ_BUFFER_SIZE),
            is_active,
            established_at: Instant::now(),
        }
    }

    /// Read and parse MSDP messages from the connection
    ///
    /// Returns a vector of (message_type, payload) tuples for complete messages
    pub async fn read_messages(&mut self) -> io::Result<Vec<(u8, Vec<u8>)>> {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let n = self.stream.read(&mut buf).await?;

        if n == 0 {
            // Connection closed
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection closed",
            ));
        }

        // Append to read buffer
        self.read_buffer.extend_from_slice(&buf[..n]);

        // Parse complete messages
        let mut messages = Vec::new();
        while self.read_buffer.len() >= MsdpHeader::SIZE {
            // Parse header
            let header = match MsdpHeader::parse(&self.read_buffer) {
                Some(h) => h,
                None => break,
            };

            // Check if we have the complete message
            let msg_len = header.length as usize;
            if msg_len > MAX_MESSAGE_SIZE {
                // Message too large - protocol error
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("message too large: {} bytes", msg_len),
                ));
            }

            if self.read_buffer.len() < msg_len {
                // Incomplete message, wait for more data
                break;
            }

            // Extract the complete message
            let msg_type = header.msg_type;
            let payload = self.read_buffer[MsdpHeader::SIZE..msg_len].to_vec();
            messages.push((msg_type, payload));

            // Remove processed message from buffer
            self.read_buffer.drain(..msg_len);
        }

        Ok(messages)
    }

    /// Send an MSDP message
    pub async fn send_message(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data).await
    }

    /// Send a keepalive message
    pub async fn send_keepalive(&mut self) -> io::Result<()> {
        let builder = MsdpKeepaliveBuilder::new();
        let packet = builder.build();
        self.send_message(&packet).await
    }

    /// Send an SA message
    pub async fn send_sa(
        &mut self,
        rp_address: Ipv4Addr,
        entries: &[(Ipv4Addr, Ipv4Addr)],
    ) -> io::Result<()> {
        let mut builder = MsdpSaBuilder::new(rp_address);
        for &(source, group) in entries {
            builder.add_entry(source, group);
        }
        let packet = builder.build();
        self.send_message(&packet).await
    }
}

/// MSDP Connection Manager
///
/// Manages all TCP connections to MSDP peers, including:
/// - Listening for incoming connections (passive)
/// - Initiating outgoing connections (active)
/// - Connection collision detection and resolution
pub struct MsdpConnectionManager {
    /// Our local address for MSDP
    pub local_address: Ipv4Addr,
    /// Active connections, keyed by peer address
    pub connections: HashMap<Ipv4Addr, Arc<Mutex<MsdpConnection>>>,
    /// Channel to send protocol events to the state machine
    pub event_tx: mpsc::Sender<ProtocolEvent>,
    /// Channel to request timer scheduling
    pub timer_tx: mpsc::Sender<TimerRequest>,
    /// Whether the manager is running
    pub running: bool,
}

impl MsdpConnectionManager {
    /// Create a new connection manager
    pub fn new(
        local_address: Ipv4Addr,
        event_tx: mpsc::Sender<ProtocolEvent>,
        timer_tx: mpsc::Sender<TimerRequest>,
    ) -> Self {
        Self {
            local_address,
            connections: HashMap::new(),
            event_tx,
            timer_tx,
            running: false,
        }
    }

    /// Determine if we should initiate (active) connection to a peer
    ///
    /// RFC 3618: The speaker with the higher IP address initiates the connection
    pub fn should_initiate_connection(&self, peer_addr: Ipv4Addr) -> bool {
        self.local_address > peer_addr
    }

    /// Attempt to connect to a peer (active connection)
    pub async fn connect_to_peer(&mut self, peer_addr: Ipv4Addr) -> io::Result<()> {
        // Check if we already have a connection
        if self.connections.contains_key(&peer_addr) {
            return Ok(());
        }

        // Only initiate if we have the higher IP
        if !self.should_initiate_connection(peer_addr) {
            // We should wait for the peer to connect to us
            return Ok(());
        }

        let socket_addr = SocketAddr::V4(SocketAddrV4::new(peer_addr, MSDP_PORT));

        match TcpStream::connect(socket_addr).await {
            Ok(stream) => {
                let conn = MsdpConnection::new(peer_addr, stream, true);
                self.connections
                    .insert(peer_addr, Arc::new(Mutex::new(conn)));

                // Notify state machine
                let _ = self
                    .event_tx
                    .send(ProtocolEvent::Msdp(
                        super::msdp::MsdpEvent::TcpConnectionEstablished {
                            peer: peer_addr,
                            is_active: true,
                        },
                    ))
                    .await;

                Ok(())
            }
            Err(e) => {
                // Notify state machine of failure
                let _ = self
                    .event_tx
                    .send(ProtocolEvent::Msdp(
                        super::msdp::MsdpEvent::TcpConnectionFailed {
                            peer: peer_addr,
                            reason: e.to_string(),
                        },
                    ))
                    .await;

                Err(e)
            }
        }
    }

    /// Handle an incoming connection
    pub async fn handle_incoming_connection(
        &mut self,
        stream: TcpStream,
        peer_socket: SocketAddr,
    ) -> io::Result<()> {
        let peer_addr = match peer_socket {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => {
                // MSDP doesn't support IPv6
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "MSDP does not support IPv6",
                ));
            }
        };

        // Check for connection collision
        if let Some(existing) = self.connections.get(&peer_addr) {
            let existing_conn = existing.lock().await;

            // Connection collision resolution:
            // The connection initiated by the higher IP wins
            if self.should_initiate_connection(peer_addr) {
                // We have higher IP, so our active connection wins
                // Reject this incoming connection
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "connection collision - keeping active connection",
                ));
            } else {
                // Peer has higher IP, so this incoming connection wins
                // Close our existing connection
                drop(existing_conn);
                self.connections.remove(&peer_addr);
            }
        }

        // Accept the incoming connection
        let conn = MsdpConnection::new(peer_addr, stream, false);
        self.connections
            .insert(peer_addr, Arc::new(Mutex::new(conn)));

        // Notify state machine
        let _ = self
            .event_tx
            .send(ProtocolEvent::Msdp(
                super::msdp::MsdpEvent::TcpConnectionEstablished {
                    peer: peer_addr,
                    is_active: false,
                },
            ))
            .await;

        Ok(())
    }

    /// Remove a connection
    pub fn remove_connection(&mut self, peer_addr: Ipv4Addr) {
        self.connections.remove(&peer_addr);
    }

    /// Get a connection to a peer
    pub fn get_connection(&self, peer_addr: Ipv4Addr) -> Option<Arc<Mutex<MsdpConnection>>> {
        self.connections.get(&peer_addr).cloned()
    }

    /// Send a keepalive to a peer
    pub async fn send_keepalive(&self, peer_addr: Ipv4Addr) -> io::Result<()> {
        if let Some(conn) = self.connections.get(&peer_addr) {
            let mut conn = conn.lock().await;
            conn.send_keepalive().await
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "peer not connected",
            ))
        }
    }

    /// Send an SA message to a peer
    pub async fn send_sa(
        &self,
        peer_addr: Ipv4Addr,
        rp_address: Ipv4Addr,
        entries: &[(Ipv4Addr, Ipv4Addr)],
    ) -> io::Result<()> {
        if let Some(conn) = self.connections.get(&peer_addr) {
            let mut conn = conn.lock().await;
            conn.send_sa(rp_address, entries).await
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "peer not connected",
            ))
        }
    }

    /// Send an SA message to all connected peers (for flooding)
    pub async fn flood_sa(
        &self,
        rp_address: Ipv4Addr,
        entries: &[(Ipv4Addr, Ipv4Addr)],
        exclude_peer: Option<Ipv4Addr>,
    ) -> Vec<io::Result<Ipv4Addr>> {
        let mut results = Vec::new();

        for (&peer_addr, conn) in &self.connections {
            // Don't flood back to the peer we learned from
            if Some(peer_addr) == exclude_peer {
                continue;
            }

            let mut conn = conn.lock().await;
            match conn.send_sa(rp_address, entries).await {
                Ok(()) => results.push(Ok(peer_addr)),
                Err(e) => results.push(Err(e)),
            }
        }

        results
    }

    /// Get list of connected peer addresses
    pub fn connected_peers(&self) -> Vec<Ipv4Addr> {
        self.connections.keys().copied().collect()
    }
}

/// Start the MSDP TCP listener
///
/// This function starts listening on port 639 for incoming MSDP connections.
/// Returns a JoinHandle for the listener task and a channel to send stop signal.
pub async fn start_msdp_listener(
    local_address: Ipv4Addr,
    _event_tx: mpsc::Sender<ProtocolEvent>,
) -> io::Result<(
    tokio::task::JoinHandle<()>,
    mpsc::Sender<()>,
    mpsc::Receiver<(TcpStream, SocketAddr)>,
)> {
    let listen_addr = SocketAddr::V4(SocketAddrV4::new(local_address, MSDP_PORT));
    let listener = TcpListener::bind(listen_addr).await?;

    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let (conn_tx, conn_rx) = mpsc::channel::<(TcpStream, SocketAddr)>(16);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.recv() => {
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            // Send the new connection to be processed
                            if conn_tx.send((stream, addr)).await.is_err() {
                                // Receiver dropped, stop listening
                                break;
                            }
                        }
                        Err(e) => {
                            // Log error but continue listening
                            eprintln!("MSDP listener error: {}", e);
                        }
                    }
                }
            }
        }
    });

    Ok((handle, stop_tx, conn_rx))
}

/// Process messages from an MSDP connection
///
/// This function reads messages from a connection and sends events to the state machine.
pub async fn process_connection_messages(
    conn: Arc<Mutex<MsdpConnection>>,
    event_tx: mpsc::Sender<ProtocolEvent>,
) -> io::Result<()> {
    let peer_addr = {
        let conn = conn.lock().await;
        conn.peer_addr
    };

    loop {
        let messages = {
            let mut conn = conn.lock().await;
            conn.read_messages().await?
        };

        for (msg_type, payload) in messages {
            let event = ProtocolEvent::Msdp(super::msdp::MsdpEvent::MessageReceived {
                peer: peer_addr,
                msg_type,
                payload,
            });

            if event_tx.send(event).await.is_err() {
                // Event channel closed
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "event channel closed",
                ));
            }
        }
    }
}

/// Commands that can be sent to the MSDP TCP runner
#[derive(Debug)]
pub enum MsdpTcpCommand {
    /// Attempt to connect to a peer
    Connect { peer: Ipv4Addr },
    /// Send a keepalive to a peer
    SendKeepalive { peer: Ipv4Addr },
    /// Send an SA message to a peer
    SendSa {
        peer: Ipv4Addr,
        rp_address: Ipv4Addr,
        entries: Vec<(Ipv4Addr, Ipv4Addr)>,
    },
    /// Flood SA to all peers (except excluded)
    FloodSa {
        rp_address: Ipv4Addr,
        entries: Vec<(Ipv4Addr, Ipv4Addr)>,
        exclude_peer: Option<Ipv4Addr>,
    },
    /// Disconnect a peer
    Disconnect { peer: Ipv4Addr },
    /// Shutdown the TCP runner
    Shutdown,
}

/// MSDP TCP Runner - manages all TCP connections for MSDP
///
/// This task runs in the background and handles:
/// - Accepting incoming connections
/// - Initiating outgoing connections
/// - Sending keepalives and SA messages
/// - Reading messages and forwarding to state machine
pub struct MsdpTcpRunner {
    /// Local address for MSDP
    local_address: Ipv4Addr,
    /// Channel to receive commands
    cmd_rx: mpsc::Receiver<MsdpTcpCommand>,
    /// Channel to send protocol events
    event_tx: mpsc::Sender<ProtocolEvent>,
    /// Active connections
    connections: HashMap<Ipv4Addr, Arc<Mutex<MsdpConnection>>>,
    /// Handles to connection reader tasks
    reader_tasks: HashMap<Ipv4Addr, tokio::task::JoinHandle<()>>,
}

impl MsdpTcpRunner {
    /// Create a new MSDP TCP runner
    pub fn new(
        local_address: Ipv4Addr,
        cmd_rx: mpsc::Receiver<MsdpTcpCommand>,
        event_tx: mpsc::Sender<ProtocolEvent>,
    ) -> Self {
        Self {
            local_address,
            cmd_rx,
            event_tx,
            connections: HashMap::new(),
            reader_tasks: HashMap::new(),
        }
    }

    /// Determine if we should initiate connection to a peer
    fn should_initiate_connection(&self, peer_addr: Ipv4Addr) -> bool {
        self.local_address > peer_addr
    }

    /// Run the MSDP TCP runner
    pub async fn run(mut self, mut incoming_rx: mpsc::Receiver<(TcpStream, SocketAddr)>) {
        loop {
            tokio::select! {
                // Handle commands from supervisor
                Some(cmd) = self.cmd_rx.recv() => {
                    match cmd {
                        MsdpTcpCommand::Shutdown => {
                            // Close all connections and exit
                            for (peer, _) in self.connections.drain() {
                                if let Some(handle) = self.reader_tasks.remove(&peer) {
                                    handle.abort();
                                }
                            }
                            break;
                        }
                        MsdpTcpCommand::Connect { peer } => {
                            self.handle_connect(peer).await;
                        }
                        MsdpTcpCommand::SendKeepalive { peer } => {
                            self.handle_send_keepalive(peer).await;
                        }
                        MsdpTcpCommand::SendSa { peer, rp_address, entries } => {
                            self.handle_send_sa(peer, rp_address, &entries).await;
                        }
                        MsdpTcpCommand::FloodSa { rp_address, entries, exclude_peer } => {
                            self.handle_flood_sa(rp_address, &entries, exclude_peer).await;
                        }
                        MsdpTcpCommand::Disconnect { peer } => {
                            self.handle_disconnect(peer).await;
                        }
                    }
                }
                // Handle incoming connections from listener
                Some((stream, addr)) = incoming_rx.recv() => {
                    self.handle_incoming_connection(stream, addr).await;
                }
                else => {
                    // Both channels closed, exit
                    break;
                }
            }
        }
    }

    async fn handle_connect(&mut self, peer: Ipv4Addr) {
        // Check if already connected
        if self.connections.contains_key(&peer) {
            return;
        }

        // Only initiate if we have the higher IP
        if !self.should_initiate_connection(peer) {
            return;
        }

        let socket_addr = SocketAddr::V4(SocketAddrV4::new(peer, MSDP_PORT));

        match TcpStream::connect(socket_addr).await {
            Ok(stream) => {
                let conn = MsdpConnection::new(peer, stream, true);
                let conn = Arc::new(Mutex::new(conn));
                self.connections.insert(peer, conn.clone());

                // Spawn reader task
                let event_tx = self.event_tx.clone();
                let handle = tokio::spawn(async move {
                    if let Err(e) = process_connection_messages(conn, event_tx.clone()).await {
                        // Connection closed or error - send event
                        let _ = event_tx
                            .send(ProtocolEvent::Msdp(
                                super::msdp::MsdpEvent::TcpConnectionClosed {
                                    peer,
                                    reason: e.to_string(),
                                },
                            ))
                            .await;
                    }
                });
                self.reader_tasks.insert(peer, handle);

                // Notify state machine
                let _ = self
                    .event_tx
                    .send(ProtocolEvent::Msdp(
                        super::msdp::MsdpEvent::TcpConnectionEstablished {
                            peer,
                            is_active: true,
                        },
                    ))
                    .await;
            }
            Err(e) => {
                // Notify state machine of failure
                let _ = self
                    .event_tx
                    .send(ProtocolEvent::Msdp(
                        super::msdp::MsdpEvent::TcpConnectionFailed {
                            peer,
                            reason: e.to_string(),
                        },
                    ))
                    .await;
            }
        }
    }

    async fn handle_incoming_connection(&mut self, stream: TcpStream, addr: SocketAddr) {
        let peer = match addr {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => return, // MSDP doesn't support IPv6
        };

        // Check for connection collision
        if self.connections.contains_key(&peer) {
            // Connection collision resolution: higher IP initiates
            if self.should_initiate_connection(peer) {
                // We have higher IP, our active connection wins - reject incoming
                return;
            } else {
                // Peer has higher IP, incoming connection wins - close existing
                if let Some(handle) = self.reader_tasks.remove(&peer) {
                    handle.abort();
                }
                self.connections.remove(&peer);
            }
        }

        // Accept the connection
        let conn = MsdpConnection::new(peer, stream, false);
        let conn = Arc::new(Mutex::new(conn));
        self.connections.insert(peer, conn.clone());

        // Spawn reader task
        let event_tx = self.event_tx.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = process_connection_messages(conn, event_tx.clone()).await {
                let _ = event_tx
                    .send(ProtocolEvent::Msdp(
                        super::msdp::MsdpEvent::TcpConnectionClosed {
                            peer,
                            reason: e.to_string(),
                        },
                    ))
                    .await;
            }
        });
        self.reader_tasks.insert(peer, handle);

        // Notify state machine
        let _ = self
            .event_tx
            .send(ProtocolEvent::Msdp(
                super::msdp::MsdpEvent::TcpConnectionEstablished {
                    peer,
                    is_active: false,
                },
            ))
            .await;
    }

    async fn handle_send_keepalive(&self, peer: Ipv4Addr) {
        if let Some(conn) = self.connections.get(&peer) {
            let mut conn = conn.lock().await;
            if let Err(e) = conn.send_keepalive().await {
                // Send failure event
                let _ = self
                    .event_tx
                    .send(ProtocolEvent::Msdp(
                        super::msdp::MsdpEvent::TcpConnectionClosed {
                            peer,
                            reason: format!("keepalive send failed: {}", e),
                        },
                    ))
                    .await;
            }
        }
    }

    async fn handle_send_sa(
        &self,
        peer: Ipv4Addr,
        rp_address: Ipv4Addr,
        entries: &[(Ipv4Addr, Ipv4Addr)],
    ) {
        if let Some(conn) = self.connections.get(&peer) {
            let mut conn = conn.lock().await;
            if let Err(e) = conn.send_sa(rp_address, entries).await {
                let _ = self
                    .event_tx
                    .send(ProtocolEvent::Msdp(
                        super::msdp::MsdpEvent::TcpConnectionClosed {
                            peer,
                            reason: format!("SA send failed: {}", e),
                        },
                    ))
                    .await;
            }
        }
    }

    async fn handle_flood_sa(
        &self,
        rp_address: Ipv4Addr,
        entries: &[(Ipv4Addr, Ipv4Addr)],
        exclude_peer: Option<Ipv4Addr>,
    ) {
        for (&peer, conn) in &self.connections {
            if Some(peer) == exclude_peer {
                continue;
            }
            let mut conn = conn.lock().await;
            // Fire and forget - don't fail the flood for one peer
            let _ = conn.send_sa(rp_address, entries).await;
        }
    }

    async fn handle_disconnect(&mut self, peer: Ipv4Addr) {
        if let Some(handle) = self.reader_tasks.remove(&peer) {
            handle.abort();
        }
        self.connections.remove(&peer);

        // Notify state machine
        let _ = self
            .event_tx
            .send(ProtocolEvent::Msdp(
                super::msdp::MsdpEvent::TcpConnectionClosed {
                    peer,
                    reason: "disconnected by request".to_string(),
                },
            ))
            .await;
    }
}

/// Start the MSDP TCP subsystem
///
/// Returns:
/// - A channel sender for commands to the TCP runner
/// - A future that runs the TCP listener
/// - A future that runs the TCP runner
pub async fn start_msdp_tcp(
    local_address: Ipv4Addr,
    event_tx: mpsc::Sender<ProtocolEvent>,
) -> io::Result<(
    mpsc::Sender<MsdpTcpCommand>,
    impl std::future::Future<Output = ()>,
    impl std::future::Future<Output = ()>,
)> {
    // Create command channel
    let (cmd_tx, cmd_rx) = mpsc::channel::<MsdpTcpCommand>(64);

    // Start listener
    let listen_addr = SocketAddr::V4(SocketAddrV4::new(local_address, MSDP_PORT));
    let listener = TcpListener::bind(listen_addr).await?;

    // Create channel for incoming connections
    let (incoming_tx, incoming_rx) = mpsc::channel::<(TcpStream, SocketAddr)>(16);

    // Listener task
    let listener_task = async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    if incoming_tx.send((stream, addr)).await.is_err() {
                        // Receiver dropped, stop listening
                        break;
                    }
                }
                Err(_e) => {
                    // Log error but continue
                    // eprintln!("MSDP listener error: {}", e);
                }
            }
        }
    };

    // Runner task
    let runner = MsdpTcpRunner::new(local_address, cmd_rx, event_tx);
    let runner_task = async move {
        runner.run(incoming_rx).await;
    };

    Ok((cmd_tx, listener_task, runner_task))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::msdp::{MSDP_KEEPALIVE, MSDP_SA};

    #[test]
    fn test_should_initiate_connection() {
        let (event_tx, _event_rx) = mpsc::channel(16);
        let (timer_tx, _timer_rx) = mpsc::channel(16);

        let manager = MsdpConnectionManager::new("10.0.0.2".parse().unwrap(), event_tx, timer_tx);

        // We have higher IP, should initiate
        assert!(manager.should_initiate_connection("10.0.0.1".parse().unwrap()));

        // Peer has higher IP, should not initiate
        assert!(!manager.should_initiate_connection("10.0.0.3".parse().unwrap()));

        // Equal IPs (edge case) - should not initiate
        assert!(!manager.should_initiate_connection("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_msdp_header_parse() {
        // Valid SA header
        let data = [0x01, 0x00, 0x14]; // Type=1, Length=20
        let header = MsdpHeader::parse(&data).unwrap();
        assert_eq!(header.msg_type, MSDP_SA);
        assert_eq!(header.length, 20);

        // Valid Keepalive header
        let data = [0x04, 0x00, 0x03]; // Type=4, Length=3
        let header = MsdpHeader::parse(&data).unwrap();
        assert_eq!(header.msg_type, MSDP_KEEPALIVE);
        assert_eq!(header.length, 3);

        // Too short
        let data = [0x01, 0x00];
        assert!(MsdpHeader::parse(&data).is_none());
    }

    #[tokio::test]
    async fn test_connection_manager_creation() {
        let (event_tx, _event_rx) = mpsc::channel(16);
        let (timer_tx, _timer_rx) = mpsc::channel(16);

        let manager = MsdpConnectionManager::new("10.0.0.1".parse().unwrap(), event_tx, timer_tx);

        assert!(manager.connections.is_empty());
        assert_eq!(
            manager.local_address,
            "10.0.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert!(!manager.running);
    }
}
