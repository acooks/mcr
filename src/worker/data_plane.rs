// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{FlowStats, ForwardingRule};
use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::OwnedFd;
use std::rc::Rc;
use tokio::sync::mpsc;
use tokio::task;
use tokio_uring::fs::File;
use tokio_uring::net::UdpSocket;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

fn parse_and_filter_packet(raw_packet: &[u8], rule: &ForwardingRule) -> Option<Vec<u8>> {
    let ethernet_packet = EthernetPacket::new(raw_packet)?;
    if ethernet_packet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;

    if ipv4_packet.get_destination() == rule.input_group
        && udp_packet.get_destination() == rule.input_port
    {
        Some(udp_packet.payload().to_vec())
    } else {
        None
    }
}

pub async fn run_flow_task(
    rule: ForwardingRule,
    raw_fd: OwnedFd,
    _stats_tx: mpsc::Sender<(ForwardingRule, FlowStats)>,
) -> Result<()> {
    let std_file = std::fs::File::from(raw_fd);
    let uring_file = File::from_std(std_file);

    // --- Egress Setup ---
    let mut output_sockets = Vec::new();
    for output in &rule.outputs {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // Bind the socket to the specified output interface.
        let if_name = CString::new(output.interface.clone())?;
        socket.bind_device(Some(if_name.as_bytes()))?;

        // It's important to bind the socket to a local address.
        // We'll use an ephemeral port on the unspecified address.
        let local_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        socket.bind(&local_addr.into())?;

        // Convert the std socket to a tokio_uring socket.
        let udp_socket = Rc::new(UdpSocket::from_std(socket.into()));
        output_sockets.push((udp_socket, output.clone()));
    }

    let mut buffer = vec![0u8; 2048]; // MTU
    let mut current_offset = 0;

    loop {
        let (res, b) = uring_file.read_at(buffer, current_offset).await;
        buffer = b;
        let bytes_read = res?;

        if bytes_read > 0 {
            current_offset += bytes_read as u64;
            let raw_packet = &buffer[..bytes_read];

            if let Some(packet_data) = parse_and_filter_packet(raw_packet, &rule) {
                // --- Egress Forwarding ---
                for (socket, dest) in &output_sockets {
                    let dest_addr = SocketAddrV4::new(dest.group, dest.port);
                    let socket_clone = Rc::clone(socket);
                    let packet_data_clone = packet_data.clone();
                    task::spawn_local(async move {
                        let _ = socket_clone
                            .send_to(packet_data_clone, dest_addr.into())
                            .await;
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;

    fn build_test_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut ethernet_buffer = vec![0u8; 14 + 20 + 8 + payload.len()];
        {
            let mut eth_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
            eth_packet.set_ethertype(EtherTypes::Ipv4);
        }

        let mut ipv4_buffer = vec![0u8; 20 + 8 + payload.len()];
        let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length((20 + 8 + payload.len()) as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4_packet.set_source(src_ip);
        ipv4_packet.set_destination(dst_ip);

        let mut udp_buffer = vec![0u8; 8 + payload.len()];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length((8 + payload.len()) as u16);
        udp_packet.set_payload(payload);

        ipv4_packet.set_payload(udp_packet.packet());
        let mut eth_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        eth_packet.set_payload(ipv4_packet.packet());

        ethernet_buffer
    }

    #[test]
    fn test_parse_and_filter_packet_matching_rule() {
        let payload = b"test payload";
        let packet = build_test_packet(
            "192.168.1.1".parse().unwrap(),
            "224.0.0.1".parse().unwrap(),
            1234,
            5000,
            payload,
        );

        let rule = ForwardingRule {
            rule_id: "test-rule".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![],
        };

        let result = parse_and_filter_packet(&packet, &rule);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn test_parse_and_filter_packet_non_matching_rule() {
        let payload = b"test payload";
        let packet = build_test_packet(
            "192.168.1.1".parse().unwrap(),
            "224.0.0.1".parse().unwrap(),
            1234,
            5000,
            payload,
        );

        let rule = ForwardingRule {
            rule_id: "test-rule".to_string(),
            input_interface: "eth0".to_string(),
            input_group: "224.0.0.2".parse().unwrap(), // Different group
            input_port: 5001,                          // Different port
            outputs: vec![],
        };

        let result = parse_and_filter_packet(&packet, &rule);
        assert!(result.is_none());
    }

    #[test]
    fn test_run_flow_task() {
        use crate::OutputDestination;
        use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        use tokio::net::UdpSocket;

        tokio_uring::start(async {
            // 1. Setup: Create a socket pair to mock the raw AF_PACKET socket.
            let (sock_a_fd, sock_b_fd) = socket::socketpair(
                AddressFamily::Unix,
                SockType::Datagram,
                None,
                SockFlag::empty(),
            )
            .unwrap();

            let sock_a_std = unsafe { std::net::UdpSocket::from_raw_fd(sock_a_fd.into_raw_fd()) };
            sock_a_std.set_nonblocking(true).unwrap();
            let sock_a = UdpSocket::from_std(sock_a_std).unwrap();
            let sock_b_owned = unsafe { OwnedFd::from_raw_fd(sock_b_fd.into_raw_fd()) };

            // Create a mock egress socket to receive the forwarded packet.
            let egress_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let egress_addr = egress_socket.local_addr().unwrap();

            // Create a forwarding rule that matches our test packet.
            let rule = ForwardingRule {
                rule_id: "test-rule".to_string(),
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![OutputDestination {
                    group: "127.0.0.1".parse().unwrap(),
                    port: egress_addr.port(),
                    interface: "lo".to_string(),
                }],
            };

            // Create a mock stats channel.
            let (stats_tx, _stats_rx) = mpsc::channel(10);

            // 2. Action: Spawn the run_flow_task with one end of the socket pair.
            let task = task::spawn_local(run_flow_task(rule, sock_b_owned, stats_tx));

            // Send a test packet into the other end of the socket pair.
            let payload = b"test payload";
            let packet = build_test_packet(
                "192.168.1.1".parse().unwrap(),
                "224.0.0.1".parse().unwrap(),
                1234,
                5000,
                payload,
            );
            sock_a.send(&packet).await.unwrap();

            // 3. Verification: Check if the packet was forwarded to the egress socket.
            let mut egress_buffer = [0; 1024];
            let len = egress_socket
                .recv(&mut egress_buffer)
                .await
                .expect("Failed to receive packet on egress socket");
            assert_eq!(&egress_buffer[..len], payload);

            // 4. Cleanup: Abort the task.
            task.abort();
        });
    }
}
