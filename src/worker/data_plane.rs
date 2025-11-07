use crate::{FlowStats, ForwardingRule};
use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;
use tokio_uring::fs::File;
use tokio_uring::net::UdpSocket;

pub fn setup_ingress_socket(interface_name: &str) -> Result<OwnedFd> {
    let if_name = CString::new(interface_name)?;
    let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
    if if_index == 0 {
        return Err(anyhow::anyhow!("Interface '{}' not found", interface_name));
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(anyhow::anyhow!("Failed to create AF_PACKET socket"));
    }

    let mut sockaddr_ll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sockaddr_ll.sll_family = libc::AF_PACKET as u16;
    sockaddr_ll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sockaddr_ll.sll_ifindex = if_index as i32;

    let bind_result = unsafe {
        libc::bind(
            fd,
            &sockaddr_ll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if bind_result < 0 {
        return Err(anyhow::anyhow!(
            "Failed to bind to interface '{}'",
            interface_name
        ));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

fn parse_and_filter_packet(
    raw_packet: &[u8],
    rule: &ForwardingRule,
) -> Option<Vec<u8>> {
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

#[allow(dead_code)]
pub async fn run_flow_task(
    rule: ForwardingRule,
    raw_fd: Arc<OwnedFd>,
    _stats_tx: mpsc::Sender<(ForwardingRule, FlowStats)>,
) -> Result<()> {
    let uring_file = unsafe { File::from_raw_fd(raw_fd.as_raw_fd()) };

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

    loop {
        let (res, b) = uring_file.read_at(buffer, 0).await;
        buffer = b;
        let bytes_read = res?;

        if bytes_read > 0 {
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
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_setup_ingress_socket_success() {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("Skipping test_setup_ingress_socket_success: requires root privileges.");
            return;
        }
        // Test with a valid interface (e.g., "lo" for loopback)
        let result = setup_ingress_socket("lo");
        assert!(result.is_ok(), "setup_ingress_socket should succeed for 'lo' interface");
        let fd = result.unwrap();
        assert!(fd.as_raw_fd() >= 0, "File descriptor should be valid");
    }

    #[test]
    fn test_setup_ingress_socket_interface_not_found() {
        // Test with a non-existent interface
        let result = setup_ingress_socket("nonexistent_interface123");
        assert!(result.is_err(), "setup_ingress_socket should fail for a non-existent interface");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Interface 'nonexistent_interface123' not found"));
    }

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
            dtls_enabled: false,
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
            input_port: 5001,                         // Different port
            outputs: vec![],
            dtls_enabled: false,
        };

        let result = parse_and_filter_packet(&packet, &rule);
        assert!(result.is_none());
    }

    #[test]
    #[ignore] // Requires kernel support for memfd
    fn test_run_flow_task() {
        use crate::OutputDestination;
        use std::os::unix::io::FromRawFd;
        use tokio::io::AsyncWriteExt;

        tokio_uring::start(async {
            // Create a memfd to act as a mock raw socket
            let memfd_name = CString::new("test_memfd").unwrap();
            let fd = unsafe { libc::memfd_create(memfd_name.as_ptr(), 0) };
            assert!(fd >= 0);
            let owned_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
            let mut memfd_file = tokio::fs::File::from(std::fs::File::from(owned_fd.try_clone().unwrap()));

            // Create a mock egress socket
            let egress_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let egress_addr = egress_socket.local_addr().unwrap();

            // Create a forwarding rule
            let rule = ForwardingRule {
                rule_id: "test-rule".to_string(),
                input_interface: "lo".to_string(),
                input_group: "224.0.0.1".parse().unwrap(),
                input_port: 5000,
                outputs: vec![OutputDestination {
                    group: "127.0.0.1".parse().unwrap(),
                    port: egress_addr.port(),
                    interface: "lo".to_string(),
                    dtls_enabled: false,
                }],
                dtls_enabled: false,
            };

            // Create a mock stats channel
            let (stats_tx, _stats_rx) = mpsc::channel(10);

            // Spawn the run_flow_task
            let task = task::spawn_local(run_flow_task(rule, owned_fd, stats_tx));

            // Write a mock packet to the memfd
            let payload = b"test payload";
            let packet = build_test_packet(
                "192.168.1.1".parse().unwrap(),
                "224.0.0.1".parse().unwrap(),
                1234,
                5000,
                payload,
            );
            memfd_file.write_all(&packet).await.unwrap();

            // Verify that the packet is received on the egress socket
            let mut egress_buffer = [0; 1024];
            let (len, _) = egress_socket.recv_from(&mut egress_buffer).unwrap();
            assert_eq!(&egress_buffer[..len], payload);

            // Clean up
            task.abort();
        });
    }
}