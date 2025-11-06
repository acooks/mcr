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
            // --- Egress Forwarding ---
            for (socket, dest) in &output_sockets {
                let packet_data = buffer[..bytes_read].to_vec();
                let dest_addr = SocketAddrV4::new(dest.group, dest.port);
                let socket_clone = Rc::clone(socket);
                // We don't await the send here to forward as quickly as possible.
                // This submits the send operation to the kernel and moves on.
                task::spawn_local(async move {
                    let _ = socket_clone.send_to(packet_data, dest_addr.into()).await;
                });
            }
        }
    }
}
