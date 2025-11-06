use crate::{FlowStats, ForwardingRule};
use anyhow::Result;
use libc;
use std::ffi::CString;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_uring::fs::File;

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

    let mut sockaddr_ll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sockaddr_ll.sll_family = libc::AF_PACKET as u16;
    sockaddr_ll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sockaddr_ll.sll_ifindex = if_index as i32;

    let bind_result = unsafe {
        libc::bind(
            fd,
            &sockaddr_ll as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as u32,
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
    _rule: ForwardingRule,
    raw_fd: Arc<OwnedFd>,
    _stats_tx: mpsc::Sender<(ForwardingRule, FlowStats)>,
) -> Result<()> {
    let uring_file = unsafe { File::from_raw_fd(raw_fd.as_raw_fd()) };
    let mut buffer = vec![0u8; 2048]; // MTU

    loop {
        let (res, b) = uring_file.read_at(buffer, 0).await;
        buffer = b;
        let bytes_read = res?;

        if bytes_read > 0 {
            // Packet processing logic will go here.
        }
    }
}
