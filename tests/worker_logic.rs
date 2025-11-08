// This file contains the unit and logic tests for the worker,
// moved from src/worker/mod.rs to separate concerns.

use multicast_relay::worker::*;
use multicast_relay::{ControlPlaneConfig, DataPlaneConfig, ForwardingRule, RelayCommand};
use std::os::unix::io::IntoRawFd;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use uuid::Uuid;

#[tokio::test]
async fn test_unix_socket_relay_command_sender() {
    let (mut client_stream, server_stream) = tokio::io::duplex(1024);
    let sender = UnixSocketRelayCommandSender::new(server_stream);

    let command = RelayCommand::AddRule(ForwardingRule {
        rule_id: "test-rule-1".to_string(),
        input_interface: "eth0".to_string(),
        input_group: "224.0.0.1".parse().unwrap(),
        input_port: 5000,
        outputs: vec![],
        dtls_enabled: false,
    });

    sender.send(command.clone()).await.unwrap();
    drop(sender); // Drop the sender to close the server_stream

    let mut buffer = Vec::new();
    client_stream.read_to_end(&mut buffer).await.unwrap();

    let received_command: RelayCommand = serde_json::from_slice(&buffer).unwrap();
    assert_eq!(command, received_command);
}

#[tokio::test]
#[ignore]
async fn test_run_control_plane_starts_successfully() -> anyhow::Result<()> {
    let socket_path = PathBuf::from(format!("/tmp/test_supervisor_{}.sock", Uuid::new_v4()));
    let _listener = UnixListener::bind(&socket_path)?;

    let (_client_stream, task_stream) = tokio::net::UnixStream::pair()?;

    let config = ControlPlaneConfig {
        uid: 65534,
        gid: 65534,
        relay_command_socket_path: socket_path.clone(),
        prometheus_addr: None,
        reporting_interval: 1,
        socket_fd: Some(task_stream.into_std()?.into_raw_fd()),
    };

    let run_future = run_control_plane(config);

    let result = tokio::time::timeout(std::time::Duration::from_millis(100), run_future).await;

    assert!(result.is_err(), "run_control_plane should time out");

    std::fs::remove_file(&socket_path)?;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_run_data_plane_starts_successfully() -> anyhow::Result<()> {
    let config = DataPlaneConfig {
        uid: 65534,
        gid: 65534,
        core_id: Some(0),
        prometheus_addr: "127.0.0.1:9002".parse().unwrap(),
        input_interface_name: Some("lo".to_string()),
        input_group: None,
        input_port: None,
        output_group: None,
        output_port: None,
        output_interface: None,
        reporting_interval: 1,
    };

    let run_future = run_data_plane(config);

    let result = tokio::time::timeout(std::time::Duration::from_millis(100), run_future).await;

    assert!(result.is_err(), "run_data_plane should time out");

    Ok(())
}
