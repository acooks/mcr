// This file contains the unit and logic tests for the worker,
// moved from src/worker/mod.rs to separate concerns.

use multicast_relay::worker::*;
use multicast_relay::{ControlPlaneConfig, DataPlaneConfig, ForwardingRule, RelayCommand};
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
async fn test_run_control_plane_starts_successfully() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let socket_path =
                PathBuf::from(format!("/tmp/test_supervisor_{}.sock", Uuid::new_v4()));
            let _listener = UnixListener::bind(&socket_path).unwrap();

            let config = ControlPlaneConfig {
                uid: 65534,
                gid: 65534,
                relay_command_socket_path: socket_path.clone(),
                prometheus_addr: None,
                reporting_interval: 1,
                socket_fd: None,
            };

            let task = tokio::task::spawn_local(run_control_plane(config));

            // Let the task run for a short time to ensure it doesn't panic immediately.
            let result = tokio::time::timeout(std::time::Duration::from_millis(100), task).await;

            // The task is expected to run indefinitely, so a timeout is expected.
            // We are checking that it didn't complete (or panic).
            assert!(result.is_err(), "run_control_plane should not complete");

            // Clean up the temporary socket file
            std::fs::remove_file(&socket_path).unwrap();
        })
        .await;
}

#[tokio::test]
async fn test_run_data_plane_starts_successfully() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let config = DataPlaneConfig {
                uid: 65534,
                gid: 65534,
                core_id: 0,
                prometheus_addr: "127.0.0.1:9002".parse().unwrap(),
                input_interface_name: None,
                input_group: None,
                input_port: None,
                output_group: None,
                output_port: None,
                output_interface: None,
                reporting_interval: 1,
            };

            let task = tokio::task::spawn_local(run_data_plane(config));

            // Let the task run for a short time to ensure it doesn't panic immediately.
            let result = tokio::time::timeout(std::time::Duration::from_millis(100), task).await;

            // The task is expected to run indefinitely, so a timeout is expected.
            // We are checking that it didn't complete (or panic).
            assert!(result.is_err(), "run_data_plane should not complete");
        })
        .await;
}
