use anyhow::Result;
use clap::Parser;
use multicast_relay::{supervisor, worker, Args, Command};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Supervisor {
            relay_command_socket_path,
        } => {
            // This channel is now unused, but we keep it for now to avoid breaking the build.
            // It will be removed in a future commit.
            let (_relay_command_tx, relay_command_rx) = mpsc::channel(100);

            // The supervisor now manages its own command socket
            if let Err(e) = supervisor::run(
                || supervisor::spawn_control_plane_worker(relay_command_socket_path.clone()),
                || supervisor::spawn_data_plane_worker(0, relay_command_socket_path.clone()),
                relay_command_rx, // This is now unused, will be removed from supervisor::run
                relay_command_socket_path.clone(),
                Arc::new(Mutex::new(HashMap::new())),
            )
            .await
            {
                eprintln!("[Supervisor] Error: {}", e);
                std::process::exit(1);
            }
        }
        Command::Worker {
            user,
            group,
            relay_command_socket_path,
            data_plane,
            core_id,
            prometheus_addr,
            input_interface_name,
            input_group,
            input_port,
            output_group,
            output_port,
            output_interface,
            reporting_interval,
        } => {
            if data_plane {
                let config = multicast_relay::DataPlaneConfig {
                    user,
                    group,
                    core_id: core_id.unwrap_or(0),
                    prometheus_addr: prometheus_addr.unwrap_or("127.0.0.1:9000".parse().unwrap()),
                    input_interface_name,
                    input_group,
                    input_port,
                    output_group,
                    output_port,
                    output_interface,
                    reporting_interval: reporting_interval.unwrap_or(1),
                };
                // D1, D7: The worker process uses a `tokio-uring` runtime
                // to drive the high-performance data plane.
                tokio_uring::start(async {
                    if let Err(e) = worker::run_data_plane(config).await {
                        eprintln!("Data Plane worker process failed: {}", e);
                        std::process::exit(1);
                    }
                });
            } else {
                let config = multicast_relay::ControlPlaneConfig {
                    user,
                    group,
                    relay_command_socket_path,
                    prometheus_addr: prometheus_addr.unwrap_or("127.0.0.1:9000".parse().unwrap()),
                    reporting_interval: reporting_interval.unwrap_or(1),
                };
                // Control Plane worker
                tokio_uring::start(async {
                    if let Err(e) = worker::run_control_plane(config).await {
                        eprintln!("Control Plane worker process failed: {}", e);
                        std::process::exit(1);
                    }
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_arg_parsing() {
        let args = Args::parse_from(["multicast_relay", "supervisor"]);
        assert_eq!(
            args.command,
            Command::Supervisor {
                relay_command_socket_path: PathBuf::from("/tmp/mcr_relay_commands.sock")
            }
        );

        let args = Args::parse_from([
            "multicast_relay",
            "worker",
            "--user",
            "test",
            "--group",
            "test",
            "--relay-command-socket-path",
            "/tmp/worker_relay.sock",
            "--data-plane",
            "--core-id",
            "0",
            "--prometheus-addr",
            "127.0.0.1:9000",
            "--input-interface-name",
            "eth0",
            "--input-group",
            "224.0.0.1",
            "--input-port",
            "5000",
            "--output-group",
            "224.0.0.2",
            "--output-port",
            "5001",
            "--output-interface",
            "eth1",
            "--reporting-interval",
            "5",
        ]);
        assert_eq!(
            args.command,
            Command::Worker {
                user: "test".to_string(),
                group: "test".to_string(),
                relay_command_socket_path: PathBuf::from("/tmp/worker_relay.sock"),
                data_plane: true,
                core_id: Some(0),
                prometheus_addr: Some("127.0.0.1:9000".parse().unwrap()),
                input_interface_name: Some("eth0".to_string()),
                input_group: Some("224.0.0.1".parse().unwrap()),
                input_port: Some(5000),
                output_group: Some("224.0.0.2".parse().unwrap()),
                output_port: Some(5001),
                output_interface: Some("eth1".to_string()),
                reporting_interval: Some(5),
            }
        );

        let args = Args::parse_from([
            "multicast_relay",
            "worker",
            "--user",
            "test",
            "--group",
            "test",
            "--relay-command-socket-path",
            "/tmp/worker_relay.sock",
        ]);
        assert_eq!(
            args.command,
            Command::Worker {
                user: "test".to_string(),
                group: "test".to_string(),
                relay_command_socket_path: PathBuf::from("/tmp/worker_relay.sock"),
                data_plane: false,
                core_id: None,
                prometheus_addr: None,
                input_interface_name: None,
                input_group: None,
                input_port: None,
                output_group: None,
                output_port: None,
                output_interface: None,
                reporting_interval: None,
            }
        );
    }
}