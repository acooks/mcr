// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::Result;
use clap::Parser;
use multicast_relay::{supervisor, worker, Args, Command};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Supervisor {
            relay_command_socket_path,
            control_socket_path,
            interface,
            user,
            group,
            num_workers,
        } => {
            // Create oneshot channel for graceful shutdown
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

            // The supervisor runs in a standard tokio runtime.
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async {
                // Set up SIGTERM handler for graceful shutdown
                let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to install SIGTERM handler");
                let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("Failed to install SIGINT handler");

                // Spawn a task to handle signals and trigger shutdown
                tokio::spawn(async move {
                    tokio::select! {
                        _ = sigterm.recv() => {
                            eprintln!("[Supervisor] Received SIGTERM, initiating graceful shutdown");
                        }
                        _ = sigint.recv() => {
                            eprintln!("[Supervisor] Received SIGINT, initiating graceful shutdown");
                        }
                    }
                    // Send shutdown signal to supervisor
                    let _ = shutdown_tx.send(());
                });

                // Run supervisor - it will exit when shutdown_rx is triggered
                let result = supervisor::run(
                    &user,
                    &group,
                    &interface,
                    relay_command_socket_path.clone(),
                    control_socket_path,
                    Arc::new(Mutex::new(HashMap::new())),
                    num_workers,
                    shutdown_rx,
                )
                .await;

                if let Err(e) = result {
                    eprintln!("[Supervisor] Error: {}", e);
                    std::process::exit(1);
                }

                // Give workers a brief moment to flush final logs
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                eprintln!("[Supervisor] Shutdown complete");
            });
        }
        Command::Worker {
            uid,
            gid,
            relay_command_socket_path,
            data_plane,
            core_id,
            input_interface_name,
            input_group,
            input_port,
            output_group,
            output_port,
            output_interface,
            reporting_interval,
            fanout_group_id,
        } => {
            // All workers are now data plane workers
            let _ = (data_plane, relay_command_socket_path); // Silence unused variable warnings

            // Get parent process ID (supervisor PID) for shared memory paths
            let supervisor_pid = std::os::unix::process::parent_id();

            let config = multicast_relay::DataPlaneConfig {
                uid,
                gid,
                supervisor_pid,
                core_id,
                input_interface_name,
                input_group,
                input_port,
                output_group,
                output_port,
                output_interface,
                reporting_interval: reporting_interval.unwrap_or(1),
                fanout_group_id,
            };
            // D1, D7: The worker process uses a `tokio-uring` runtime
            // to drive the high-performance data plane.
            tokio_uring::start(async {
                if let Err(e) = worker::run_data_plane(config, worker::DefaultWorkerLifecycle).await
                {
                    eprintln!("Data Plane worker process failed: {}", e);
                    std::process::exit(1);
                }
            });
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
                relay_command_socket_path: PathBuf::from("/tmp/mcr_relay_commands.sock"),
                control_socket_path: PathBuf::from("/tmp/multicast_relay_control.sock"),
                interface: "lo".to_string(),
                user: "nobody".to_string(),
                group: "daemon".to_string(),
                num_workers: None,
            }
        );

        let args = Args::parse_from([
            "multicast_relay",
            "worker",
            "--uid",
            "0",
            "--gid",
            "0",
            "--relay-command-socket-path",
            "/tmp/worker_relay.sock",
            "--data-plane",
            "--core-id",
            "0",
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
                uid: Some(0),
                gid: Some(0),
                relay_command_socket_path: PathBuf::from("/tmp/worker_relay.sock"),
                data_plane: true,
                core_id: Some(0),
                input_interface_name: Some("eth0".to_string()),
                input_group: Some("224.0.0.1".parse().unwrap()),
                input_port: Some(5000),
                output_group: Some("224.0.0.2".parse().unwrap()),
                output_port: Some(5001),
                output_interface: Some("eth1".to_string()),
                reporting_interval: Some(5),
                fanout_group_id: None,
            }
        );

        let args = Args::parse_from([
            "multicast_relay",
            "worker",
            "--uid",
            "0",
            "--gid",
            "0",
            "--relay-command-socket-path",
            "/tmp/worker_relay.sock",
        ]);
        assert_eq!(
            args.command,
            Command::Worker {
                uid: Some(0),
                gid: Some(0),
                relay_command_socket_path: PathBuf::from("/tmp/worker_relay.sock"),
                data_plane: false,
                core_id: None,
                input_interface_name: None,
                input_group: None,
                input_port: None,
                output_group: None,
                output_port: None,
                output_interface: None,
                reporting_interval: None,
                fanout_group_id: None,
            }
        );
    }
}
