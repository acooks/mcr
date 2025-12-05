// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::{Context, Result};
use clap::Parser;
use multicast_relay::{config::Config, supervisor, worker, Args, Command};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Supervisor {
            config: config_path,
            control_socket_path,
            interface,
            num_workers,
        } => {
            // Load and validate config file if provided
            let startup_config = if let Some(ref path) = config_path {
                let config = Config::load_from_file(path)
                    .with_context(|| format!("Failed to load config from {:?}", path))?;
                config
                    .validate()
                    .with_context(|| format!("Invalid config in {:?}", path))?;
                eprintln!(
                    "[Supervisor] Loaded config from {:?} ({} rules)",
                    path,
                    config.rules.len()
                );
                Some(config)
            } else {
                None
            };

            // Determine which interface to use:
            // - If config provided with rules, use first input interface from config
            // - Otherwise, use CLI --interface (default: lo)
            let effective_interface = if let Some(ref config) = startup_config {
                if let Some(first_rule) = config.rules.first() {
                    first_rule.input.interface.clone()
                } else {
                    interface.clone()
                }
            } else {
                interface.clone()
            };
            // Pre-populate master_rules from config if provided
            let master_rules: Arc<Mutex<HashMap<String, multicast_relay::ForwardingRule>>> =
                if let Some(ref config) = startup_config {
                    let rules: HashMap<_, _> = config
                        .to_forwarding_rules()
                        .into_iter()
                        .map(|r| (r.rule_id.clone(), r))
                        .collect();
                    Arc::new(Mutex::new(rules))
                } else {
                    Arc::new(Mutex::new(HashMap::new()))
                };

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
                    &effective_interface,
                    control_socket_path,
                    master_rules,
                    num_workers,
                    startup_config,
                    config_path.clone(),
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
            let _ = data_plane; // Silence unused variable warning

            // Get parent process ID (supervisor PID) for shared memory paths
            let supervisor_pid = std::os::unix::process::parent_id();

            let config = multicast_relay::DataPlaneConfig {
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
        let args = Args::parse_from(["mcrd", "supervisor"]);
        assert_eq!(
            args.command,
            Command::Supervisor {
                config: None,
                control_socket_path: PathBuf::from("/tmp/mcrd_control.sock"),
                interface: "lo".to_string(),
                num_workers: None,
            }
        );

        let args = Args::parse_from([
            "mcrd",
            "worker",
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

        let args = Args::parse_from(["mcrd", "worker"]);
        assert_eq!(
            args.command,
            Command::Worker {
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
