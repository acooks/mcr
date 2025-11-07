use anyhow::Result;
use clap::Parser;
use multicast_relay::{supervisor, worker};
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug, PartialEq)]
enum Command {
    /// Run the supervisor process
    Supervisor {
        #[arg(long, default_value = "/tmp/mcr_relay_commands.sock")]
        relay_command_socket_path: PathBuf,
    },
    /// Run the worker process (intended to be called by the supervisor)
    Worker {
        #[arg(long, default_value = "nobody")]
        user: String,
        #[arg(long, default_value = "nogroup")]
        group: String,
        #[arg(long)]
        relay_command_socket_path: PathBuf,
        #[arg(long)]
        data_plane: bool,
        #[arg(long)]
        core_id: Option<u32>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Supervisor {
            relay_command_socket_path,
        } => {
            let (_relay_command_tx, relay_command_rx) = mpsc::channel(100);
            if let Err(e) = supervisor::run(
                || supervisor::spawn_control_plane_worker(relay_command_socket_path.clone()),
                || supervisor::spawn_data_plane_worker(0, relay_command_socket_path.clone()),
                relay_command_rx, // This is now unused, will be removed from supervisor::run
                relay_command_socket_path.clone(),
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
        } => {
            if data_plane {
                // D1, D7: The worker process uses a `tokio-uring` runtime
                // to drive the high-performance data plane.
                tokio_uring::start(async {
                    if let Err(e) = worker::run_data_plane(user, group, core_id.unwrap_or(0)).await
                    {
                        eprintln!("Data Plane worker process failed: {}", e);
                        std::process::exit(1);
                    }
                });
            } else {
                // Control Plane worker
                tokio_uring::start(async {
                    if let Err(e) =
                        worker::run_control_plane(user, group, relay_command_socket_path).await
                    {
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
        ]);
        assert_eq!(
            args.command,
            Command::Worker {
                user: "test".to_string(),
                group: "test".to_string(),
                relay_command_socket_path: PathBuf::from("/tmp/worker_relay.sock"),
                data_plane: true,
                core_id: Some(0),
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
            }
        );
    }
}
