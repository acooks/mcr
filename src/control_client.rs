// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::Result;
use clap::Parser;
use multicast_relay::logging::{Facility, Severity};
use multicast_relay::OutputDestination;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: CliCommand,

    /// Path to the control socket
    #[arg(long, default_value = "/tmp/multicast_relay_control.sock")]
    socket_path: PathBuf,
}

#[derive(Parser, Debug)]
pub enum CliCommand {
    /// Add a new forwarding rule
    Add {
        #[arg(long)]
        rule_id: Option<String>,
        #[arg(long)]
        input_interface: String,
        #[arg(long)]
        input_group: Ipv4Addr,
        #[arg(long)]
        input_port: u16,
        #[arg(long, value_parser = parse_output_destination, value_delimiter = ',')]
        outputs: Vec<OutputDestination>,
    },
    /// Remove a forwarding rule
    Remove {
        #[arg(long)]
        rule_id: String,
    },
    /// List all forwarding rules
    List,
    /// List all active forwarding rules
    ListRules,
    /// Get statistics from the supervisor
    Stats,
    /// List all worker processes
    ListWorkers,
    /// Health check - test if supervisor is ready
    Ping,
    /// Log level control
    LogLevel {
        #[clap(subcommand)]
        action: LogLevelAction,
    },
}

#[derive(Parser, Debug)]
pub enum LogLevelAction {
    /// Get current log levels
    Get,
    /// Set log level
    Set {
        /// Set global log level
        #[arg(long, conflicts_with = "facility")]
        global: Option<String>,
        /// Set log level for specific facility
        #[arg(long, requires = "level")]
        facility: Option<String>,
        /// Log level to set
        #[arg(long)]
        level: Option<String>,
    },
}

fn parse_output_destination(s: &str) -> Result<OutputDestination, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid format. Expected group:port:interface".to_string());
    }
    let group = parts[0]
        .parse()
        .map_err(|e| format!("Invalid group IP: {}", e))?;
    let port = parts[1]
        .parse()
        .map_err(|e| format!("Invalid port: {}", e))?;
    let interface = parts[2]
        .parse()
        .map_err(|e| format!("Invalid interface IP: {}", e))?;
    Ok(OutputDestination {
        group,
        port,
        interface,
    })
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "emergency" | "emerg" => Ok(Severity::Emergency),
        "alert" => Ok(Severity::Alert),
        "critical" | "crit" => Ok(Severity::Critical),
        "error" | "err" => Ok(Severity::Error),
        "warning" | "warn" => Ok(Severity::Warning),
        "notice" => Ok(Severity::Notice),
        "info" | "informational" => Ok(Severity::Info),
        "debug" => Ok(Severity::Debug),
        _ => Err(format!(
            "Invalid severity level: {}. Valid values: emergency, alert, critical, error, warning, notice, info, debug",
            s
        )),
    }
}

fn parse_facility(s: &str) -> Result<Facility, String> {
    match s {
        "Supervisor" => Ok(Facility::Supervisor),
        "RuleDispatch" => Ok(Facility::RuleDispatch),
        "ControlSocket" => Ok(Facility::ControlSocket),
        "ControlPlane" => Ok(Facility::ControlPlane),
        "DataPlane" => Ok(Facility::DataPlane),
        "Ingress" => Ok(Facility::Ingress),
        "Egress" => Ok(Facility::Egress),
        "BufferPool" => Ok(Facility::BufferPool),
        "PacketParser" => Ok(Facility::PacketParser),
        "Stats" => Ok(Facility::Stats),
        "Security" => Ok(Facility::Security),
        "Network" => Ok(Facility::Network),
        "Test" => Ok(Facility::Test),
        _ => Err(format!(
            "Invalid facility: {}. Valid values: Supervisor, RuleDispatch, ControlSocket, ControlPlane, DataPlane, Ingress, Egress, BufferPool, PacketParser, Stats, Security, Network, Test",
            s
        )),
    }
}

pub fn build_command(cli_command: CliCommand) -> Result<multicast_relay::SupervisorCommand> {
    Ok(match cli_command {
        CliCommand::Add {
            rule_id,
            input_interface,
            input_group,
            input_port,
            outputs,
        } => multicast_relay::SupervisorCommand::AddRule {
            rule_id: rule_id.unwrap_or_default(),
            input_interface,
            input_group,
            input_port,
            outputs,
        },
        CliCommand::Remove { rule_id } => {
            multicast_relay::SupervisorCommand::RemoveRule { rule_id }
        }
        CliCommand::List => multicast_relay::SupervisorCommand::ListRules,
        CliCommand::ListRules => multicast_relay::SupervisorCommand::ListRules,
        CliCommand::Stats => multicast_relay::SupervisorCommand::GetStats,
        CliCommand::ListWorkers => multicast_relay::SupervisorCommand::ListWorkers,
        CliCommand::Ping => multicast_relay::SupervisorCommand::Ping,
        CliCommand::LogLevel { action } => match action {
            LogLevelAction::Get => multicast_relay::SupervisorCommand::GetLogLevels,
            LogLevelAction::Set {
                global,
                facility,
                level,
            } => {
                if let Some(level_str) = global {
                    let level = parse_severity(&level_str).map_err(|e| anyhow::anyhow!("{}", e))?;
                    multicast_relay::SupervisorCommand::SetGlobalLogLevel { level }
                } else if let (Some(facility_str), Some(level_str)) = (facility, level) {
                    let facility =
                        parse_facility(&facility_str).map_err(|e| anyhow::anyhow!("{}", e))?;
                    let level = parse_severity(&level_str).map_err(|e| anyhow::anyhow!("{}", e))?;
                    multicast_relay::SupervisorCommand::SetFacilityLogLevel { facility, level }
                } else {
                    return Err(anyhow::anyhow!(
                        "Must specify either --global <LEVEL> or --facility <FACILITY> --level <LEVEL>"
                    ));
                }
            }
        },
    })
}

#[cfg(not(test))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    use multicast_relay::Response;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let args = Args::parse();
    let command = build_command(args.command)?;

    let mut stream = UnixStream::connect(args.socket_path).await?;
    let command_bytes = serde_json::to_vec(&command)?;
    stream.write_all(&command_bytes).await?;
    stream.shutdown().await?;

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await?;

    let response: Response = serde_json::from_slice(&response_bytes)?;
    println!("{}", serde_json::to_string_pretty(&response)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use multicast_relay::SupervisorCommand;

    #[test]
    fn test_parse_output_destination() {
        // --- Success Cases ---
        let s = "224.0.0.1:5000:127.0.0.1";
        let dest = parse_output_destination(s).unwrap();
        assert_eq!(dest.group, "224.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(dest.port, 5000);
        assert_eq!(dest.interface, "127.0.0.1".to_string());

        // --- Error Cases ---
        let s_invalid_parts = "invalid";
        assert!(parse_output_destination(s_invalid_parts).is_err());

        let s_invalid_ip = "not-an-ip:5000:127.0.0.1";
        assert!(parse_output_destination(s_invalid_ip).is_err());

        let s_invalid_port = "224.0.0.1:not-a-port:127.0.0.1";
        assert!(parse_output_destination(s_invalid_port).is_err());

        let s_too_many_parts = "224.0.0.1:5000:127.0.0.1:extra";
        assert!(parse_output_destination(s_too_many_parts).is_err());
    }

    #[tokio::test]
    async fn test_main_sends_command_and_prints_response() {
        use multicast_relay::Response;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        // 1. Setup: Create a mock Unix socket listener.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        // Spawn a task to act as the server.
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read the command from the client.
            let mut command_bytes = Vec::new();
            stream.read_to_end(&mut command_bytes).await.unwrap();
            let command: SupervisorCommand = serde_json::from_slice(&command_bytes).unwrap();

            // Verify the command is what we expect.
            assert!(matches!(command, SupervisorCommand::ListRules));

            // Send a mock response.
            let response = Response::Rules(vec![]);
            let response_bytes = serde_json::to_vec(&response).unwrap();
            stream.write_all(&response_bytes).await.unwrap();
        });

        // 2. Action: Run the client's main logic.
        let client_task = tokio::spawn(run_control_client(CliCommand::List, sock_path.clone()));

        // 3. Verification: Wait for both tasks to complete.
        server_task.await.unwrap();
        let result = client_task.await.unwrap();

        // Assert that the client finished successfully.
        assert!(result.is_ok());
    }

    async fn run_control_client(command: CliCommand, socket_path: PathBuf) -> Result<()> {
        use multicast_relay::Response;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let command = build_command(command)?;

        let mut stream = UnixStream::connect(socket_path).await?;
        let command_bytes = serde_json::to_vec(&command)?;
        stream.write_all(&command_bytes).await?;
        stream.shutdown().await?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await?;

        let response: Response = serde_json::from_slice(&response_bytes)?;
        // In a real app, we'd print this. For the test, we just care that it deserializes.
        let _ = serde_json::to_string_pretty(&response)?;

        Ok(())
    }

    #[test]
    fn test_parse_severity() {
        // Valid values
        assert_eq!(parse_severity("emergency").unwrap(), Severity::Emergency);
        assert_eq!(parse_severity("emerg").unwrap(), Severity::Emergency);
        assert_eq!(parse_severity("EMERGENCY").unwrap(), Severity::Emergency);
        assert_eq!(parse_severity("alert").unwrap(), Severity::Alert);
        assert_eq!(parse_severity("critical").unwrap(), Severity::Critical);
        assert_eq!(parse_severity("crit").unwrap(), Severity::Critical);
        assert_eq!(parse_severity("error").unwrap(), Severity::Error);
        assert_eq!(parse_severity("err").unwrap(), Severity::Error);
        assert_eq!(parse_severity("warning").unwrap(), Severity::Warning);
        assert_eq!(parse_severity("warn").unwrap(), Severity::Warning);
        assert_eq!(parse_severity("notice").unwrap(), Severity::Notice);
        assert_eq!(parse_severity("info").unwrap(), Severity::Info);
        assert_eq!(parse_severity("informational").unwrap(), Severity::Info);
        assert_eq!(parse_severity("debug").unwrap(), Severity::Debug);

        // Invalid value
        assert!(parse_severity("invalid").is_err());
    }

    #[test]
    fn test_parse_facility() {
        // Valid values
        assert_eq!(parse_facility("Supervisor").unwrap(), Facility::Supervisor);
        assert_eq!(parse_facility("Ingress").unwrap(), Facility::Ingress);
        assert_eq!(parse_facility("Egress").unwrap(), Facility::Egress);
        assert_eq!(parse_facility("DataPlane").unwrap(), Facility::DataPlane);

        // Invalid value
        assert!(parse_facility("InvalidFacility").is_err());
    }

    #[test]
    fn test_build_log_level_commands() {
        // Test GetLogLevels
        let cmd = CliCommand::LogLevel {
            action: LogLevelAction::Get,
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(
            supervisor_cmd,
            multicast_relay::SupervisorCommand::GetLogLevels
        ));

        // Test SetGlobalLogLevel
        let cmd = CliCommand::LogLevel {
            action: LogLevelAction::Set {
                global: Some("info".to_string()),
                facility: None,
                level: None,
            },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(
            supervisor_cmd,
            multicast_relay::SupervisorCommand::SetGlobalLogLevel {
                level: Severity::Info
            }
        ));

        // Test SetFacilityLogLevel
        let cmd = CliCommand::LogLevel {
            action: LogLevelAction::Set {
                global: None,
                facility: Some("Ingress".to_string()),
                level: Some("debug".to_string()),
            },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(
            supervisor_cmd,
            multicast_relay::SupervisorCommand::SetFacilityLogLevel {
                facility: Facility::Ingress,
                level: Severity::Debug
            }
        ));

        // Test error case: neither global nor facility specified
        let cmd = CliCommand::LogLevel {
            action: LogLevelAction::Set {
                global: None,
                facility: None,
                level: None,
            },
        };
        assert!(build_command(cmd).is_err());
    }
}
