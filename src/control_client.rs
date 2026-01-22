// SPDX-License-Identifier: Apache-2.0 OR MIT
use anyhow::Result;
use clap::Parser;
use multicast_relay::logging::{Facility, Severity};
use multicast_relay::{Config, OutputDestination};
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: CliCommand,

    /// Path to the control socket
    #[arg(long, default_value = "/tmp/mcrd_control.sock")]
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
    /// Get supervisor protocol version
    Version,
    /// Configuration management
    Config {
        #[clap(subcommand)]
        action: ConfigAction,
    },
    /// PIM-SM protocol management
    Pim {
        #[clap(subcommand)]
        action: PimAction,
    },
    /// IGMP protocol management
    Igmp {
        #[clap(subcommand)]
        action: IgmpAction,
    },
    /// MSDP protocol management
    Msdp {
        #[clap(subcommand)]
        action: MsdpAction,
    },
    /// Show multicast routing table
    Mroute,
}

#[derive(Parser, Debug)]
pub enum ConfigAction {
    /// Show running configuration (JSON5 format)
    Show,
    /// Load configuration from a file
    Load {
        /// Path to configuration file
        #[arg(long)]
        file: PathBuf,
        /// Replace all existing rules (default: merge with existing)
        #[arg(long)]
        replace: bool,
    },
    /// Save running configuration to a file
    Save {
        /// Path to save configuration to
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Validate a configuration file without loading it
    Check {
        /// Path to configuration file
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Parser, Debug)]
pub enum PimAction {
    /// Show PIM neighbor table
    Neighbors,
    /// Enable PIM on an interface
    Enable {
        /// Interface name
        #[arg(long)]
        interface: String,
        /// DR priority (default: 1)
        #[arg(long, default_value = "1")]
        dr_priority: u32,
    },
    /// Disable PIM on an interface
    Disable {
        /// Interface name
        #[arg(long)]
        interface: String,
    },
    /// Set a static RP mapping
    SetRp {
        /// Group prefix (e.g., "239.0.0.0/8" or "239.1.1.1")
        #[arg(long)]
        group: String,
        /// RP address
        #[arg(long)]
        rp: Ipv4Addr,
    },
}

#[derive(Parser, Debug)]
pub enum IgmpAction {
    /// Show IGMP group membership table
    Groups,
    /// Enable IGMP querier on an interface
    EnableQuerier {
        /// Interface name
        #[arg(long)]
        interface: String,
    },
    /// Disable IGMP querier on an interface
    DisableQuerier {
        /// Interface name
        #[arg(long)]
        interface: String,
    },
}

#[derive(Parser, Debug)]
pub enum MsdpAction {
    /// Show MSDP peer table
    Peers,
    /// Show MSDP SA cache
    SaCache,
    /// Add an MSDP peer
    AddPeer {
        /// Peer address
        #[arg(long)]
        address: Ipv4Addr,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Optional mesh group name
        #[arg(long)]
        mesh_group: Option<String>,
        /// Mark as default peer
        #[arg(long)]
        default_peer: bool,
    },
    /// Remove an MSDP peer
    RemovePeer {
        /// Peer address
        #[arg(long)]
        address: Ipv4Addr,
    },
    /// Clear the MSDP SA cache
    ClearSaCache,
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
            "Invalid facility: {}. Valid values: Supervisor, RuleDispatch, ControlSocket, DataPlane, Ingress, Egress, BufferPool, PacketParser, Stats, Security, Network, Test",
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
            name: None, // TODO: Add --name option to CLI
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
        CliCommand::Version => multicast_relay::SupervisorCommand::GetVersion,
        CliCommand::Config { action } => match action {
            ConfigAction::Show => multicast_relay::SupervisorCommand::GetConfig,
            ConfigAction::Load { file, replace } => {
                // Load and parse the config file
                let config = Config::load_from_file(&file).map_err(|e| anyhow::anyhow!("{}", e))?;
                multicast_relay::SupervisorCommand::LoadConfig { config, replace }
            }
            ConfigAction::Save { file } => {
                multicast_relay::SupervisorCommand::SaveConfig { path: file }
            }
            ConfigAction::Check { file } => {
                // Load and parse the config file for validation
                let config = Config::load_from_file(&file).map_err(|e| anyhow::anyhow!("{}", e))?;
                multicast_relay::SupervisorCommand::CheckConfig { config }
            }
        },
        CliCommand::Pim { action } => match action {
            PimAction::Neighbors => multicast_relay::SupervisorCommand::GetPimNeighbors,
            PimAction::Enable {
                interface,
                dr_priority,
            } => multicast_relay::SupervisorCommand::EnablePim {
                interface,
                dr_priority: Some(dr_priority),
            },
            PimAction::Disable { interface } => {
                multicast_relay::SupervisorCommand::DisablePim { interface }
            }
            PimAction::SetRp { group, rp } => multicast_relay::SupervisorCommand::SetStaticRp {
                group_prefix: group,
                rp_address: rp,
            },
        },
        CliCommand::Igmp { action } => match action {
            IgmpAction::Groups => multicast_relay::SupervisorCommand::GetIgmpGroups,
            IgmpAction::EnableQuerier { interface } => {
                multicast_relay::SupervisorCommand::EnableIgmpQuerier { interface }
            }
            IgmpAction::DisableQuerier { interface } => {
                multicast_relay::SupervisorCommand::DisableIgmpQuerier { interface }
            }
        },
        CliCommand::Msdp { action } => match action {
            MsdpAction::Peers => multicast_relay::SupervisorCommand::GetMsdpPeers,
            MsdpAction::SaCache => multicast_relay::SupervisorCommand::GetMsdpSaCache,
            MsdpAction::AddPeer {
                address,
                description,
                mesh_group,
                default_peer,
            } => multicast_relay::SupervisorCommand::AddMsdpPeer {
                address,
                description,
                mesh_group,
                default_peer,
            },
            MsdpAction::RemovePeer { address } => {
                multicast_relay::SupervisorCommand::RemoveMsdpPeer { address }
            }
            MsdpAction::ClearSaCache => multicast_relay::SupervisorCommand::ClearMsdpSaCache,
        },
        CliCommand::Mroute => multicast_relay::SupervisorCommand::GetMroute,
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

    #[test]
    fn test_build_command_add() {
        let cmd = CliCommand::Add {
            rule_id: Some("test-rule".to_string()),
            input_interface: "eth0".to_string(),
            input_group: "239.1.1.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![OutputDestination {
                group: "239.2.2.2".parse().unwrap(),
                port: 6000,
                interface: "eth1".to_string(),
            }],
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::AddRule {
                rule_id,
                name,
                input_interface,
                input_group,
                input_port,
                outputs,
            } => {
                assert_eq!(rule_id, "test-rule");
                assert!(name.is_none());
                assert_eq!(input_interface, "eth0");
                assert_eq!(input_group, "239.1.1.1".parse::<Ipv4Addr>().unwrap());
                assert_eq!(input_port, 5000);
                assert_eq!(outputs.len(), 1);
            }
            _ => panic!("Expected AddRule command"),
        }

        // Test with no rule_id (should default to empty string)
        let cmd = CliCommand::Add {
            rule_id: None,
            input_interface: "eth0".to_string(),
            input_group: "239.1.1.1".parse().unwrap(),
            input_port: 5000,
            outputs: vec![],
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::AddRule { rule_id, .. } => {
                assert_eq!(rule_id, "");
            }
            _ => panic!("Expected AddRule command"),
        }
    }

    #[test]
    fn test_build_command_remove() {
        let cmd = CliCommand::Remove {
            rule_id: "rule-to-remove".to_string(),
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::RemoveRule { rule_id } => {
                assert_eq!(rule_id, "rule-to-remove");
            }
            _ => panic!("Expected RemoveRule command"),
        }
    }

    #[test]
    fn test_build_command_list_and_list_rules() {
        // Both List and ListRules should map to ListRules
        let cmd = CliCommand::List;
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::ListRules));

        let cmd = CliCommand::ListRules;
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::ListRules));
    }

    #[test]
    fn test_build_command_stats() {
        let cmd = CliCommand::Stats;
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::GetStats));
    }

    #[test]
    fn test_build_command_list_workers() {
        let cmd = CliCommand::ListWorkers;
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::ListWorkers));
    }

    #[test]
    fn test_build_command_ping() {
        let cmd = CliCommand::Ping;
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::Ping));
    }

    #[test]
    fn test_build_command_version() {
        let cmd = CliCommand::Version;
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::GetVersion));
    }

    #[test]
    fn test_build_command_config_show() {
        let cmd = CliCommand::Config {
            action: ConfigAction::Show,
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::GetConfig));
    }

    #[test]
    fn test_build_command_config_save() {
        // With path
        let cmd = CliCommand::Config {
            action: ConfigAction::Save {
                file: Some(PathBuf::from("/tmp/config.json5")),
            },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::SaveConfig { path } => {
                assert_eq!(path, Some(PathBuf::from("/tmp/config.json5")));
            }
            _ => panic!("Expected SaveConfig command"),
        }

        // Without path (use startup path)
        let cmd = CliCommand::Config {
            action: ConfigAction::Save { file: None },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::SaveConfig { path } => {
                assert!(path.is_none());
            }
            _ => panic!("Expected SaveConfig command"),
        }
    }

    #[test]
    fn test_build_command_config_load_nonexistent_file() {
        let cmd = CliCommand::Config {
            action: ConfigAction::Load {
                file: PathBuf::from("/nonexistent/config.json5"),
                replace: false,
            },
        };
        // Should fail because file doesn't exist
        assert!(build_command(cmd).is_err());
    }

    #[test]
    fn test_build_command_config_check_nonexistent_file() {
        let cmd = CliCommand::Config {
            action: ConfigAction::Check {
                file: PathBuf::from("/nonexistent/config.json5"),
            },
        };
        // Should fail because file doesn't exist
        assert!(build_command(cmd).is_err());
    }

    #[test]
    fn test_build_command_config_load_valid_file() {
        use std::io::Write;

        // Create a temporary config file
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{
            rules: [
                {{
                    input: {{ interface: "eth0", group: "239.1.1.1", port: 5000 }},
                    outputs: [{{ interface: "eth1", group: "239.2.2.2", port: 6000 }}]
                }}
            ]
        }}"#
        )
        .unwrap();
        temp.flush().unwrap();

        let cmd = CliCommand::Config {
            action: ConfigAction::Load {
                file: temp.path().to_path_buf(),
                replace: true,
            },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::LoadConfig { config, replace } => {
                assert!(replace);
                assert_eq!(config.rules.len(), 1);
            }
            _ => panic!("Expected LoadConfig command"),
        }
    }

    #[test]
    fn test_build_command_config_check_valid_file() {
        use std::io::Write;

        // Create a temporary config file
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{
            rules: [
                {{
                    input: {{ interface: "eth0", group: "239.1.1.1", port: 5000 }},
                    outputs: [{{ interface: "eth1", group: "239.2.2.2", port: 6000 }}]
                }}
            ]
        }}"#
        )
        .unwrap();
        temp.flush().unwrap();

        let cmd = CliCommand::Config {
            action: ConfigAction::Check {
                file: temp.path().to_path_buf(),
            },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::CheckConfig { config } => {
                assert_eq!(config.rules.len(), 1);
            }
            _ => panic!("Expected CheckConfig command"),
        }
    }

    #[test]
    fn test_parse_facility_all_variants() {
        // Test all facility variants
        assert_eq!(parse_facility("Supervisor").unwrap(), Facility::Supervisor);
        assert_eq!(
            parse_facility("RuleDispatch").unwrap(),
            Facility::RuleDispatch
        );
        assert_eq!(
            parse_facility("ControlSocket").unwrap(),
            Facility::ControlSocket
        );
        assert_eq!(parse_facility("DataPlane").unwrap(), Facility::DataPlane);
        assert_eq!(parse_facility("Ingress").unwrap(), Facility::Ingress);
        assert_eq!(parse_facility("Egress").unwrap(), Facility::Egress);
        assert_eq!(parse_facility("BufferPool").unwrap(), Facility::BufferPool);
        assert_eq!(
            parse_facility("PacketParser").unwrap(),
            Facility::PacketParser
        );
        assert_eq!(parse_facility("Stats").unwrap(), Facility::Stats);
        assert_eq!(parse_facility("Security").unwrap(), Facility::Security);
        assert_eq!(parse_facility("Network").unwrap(), Facility::Network);
        assert_eq!(parse_facility("Test").unwrap(), Facility::Test);

        // Invalid facility
        let err = parse_facility("NotAFacility").unwrap_err();
        assert!(err.contains("Invalid facility"));
    }

    #[test]
    fn test_log_level_set_invalid_severity() {
        let cmd = CliCommand::LogLevel {
            action: LogLevelAction::Set {
                global: Some("not-a-level".to_string()),
                facility: None,
                level: None,
            },
        };
        assert!(build_command(cmd).is_err());
    }

    #[test]
    fn test_log_level_set_invalid_facility() {
        let cmd = CliCommand::LogLevel {
            action: LogLevelAction::Set {
                global: None,
                facility: Some("NotAFacility".to_string()),
                level: Some("debug".to_string()),
            },
        };
        assert!(build_command(cmd).is_err());
    }

    #[test]
    fn test_build_command_msdp_peers() {
        let cmd = CliCommand::Msdp {
            action: MsdpAction::Peers,
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::GetMsdpPeers));
    }

    #[test]
    fn test_build_command_msdp_sa_cache() {
        let cmd = CliCommand::Msdp {
            action: MsdpAction::SaCache,
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(supervisor_cmd, SupervisorCommand::GetMsdpSaCache));
    }

    #[test]
    fn test_build_command_msdp_add_peer() {
        let cmd = CliCommand::Msdp {
            action: MsdpAction::AddPeer {
                address: "10.1.0.1".parse().unwrap(),
                description: Some("Remote RP".to_string()),
                mesh_group: Some("anycast-rp".to_string()),
                default_peer: true,
            },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::AddMsdpPeer {
                address,
                description,
                mesh_group,
                default_peer,
            } => {
                assert_eq!(address, "10.1.0.1".parse::<Ipv4Addr>().unwrap());
                assert_eq!(description, Some("Remote RP".to_string()));
                assert_eq!(mesh_group, Some("anycast-rp".to_string()));
                assert!(default_peer);
            }
            _ => panic!("Expected AddMsdpPeer command"),
        }
    }

    #[test]
    fn test_build_command_msdp_add_peer_minimal() {
        let cmd = CliCommand::Msdp {
            action: MsdpAction::AddPeer {
                address: "10.2.0.1".parse().unwrap(),
                description: None,
                mesh_group: None,
                default_peer: false,
            },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::AddMsdpPeer {
                address,
                description,
                mesh_group,
                default_peer,
            } => {
                assert_eq!(address, "10.2.0.1".parse::<Ipv4Addr>().unwrap());
                assert!(description.is_none());
                assert!(mesh_group.is_none());
                assert!(!default_peer);
            }
            _ => panic!("Expected AddMsdpPeer command"),
        }
    }

    #[test]
    fn test_build_command_msdp_remove_peer() {
        let cmd = CliCommand::Msdp {
            action: MsdpAction::RemovePeer {
                address: "10.1.0.1".parse().unwrap(),
            },
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        match supervisor_cmd {
            SupervisorCommand::RemoveMsdpPeer { address } => {
                assert_eq!(address, "10.1.0.1".parse::<Ipv4Addr>().unwrap());
            }
            _ => panic!("Expected RemoveMsdpPeer command"),
        }
    }

    #[test]
    fn test_build_command_msdp_clear_sa_cache() {
        let cmd = CliCommand::Msdp {
            action: MsdpAction::ClearSaCache,
        };
        let supervisor_cmd = build_command(cmd).unwrap();
        assert!(matches!(
            supervisor_cmd,
            SupervisorCommand::ClearMsdpSaCache
        ));
    }
}
