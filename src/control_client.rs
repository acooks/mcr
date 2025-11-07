use anyhow::Result;
use clap::Parser;
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
        #[arg(long, value_parser = parse_output_destination)]
        outputs: Vec<OutputDestination>,
    },
    /// Remove a forwarding rule
    Remove {
        #[arg(long)]
        rule_id: String,
    },
    /// List all forwarding rules
    List,
    /// Get statistics for all flows
    Stats,
}

fn parse_output_destination(s: &str) -> Result<OutputDestination, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 && parts.len() != 4 {
        return Err("Invalid format. Expected group:port:interface[:dtls]".to_string());
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
    let dtls_enabled = if parts.len() == 4 {
        parts[3]
            .parse()
            .map_err(|e| format!("Invalid dtls flag: {}", e))?
    } else {
        false
    };
    Ok(OutputDestination {
        group,
        port,
        interface,
        dtls_enabled,
    })
}

pub fn build_command(cli_command: CliCommand) -> multicast_relay::SupervisorCommand {
    match cli_command {
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
            dtls_enabled: false,
        },
        CliCommand::Remove { rule_id } => multicast_relay::SupervisorCommand::RemoveRule { rule_id },
        CliCommand::List => multicast_relay::SupervisorCommand::ListRules,
        CliCommand::Stats => multicast_relay::SupervisorCommand::GetStats,
    }
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<()> {
    use multicast_relay::Response;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let args = Args::parse();
    let command = build_command(args.command);

    let mut stream = UnixStream::connect(args.socket_path).await?;
    let command_bytes = serde_json::to_vec(&command)?;
    stream.write_all(&command_bytes).await?;

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
        assert!(!dest.dtls_enabled);

        let s_dtls_true = "224.0.0.1:5000:127.0.0.1:true";
        let dest_dtls_true = parse_output_destination(s_dtls_true).unwrap();
        assert!(dest_dtls_true.dtls_enabled);

        let s_dtls_false = "224.0.0.1:5000:127.0.0.1:false";
        let dest_dtls_false = parse_output_destination(s_dtls_false).unwrap();
        assert!(!dest_dtls_false.dtls_enabled);

        // --- Error Cases ---
        let s_invalid_parts = "invalid";
        assert!(parse_output_destination(s_invalid_parts).is_err());

        let s_invalid_ip = "not-an-ip:5000:127.0.0.1";
        assert!(parse_output_destination(s_invalid_ip).is_err());

        let s_invalid_port = "224.0.0.1:not-a-port:127.0.0.1";
        assert!(parse_output_destination(s_invalid_port).is_err());

        let s_invalid_dtls = "224.0.0.1:5000:127.0.0.1:not-a-bool";
        assert!(parse_output_destination(s_invalid_dtls).is_err());

        let s_too_many_parts = "224.0.0.1:5000:127.0.0.1:true:extra";
        assert!(parse_output_destination(s_too_many_parts).is_err());
    }

    #[test]
    fn test_cli_command_parsing() {

        // --- Test 'add' command ---
        let add_args = Args::parse_from([
            "control_client",
            "add",
            "--input-interface",
            "eth0",
            "--input-group",
            "224.0.0.1",
            "--input-port",
            "5000",
            "--outputs",
            "224.0.0.2:5001:lo",
        ]);
        let command = build_command(add_args.command);
        assert!(matches!(command, SupervisorCommand::AddRule { .. }));
                if let SupervisorCommand::AddRule {
                    rule_id: _,
                    input_interface,
                    input_group: _,
                    input_port: _,
                    outputs: _,
                    dtls_enabled: _,
                } = command
                {
            assert_eq!(input_interface, "eth0");
        }

        // --- Test 'remove' command ---
        let remove_args =
            Args::parse_from(["control_client", "remove", "--rule-id", "test-rule-123"]);
        let command = build_command(remove_args.command);
        assert!(matches!(command, SupervisorCommand::RemoveRule { .. }));
        if let SupervisorCommand::RemoveRule { rule_id, .. } = command {
            assert_eq!(rule_id, "test-rule-123");
        }

        // --- Test 'list' command ---
        let list_args = Args::parse_from(["control_client", "list"]);
        let command = build_command(list_args.command);
        assert!(matches!(command, SupervisorCommand::ListRules));

        // --- Test 'stats' command ---
        let stats_args = Args::parse_from(["control_client", "stats"]);
        let command = build_command(stats_args.command);
        assert!(matches!(command, SupervisorCommand::GetStats));
    }
}
