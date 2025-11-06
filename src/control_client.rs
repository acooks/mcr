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
enum CliCommand {
    /// Add a new forwarding rule
    Add {
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
        input_group: Ipv4Addr,
        #[arg(long)]
        input_port: u16,
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

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<()> {
    use clap::Parser;
    use multicast_relay::{Command, Response};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let args = Args::parse();

    let command = match args.command {
        CliCommand::Add {
            input_group,
            input_port,
            outputs,
        } => Command::AddRule {
            input_group,
            input_port,
            outputs,
            dtls_enabled: false,
        },
        CliCommand::Remove {
            input_group,
            input_port,
        } => Command::RemoveRule {
            input_group,
            input_port,
        },
        CliCommand::List => Command::ListRules,
        CliCommand::Stats => Command::GetStats,
    };

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

    #[test]
    fn test_parse_output_destination() {
        let s = "224.0.0.1:5000:127.0.0.1";
        let dest = parse_output_destination(s).unwrap();
        assert_eq!(dest.group, "224.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(dest.port, 5000);
        assert_eq!(dest.interface, "127.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert!(!dest.dtls_enabled);

        let s = "224.0.0.1:5000:127.0.0.1:true";
        let dest = parse_output_destination(s).unwrap();
        assert!(dest.dtls_enabled);

        let s = "224.0.0.1:5000:127.0.0.1:false";
        let dest = parse_output_destination(s).unwrap();
        assert!(!dest.dtls_enabled);

        let s = "invalid";
        assert!(parse_output_destination(s).is_err());
    }
}
