use anyhow::Result;
use clap::Parser;
use multicast_relay::{supervisor, worker};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug, PartialEq)]
enum Command {
    /// Run the supervisor process
    Supervisor,
    /// Run the worker process (intended to be called by the supervisor)
    Worker {
        #[arg(long, default_value = "nobody")]
        user: String,
        #[arg(long, default_value = "nogroup")]
        group: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Supervisor => {
            supervisor::run().await?;
        }
        Command::Worker { user, group } => {
            // D1, D7: The worker process uses a `tokio-uring` runtime
            // to drive the high-performance data plane.
            tokio_uring::start(async {
                if let Err(e) = worker::run(user, group).await {
                    eprintln!("Worker process failed: {}", e);
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

    #[test]
    fn test_arg_parsing() {
        let args = Args::parse_from(["multicast_relay", "supervisor"]);
        assert_eq!(args.command, Command::Supervisor);

        let args = Args::parse_from([
            "multicast_relay",
            "worker",
            "--user",
            "test",
            "--group",
            "test",
        ]);
        assert_eq!(
            args.command,
            Command::Worker {
                user: "test".to_string(),
                group: "test".to_string()
            }
        );
    }
}
