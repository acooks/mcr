use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};
use anyhow::Result;
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::time::{Instant, Duration};
use tokio::net::{UnixListener, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::path::Path;
use std::fs;
use std::collections::HashMap;
use tokio::sync::mpsc;
use std::sync::Arc;
use tokio::sync::Mutex;
use metrics::{counter, describe_counter, gauge, describe_gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use sysinfo::{System, Pid};

use multicast_relay::{Command, Response, ForwardingRule, FlowStats, RelayCommand, OutputDestination};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    input_group: Option<Ipv4Addr>,
    #[arg(long)]
    input_port: Option<u16>,
    #[arg(long)]
    output_group: Option<Ipv4Addr>,
    #[arg(long)]
    output_port: Option<u16>,
    #[arg(long)]
    output_interface: Option<Ipv4Addr>,
    #[arg(long, default_value_t = 5)]
    reporting_interval: u64,
    #[arg(long, default_value = "127.0.0.1:9090")]
    prometheus_addr: SocketAddr,
}

async fn run_flow_task(
    rule: ForwardingRule,
    stats_tx: mpsc::Sender<(ForwardingRule, FlowStats)>,
) -> Result<()> {
    let listen_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, rule.input_port);
    let receiver_std_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    receiver_std_socket.set_reuse_address(true)?;
    receiver_std_socket.set_reuse_port(true)?;
    receiver_std_socket.bind(&listen_addr.into())?;
    receiver_std_socket.join_multicast_v4(&rule.input_group, &Ipv4Addr::UNSPECIFIED)?;
    receiver_std_socket.set_nonblocking(true)?;
    let receiver_socket = UdpSocket::from_std(receiver_std_socket.into())?;

    let mut sender_sockets = Vec::new();
    for output in &rule.outputs {
        let sender_std_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sender_std_socket.set_multicast_loop_v4(true)?;
        sender_std_socket.set_multicast_if_v4(&output.interface)?;
        sender_std_socket.bind(&SocketAddrV4::new(output.interface, 0).into())?;
        sender_std_socket.set_nonblocking(true)?;
        sender_sockets.push(UdpSocket::from_std(sender_std_socket.into())?);
    }

    println!("Flow task started: Listening on {}:{}", rule.input_group, rule.input_port);
    let mut buf = vec![0u8; 1500];
    let mut packets_relayed = 0;
    let mut bytes_relayed = 0;
    let mut last_update_time = Instant::now();
    let update_interval = Duration::from_secs(1);

    loop {
        match receiver_socket.recv_from(&mut buf).await {
            Ok((len, _)) => {
                for (i, output) in rule.outputs.iter().enumerate() {
                    let sender_socket = &sender_sockets[i];
                    let dest_addr = SocketAddrV4::new(output.group, output.port);
                    let _ = sender_socket.send_to(&buf[..len], dest_addr).await;
                }
                packets_relayed += 1;
                bytes_relayed += len as u64;
                counter!("packets_relayed_total").increment(1);
                counter!("bytes_relayed_total").increment(len as u64);
            }
            Err(e) => eprintln!("Error receiving packet: {}", e),
        }

        if last_update_time.elapsed() >= update_interval {
            let elapsed_secs = last_update_time.elapsed().as_secs_f64();
            let stats = FlowStats {
                input_group: rule.input_group,
                input_port: rule.input_port,
                packets_relayed,
                bytes_relayed,
                packets_per_second: packets_relayed as f64 / elapsed_secs,
                bits_per_second: (bytes_relayed as f64 * 8.0) / elapsed_secs,
            };
            if stats_tx.send((rule.clone(), stats)).await.is_err() {
                eprintln!("Failed to send stats");
            }
            packets_relayed = 0;
            bytes_relayed = 0;
            last_update_time = Instant::now();
        }
    }
}

async fn run_multicast_relay(
    mut relay_command_rx: mpsc::Receiver<RelayCommand>,
    initial_rule: Option<ForwardingRule>,
    stats_tx: mpsc::Sender<(ForwardingRule, FlowStats)>,
) -> Result<()> {
    let mut flow_tasks = HashMap::new();
    if let Some(rule) = initial_rule {
        let stats_tx_clone = stats_tx.clone();
        let key = (rule.input_group, rule.input_port);
        let task = tokio::spawn(async move {
            if let Err(e) = run_flow_task(rule.clone(), stats_tx_clone).await {
                eprintln!("Flow task failed: {}", e);
            }
        });
        flow_tasks.insert(key, task);
    }

    while let Some(command) = relay_command_rx.recv().await {
        match command {
            RelayCommand::AddRule(rule) => {
                let key = (rule.input_group, rule.input_port);
                if let Some(existing_task) = flow_tasks.remove(&key) {
                    existing_task.abort();
                }
                let stats_tx_clone = stats_tx.clone();
                let task = tokio::spawn(async move {
                    if let Err(e) = run_flow_task(rule.clone(), stats_tx_clone).await {
                        eprintln!("Flow task failed: {}", e);
                    }
                });
                flow_tasks.insert(key, task);
            }
            RelayCommand::RemoveRule { input_group, input_port } => {
                if let Some(task) = flow_tasks.remove(&(input_group, input_port)) {
                    task.abort();
                }
            }
        }
    }
    Ok(())
}

async fn stats_aggregator_task(
    mut stats_rx: mpsc::Receiver<(ForwardingRule, FlowStats)>,
    shared_flows: Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>>,
) -> Result<()> {
    while let Some((rule, stats)) = stats_rx.recv().await {
        let mut flows = shared_flows.lock().await;
        flows.insert((rule.input_group, rule.input_port), (rule, stats));
    }
    Ok(())
}

async fn control_plane_task(
    socket_path: &Path,
    relay_command_tx: mpsc::Sender<RelayCommand>,
    shared_flows: Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>>,
) -> Result<()> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let relay_command_tx = relay_command_tx.clone();
        let shared_flows = shared_flows.clone();
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            if stream.read_to_end(&mut buffer).await.is_err() {
                return;
            }
            let command: Result<Command, _> = serde_json::from_slice(&buffer);
            let response = match command {
                Ok(cmd) => match cmd {
                    Command::AddRule { input_group, input_port, outputs, dtls_enabled } => {
                        let rule = ForwardingRule { input_group, input_port, outputs, dtls_enabled };
                        if relay_command_tx.send(RelayCommand::AddRule(rule)).await.is_ok() {
                            Response::Success("Rule added".to_string())
                        } else {
                            Response::Error("Failed to add rule".to_string())
                        }
                    }
                    Command::RemoveRule { input_group, input_port } => {
                        if relay_command_tx.send(RelayCommand::RemoveRule { input_group, input_port }).await.is_ok() {
                            Response::Success("Rule removed".to_string())
                        } else {
                            Response::Error("Failed to remove rule".to_string())
                        }
                    }
                    Command::ListRules => {
                        let flows = shared_flows.lock().await;
                        Response::Rules(flows.values().map(|(r, _)| r.clone()).collect())
                    }
                    Command::GetStats => {
                        let flows = shared_flows.lock().await;
                        Response::Stats(flows.values().map(|(_, s)| s.clone()).collect())
                    }
                },
                Err(e) => Response::Error(e.to_string()),
            };
            let response_bytes = serde_json::to_vec(&response).unwrap();
            let _ = stream.write_all(&response_bytes).await;
        });
    }
}

async fn monitoring_task(
    _shared_flows: Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>>,
    reporting_interval: u64,
) {
    let mut sys = System::new_all();
    let pid = Pid::from(std::process::id() as usize);
    loop {
        tokio::time::sleep(Duration::from_secs(reporting_interval)).await;
        sys.refresh_process(pid);
        if let Some(process) = sys.process(pid) {
            gauge!("cpu_usage_percent").set(process.cpu_usage() as f64);
            gauge!("memory_usage_bytes").set(process.memory() as f64);
        }
        // ... print stats ...
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let builder = PrometheusBuilder::new();
    builder.with_http_listener(args.prometheus_addr).install()?;
    describe_counter!("packets_relayed_total", "Total packets relayed");
    describe_gauge!("memory_usage_bytes", "Current memory usage");

    let shared_flows = Arc::new(Mutex::new(HashMap::new()));
    let (relay_command_tx, relay_command_rx) = mpsc::channel(100);
    let (stats_tx, stats_rx) = mpsc::channel(100);

    let initial_rule = if let (Some(ig), Some(ip), Some(og), Some(op), Some(oi)) =
        (args.input_group, args.input_port, args.output_group, args.output_port, args.output_interface) {
        Some(ForwardingRule {
            input_group: ig,
            input_port: ip,
            outputs: vec![OutputDestination { group: og, port: op, interface: oi, dtls_enabled: false }],
            dtls_enabled: false,
        })
    } else {
        None
    };

    let control_socket_path = Path::new("/tmp/multicast_relay_control.sock");

    tokio::select! {
        _ = run_multicast_relay(relay_command_rx, initial_rule, stats_tx) => {},
        _ = stats_aggregator_task(stats_rx, shared_flows.clone()) => {},
        _ = control_plane_task(control_socket_path, relay_command_tx, shared_flows.clone()) => {},
        _ = monitoring_task(shared_flows.clone(), args.reporting_interval) => {},
    }

    Ok(())
}