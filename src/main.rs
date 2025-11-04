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
use tokio::task::JoinHandle;
use metrics::{counter, describe_counter, gauge, describe_gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use sysinfo::{System, Pid};

use multicast_relay::control_plane::{Command, Response, ForwardingRule, FlowStats, RelayCommand, OutputDestination};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Initial multicast group IP address to listen on
    #[arg(long)]
    input_group: Option<Ipv4Addr>,

    /// Initial port to listen on
    #[arg(long)]
    input_port: Option<u16>,

    /// Initial multicast group IP address to retransmit to
    #[arg(long)]
    output_group: Option<Ipv4Addr>,

    /// Initial port to retransmit to
    #[arg(long)]
    output_port: Option<u16>,

    /// Initial local interface IP address to send from
    #[arg(long)]
    output_interface: Option<Ipv4Addr>,

    /// Interval in seconds for reporting statistics
    #[arg(long, default_value_t = 5)]
    reporting_interval: u64,

    /// Prometheus exporter listen address
    #[arg(long, default_value = "127.0.0.1:9090")]
    prometheus_addr: SocketAddr,
}

async fn run_flow_task(
    rule: ForwardingRule,
    stats_tx: mpsc::Sender<(ForwardingRule, FlowStats)>,
) -> Result<()> {
    let listen_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, rule.input_port);

    // Receiver socket setup
    let receiver_std_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    receiver_std_socket.set_reuse_address(true)?;
    receiver_std_socket.set_reuse_port(true)?;
    receiver_std_socket.bind(&listen_addr.into())?;
    receiver_std_socket.join_multicast_v4(&rule.input_group, &Ipv4Addr::UNSPECIFIED)?;
    receiver_std_socket.set_nonblocking(true)?;
    let receiver_socket = UdpSocket::from_std(receiver_std_socket.into())?;

    // Sender sockets setup
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
            Ok((len, _remote_addr)) => {
                let data = &buf[..len];
                for (i, output) in rule.outputs.iter().enumerate() {
                    let sender_socket = &sender_sockets[i];
                    let dest_addr = SocketAddrV4::new(output.group, output.port);
                    if let Err(e) = sender_socket.send_to(data, dest_addr).await {
                        eprintln!("Error sending packet for flow {}:{}: {}", rule.input_group, rule.input_port, e);
                    }
                }
                packets_relayed += 1;
                bytes_relayed += len as u64;
                counter!("packets_relayed_total").increment(1);
                counter!("bytes_relayed_total").increment(len as u64);
            },
            Err(e) => {
                eprintln!("Error receiving packet for flow {}:{}: {}", rule.input_group, rule.input_port, e);
            }
        }

        if last_update_time.elapsed() >= update_interval {
            let elapsed_secs = last_update_time.elapsed().as_secs_f64();
            let pps = packets_relayed as f64 / elapsed_secs;
            let bps = (bytes_relayed as f64 * 8.0) / elapsed_secs;
            
            let stats = FlowStats {
                input_group: rule.input_group,
                input_port: rule.input_port,
                packets_relayed,
                bytes_relayed,
                packets_per_second: pps,
                bits_per_second: bps,
            };

            if let Err(e) = stats_tx.send((rule.clone(), stats)).await {
                eprintln!("Failed to send stats: {}", e);
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
    shared_flows: Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>>,
) -> Result<()> {
    let mut flow_tasks: HashMap<(Ipv4Addr, u16), JoinHandle<()>> = HashMap::new();

    if let Some(rule) = initial_rule {
        let stats_tx_clone = stats_tx.clone();
        let key = (rule.input_group, rule.input_port);
        let task = tokio::spawn(async move {
            if let Err(e) = run_flow_task(rule.clone(), stats_tx_clone).await {
                eprintln!("Flow task for {}:{} failed: {}", rule.input_group, rule.input_port, e);
            }
        });
        flow_tasks.insert(key, task);
    }

    while let Some(command) = relay_command_rx.recv().await {
        match command {
            RelayCommand::AddRule(rule) => {
                println!("Adding rule: {:?}", rule);
                let key = (rule.input_group, rule.input_port);
                if let Some(existing_task) = flow_tasks.remove(&key) {
                    existing_task.abort();
                }
                let stats_tx_clone = stats_tx.clone();
                let task = tokio::spawn(async move {
                    if let Err(e) = run_flow_task(rule.clone(), stats_tx_clone).await {
                        eprintln!("Flow task for {}:{} failed: {}", rule.input_group, rule.input_port, e);
                    }
                });
                flow_tasks.insert(key, task);
                println!("Rule added successfully.");
            },
            RelayCommand::RemoveRule { input_group, input_port } => {
                println!("Removing rule for {}:{}", input_group, input_port);
                if let Some(task) = flow_tasks.remove(&(input_group, input_port)) {
                    task.abort();
                    println!("Rule removed successfully.");
                } else {
                    println!("Rule not found.");
                }
                let mut flows_guard = shared_flows.lock().await;
                flows_guard.remove(&(input_group, input_port));
            },
        }
    }

    Ok(())
}

async fn stats_aggregator_task(
    mut stats_rx: mpsc::Receiver<(ForwardingRule, FlowStats)>,
    shared_flows: Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>>,
) -> Result<()> {
    while let Some((rule, stats)) = stats_rx.recv().await {
        let mut flows_guard = shared_flows.lock().await;
        flows_guard.insert((rule.input_group, rule.input_port), (rule, stats));
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
    println!("Control plane listening on {:?}", socket_path);

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        let relay_command_tx = relay_command_tx.clone();
        let shared_flows = shared_flows.clone();

        tokio::spawn(async move {
            let mut buffer = Vec::new();
            if let Err(e) = stream.read_to_end(&mut buffer).await {
                eprintln!("Control plane client connection error: {}", e);
                return;
            }

            let command: Result<Command, _> = serde_json::from_slice(&buffer);
            let response = match command {
                Ok(cmd) => {
                    println!("Received command: {:?}", cmd);
                    match cmd {
                        Command::AddRule { input_group, input_port, outputs, dtls_enabled } => {
                            let rule = ForwardingRule { input_group, input_port, outputs, dtls_enabled };
                            match relay_command_tx.send(RelayCommand::AddRule(rule)).await {
                                Ok(_) => Response::Success("Rule addition command sent.".to_string()),
                                Err(e) => Response::Error(format!("Failed to send add rule command: {}", e)),
                            }
                        },
                        Command::RemoveRule { input_group, input_port } => {
                            match relay_command_tx.send(RelayCommand::RemoveRule { input_group, input_port }).await {
                                Ok(_) => Response::Success("Rule removal command sent.".to_string()),
                                Err(e) => Response::Error(format!("Failed to send remove rule command: {}", e)),
                            }
                        },
                        Command::ListRules => {
                            let flows_guard = shared_flows.lock().await;
                            let rules: Vec<ForwardingRule> = flows_guard.values().map(|(rule, _)| rule.clone()).collect();
                            Response::Rules(rules)
                        },
                        Command::GetStats => {
                            let flows_guard = shared_flows.lock().await;
                            let stats: Vec<FlowStats> = flows_guard.values().map(|(_, stats)| stats.clone()).collect();
                            Response::Stats(stats)
                        },
                    }
                },
                Err(e) => Response::Error(format!("Failed to deserialize command: {}", e)),
            };

            let response_bytes = serde_json::to_vec(&response).unwrap();
            if let Err(e) = stream.write_all(&response_bytes).await {
                eprintln!("Failed to send response to control plane client: {}", e);
            }
        });
    }
}

async fn monitoring_task(
    shared_flows: Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>>,
    reporting_interval: u64,
) -> Result<()> {
    let mut sys = System::new_all();
    let pid = Pid::from(std::process::id() as usize);
    let interval = Duration::from_secs(reporting_interval);

    loop {
        tokio::time::sleep(interval).await;

        sys.refresh_process(pid);
        let process = sys.process(pid).unwrap();

        let cpu_usage = process.cpu_usage();
        let memory_usage = process.memory();

        gauge!("cpu_usage_percent").set(cpu_usage as f64);
        gauge!("memory_usage_bytes").set(memory_usage as f64);

        let flows_guard = shared_flows.lock().await;
        let mut _total_packets_relayed = 0;
        let mut _total_bytes_relayed = 0;
        let mut total_pps = 0.0;
        let mut total_bps = 0.0;

        println!("\n--- Monitoring Report ---");
        println!("CPU: {:.2}%, Memory: {} KB", cpu_usage, memory_usage / 1024);
        println!("Active flows: {}", flows_guard.len());

        for ((input_group, input_port), (_, stats)) in flows_guard.iter() {
            println!(
                "  Flow {}:{}: {:.2} pps, {:.2} Mbps",
                input_group,
                input_port,
                stats.packets_per_second,
                stats.bits_per_second / 1_000_000.0
            );
            total_pps += stats.packets_per_second;
            total_bps += stats.bits_per_second;
        }

        println!(
            "Total: {:.2} pps, {:.2} Mbps",
            total_pps,
            total_bps / 1_000_000.0
        );
        println!("-----------------------\n");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let builder = PrometheusBuilder::new();
    builder.with_http_listener(args.prometheus_addr).install()?;

    describe_counter!("packets_relayed_total", "Total number of packets relayed");
    describe_counter!("bytes_relayed_total", "Total number of bytes relayed");
    describe_gauge!("cpu_usage_percent", "Current CPU usage of the application in percent");
    describe_gauge!("memory_usage_bytes", "Current memory usage of the application in bytes");

    let control_socket_path = Path::new("/tmp/multicast_relay_control.sock");
    let (relay_command_tx, relay_command_rx) = mpsc::channel::<RelayCommand>(100);
    let (stats_tx, stats_rx) = mpsc::channel::<(ForwardingRule, FlowStats)>(100);

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

    let shared_flows: Arc<Mutex<HashMap<(Ipv4Addr, u16), (ForwardingRule, FlowStats)>>> = Arc::new(Mutex::new(HashMap::new()));

    tokio::select! {
        res = run_multicast_relay(relay_command_rx, initial_rule, stats_tx, shared_flows.clone()) => {
            if let Err(e) = res { eprintln!("Multicast relay task failed: {}", e); }
        }
        res = control_plane_task(control_socket_path, relay_command_tx, shared_flows.clone()) => {
            if let Err(e) = res { eprintln!("Control plane task failed: {}", e); }
        }
        res = monitoring_task(shared_flows.clone(), args.reporting_interval) => {
            if let Err(e) = res { eprintln!("Monitoring task failed: {}", e); }
        }
        res = stats_aggregator_task(stats_rx, shared_flows.clone()) => {
            if let Err(e) = res { eprintln!("Stats aggregator task failed: {}", e); }
        }
    }

    Ok(())
}