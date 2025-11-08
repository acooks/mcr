use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use poc_io_uring_egress::{ConnectedEgressSender, EgressConfig};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

/// Helper: Create a receiver socket on localhost
fn create_receiver(port: u16) -> UdpSocket {
    let addr = format!("127.0.0.1:{}", port);
    let socket = UdpSocket::bind(&addr).expect("Failed to bind receiver");
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("Failed to set timeout");
    socket
}

/// Benchmark: Throughput with different batch sizes
fn throughput_batch_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_batch_size");
    group.measurement_time(Duration::from_secs(10));

    // Start a receiver on a port
    let receiver_port = 19000;

    // Spawn a thread to drain the receiver socket
    thread::spawn(move || {
        let receiver = UdpSocket::bind(format!("127.0.0.1:{}", receiver_port))
            .expect("Failed to bind drain socket");
        let mut buf = vec![0u8; 9000];
        loop {
            let _ = receiver.recv_from(&mut buf);
        }
    });

    // Wait for receiver to be ready
    thread::sleep(Duration::from_millis(100));

    let packet_sizes = [1000]; // Small packet size for speed

    for &packet_size in &packet_sizes {
        for batch_size in [1, 16, 32, 64, 128] {
            group.throughput(Throughput::Elements(batch_size as u64));

            group.bench_with_input(
                BenchmarkId::new("batch", batch_size),
                &batch_size,
                |b, &batch_size| {
                    let config = EgressConfig {
                        queue_depth: 128,
                        source_addr: None,
                        track_stats: false, // Disable stats for pure speed
                    };

                    let mut sender = ConnectedEgressSender::new(
                        config,
                        format!("127.0.0.1:{}", receiver_port).parse().unwrap(),
                    )
                    .expect("Failed to create sender");

                    // Prepare packets
                    let data = vec![0xAB; packet_size];
                    let packets: Vec<&[u8]> = (0..batch_size).map(|_| data.as_slice()).collect();

                    b.iter(|| {
                        let sent = sender.send_batch(black_box(&packets)).expect("Send failed");
                        black_box(sent);
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark: Throughput with different queue depths
fn throughput_queue_depths(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_queue_depth");
    group.measurement_time(Duration::from_secs(10));

    let receiver_port = 19001;

    // Spawn drain thread
    thread::spawn(move || {
        let receiver = UdpSocket::bind(format!("127.0.0.1:{}", receiver_port))
            .expect("Failed to bind drain socket");
        let mut buf = vec![0u8; 9000];
        loop {
            let _ = receiver.recv_from(&mut buf);
        }
    });

    thread::sleep(Duration::from_millis(100));

    let batch_size = 64; // Fixed batch size

    for queue_depth in [32, 64, 128, 256] {
        group.bench_with_input(
            BenchmarkId::new("queue_depth", queue_depth),
            &queue_depth,
            |b, &queue_depth| {
                let config = EgressConfig {
                    queue_depth,
                    source_addr: None,
                    track_stats: false,
                };

                let mut sender = ConnectedEgressSender::new(
                    config,
                    format!("127.0.0.1:{}", receiver_port).parse().unwrap(),
                )
                .expect("Failed to create sender");

                let data = vec![0xAB; 1000];
                let packets: Vec<&[u8]> = (0..batch_size).map(|_| data.as_slice()).collect();

                b.iter(|| {
                    let sent = sender.send_batch(black_box(&packets)).expect("Send failed");
                    black_box(sent);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Throughput with different packet sizes
fn throughput_packet_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_packet_size");
    group.measurement_time(Duration::from_secs(10));

    let receiver_port = 19002;

    thread::spawn(move || {
        let receiver = UdpSocket::bind(format!("127.0.0.1:{}", receiver_port))
            .expect("Failed to bind drain socket");
        let mut buf = vec![0u8; 9000];
        loop {
            let _ = receiver.recv_from(&mut buf);
        }
    });

    thread::sleep(Duration::from_millis(100));

    for packet_size in [100, 500, 1000, 1500, 4000, 8000] {
        group.throughput(Throughput::Bytes(packet_size as u64));

        group.bench_with_input(
            BenchmarkId::new("packet_size", packet_size),
            &packet_size,
            |b, &packet_size| {
                let config = EgressConfig {
                    queue_depth: 128,
                    source_addr: None,
                    track_stats: false,
                };

                let mut sender = ConnectedEgressSender::new(
                    config,
                    format!("127.0.0.1:{}", receiver_port).parse().unwrap(),
                )
                .expect("Failed to create sender");

                let data = vec![0xAB; packet_size];
                let packets: Vec<&[u8]> = (0..64).map(|_| data.as_slice()).collect();

                b.iter(|| {
                    let sent = sender.send_batch(black_box(&packets)).expect("Send failed");
                    black_box(sent);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Stats overhead
fn stats_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("stats_overhead");

    let receiver_port = 19003;

    thread::spawn(move || {
        let receiver = UdpSocket::bind(format!("127.0.0.1:{}", receiver_port))
            .expect("Failed to bind drain socket");
        let mut buf = vec![0u8; 9000];
        loop {
            let _ = receiver.recv_from(&mut buf);
        }
    });

    thread::sleep(Duration::from_millis(100));

    // With stats
    group.bench_function("with_stats", |b| {
        let config = EgressConfig {
            queue_depth: 128,
            source_addr: None,
            track_stats: true,
        };

        let mut sender = ConnectedEgressSender::new(
            config,
            format!("127.0.0.1:{}", receiver_port).parse().unwrap(),
        )
        .expect("Failed to create sender");

        let data = vec![0xAB; 1000];
        let packets: Vec<&[u8]> = (0..64).map(|_| data.as_slice()).collect();

        b.iter(|| {
            let sent = sender.send_batch(black_box(&packets)).expect("Send failed");
            black_box(sent);
        });
    });

    // Without stats
    group.bench_function("without_stats", |b| {
        let config = EgressConfig {
            queue_depth: 128,
            source_addr: None,
            track_stats: false,
        };

        let mut sender = ConnectedEgressSender::new(
            config,
            format!("127.0.0.1:{}", receiver_port).parse().unwrap(),
        )
        .expect("Failed to create sender");

        let data = vec![0xAB; 1000];
        let packets: Vec<&[u8]> = (0..64).map(|_| data.as_slice()).collect();

        b.iter(|| {
            let sent = sender.send_batch(black_box(&packets)).expect("Send failed");
            black_box(sent);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    throughput_batch_sizes,
    throughput_queue_depths,
    throughput_packet_sizes,
    stats_overhead
);
criterion_main!(benches);
