// SPDX-License-Identifier: Apache-2.0 OR MIT
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use poc_buffer_pool_performance::{BufferPool, BufferSize};

/// Benchmark: Pool allocation/deallocation latency vs Vec
fn latency_pool_vs_vec(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency");

    // Pool allocation (without metrics)
    group.bench_function("pool_alloc_small_no_metrics", |b| {
        let mut pool = BufferPool::new(false);
        b.iter(|| {
            let buffer = pool.allocate(1000).unwrap();
            pool.deallocate(black_box(buffer));
        });
    });

    // Pool allocation (with metrics)
    group.bench_function("pool_alloc_small_with_metrics", |b| {
        let mut pool = BufferPool::new(true);
        b.iter(|| {
            let buffer = pool.allocate(1000).unwrap();
            pool.deallocate(black_box(buffer));
        });
    });

    // Vec allocation (baseline comparison)
    group.bench_function("vec_alloc_small", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(1500);
            vec.resize(1500, 0);
            black_box(vec);
        });
    });

    // Pool allocation - Standard size
    group.bench_function("pool_alloc_standard_no_metrics", |b| {
        let mut pool = BufferPool::new(false);
        b.iter(|| {
            let buffer = pool.allocate(2000).unwrap();
            pool.deallocate(black_box(buffer));
        });
    });

    // Vec allocation - Standard size
    group.bench_function("vec_alloc_standard", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(4096);
            vec.resize(4096, 0);
            black_box(vec);
        });
    });

    // Pool allocation - Jumbo size
    group.bench_function("pool_alloc_jumbo_no_metrics", |b| {
        let mut pool = BufferPool::new(false);
        b.iter(|| {
            let buffer = pool.allocate(8000).unwrap();
            pool.deallocate(black_box(buffer));
        });
    });

    // Vec allocation - Jumbo size
    group.bench_function("vec_alloc_jumbo", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(9000);
            vec.resize(9000, 0);
            black_box(vec);
        });
    });

    group.finish();
}

/// Benchmark: Throughput (operations per second)
fn throughput_sustained(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    // Set measurement time for throughput tests
    group.measurement_time(std::time::Duration::from_secs(10));

    // Throughput: Pool allocations without metrics
    group.throughput(Throughput::Elements(1));
    group.bench_function("pool_ops_per_sec_no_metrics", |b| {
        let mut pool = BufferPool::new(false);
        b.iter(|| {
            let buffer = pool.allocate(1000).unwrap();
            pool.deallocate(buffer);
        });
    });

    // Throughput: Pool allocations with metrics
    group.throughput(Throughput::Elements(1));
    group.bench_function("pool_ops_per_sec_with_metrics", |b| {
        let mut pool = BufferPool::new(true);
        b.iter(|| {
            let buffer = pool.allocate(1000).unwrap();
            pool.deallocate(buffer);
        });
    });

    // Throughput: Vec allocations (baseline)
    group.throughput(Throughput::Elements(1));
    group.bench_function("vec_ops_per_sec", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(1500);
            vec.resize(1500, 0);
            black_box(vec);
        });
    });

    group.finish();
}

/// Benchmark: Scaling with different pool sizes
fn scaling_pool_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling");

    for size in [100, 500, 1000, 5000].iter() {
        group.bench_with_input(BenchmarkId::new("pool", size), size, |b, &size| {
            let mut pool = BufferPool::with_capacities(size, size, size, false);
            b.iter(|| {
                let buffer = pool.allocate(1000).unwrap();
                pool.deallocate(buffer);
            });
        });
    }

    group.finish();
}

/// Benchmark: Burst scenario (allocate many, then deallocate all)
fn burst_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("burst");

    for burst_size in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("allocate_batch", burst_size),
            burst_size,
            |b, &burst_size| {
                let mut pool = BufferPool::with_capacities(1000, 1000, 1000, false);
                b.iter(|| {
                    let buffers: Vec<_> = (0..burst_size)
                        .map(|_| pool.allocate(1000).unwrap())
                        .collect();
                    for buffer in buffers {
                        pool.deallocate(buffer);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Memory copy operations (simulating packet processing)
fn memory_copy_with_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_copy");

    // Simulate packet processing: allocate, copy data, deallocate
    group.bench_function("pool_with_copy_small", |b| {
        let mut pool = BufferPool::new(false);
        let source_data = vec![0xAB; 1000];

        b.iter(|| {
            let mut buffer = pool.allocate(1000).unwrap();
            buffer.as_mut_slice()[..1000].copy_from_slice(&source_data);
            black_box(&buffer);
            pool.deallocate(buffer);
        });
    });

    group.bench_function("vec_with_copy_small", |b| {
        let source_data = vec![0xAB; 1000];

        b.iter(|| {
            let mut vec = Vec::with_capacity(1500);
            vec.resize(1500, 0);
            vec[..1000].copy_from_slice(&source_data);
            black_box(&vec);
        });
    });

    group.bench_function("pool_with_copy_jumbo", |b| {
        let mut pool = BufferPool::new(false);
        let source_data = vec![0xAB; 8000];

        b.iter(|| {
            let mut buffer = pool.allocate(8000).unwrap();
            buffer.as_mut_slice()[..8000].copy_from_slice(&source_data);
            black_box(&buffer);
            pool.deallocate(buffer);
        });
    });

    group.bench_function("vec_with_copy_jumbo", |b| {
        let source_data = vec![0xAB; 8000];

        b.iter(|| {
            let mut vec = Vec::with_capacity(9000);
            vec.resize(9000, 0);
            vec[..8000].copy_from_slice(&source_data);
            black_box(&vec);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    latency_pool_vs_vec,
    throughput_sustained,
    scaling_pool_size,
    burst_allocation,
    memory_copy_with_pool
);
criterion_main!(benches);
