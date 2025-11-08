use super::*;

#[test]
fn test_buffer_pool_creation() {
    let pool = BufferPool::with_capacities(10, 10, 10, false);
    assert_eq!(
        pool.small_pool.capacity() + pool.standard_pool.capacity() + pool.jumbo_pool.capacity(),
        30
    );
    assert_eq!(
        pool.small_pool.available() + pool.standard_pool.available() + pool.jumbo_pool.available(),
        30
    );
}

#[test]
fn test_buffer_allocation_deallocation() {
    let mut pool = BufferPool::with_capacities(1, 1, 1, false);
    assert_eq!(
        pool.small_pool.available() + pool.standard_pool.available() + pool.jumbo_pool.available(),
        3
    );

    // Allocate one of each size
    let small_buffer = pool.allocate(100).unwrap(); // Small
    assert_eq!(small_buffer.capacity(), BufferSize::Small.size());
    assert_eq!(pool.small_pool.available(), 0);

    let standard_buffer = pool.allocate(2000).unwrap(); // Standard
    assert_eq!(standard_buffer.capacity(), BufferSize::Standard.size());
    assert_eq!(pool.standard_pool.available(), 0);

    let large_buffer = pool.allocate(9000).unwrap(); // Large
    assert_eq!(large_buffer.capacity(), BufferSize::Jumbo.size());
    assert_eq!(pool.jumbo_pool.available(), 0);

    // Deallocate
    pool.deallocate(small_buffer);
    assert_eq!(pool.small_pool.available(), 1);

    pool.deallocate(standard_buffer);
    assert_eq!(pool.standard_pool.available(), 1);

    pool.deallocate(large_buffer);
    assert_eq!(pool.jumbo_pool.available(), 1);
}

#[test]
fn test_pool_exhaustion() {
    let mut pool = BufferPool::with_capacities(1, 0, 0, false);
    assert_eq!(pool.small_pool.available(), 1);

    let _buffer = pool.allocate(100).unwrap();
    assert_eq!(pool.small_pool.available(), 0);

    // Next allocation should fail
    assert!(pool.allocate(100).is_none());
}

#[test]
#[should_panic(expected = "Buffer size class mismatch")]
fn test_wrong_pool_deallocation() {
    let mut pool = BufferPool::with_capacities(1, 1, 0, false);
    let small_buffer = pool.allocate(100).unwrap(); // Small

    // Intentionally deallocate to the wrong pool
    pool.standard_pool.deallocate(small_buffer);
}

#[test]
fn test_size_class_selection() {
    let mut pool = BufferPool::with_capacities(1, 1, 1, false);
    let small = pool.allocate(BufferSize::Small.size()).unwrap();
    assert_eq!(small.capacity(), BufferSize::Small.size());

    let standard = pool.allocate(BufferSize::Standard.size()).unwrap();
    assert_eq!(standard.capacity(), BufferSize::Standard.size());

    let large = pool.allocate(BufferSize::Jumbo.size()).unwrap();
    assert_eq!(large.capacity(), BufferSize::Jumbo.size());
}

#[test]
fn test_metrics_tracking() {
    let mut pool = BufferPool::with_capacities(5, 5, 5, true);
    let _ = pool.allocate(100);
    let _ = pool.allocate(2000);
    let _ = pool.allocate(9000);

    let stats = pool.aggregate_stats();
    assert_eq!(stats.small.allocations_total, 1);
    assert_eq!(stats.standard.allocations_total, 1);
    assert_eq!(stats.jumbo.allocations_total, 1);
    assert_eq!(stats.total_allocations(), 3);
}

#[test]
fn test_memory_footprint() {
    let pool = BufferPool::with_capacities(10, 20, 30, false);
    let expected_footprint = (10 * BufferSize::Small.size())
        + (20 * BufferSize::Standard.size())
        + (30 * BufferSize::Jumbo.size());
    assert_eq!(pool.memory_footprint(), expected_footprint);
}

#[test]
fn test_buffer_size_for_payload() {
    assert_eq!(BufferSize::for_payload(1), Some(BufferSize::Small));
    assert_eq!(
        BufferSize::for_payload(BufferSize::Small.size()),
        Some(BufferSize::Small)
    );
    assert_eq!(
        BufferSize::for_payload(BufferSize::Small.size() + 1),
        Some(BufferSize::Standard)
    );
    assert_eq!(
        BufferSize::for_payload(BufferSize::Standard.size()),
        Some(BufferSize::Standard)
    );
    assert_eq!(
        BufferSize::for_payload(BufferSize::Standard.size() + 1),
        Some(BufferSize::Jumbo)
    );
    assert_eq!(
        BufferSize::for_payload(BufferSize::Jumbo.size()),
        Some(BufferSize::Jumbo)
    );
    assert_eq!(BufferSize::for_payload(BufferSize::Jumbo.size() + 1), None);
}
