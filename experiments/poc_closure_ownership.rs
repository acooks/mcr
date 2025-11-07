//! Proof of Concept: Demonstrating Correct Ownership for `FnMut` Closures
//!
//! This PoC isolates and demonstrates the correct way to handle ownership
//! when passing closures that capture a non-Copy type (like `String` or `PathBuf`)
//! to a function that expects `FnMut`.
//!
//! The problem arises when a captured variable is moved out of the closure's
//! environment on the first call, making it unavailable for subsequent calls,
//! which violates the `FnMut` contract.

use std::future::Future;
use std::path::PathBuf;

/// A simplified function that mimics the signature of `supervisor::run`.
/// It takes two `FnMut` closures that are expected to be callable multiple times.
async fn runner<F1, F2, Fut1, Fut2>(mut f1: F1, mut f2: F2, final_val: PathBuf)
where
    F1: FnMut() -> Fut1,
    Fut1: Future<Output = ()>,
    F2: FnMut() -> Fut2,
    Fut2: Future<Output = ()>,
{
    println!("Runner starting.");
    println!("Final value received: {:?}", final_val);

    // Call the closures multiple times to demonstrate the `FnMut` requirement.
    f1().await;
    f2().await;
    println!("---");
    f1().await;
    f2().await;

    println!("Runner finished.");
}

/// A dummy async function that simulates the work done by a spawner.
async fn dummy_spawner(val: PathBuf) {
    println!("Dummy spawner called with: {:?}", val);
}

#[tokio::main]
async fn main() {
    let original_path = PathBuf::from("/tmp/my_test_path.sock");
    println!("'main' created and owns 'original_path': {:?}", original_path);

    // Clone `original_path` once for each closure.
    // Each clone is a new, independent owned value.
    let path_for_closure1 = original_path.clone();
    let path_for_closure2 = original_path.clone();
    println!("'main' created 'path_for_closure1' and 'path_for_closure2' via clone.");

    // The `async move` block takes ownership of `original_path`.
    tokio::spawn(async move {
        runner(
            // `move` closure takes ownership of `path_for_closure1`.
            // It can be called multiple times because it owns its captured data.
            move || dummy_spawner(path_for_closure1.clone()),
            // `move` closure takes ownership of `path_for_closure2`.
            // It can be called multiple times because it owns its captured data.
            move || dummy_spawner(path_for_closure2.clone()),
            original_path, // The original `original_path` (owned by the async block) is moved here.
        )
        .await
    });

    // Allow time for the spawned task to run
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}