//! Minimal example to solve the async closure passing problem.

use anyhow::Result;

// --- The "Library" Code (Represents supervisor.rs) ---

// This is the signature we WANT to have. It's simple, but it doesn't
// work when one of the spawners is async.
pub fn supervisor_runner<F>(mut spawner: F)
where
    F: FnMut() -> Result<String>,
{
    let result = spawner();
    println!("Spawner returned: {:?}", result);
}

// --- The "Test" Code (Represents supervisor_integration.rs) ---

// A synchronous spawner. This works fine.
fn sync_spawner() -> Result<String> {
    Ok("sync_spawner_ok".to_string())
}

// An asynchronous spawner. This is the source of the problem.
#[allow(dead_code)]
async fn async_spawner() -> Result<String> {
    Ok("async_spawner_ok".to_string())
}

#[tokio::main]
async fn main() {
    println!("--- Testing sync spawner (should work) ---");
    supervisor_runner(sync_spawner);

    println!("\n--- Testing async spawner (should fail) ---");
    // The line below is the problem.
    // The closure `|| async_spawner()` does not return a `Result<String>`.
    // It returns a `Future` that resolves to a `Result<String>`.
    // How do we bridge this gap?
    // supervisor_runner(|| async_spawner());
}
