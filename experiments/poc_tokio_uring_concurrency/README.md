# PoC: Task Management in a Single-Threaded `tokio-uring` Runtime

This experiment is a minimal, self-contained proof-of-concept to demonstrate and verify the correct concurrency pattern for a single-threaded `tokio-uring` application.

## Purpose

The `tokio-uring` runtime is single-threaded. This means that any types used with it (like `tokio_uring::fs::File`) are not required to be `Send` or `Sync`. This is a key feature for performance, as it avoids the overhead of atomic reference counting and mutexes.

However, this creates a conflict with the standard `tokio::spawn` function, which is designed for multi-threaded runtimes and requires all spawned futures to be `Send`. Attempting to use `tokio::spawn` in a `tokio-uring` context results in compilation errors.

The correct solution is to use `tokio::task::spawn_local`. This function spawns a future that will only be run on the current thread, which is exactly what the `tokio-uring` runtime provides.

This PoC demonstrates the correct pattern for:

1.  Starting a `tokio-uring` runtime.
2.  Using `tokio::task::spawn_local` to run multiple, long-lived, concurrent background tasks.
3.  Using a `tokio::select!` loop to manage the application state.
4.  Dynamically starting and stopping one of the local tasks by storing and aborting its `JoinHandle`.

This provides a clear, working blueprint for the main application's `worker/mod.rs` file.

## How to Run

This is a self-contained crate. No special setup is required.

```sh
cargo run
```

You will see output from the "Manager", "Control Task", "Stats Task", and the dynamically replaced "Flow Task", demonstrating that all tasks are running concurrently on the single thread.
