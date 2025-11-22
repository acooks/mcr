// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Proof-of-Concept: Task Management in a Single-Threaded `tokio-uring` Runtime
//!
//! This binary demonstrates the correct concurrency pattern for managing multiple
//! long-running, concurrent tasks within a single-threaded `tokio-uring` runtime.
//!
//! ## Problem
//!
//! `tokio-uring` creates a single-threaded runtime. Types used with it (like
//! `tokio_uring::fs::File`) are often `!Send` and `!Sync`, meaning they cannot be
//! passed between threads. This conflicts with `tokio::spawn`, which is for
//! multi-threaded environments. The solution is to use `tokio::task::spawn_local`
//! to ensure tasks are managed by the single-threaded scheduler.
//!
//! This PoC also demonstrates how to manage these locally-spawned tasks,
//! including dynamically stopping and starting one of them, which is a requirement
//! for the main application's `run_flow_task`.
//!
//! ## Usage
//!
//! ```sh
//! cargo run
//! ```

use anyhow::Result;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::{spawn_local, JoinHandle};

/// Simulates a long-running, static task like the control plane listener.
async fn control_task() {
    println!("[Control Task] Started.");
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    loop {
        interval.tick().await;
        println!("[Control Task] Running...");
    }
}

/// Simulates a long-running, static task like the stats aggregator.
async fn stats_task() {
    println!("[Stats Task] Started.");
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        println!("[Stats Task] Running...");
    }
}

/// Simulates a dynamic, replaceable task like a `run_flow_task`.
async fn replaceable_task(id: u32) {
    println!("[Flow Task {}] Started.", id);
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        println!("[Flow Task {}] Reading packet...", id);
    }
}

/// The main manager that orchestrates all other tasks.
async fn run_manager() -> Result<()> {
    println!("[Manager] Starting...");

    // --- Spawn static, long-running tasks ---
    // We use `spawn_local` because we are in a single-threaded runtime.
    // These tasks will run concurrently with the manager's main loop.
    spawn_local(control_task());
    spawn_local(stats_task());

    // --- Set up for dynamic tasks ---
    // A channel to receive commands to change the dynamic task.
    let (command_tx, mut command_rx) = mpsc::channel(10);

    // A handle to the currently running dynamic task, so we can abort it.
    let mut flow_task_handle: Option<JoinHandle<()>> = None;

    // --- Simulate external commands ---
    // Spawn a local task that sends commands to the manager.
    spawn_local(async move {
        println!("[Command Simulator] Sending START(1) in 2s...");
        tokio::time::sleep(Duration::from_secs(2)).await;
        command_tx.send(1).await.unwrap();

        println!("[Command Simulator] Sending START(2) in 4s...");
        tokio::time::sleep(Duration::from_secs(4)).await;
        command_tx.send(2).await.unwrap();

        println!("[Command Simulator] Sending STOP in 3s...");
        tokio::time::sleep(Duration::from_secs(3)).await;
        command_tx.send(99).await.unwrap(); // 99 means STOP
    });

    println!("[Manager] Entering main select loop...");
    // --- Main Event Loop ---
    loop {
        tokio::select! {
            // Listen for a command from the channel.
            Some(flow_id) = command_rx.recv() => {
                println!("[Manager] Received command: START({})", flow_id);

                // 1. If a flow task is already running, abort it.
                if let Some(handle) = flow_task_handle.take() {
                    println!("[Manager] Aborting previous flow task.");
                    handle.abort();
                }

                // 2. If the command is not STOP, spawn a new replaceable task.
                if flow_id != 99 {
                    println!("[Manager] Spawning new flow task: {}.", flow_id);
                    flow_task_handle = Some(spawn_local(replaceable_task(flow_id)));
                } else {
                    println!("[Manager] Received STOP command. No task running.");
                }
            }
        }
    }
}

fn main() -> Result<()> {
    // Start the single-threaded `tokio-uring` runtime.
    tokio_uring::start(run_manager())
}
