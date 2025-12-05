// SPDX-License-Identifier: Apache-2.0 OR MIT
//! MCR instance management for testing
//!
//! This module provides a unified `McrInstance` for starting and managing
//! mcrd supervisor processes in integration tests. All tests should use this
//! instead of creating their own process management code.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! // Simple: start with interface
//! let mcr = McrInstance::builder()
//!     .interface("veth0p")
//!     .start()?;
//!
//! // With config file
//! let mcr = McrInstance::builder()
//!     .config_content("{ rules: [] }")
//!     .num_workers(2)
//!     .start()?;
//!
//! // With CPU pinning
//! let mcr = McrInstance::builder()
//!     .interface("lo")
//!     .core(0)
//!     .start()?;
//! ```

use super::{binary_path, Stats};
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;
use wait_timeout::ChildExt;

static INSTANCE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Builder for configuring an McrInstance
#[derive(Default)]
pub struct McrInstanceBuilder {
    interface: Option<String>,
    config_content: Option<String>,
    num_workers: Option<u32>,
    core: Option<u32>,
}

impl McrInstanceBuilder {
    /// Set the network interface to listen on
    ///
    /// This is required unless a config file is provided with rules.
    pub fn interface(mut self, interface: &str) -> Self {
        self.interface = Some(interface.to_string());
        self
    }

    /// Set the JSON5 config file content
    ///
    /// When provided, mcrd will be started with `--config` pointing to a
    /// temporary file containing this content.
    pub fn config_content(mut self, content: &str) -> Self {
        self.config_content = Some(content.to_string());
        self
    }

    /// Set the number of workers per interface
    ///
    /// Defaults to 1 if not specified.
    pub fn num_workers(mut self, n: u32) -> Self {
        self.num_workers = Some(n);
        self
    }

    /// Pin the supervisor to a specific CPU core using taskset
    pub fn core(mut self, core_id: u32) -> Self {
        self.core = Some(core_id);
        self
    }

    /// Start the McrInstance with the configured options
    pub fn start(self) -> Result<McrInstance> {
        McrInstance::start_with_builder(self)
    }

    /// Start the McrInstance asynchronously (for tokio tests)
    ///
    /// This is equivalent to `start()` but uses async sleep for waiting.
    pub async fn start_async(self) -> Result<McrInstance> {
        McrInstance::start_with_builder_async(self).await
    }
}

/// MCR relay instance for testing
///
/// Manages the lifecycle of an mcrd supervisor process. The process is
/// automatically killed and sockets cleaned up when the instance is dropped.
pub struct McrInstance {
    process: Child,
    control_socket: PathBuf,
    log_file: PathBuf,
    interface: Option<String>,
    #[allow(dead_code)]
    config_file: Option<NamedTempFile>, // Keep alive for process lifetime
}

impl McrInstance {
    /// Create a new builder for configuring an McrInstance
    pub fn builder() -> McrInstanceBuilder {
        McrInstanceBuilder::default()
    }

    /// Internal: Start with builder configuration (sync version)
    fn start_with_builder(builder: McrInstanceBuilder) -> Result<Self> {
        let instance_id = INSTANCE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();

        let control_socket = PathBuf::from(format!("/tmp/test_mcr_{}_{}.sock", pid, instance_id));
        let log_file = PathBuf::from(format!("/tmp/test_mcr_{}_{}.log", pid, instance_id));

        // Clean up any existing files
        let _ = std::fs::remove_file(&control_socket);
        let _ = std::fs::remove_file(&log_file);

        // Create config file if content provided
        let config_file = if let Some(ref content) = builder.config_content {
            let mut file = NamedTempFile::new()?;
            file.write_all(content.as_bytes())?;
            file.flush()?;
            Some(file)
        } else {
            None
        };

        let relay_bin = binary_path("mcrd");

        // Build command (optionally with taskset for CPU pinning)
        let mut cmd = if let Some(core_id) = builder.core {
            let mut c = Command::new("taskset");
            c.arg("-c").arg(core_id.to_string());
            c.arg(&relay_bin);
            c
        } else {
            Command::new(&relay_bin)
        };

        cmd.arg("supervisor")
            .arg("--control-socket-path")
            .arg(&control_socket);

        // Add config file if provided
        if let Some(ref cf) = config_file {
            cmd.arg("--config").arg(cf.path());
        }

        // Add interface if provided (required if no config)
        if let Some(ref iface) = builder.interface {
            cmd.arg("--interface").arg(iface);
        }

        // Add num_workers (default to 1)
        let num_workers = builder.num_workers.unwrap_or(1);
        cmd.arg("--num-workers").arg(num_workers.to_string());

        // Always capture output to avoid noisy test output
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn MCR process")?;

        // Capture stdout/stderr to log file in background threads
        let stdout = child.stdout.take().context("Failed to get stdout")?;
        let stderr = child.stderr.take().context("Failed to get stderr")?;

        let log_file_clone = log_file.clone();
        thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let mut log = match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file_clone)
            {
                Ok(f) => f,
                Err(_) => return,
            };
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                let _ = writeln!(log, "{}", line);
                let _ = log.flush();
            }
        });

        let log_file_clone2 = log_file.clone();
        thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let mut log = match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file_clone2)
            {
                Ok(f) => f,
                Err(_) => return,
            };
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let _ = writeln!(log, "{}", line);
                let _ = log.flush();
            }
        });

        // Wait for control socket to appear (sync)
        for _ in 0..50 {
            if control_socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        if !control_socket.exists() {
            // Kill the process since startup failed
            let _ = child.kill();
            bail!(
                "Control socket not found after 5 seconds: {:?}",
                control_socket
            );
        }

        // Brief stabilization delay
        thread::sleep(Duration::from_millis(200));

        Ok(Self {
            process: child,
            control_socket,
            log_file,
            interface: builder.interface,
            config_file,
        })
    }

    /// Internal: Start with builder configuration (async version)
    async fn start_with_builder_async(builder: McrInstanceBuilder) -> Result<Self> {
        let instance_id = INSTANCE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();

        let control_socket = PathBuf::from(format!("/tmp/test_mcr_{}_{}.sock", pid, instance_id));
        let log_file = PathBuf::from(format!("/tmp/test_mcr_{}_{}.log", pid, instance_id));

        // Clean up any existing files
        let _ = std::fs::remove_file(&control_socket);
        let _ = std::fs::remove_file(&log_file);

        // Create config file if content provided
        let config_file = if let Some(ref content) = builder.config_content {
            let mut file = NamedTempFile::new()?;
            file.write_all(content.as_bytes())?;
            file.flush()?;
            Some(file)
        } else {
            None
        };

        let relay_bin = binary_path("mcrd");

        // Build command (optionally with taskset for CPU pinning)
        let mut cmd = if let Some(core_id) = builder.core {
            let mut c = Command::new("taskset");
            c.arg("-c").arg(core_id.to_string());
            c.arg(&relay_bin);
            c
        } else {
            Command::new(&relay_bin)
        };

        cmd.arg("supervisor")
            .arg("--control-socket-path")
            .arg(&control_socket);

        // Add config file if provided
        if let Some(ref cf) = config_file {
            cmd.arg("--config").arg(cf.path());
        }

        // Add interface if provided (required if no config)
        if let Some(ref iface) = builder.interface {
            cmd.arg("--interface").arg(iface);
        }

        // Add num_workers (default to 1)
        let num_workers = builder.num_workers.unwrap_or(1);
        cmd.arg("--num-workers").arg(num_workers.to_string());

        // Always capture output to avoid noisy test output
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn MCR process")?;

        // Capture stdout/stderr to log file in background threads
        let stdout = child.stdout.take().context("Failed to get stdout")?;
        let stderr = child.stderr.take().context("Failed to get stderr")?;

        let log_file_clone = log_file.clone();
        thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let mut log = match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file_clone)
            {
                Ok(f) => f,
                Err(_) => return,
            };
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                let _ = writeln!(log, "{}", line);
                let _ = log.flush();
            }
        });

        let log_file_clone2 = log_file.clone();
        thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let mut log = match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file_clone2)
            {
                Ok(f) => f,
                Err(_) => return,
            };
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let _ = writeln!(log, "{}", line);
                let _ = log.flush();
            }
        });

        // Wait for control socket to appear (async)
        for _ in 0..50 {
            if control_socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if !control_socket.exists() {
            // Kill the process since startup failed
            let _ = child.kill();
            bail!(
                "Control socket not found after 5 seconds: {:?}",
                control_socket
            );
        }

        // Brief stabilization delay
        tokio::time::sleep(Duration::from_millis(200)).await;

        Ok(Self {
            process: child,
            control_socket,
            log_file,
            interface: builder.interface,
            config_file,
        })
    }

    /// Get the control socket path for mcrctl commands
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    /// Get the log file path
    pub fn log_path(&self) -> &Path {
        &self.log_file
    }

    /// Get the config file path (if started with config_content)
    pub fn config_path(&self) -> Option<&Path> {
        self.config_file.as_ref().map(|f| f.path())
    }

    /// Add a forwarding rule
    ///
    /// # Arguments
    /// * `input` - Input multicast group and port (e.g., "239.1.1.1:5001")
    /// * `outputs` - Output destinations (e.g., vec!["239.2.2.2:5002:lo"])
    pub fn add_rule(&mut self, input: &str, outputs: Vec<&str>) -> Result<()> {
        let interface = self
            .interface
            .as_ref()
            .context("add_rule requires interface to be set")?;

        let control_bin = binary_path("mcrctl");

        // Parse input
        let input_parts: Vec<&str> = input.split(':').collect();
        if input_parts.len() != 2 {
            bail!("Input must be in format group:port");
        }

        // Build outputs string
        let outputs_str = outputs.join(",");

        let output = Command::new(control_bin)
            .arg("--socket-path")
            .arg(&self.control_socket)
            .arg("add")
            .arg("--input-interface")
            .arg(interface)
            .arg("--input-group")
            .arg(input_parts[0])
            .arg("--input-port")
            .arg(input_parts[1])
            .arg("--outputs")
            .arg(outputs_str)
            .output()
            .context("Failed to execute mcrctl")?;

        if !output.status.success() {
            bail!(
                "Failed to add rule: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Wait for MCR to be ready to process traffic
        self.wait_until_ready(10)?;

        Ok(())
    }

    /// Run an mcrctl command and return the output
    #[allow(dead_code)]
    pub fn run_mcrctl(&self, args: &[&str]) -> Result<String> {
        let control_bin = binary_path("mcrctl");

        let output = Command::new(control_bin)
            .arg("--socket-path")
            .arg(&self.control_socket)
            .args(args)
            .output()
            .context("Failed to execute mcrctl")?;

        if !output.status.success() {
            bail!("mcrctl failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Wait until MCR is ready to process traffic by polling the ping command
    pub fn wait_until_ready(&mut self, timeout_secs: u64) -> Result<()> {
        let control_bin = binary_path("mcrctl");
        let start = std::time::Instant::now();
        let mut successful_pings = 0;
        const REQUIRED_PINGS: u32 = 3;

        loop {
            // Check if process is still alive
            match self.process.try_wait() {
                Ok(Some(status)) => {
                    bail!("MCR process exited with status: {}", status);
                }
                Ok(None) => {}
                Err(e) => {
                    bail!("Error checking process status: {}", e);
                }
            }

            let output = Command::new(&control_bin)
                .arg("--socket-path")
                .arg(&self.control_socket)
                .arg("ping")
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    successful_pings += 1;
                    if successful_pings >= REQUIRED_PINGS {
                        return Ok(());
                    }
                } else {
                    successful_pings = 0;
                }
            } else {
                successful_pings = 0;
            }

            if start.elapsed().as_secs() >= timeout_secs {
                bail!(
                    "Timeout waiting for MCR to be ready after {} seconds",
                    timeout_secs
                );
            }

            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Shutdown gracefully and get final stats
    pub fn shutdown_and_get_stats(mut self) -> Result<Stats> {
        // Send SIGTERM for graceful shutdown
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.process.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .context("Failed to send SIGTERM")?;

        // Wait for process to exit
        let _ = self.process.wait_timeout(Duration::from_secs(5))?;

        // Force kill if still running
        let _ = self.process.kill();
        let _ = self.process.wait();

        // Give logs time to flush
        thread::sleep(Duration::from_millis(500));

        // Parse stats from log
        Stats::from_log_file(&self.log_file)
    }
}

impl Drop for McrInstance {
    fn drop(&mut self) {
        // Ensure process is killed
        let _ = self.process.kill();
        let _ = self.process.wait();

        // Clean up sockets
        let _ = std::fs::remove_file(&self.control_socket);
    }
}
