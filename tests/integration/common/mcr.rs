// MCR instance management for testing

use super::{binary_path, Stats};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// MCR relay instance for testing
pub struct McrInstance {
    process: Child,
    control_socket: PathBuf,
    log_file: PathBuf,
}

impl McrInstance {
    /// Start a new MCR instance
    ///
    /// # Arguments
    /// * `interface` - Network interface to listen on
    /// * `core` - CPU core to pin to (optional)
    pub fn start(interface: &str, core: Option<u32>) -> Result<Self> {
        let relay_socket = format!("/tmp/test_relay_{}.sock", std::process::id());
        let control_socket = format!("/tmp/test_mcr_{}.sock", std::process::id());
        let log_file = format!("/tmp/test_mcr_{}.log", std::process::id());

        // Clean up any existing sockets
        let _ = std::fs::remove_file(&relay_socket);
        let _ = std::fs::remove_file(&control_socket);
        let _ = std::fs::remove_file(&log_file);

        let relay_bin = binary_path("multicast_relay");

        // Build command
        let mut cmd = if let Some(core_id) = core {
            let mut c = Command::new("taskset");
            c.arg("-c").arg(core_id.to_string());
            c.arg(relay_bin);
            c
        } else {
            Command::new(relay_bin)
        };

        cmd.arg("supervisor")
            .arg("--relay-command-socket-path")
            .arg(&relay_socket)
            .arg("--control-socket-path")
            .arg(&control_socket)
            .arg("--interface")
            .arg(interface)
            .arg("--num-workers")
            .arg("1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Redirect output to log file
        let log_file_clone = log_file.clone();
        let mut child = cmd.spawn().context("Failed to spawn MCR process")?;

        // Capture stdout/stderr to log file
        let stdout = child.stdout.take().context("Failed to get stdout")?;
        let stderr = child.stderr.take().context("Failed to get stderr")?;

        thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file_clone)
                .expect("Failed to open log file");

            let stdout_reader = BufReader::new(stdout);
            let stderr_reader = BufReader::new(stderr);

            for line in stdout_reader.lines().chain(stderr_reader.lines()) {
                if let Ok(line) = line {
                    writeln!(log, "{}", line).ok();
                }
            }
        });

        // Wait for control socket to appear
        let socket_path = PathBuf::from(&control_socket);
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        if !socket_path.exists() {
            bail!("Control socket not found after 5 seconds: {:?}", socket_path);
        }

        // Give MCR time to fully initialize
        thread::sleep(Duration::from_secs(2));

        Ok(Self {
            process: child,
            control_socket: socket_path,
            log_file: PathBuf::from(log_file),
        })
    }

    /// Add a forwarding rule
    ///
    /// # Arguments
    /// * `input` - Input multicast group and port (e.g., "239.1.1.1:5001")
    /// * `outputs` - Output destinations (e.g., vec!["239.2.2.2:5002:lo"])
    pub fn add_rule(&mut self, input: &str, outputs: Vec<&str>) -> Result<()> {
        let control_bin = binary_path("control_client");

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
            .arg("veth0p") // TODO: Make this configurable
            .arg("--input-group")
            .arg(input_parts[0])
            .arg("--input-port")
            .arg(input_parts[1])
            .arg("--outputs")
            .arg(outputs_str)
            .output()
            .context("Failed to execute control_client")?;

        if !output.status.success() {
            bail!(
                "Failed to add rule: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Give rule time to be applied
        thread::sleep(Duration::from_secs(1));

        Ok(())
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

    /// Get the log file path
    pub fn log_path(&self) -> &Path {
        &self.log_file
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

use anyhow::bail;
use wait_timeout::ChildExt;
