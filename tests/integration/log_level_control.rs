// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration Tests: Runtime Log Level Control
//!
//! These tests verify that log levels can be changed at runtime via the control socket
//! and that the changes take effect immediately. Most command logic is covered by unit
//! tests in src/supervisor.rs. These integration tests focus on IPC communication.

#[cfg(test)]
mod tests {
    use crate::tests::{cleanup_socket, unique_socket_path_with_prefix};
    use anyhow::Result;
    use multicast_relay::logging::{Facility, Severity};
    use multicast_relay::{Response, SupervisorCommand};
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::process::{Child, Command};
    use tokio::time::sleep;

    /// Spawns a supervisor process with a unique socket path
    async fn spawn_supervisor(socket_path: &PathBuf) -> Result<Child> {
        let current_exe = std::env::current_exe().expect("Failed to get current executable path");

        cleanup_socket(socket_path);

        let mut supervisor_cmd = Command::new(current_exe);
        supervisor_cmd
            .arg("supervisor")
            .arg("--control-socket-path")
            .arg(socket_path.as_os_str())
            .arg("--user")
            .arg(std::env::var("USER").unwrap_or_else(|_| "nobody".to_string()))
            .arg("--group")
            .arg(std::env::var("USER").unwrap_or_else(|_| "nogroup".to_string()))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let supervisor_process = supervisor_cmd.spawn()?;

        // Wait for socket to be created
        let mut wait_count = 0;
        while !socket_path.exists() {
            if wait_count > 20 {
                return Err(anyhow::anyhow!("Socket creation timeout"));
            }
            sleep(Duration::from_millis(100)).await;
            wait_count += 1;
        }

        sleep(Duration::from_millis(100)).await;
        Ok(supervisor_process)
    }

    /// Send a command to the supervisor and get the response
    async fn send_command(socket_path: &PathBuf, command: SupervisorCommand) -> Result<Response> {
        let mut stream = UnixStream::connect(socket_path).await?;
        let command_bytes = serde_json::to_vec(&command)?;
        stream.write_all(&command_bytes).await?;
        stream.shutdown().await?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await?;

        let response: Response = serde_json::from_slice(&response_bytes)?;
        Ok(response)
    }

    /// Tests basic IPC communication: Set global log level and verify via GetLogLevels.
    /// Command logic is covered by unit tests; this validates IPC serialization/communication.
    #[tokio::test]
    async fn test_set_and_get_global_log_level_via_ipc() -> Result<()> {
        if unsafe { libc::getuid() } != 0 {
            println!(
                "Skipping test_set_and_get_global_log_level_via_ipc: requires root privileges."
            );
            return Ok(());
        }

        let socket_path = unique_socket_path_with_prefix("log_level_ipc_global");
        let mut supervisor = spawn_supervisor(&socket_path).await?;

        // Verify default level is Info
        let get_response = send_command(&socket_path, SupervisorCommand::GetLogLevels).await?;
        match get_response {
            Response::LogLevels {
                global,
                facility_overrides,
            } => {
                assert_eq!(
                    global,
                    Severity::Info,
                    "Default global level should be Info"
                );
                assert!(
                    facility_overrides.is_empty(),
                    "No facility overrides by default"
                );
            }
            _ => panic!("Expected Response::LogLevels, got {:?}", get_response),
        }

        // Set global log level to Warning via IPC
        let set_response = send_command(
            &socket_path,
            SupervisorCommand::SetGlobalLogLevel {
                level: Severity::Warning,
            },
        )
        .await?;

        match set_response {
            Response::Success(msg) => {
                assert!(
                    msg.contains("Warning") || msg.contains("WARNING"),
                    "Success message should mention Warning level"
                );
            }
            _ => panic!("Expected Response::Success, got {:?}", set_response),
        }

        // Verify the change via IPC
        let get_response = send_command(&socket_path, SupervisorCommand::GetLogLevels).await?;
        match get_response {
            Response::LogLevels {
                global,
                facility_overrides,
            } => {
                assert_eq!(global, Severity::Warning, "Global level should be Warning");
                assert!(
                    facility_overrides.is_empty(),
                    "No facility overrides should be set"
                );
            }
            _ => panic!("Expected Response::LogLevels, got {:?}", get_response),
        }

        supervisor.kill().await?;
        cleanup_socket(&socket_path);
        Ok(())
    }

    /// Tests facility-specific overrides via IPC. Demonstrates that facility-level
    /// settings can override global settings (hierarchy).
    #[tokio::test]
    async fn test_facility_override_via_ipc() -> Result<()> {
        if unsafe { libc::getuid() } != 0 {
            println!("Skipping test_facility_override_via_ipc: requires root privileges.");
            return Ok(());
        }

        let socket_path = unique_socket_path_with_prefix("log_level_ipc_facility");
        let mut supervisor = spawn_supervisor(&socket_path).await?;

        // Set global level to Error (restrictive)
        send_command(
            &socket_path,
            SupervisorCommand::SetGlobalLogLevel {
                level: Severity::Error,
            },
        )
        .await?;

        // Set Ingress facility to Debug (permissive, overrides global)
        let set_response = send_command(
            &socket_path,
            SupervisorCommand::SetFacilityLogLevel {
                facility: Facility::Ingress,
                level: Severity::Debug,
            },
        )
        .await?;

        match set_response {
            Response::Success(msg) => {
                assert!(
                    msg.contains("Ingress") && (msg.contains("Debug") || msg.contains("DEBUG")),
                    "Success message should mention Ingress and Debug"
                );
            }
            _ => panic!("Expected Response::Success, got {:?}", set_response),
        }

        // Verify facility override hierarchy via IPC
        let get_response = send_command(&socket_path, SupervisorCommand::GetLogLevels).await?;
        match get_response {
            Response::LogLevels {
                global,
                facility_overrides,
            } => {
                assert_eq!(global, Severity::Error, "Global level should be Error");
                assert_eq!(
                    facility_overrides.len(),
                    1,
                    "Should have one facility override"
                );
                assert_eq!(
                    facility_overrides.get(&Facility::Ingress),
                    Some(&Severity::Debug),
                    "Ingress should override global Error with Debug"
                );
            }
            _ => panic!("Expected Response::LogLevels, got {:?}", get_response),
        }

        supervisor.kill().await?;
        cleanup_socket(&socket_path);
        Ok(())
    }
}
