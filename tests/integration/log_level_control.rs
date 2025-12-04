// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration Tests: Runtime Log Level Control
//!
//! These tests verify that log levels can be changed at runtime via the control socket
//! and that the changes take effect immediately. Most command logic is covered by unit
//! tests in src/supervisor.rs. These integration tests focus on IPC communication.

#[cfg(test)]
mod tests {
    use crate::common::{ControlClient, McrInstance};
    use anyhow::{Context, Result};
    use multicast_relay::logging::{Facility, Severity};
    use multicast_relay::{Response, SupervisorCommand};
    use std::time::Duration;
    use tokio::time::sleep;

    /// Tests basic IPC communication: Set global log level and verify via GetLogLevels.
    /// Command logic is covered by unit tests; this validates IPC serialization/communication.
    #[tokio::test]
    async fn test_set_and_get_global_log_level_via_ipc() -> Result<()> {
        require_root!();

        let mcr = McrInstance::builder()
            .num_workers(1)
            .start_async()
            .await
            .context("Failed to start supervisor")?;

        let client = ControlClient::new(mcr.control_socket());

        // Give supervisor time to initialize
        sleep(Duration::from_millis(300)).await;

        // Verify default level is Info
        let get_response = client.send_command(SupervisorCommand::GetLogLevels).await?;
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
        let set_response = client
            .send_command(SupervisorCommand::SetGlobalLogLevel {
                level: Severity::Warning,
            })
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
        let get_response = client.send_command(SupervisorCommand::GetLogLevels).await?;
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

        // Cleanup happens automatically when McrInstance is dropped
        Ok(())
    }

    /// Tests facility-specific overrides via IPC. Demonstrates that facility-level
    /// settings can override global settings (hierarchy).
    #[tokio::test]
    async fn test_facility_override_via_ipc() -> Result<()> {
        require_root!();

        let mcr = McrInstance::builder()
            .num_workers(1)
            .start_async()
            .await
            .context("Failed to start supervisor")?;

        let client = ControlClient::new(mcr.control_socket());

        // Give supervisor time to initialize
        sleep(Duration::from_millis(300)).await;

        // Set global level to Error (restrictive)
        client
            .send_command(SupervisorCommand::SetGlobalLogLevel {
                level: Severity::Error,
            })
            .await?;

        // Set Ingress facility to Debug (permissive, overrides global)
        let set_response = client
            .send_command(SupervisorCommand::SetFacilityLogLevel {
                facility: Facility::Ingress,
                level: Severity::Debug,
            })
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
        let get_response = client.send_command(SupervisorCommand::GetLogLevels).await?;
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

        // Cleanup happens automatically when McrInstance is dropped
        Ok(())
    }
}
