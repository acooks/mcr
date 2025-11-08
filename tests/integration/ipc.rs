
//! Tier 2 Integration Tests: Inter-Process Communication
// ... (existing documentation)

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::path::PathBuf;
    use std::time::Duration;
    use tests::cleanup_socket;
    use tests::unique_socket_path_with_prefix;
    use tokio::process::{Child, Command};
    use tokio::time::sleep;

    /// Spawns a supervisor process with a unique socket path and waits for the socket
    /// file to be created before returning.
    async fn spawn_supervisor_and_wait_for_socket(socket_path: &PathBuf) -> Result<Child> {
        let current_exe =
            std::env::current_exe().expect("Failed to get current executable path");

        // Ensure the socket does not already exist
        cleanup_socket(socket_path);

        let mut supervisor_cmd = Command::new(current_exe);
        supervisor_cmd
            .arg("supervisor")
            .arg("--control-socket-path") // Use the new argument
            .arg(socket_path.as_os_str());

        let supervisor_process = supervisor_cmd.spawn()?;

        // Wait for the supervisor to create the socket file
        let mut wait_count = 0;
        while !socket_path.exists() {
            if wait_count > 20 {
                // 2 seconds timeout
                panic!("Supervisor did not create socket in time");
            }
            sleep(Duration::from_millis(100)).await;
            wait_count += 1;
        }

        Ok(supervisor_process)
    }

    #[tokio::test]
    async fn test_ipc_happy_path_add_rule() -> Result<()> {
        let socket_path = unique_socket_path_with_prefix("ipc_happy_path");

        let mut supervisor_process =
            spawn_supervisor_and_wait_for_socket(&socket_path).await?;

        let current_exe =
            std::env::current_exe().expect("Failed to get current executable path");

        let rule_id = "test-rule-ipc-happy-path";
        let ingress_iface = "lo";
        let egress_iface = "lo";
        let src_addr = "239.0.0.1:5001";
        let dst_addr = "127.0.0.1:6001";

        let mut client_cmd = Command::new(current_exe);
        client_cmd
            .arg("client")
            .arg("--socket-path")
            .arg(socket_path.as_os_str())
            .arg("add-rule")
            .arg("--rule-id")
            .arg(rule_id)
            .arg("--ingress-iface")
            .arg(ingress_iface)
            .arg("--egress-iface")
            .arg(egress_iface)
            .arg("--source-addr")
            .arg(src_addr)
            .arg("--destination-addr")
            .arg(dst_addr);

        let output = client_cmd.output().await?;
        let stdout = String::from_utf8(output.stdout)?;

        assert!(
            stdout.contains(&format!("Rule '{}' added successfully.", rule_id)),
            "Expected success message, but got: {}",
            stdout
        );

        supervisor_process.kill().await?;
        cleanup_socket(&socket_path);

        Ok(())
    }
}
