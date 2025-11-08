
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
use nix::unistd::{Gid, Uid, User, Group};
// ...
    async fn spawn_supervisor_and_wait_for_socket(socket_path: &PathBuf) -> Result<Child> {
        let current_exe =
            std::env::current_exe().expect("Failed to get current executable path");

        cleanup_socket(socket_path);

        // Use the current user and group to avoid lookup failures in test environments
        let current_uid = Uid::current();
        let current_gid = Gid::current();
        let current_user = User::from_uid(current_uid)?.unwrap().name;
        let current_group = Group::from_gid(current_gid)?.unwrap().name;

        let mut supervisor_cmd = Command::new(current_exe);
        supervisor_cmd
            .arg("supervisor")
            .arg("--control-socket-path")
            .arg(socket_path.as_os_str())
            .arg("--user")
            .arg(current_user)
            .arg("--group")
            .arg(current_group)
            .stdout(std::process::Stdio::piped()) // Capture stdout
            .stderr(std::process::Stdio::piped()); // Capture stderr

        let mut supervisor_process = supervisor_cmd.spawn()?;

        let mut wait_count = 0;
        while !socket_path.exists() {
            if wait_count > 20 {
                let stdout = supervisor_process
                    .stdout
                    .take()
                    .map(|s| {
                        let mut reader = tokio::io::BufReader::new(s);
                        let mut buffer = String::new();
                        // This is a bit complex because we can't easily block here.
                        // A simple read_to_string would be ideal but it's async.
                        // For the purpose of debugging, we'll try a non-blocking read.
                        // In a real-world scenario, you might handle this differently.
                        if let Ok(mut stdout_handle) = supervisor_process.stdout.take() {
                            let mut output = vec![];
                            if tokio::io::AsyncReadExt::read_to_end(&mut stdout_handle, &mut output).await.is_ok() {
                                String::from_utf8_lossy(&output).to_string()
                            } else {
                                "Failed to read stdout".to_string()
                            }
                        } else {
                            "No stdout".to_string()
                        }
                    })
                    .unwrap_or_else(|| "No stdout".to_string());

                let stderr = if let Some(mut stderr_handle) = supervisor_process.stderr.take() {
                    let mut output = vec![];
                    if tokio::io::AsyncReadExt::read_to_end(&mut stderr_handle, &mut output).await.is_ok() {
                        String::from_utf8_lossy(&output).to_string()
                    } else {
                        "Failed to read stderr".to_string()
                    }
                } else {
                    "No stderr".to_string()
                };

                panic!(
                    "Supervisor did not create socket in time.\nStdout:\n{}\nStderr:\n{}",
                    stdout, stderr
                );
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
    }    #[tokio::test]
    async fn test_ipc_list_rules() -> Result<()> {
        let socket_path = unique_socket_path_with_prefix("ipc_list_rules");
        let mut supervisor_process = spawn_supervisor_and_wait_for_socket(&socket_path).await?;

        let current_exe = std::env::current_exe().expect("Failed to get current executable path");

        // --- Add a rule ---
        let rule_id = "test-rule-ipc-list-rules";
        let mut add_client_cmd = Command::new(current_exe.clone());
        add_client_cmd
            .arg("client")
            .arg("--socket-path")
            .arg(socket_path.as_os_str())
            .arg("add-rule")
            .arg("--rule-id")
            .arg(rule_id)
            .arg("--ingress-iface")
            .arg("lo")
            .arg("--egress-iface")
            .arg("lo")
            .arg("--source-addr")
            .arg("239.0.0.1:5001")
            .arg("--destination-addr")
            .arg("127.0.0.1:6001");

        let add_output = add_client_cmd.output().await?;
        assert!(
            add_output.status.success(),
            "Failed to add rule: {}",
            String::from_utf8_lossy(&add_output.stderr)
        );

        // --- List rules and verify ---
        let mut list_client_cmd = Command::new(current_exe);
        list_client_cmd
            .arg("client")
            .arg("--socket-path")
            .arg(socket_path.as_os_str())
            .arg("list-rules");

        let list_output = list_client_cmd.output().await?;
        let list_stdout = String::from_utf8(list_output.stdout)?;

        assert!(
            list_stdout.contains(rule_id),
            "Expected to find rule '{}' in the list, but got: {}",
            rule_id,
            list_stdout
        );

        supervisor_process.kill().await?;
        cleanup_socket(&socket_path);

        Ok(())
    }
}
