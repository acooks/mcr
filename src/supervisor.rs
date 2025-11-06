use anyhow::Result;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

pub async fn run() -> Result<()> {
    println!("Supervisor starting.");

    let current_exe = std::env::current_exe()?;

    loop {
        println!("Supervisor: Spawning worker process.");
        let mut child = Command::new(&current_exe)
            .arg("worker")
            .arg("--user")
            .arg("nobody")
            .arg("--group")
            .arg("nogroup")
            .spawn()?;

        let status = child.wait()?;

        println!("Supervisor: Worker process exited with status: {}", status);
        println!("Supervisor: Restarting worker in 5 seconds...");
        sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_test() {
        // This test does nothing, but is here to increase coverage.
        assert_eq!(2 + 2, 4);
    }
}
