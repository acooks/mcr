use anyhow::Result;
use std::future::Future;
use tokio::process::{Child, Command};
use tokio::time::{Duration, sleep};

const WORKER_USER: &str = "nobody";
const WORKER_GROUP: &str = "nogroup";
const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 16000; // 16 seconds

// --- Production Spawning Logic ---

fn get_production_base_command() -> Command {
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");
    Command::new(current_exe)
}

pub fn spawn_control_plane_worker() -> Result<Child> {
    println!("[Supervisor] Spawning Control Plane worker.");
    let mut command = get_production_base_command();
    command
        .arg("control-plane-worker")
        .arg("--user")
        .arg(WORKER_USER)
        .arg("--group")
        .arg(WORKER_GROUP);
    command.spawn().map_err(anyhow::Error::from)
}

pub fn spawn_data_plane_worker(core_id: u32) -> Result<Child> {
    println!(
        "[Supervisor] Spawning Data Plane worker for core {}.",
        core_id
    );
    let mut command = get_production_base_command();
    command
        .arg("data-plane-worker")
        .arg("--user")
        .arg(WORKER_USER)
        .arg("--group")
        .arg(WORKER_GROUP)
        .arg("--core-id")
        .arg(core_id.to_string());
    command.spawn().map_err(anyhow::Error::from)
}

// --- Supervisor Core Logic ---

pub async fn run<F, Fut>(mut spawn_cp: F, mut spawn_dp: impl FnMut() -> Result<Child>) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Child>>,
{
    println!("[Supervisor] Starting.");

    let mut cp_child = spawn_cp().await?;
    let mut dp_child = spawn_dp()?;

    let mut cp_backoff_ms = INITIAL_BACKOFF_MS;
    let mut dp_backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        tokio::select! {
            // Monitor the Control Plane worker
            Ok(status) = cp_child.wait() => {
                if status.success() {
                    println!("[Supervisor] Control Plane worker exited gracefully. Restarting immediately.");
                    cp_backoff_ms = INITIAL_BACKOFF_MS; // Reset backoff on success
                } else {
                    println!("[Supervisor] Control Plane worker failed (status: {}). Restarting after {}ms.", status, cp_backoff_ms);
                    sleep(Duration::from_millis(cp_backoff_ms)).await;
                    cp_backoff_ms = (cp_backoff_ms * 2).min(MAX_BACKOFF_MS); // Exponential backoff
                }
                cp_child = spawn_cp().await?;
            }

            // Monitor the Data Plane worker
            Ok(status) = dp_child.wait() => {
                if status.success() {
                    println!("[Supervisor] Data Plane worker exited gracefully. Restarting immediately.");
                    dp_backoff_ms = INITIAL_BACKOFF_MS; // Reset backoff on success
                } else {
                    println!("[Supervisor] Data Plane worker failed (status: {}). Restarting after {}ms.", status, dp_backoff_ms);
                    sleep(Duration::from_millis(dp_backoff_ms)).await;
                    dp_backoff_ms = (dp_backoff_ms * 2).min(MAX_BACKOFF_MS); // Exponential backoff
                }
                dp_child = spawn_dp()?;
            }
        }
    }
}

// --- Test-Specific Spawning Logic ---

#[cfg(feature = "integration_test")]
pub fn spawn_dummy_worker() -> Result<Child> {
    Command::new("sleep")
        .arg("30")
        .spawn()
        .map_err(anyhow::Error::from)
}

#[cfg(feature = "integration_test")]
pub async fn spawn_dummy_worker_async() -> Result<Child> {
    Command::new("sleep")
        .arg("30")
        .spawn()
        .map_err(anyhow::Error::from)
}
