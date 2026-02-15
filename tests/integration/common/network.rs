// SPDX-License-Identifier: Apache-2.0 OR MIT
// Network namespace and veth pair management

use anyhow::{bail, Context, Result};
use nix::sched::{unshare, CloneFlags};
use nix::unistd;
use std::process::Command;

/// Network namespace guard - automatically cleaned up on drop
///
/// The namespace is destroyed when the test process exits.
pub struct NetworkNamespace;

impl NetworkNamespace {
    /// Enter a new network namespace
    ///
    /// This unshares the network namespace, isolating all network operations.
    /// The namespace is automatically destroyed when the process exits.
    pub fn enter() -> Result<Self> {
        // We need to be root
        if !unistd::geteuid().is_root() {
            bail!("Network namespace creation requires root privileges");
        }

        // Create new network namespace
        unshare(CloneFlags::CLONE_NEWNET).context("Failed to unshare network namespace")?;

        Ok(Self)
    }

    /// Enable the loopback interface
    pub async fn enable_loopback(&self) -> Result<()> {
        let output = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .output()
            .context("Failed to run ip command")?;

        if !output.status.success() {
            bail!(
                "Failed to bring up loopback: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        // Network namespace is automatically destroyed when process exits
        // or when we restore the original namespace
    }
}

/// Veth pair - virtual ethernet device pair
pub struct VethPair {
    veth_a: String,
    veth_b: String,
}

impl VethPair {
    /// Create a new veth pair
    pub async fn create(veth_a: &str, veth_b: &str) -> Result<Self> {
        let output = Command::new("ip")
            .args([
                "link", "add", veth_a, "type", "veth", "peer", "name", veth_b,
            ])
            .output()
            .context("Failed to run ip command")?;

        if !output.status.success() {
            bail!(
                "Failed to create veth pair {} <-> {}: {}",
                veth_a,
                veth_b,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(Self {
            veth_a: veth_a.to_string(),
            veth_b: veth_b.to_string(),
        })
    }

    /// Set IP address on an interface
    pub async fn set_addr(&self, interface: &str, addr: &str) -> Result<&Self> {
        let output = Command::new("ip")
            .args(["addr", "add", addr, "dev", interface])
            .output()
            .context("Failed to run ip command")?;

        if !output.status.success() {
            bail!(
                "Failed to add address {} to {}: {}",
                addr,
                interface,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(self)
    }

    /// Bring up both interfaces
    pub async fn up(&self) -> Result<&Self> {
        self.set_up(&self.veth_a).await?;
        self.set_up(&self.veth_b).await?;
        Ok(self)
    }

    /// Bring up a specific interface
    async fn set_up(&self, interface: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(["link", "set", interface, "up"])
            .output()
            .context("Failed to run ip command")?;

        if !output.status.success() {
            bail!(
                "Failed to bring up interface {}: {}",
                interface,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        // Veth pairs are automatically destroyed when network namespace is destroyed
        // No explicit cleanup needed
    }
}
