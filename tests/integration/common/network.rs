// SPDX-License-Identifier: Apache-2.0 OR MIT
// Network namespace and veth pair management

use anyhow::{bail, Context, Result};
use nix::sched::{unshare, CloneFlags};
use nix::unistd;
use rtnetlink::{new_connection, Handle, LinkUnspec, LinkVeth};
use std::net::Ipv4Addr;

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
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        // Find loopback interface
        let mut links = handle.link().get().match_name("lo".to_string()).execute();
        let lo = links
            .try_next()
            .await?
            .context("Loopback interface not found")?;

        // Bring it up
        handle
            .link()
            .set(LinkUnspec::new_with_index(lo.header.index).up().build())
            .execute()
            .await?;

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
    handle: Handle,
    veth_a: String,
    veth_b: String,
    _connection_handle: tokio::task::JoinHandle<()>,
}

impl VethPair {
    /// Create a new veth pair
    pub async fn create(veth_a: &str, veth_b: &str) -> Result<Self> {
        let (connection, handle, _) = new_connection()?;
        let connection_handle = tokio::spawn(connection);

        // Create veth pair
        handle
            .link()
            .add(LinkVeth::new(veth_a, veth_b).build())
            .execute()
            .await
            .with_context(|| format!("Failed to create veth pair {} <-> {}", veth_a, veth_b))?;

        Ok(Self {
            handle,
            veth_a: veth_a.to_string(),
            veth_b: veth_b.to_string(),
            _connection_handle: connection_handle,
        })
    }

    /// Set IP address on an interface
    pub async fn set_addr(&self, interface: &str, addr: &str) -> Result<&Self> {
        // Parse address (e.g., "10.0.0.1/24")
        let parts: Vec<&str> = addr.split('/').collect();
        if parts.len() != 2 {
            bail!("Address must be in CIDR format: {}", addr);
        }

        let ip: Ipv4Addr = parts[0]
            .parse()
            .with_context(|| format!("Invalid IP address: {}", parts[0]))?;
        let prefix_len: u8 = parts[1]
            .parse()
            .with_context(|| format!("Invalid prefix length: {}", parts[1]))?;

        // Get interface index
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(interface.to_string())
            .execute();
        let link = links
            .try_next()
            .await?
            .with_context(|| format!("Interface not found: {}", interface))?;

        // Add address
        self.handle
            .address()
            .add(link.header.index, ip.into(), prefix_len)
            .execute()
            .await
            .with_context(|| format!("Failed to add address {} to {}", addr, interface))?;

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
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(interface.to_string())
            .execute();
        let link = links
            .try_next()
            .await?
            .with_context(|| format!("Interface not found: {}", interface))?;

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(link.header.index).up().build())
            .execute()
            .await
            .with_context(|| format!("Failed to bring up interface {}", interface))?;

        Ok(())
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        // Veth pairs are automatically destroyed when network namespace is destroyed
        // No explicit cleanup needed
    }
}

// Re-export for convenience
use futures_util::stream::TryStreamExt;
