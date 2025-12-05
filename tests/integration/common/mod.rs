// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test utilities
//
// This module provides abstractions for integration testing of the multicast relay.
// All tests require root privileges to create network namespaces and veth interfaces.

/// Check if running as root; if not, fail the test with a clear message.
///
/// Integration tests require root privileges for creating network namespaces
/// and veth pairs (CAP_SYS_ADMIN). This is different from mcrd runtime which
/// only needs CAP_NET_RAW, CAP_CHOWN, CAP_SETUID, CAP_SETGID.
///
/// Use this macro at the start of every test function:
///
/// ```rust,ignore
/// #[test]
/// fn test_something() -> Result<()> {
///     require_root!();
///     // ... test code
/// }
/// ```
#[macro_export]
macro_rules! require_root {
    () => {
        if !nix::unistd::geteuid().is_root() {
            panic!(
                "This test requires root privileges for network namespace creation.\n\
                 Run with: sudo -E cargo test --test integration\n\
                 \n\
                 Note: The mcrd binary itself can run without root using capabilities:\n\
                 sudo setcap 'cap_net_raw,cap_chown,cap_setuid,cap_setgid=eip' mcrd"
            );
        }
    };
}

pub mod control_client;
pub mod mcr;
pub mod network;
pub mod stats;
pub mod traffic;

pub use control_client::ControlClient;
pub use mcr::McrInstance;
pub use network::{NetworkNamespace, VethPair};
pub use stats::Stats;

use std::path::PathBuf;

/// Get the path to a compiled binary
pub fn binary_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");

    // Use release binaries for tests (they're faster and closer to production)
    path.push("release");
    path.push(name);

    if !path.exists() {
        panic!(
            "Binary '{}' not found at {:?}. Run: cargo build --release --bins",
            name, path
        );
    }

    path
}
