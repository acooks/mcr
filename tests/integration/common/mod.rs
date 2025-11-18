// Integration test utilities
//
// This module provides abstractions for integration testing of the multicast relay.
// All tests require root privileges to create network namespaces and veth interfaces.

pub mod mcr;
pub mod network;
pub mod stats;
pub mod traffic;

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
