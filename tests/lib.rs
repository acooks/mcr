//! Common Test Utilities and Helpers
//!
//! This module provides shared utilities for integration tests, including:
//! - Socket path generation to avoid test contention
//! - Common test fixtures and constants
//! - Setup/teardown helpers
//! - Test documentation templates

use std::path::PathBuf;
use uuid::Uuid;

/// Generates a unique Unix socket path for test isolation.
///
/// This prevents tests from competing for the same socket path when run in parallel.
/// Each invocation creates a unique path using UUIDv4.
///
/// # Returns
///
/// A `PathBuf` pointing to `/tmp/test_{uuid}.sock`
///
/// # Example
///
/// ```no_run
/// use tests::unique_socket_path;
///
/// let socket_path = unique_socket_path();
/// // Use socket_path for your test...
/// cleanup_socket(&socket_path);
/// ```
pub fn unique_socket_path() -> PathBuf {
    PathBuf::from(format!("/tmp/test_{}.sock", Uuid::new_v4()))
}

/// Generates a unique socket path with a specific prefix for easier debugging.
///
/// # Arguments
///
/// * `prefix` - A string prefix to identify the test (e.g., "supervisor", "ipc")
///
/// # Example
///
/// ```no_run
/// use tests::unique_socket_path_with_prefix;
///
/// let socket_path = unique_socket_path_with_prefix("supervisor");
/// // Creates: /tmp/test_supervisor_{uuid}.sock
/// ```
pub fn unique_socket_path_with_prefix(prefix: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/test_{}_{}.sock", prefix, Uuid::new_v4()))
}

/// Cleans up a Unix socket file, ignoring errors if the file doesn't exist.
///
/// # Arguments
///
/// * `socket_path` - Path to the socket file to remove
///
/// # Example
///
/// ```no_run
/// use tests::{unique_socket_path, cleanup_socket};
///
/// let socket_path = unique_socket_path();
/// // ... test code ...
/// cleanup_socket(&socket_path);
/// ```
pub fn cleanup_socket(socket_path: &PathBuf) {
    let _ = std::fs::remove_file(socket_path);
}

/// Common test constants
pub mod constants {
    /// Default timeout for async operations in tests (milliseconds)
    pub const TEST_TIMEOUT_MS: u64 = 5000;

    /// Time to wait for processes to start (milliseconds)
    pub const PROCESS_START_WAIT_MS: u64 = 500;

    /// Time to wait for processes to stop (milliseconds)
    pub const PROCESS_STOP_WAIT_MS: u64 = 1000;

    /// Default test multicast group
    pub const TEST_MULTICAST_GROUP: &str = "224.0.0.251";

    /// Default test port
    pub const TEST_PORT: u16 = 15000;
}

/// Test documentation template
///
/// Use this pattern for documenting all integration tests:
///
/// ```rust,no_run
/// /// **Tier 2 Integration Test**
/// ///
/// /// - **Purpose:** Describe what this test validates
/// /// - **Method:** Describe how the test works (setup, action, assertion)
/// /// - **Tier:** 2 (Integration)
/// #[tokio::test]
/// async fn test_example() {
///     // Test implementation
/// }
/// ```
pub mod doc_template {
    // This module exists solely for documentation purposes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_socket_path_creates_different_paths() {
        let path1 = unique_socket_path();
        let path2 = unique_socket_path();
        assert_ne!(path1, path2, "Should generate unique paths");
        assert!(path1.to_str().unwrap().starts_with("/tmp/test_"));
        assert!(path1.to_str().unwrap().ends_with(".sock"));
    }

    #[test]
    fn test_unique_socket_path_with_prefix() {
        let path = unique_socket_path_with_prefix("supervisor");
        let path_str = path.to_str().unwrap();
        assert!(path_str.contains("supervisor"));
        assert!(path_str.starts_with("/tmp/test_supervisor_"));
        assert!(path_str.ends_with(".sock"));
    }

    #[test]
    fn test_cleanup_socket_doesnt_panic_if_file_missing() {
        let path = PathBuf::from("/tmp/nonexistent_test_socket.sock");
        cleanup_socket(&path); // Should not panic
    }
}
