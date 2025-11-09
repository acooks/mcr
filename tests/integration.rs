//! Integration Tests
//!
//! This file makes the integration test modules in `integration/` directory
//! discoverable by cargo and tarpaulin. Without this file, tests in subdirectories
//! are not compiled or run.

// Test utilities - shared with integration test modules
// Note: These are duplicated from tests/lib.rs because integration test crates
// cannot import from each other. This is the standard Rust pattern.
mod tests {
    use std::path::PathBuf;
    use uuid::Uuid;

    pub fn unique_socket_path_with_prefix(prefix: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/test_{}_{}.sock", prefix, Uuid::new_v4()))
    }

    pub fn cleanup_socket(socket_path: &PathBuf) {
        let _ = std::fs::remove_file(socket_path);
    }
}

// Include integration test modules
#[path = "integration/cli.rs"]
mod cli;

#[path = "integration/log_level_control.rs"]
mod log_level_control;

#[path = "integration/rule_management.rs"]
mod rule_management;

// REMOVED: supervisor.rs - redundant with unit tests in src/supervisor.rs
// REMOVED: ipc.rs - broken code, redundant with rule_management.rs

// DEFERRED: supervisor_resilience.rs - needs complete rewrite for current supervisor API
// This contains 7 important tests that should be implemented after Phase 2-3 completion:
// - test_supervisor_restarts_control_plane_worker
// - test_supervisor_restarts_data_plane_worker
// - test_supervisor_resyncs_rules_on_restart
// - test_supervisor_applies_exponential_backoff
// - test_supervisor_handles_multiple_failures
// - test_supervisor_in_namespace
// - test_supervisor_handles_concurrent_requests
