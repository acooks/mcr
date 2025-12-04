// SPDX-License-Identifier: Apache-2.0 OR MIT
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

// Include common utilities for integration tests
#[path = "integration/common/mod.rs"]
mod common;

// Include integration test modules
#[path = "integration/cli.rs"]
mod cli; // 3 tests: CLI smoke tests for supervisor and worker modes

#[path = "integration/log_level_control.rs"]
mod log_level_control; // 2 tests: IPC communication for log level control (command logic in unit tests)

#[path = "integration/rule_management.rs"]
mod rule_management; // 1 test: E2E rule propagation from supervisor to data plane workers

#[path = "integration/test_basic.rs"]
mod test_basic; // Network integration tests with veth pairs and namespaces (requires root)

#[path = "integration/test_scaling.rs"]
mod test_scaling; // Scaling tests at different packet counts (requires root)

#[path = "integration/test_topologies.rs"]
mod test_topologies; // Multi-hop and fanout topology tests (requires root)

#[path = "integration/multi_interface.rs"]
mod multi_interface; // Multi-interface architecture tests (requires root)

#[path = "integration/cli_functional.rs"]
mod cli_functional; // CLI functional tests: mcrctl commands against running supervisor (requires root)

// REMOVED: supervisor.rs - redundant with unit tests in src/supervisor.rs
// REMOVED: ipc.rs - broken code, redundant with rule_management.rs
// REMOVED: 4 tests from log_level_control.rs - redundant with supervisor unit tests (kept 2 IPC tests)

// DEFERRED: supervisor_resilience.rs - needs complete rewrite for current supervisor API
// This contains 6 important tests that should be implemented after Phase 2-3 completion:
// - test_supervisor_restarts_data_plane_worker
// - test_supervisor_resyncs_rules_on_restart
// - test_supervisor_applies_exponential_backoff
// - test_supervisor_handles_multiple_failures
// - test_supervisor_in_namespace
// - test_supervisor_handles_concurrent_requests
