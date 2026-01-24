// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration Tests
//!
//! This file makes the integration test modules in `integration/` directory
//! discoverable by cargo and tarpaulin. Without this file, tests in subdirectories
//! are not compiled or run.

// Include common utilities for integration tests
// The require_root! macro is exported from this module and available crate-wide
#[macro_use]
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

#[path = "integration/supervisor_resilience.rs"]
mod supervisor_resilience; // 3 tests: Worker restart, rule persistence, multi-failure handling

// Protocol integration tests
#[path = "integration/protocol_igmp.rs"]
mod protocol_igmp; // IGMP querier control and configuration tests (requires root)

#[path = "integration/protocol_pim.rs"]
mod protocol_pim; // PIM neighbor management and configuration tests (requires root)

#[path = "integration/protocol_msdp.rs"]
mod protocol_msdp; // MSDP peer management and SA cache tests (requires root)

#[path = "integration/protocol_cli.rs"]
mod protocol_cli; // Protocol enable via CLI without config file (requires root)

// Topology tests - multi-node protocol validation
#[path = "integration/topology.rs"]
mod topology; // PIM Hello exchange, IGMP querier election, MSDP TCP session (requires root)

// REMOVED: supervisor.rs - redundant with unit tests in src/supervisor.rs
// REMOVED: ipc.rs - broken code, redundant with rule_management.rs
// REMOVED: 4 tests from log_level_control.rs - redundant with supervisor unit tests (kept 2 IPC tests)
