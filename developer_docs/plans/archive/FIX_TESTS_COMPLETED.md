# Complete Plan to Fix Test Issues

## Phase 1: Critical Issues (must fix)

1. Fix test_get_stats_e2e silent skip (rule_management.rs)
   - Currently returns Ok(()) if traffic generator fails
   - Change to fail the test explicitly if mcrgen doesn't run
   - Ensure test actually validates packet forwarding
2. Fix test_cli_add_and_list_rule invalid rule (cli_functional.rs)
   - Currently uses empty outputs which fails validation
   - Change to use a valid rule with different input/output interfaces
3. Tighten test_tree_fanout_1_to_3 tolerance (test_topologies.rs)
   - Currently allows 10% deviation on replication
   - Tighten to 2-3% for replication validation
   - Also validate each leaf receives approximately equal share
4. Fix test_single_hop_1000_packets weak assertion (test_basic.rs)
   - Currently accepts any match > 0 when sending 1000 packets
   - Add assertion for minimum percentage matched (e.g., >= 400 given veth duplication)

## Phase 2: Medium Issues (improve quality)

1. Fix test_max_workers_spawning interface (rule_management.rs)
   - Change from "eth0" to "lo" for test portability
2. Add level verification to test_cli_log_level_set_global (cli_functional.rs)
   - After setting level, verify the returned level actually changed
3. Fix test_dynamic_worker_spawn_on_add_rule logic (multi_interface.rs)
   - Currently adds rule to same interface, contradicting test purpose
   - Should add rule to different interface to test dynamic spawning

## Phase 3: Fix Redundancy

1. Remove test_minimal_10_packets (test_basic.rs)
   - Redundant with test_single_hop_1000_packets
   - Delete entirely
2. Consolidate scaling tests (test_scaling.rs)
   - Three tests have identical validation logic
   - Refactor into single parameterized test function
3. Remove CLI/log_level_control overlap (cli_functional.rs)
   - test_cli_log_level_get, test_cli_log_level_set_global, test_cli_log_level_set_facility overlap with log_level_control.rs
   - Keep CLI tests focused on CLI behavior (output format)
   - Keep IPC tests focused on protocol correctness

## Phase 4: Fill Coverage Gaps

1. Add edge case tests (test_basic.rs)
   - Single packet forwarding
   - Maximum size packet (jumbo frame if supported)
2. Add convergence topology test (test_topologies.rs)
   - N:1 fanout (multiple inputs → single output)
   - Validates aggregation behavior
3. Add rule removal during traffic test (rule_management.rs or new file)
   - Start traffic flow
   - Remove rule mid-stream
   - Verify clean shutdown without crashes
4. Enable supervisor resilience tests (supervisor_resilience.rs)
   - Update for current API
   - Add to test suite in integration.rs
   - Tests: worker restart, rule resync, exponential backoff
5. Add concurrent rule modification test (multi_interface.rs or rule_management.rs)
   - Add/remove rules simultaneously from multiple tasks
   - Verify no race conditions or data corruption

## Summary

| Phase   | Items              | Priority                     |
|---------|--------------------|-----------------------------|
| Phase 1 | 4 critical fixes   | High - blocks reliability    |
| Phase 2 | 3 quality fixes    | Medium - improves signal     |
| Phase 3 | 3 redundancy fixes | Medium - reduces maintenance |
| Phase 4 | 5 coverage gaps    | Lower - expands coverage     |
