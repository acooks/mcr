//! Rule Dispatch Module
//!
//! **Priority: CRITICAL - Sprint 1, Days 1-2**
//!
//! This module implements the core rule dispatch logic for the supervisor.
//! It handles distributing forwarding rules to the appropriate worker processes
//! and managing the lifecycle of those rules.
//!
//! ## Design References
//! - D23: Supervisor dispatches rules to workers via non-blocking channels
//! - D29: Rule dispatch must handle worker failures gracefully
//! - D18: Supervisor is single source of truth for configuration
//!
//! ## Implementation Status
//! - [ ] Basic rule dispatch to control plane worker
//! - [ ] Rule dispatch to appropriate data plane workers
//! - [ ] Failure handling and retry logic
//! - [ ] Rule removal dispatch
//! - [ ] Rule update handling (remove + add)

use anyhow::{Context, Result};
use std::collections::HashMap;
use tokio::sync::mpsc;

use crate::{ForwardingRule, RelayCommand};

/// Handle to a worker process for sending commands
pub struct WorkerHandle {
    /// Worker process ID
    pub pid: u32,

    /// Channel for sending commands to this worker
    pub command_tx: mpsc::Sender<RelayCommand>,

    /// Worker type (control plane or data plane)
    pub worker_type: WorkerType,

    /// For data plane workers: which core/interface this worker handles
    pub core_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WorkerType {
    ControlPlane,
    DataPlane { core_id: u32 },
}

/// Manages the dispatch of rules to worker processes
pub struct RuleDispatcher {
    /// Map of worker ID to worker handle
    workers: HashMap<u32, WorkerHandle>,

    /// Currently active rules (supervisor is source of truth)
    active_rules: HashMap<String, ForwardingRule>,
}

impl RuleDispatcher {
    pub fn new() -> Self {
        Self {
            workers: HashMap::new(),
            active_rules: HashMap::new(),
        }
    }

    /// Register a new worker with the dispatcher
    ///
    /// This is called when the supervisor spawns a new worker process.
    ///
    /// # Arguments
    /// * `worker_id` - Unique identifier for the worker (typically PID)
    /// * `command_tx` - Channel for sending commands to the worker
    /// * `worker_type` - Type of worker (control plane or data plane)
    pub fn register_worker(
        &mut self,
        worker_id: u32,
        command_tx: mpsc::Sender<RelayCommand>,
        worker_type: WorkerType,
    ) -> Result<()> {
        let core_id = match worker_type {
            WorkerType::DataPlane { core_id } => Some(core_id),
            WorkerType::ControlPlane => None,
        };

        let handle = WorkerHandle {
            pid: worker_id,
            command_tx,
            worker_type,
            core_id,
        };

        self.workers.insert(worker_id, handle);
        Ok(())
    }

    /// Unregister a worker (called when worker exits)
    pub fn unregister_worker(&mut self, worker_id: u32) {
        self.workers.remove(&worker_id);
    }

    /// Dispatch a new forwarding rule to all appropriate workers
    ///
    /// **TODO: IMPLEMENT THIS - CRITICAL**
    ///
    /// This is the core dispatch logic. It must:
    /// 1. Add the rule to active_rules (supervisor is source of truth)
    /// 2. Send AddRule command to control plane worker
    /// 3. Determine which data plane workers need this rule
    /// 4. Send AddRule command to those data plane workers
    /// 5. Handle any send failures gracefully
    ///
    /// ## Error Handling Strategy
    /// - If control plane send fails: Return error (critical failure)
    /// - If data plane send fails: Log warning, continue (worker will be restarted)
    /// - Use non-blocking sends with timeout
    ///
    /// ## Determining Data Plane Workers
    /// For now, send to ALL data plane workers. Future optimization: only send
    /// to workers handling the specific interface/core.
    pub async fn dispatch_add_rule(&mut self, rule: ForwardingRule) -> Result<()> {
        // TODO: Step 1 - Add to active_rules
        // self.active_rules.insert(rule.rule_id.clone(), rule.clone());

        // TODO: Step 2 - Send to control plane worker
        // Find control plane worker in self.workers
        // Send RelayCommand::AddRule(rule.clone())
        // Handle error if send fails

        // TODO: Step 3 - Send to all data plane workers
        // for (worker_id, handle) in &self.workers {
        //     if matches!(handle.worker_type, WorkerType::DataPlane { .. }) {
        //         // Send command with timeout
        //         // Log warning if send fails, but continue
        //     }
        // }

        todo!("Implement rule dispatch - see comments above")
    }

    /// Dispatch a rule removal to all workers
    ///
    /// **TODO: IMPLEMENT THIS - CRITICAL**
    ///
    /// Similar to dispatch_add_rule but for removal:
    /// 1. Verify rule exists in active_rules
    /// 2. Send RemoveRule to control plane
    /// 3. Send RemoveRule to all data plane workers
    /// 4. Remove from active_rules only after successful dispatch
    pub async fn dispatch_remove_rule(&mut self, rule_id: &str) -> Result<()> {
        // TODO: Implement
        todo!("Implement rule removal dispatch")
    }

    /// Re-dispatch all active rules to a newly started worker
    ///
    /// **TODO: IMPLEMENT THIS - HIGH PRIORITY**
    ///
    /// Called when a worker is restarted. The worker needs to receive
    /// all currently active rules to synchronize its state.
    ///
    /// This is critical for the supervisor's resilience model (D18).
    pub async fn resync_worker(&self, worker_id: u32) -> Result<()> {
        // TODO: Step 1 - Find the worker handle
        // let handle = self.workers.get(&worker_id)
        //     .context("Worker not found")?;

        // TODO: Step 2 - Send all active rules to this worker
        // for rule in self.active_rules.values() {
        //     handle.command_tx.send(RelayCommand::AddRule(rule.clone()))
        //         .await
        //         .context("Failed to resync rule")?;
        // }

        todo!("Implement worker resynchronization")
    }

    /// Get the current count of active rules
    pub fn active_rule_count(&self) -> usize {
        self.active_rules.len()
    }

    /// Get the current count of registered workers
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Check if a specific rule is active
    pub fn has_rule(&self, rule_id: &str) -> bool {
        self.active_rules.contains_key(rule_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify worker registration works correctly
    /// - **Method:** Register workers and verify count
    /// - **Tier:** 1 (Logic)
    #[test]
    fn test_register_worker() {
        let mut dispatcher = RuleDispatcher::new();
        let (tx, _rx) = mpsc::channel(10);

        dispatcher
            .register_worker(1, tx, WorkerType::ControlPlane)
            .unwrap();

        assert_eq!(dispatcher.worker_count(), 1);
    }

    /// **Tier 1 Unit Test**
    ///
    /// - **Purpose:** Verify worker unregistration
    /// - **Method:** Register then unregister worker
    /// - **Tier:** 1 (Logic)
    #[test]
    fn test_unregister_worker() {
        let mut dispatcher = RuleDispatcher::new();
        let (tx, _rx) = mpsc::channel(10);

        dispatcher
            .register_worker(1, tx, WorkerType::ControlPlane)
            .unwrap();
        dispatcher.unregister_worker(1);

        assert_eq!(dispatcher.worker_count(), 0);
    }

    // TODO: Add test for dispatch_add_rule
    // TODO: Add test for dispatch_remove_rule
    // TODO: Add test for resync_worker
    // TODO: Add test for handling send failures
}
