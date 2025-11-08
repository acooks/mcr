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
        self.active_rules
            .insert(rule.rule_id.clone(), rule.clone());

        let mut cp_sent = false;
        for handle in self.workers.values() {
            let command = RelayCommand::AddRule(rule.clone());
            match handle.worker_type {
                WorkerType::ControlPlane => {
                    handle
                        .command_tx
                        .send(command)
                        .await
                        .context("Failed to send AddRule to control plane worker")?;
                    cp_sent = true;
                }
                WorkerType::DataPlane { .. } => {
                    if let Err(e) = handle.command_tx.try_send(command) {
                        eprintln!(
                            "[Supervisor] Warning: Failed to send AddRule to DP worker {}: {}. Worker may be busy or restarting.",
                            handle.pid, e
                        );
                    }
                }
            }
        }

        if !cp_sent {
            anyhow::bail!("Control plane worker not found, cannot dispatch rule.");
        }

        Ok(())
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
        if !self.has_rule(rule_id) {
            return Ok(()); // Rule already removed, idempotent success
        }

        let command = RelayCommand::RemoveRule(rule_id.to_string());
        let mut cp_sent = false;

        for handle in self.workers.values() {
            match handle.worker_type {
                WorkerType::ControlPlane => {
                    handle
                        .command_tx
                        .send(command.clone())
                        .await
                        .context("Failed to send RemoveRule to control plane worker")?;
                    cp_sent = true;
                }
                WorkerType::DataPlane { .. } => {
                    if let Err(e) = handle.command_tx.try_send(command.clone()) {
                        eprintln!(
                            "[Supervisor] Warning: Failed to send RemoveRule to DP worker {}: {}. Worker may be busy or restarting.",
                            handle.pid, e
                        );
                    }
                }
            }
        }

        if !cp_sent {
            anyhow::bail!("Control plane worker not found, cannot dispatch rule removal.");
        }

        self.active_rules.remove(rule_id);

        Ok(())
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
        let handle = self
            .workers
            .get(&worker_id)
            .context(format!("Worker {} not found for resync", worker_id))?;

        println!(
            "[Supervisor] Resyncing {} active rules to worker {}",
            self.active_rules.len(),
            worker_id
        );

        for rule in self.active_rules.values() {
            let command = RelayCommand::AddRule(rule.clone());
            handle
                .command_tx
                .send(command)
                .await
                .context(format!("Failed to resync rule to worker {}", worker_id))?;
        }

        Ok(())
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

    // TODO: Add test for handling send failures

    fn dummy_rule(id: &str) -> ForwardingRule {
        ForwardingRule {
            rule_id: id.to_string(),
            ingress_iface: "eth0".to_string(),
            egress_iface: "eth1".to_string(),
            source_addr: "224.0.0.1:5001".parse().unwrap(),
            destination_addr: "127.0.0.1:6001".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn test_dispatch_add_rule() {
        let mut dispatcher = RuleDispatcher::new();
        let (cp_tx, mut cp_rx) = mpsc::channel(10);
        let (dp_tx, mut dp_rx) = mpsc::channel(10);

        dispatcher
            .register_worker(1, cp_tx, WorkerType::ControlPlane)
            .unwrap();
        dispatcher
            .register_worker(2, dp_tx, WorkerType::DataPlane { core_id: 0 })
            .unwrap();

        let rule = dummy_rule("rule1");
        dispatcher.dispatch_add_rule(rule.clone()).await.unwrap();

        assert!(dispatcher.has_rule("rule1"));
        assert_eq!(dispatcher.active_rule_count(), 1);

        // Verify CP worker received the command
        let cp_cmd = cp_rx.recv().await.unwrap();
        assert!(matches!(cp_cmd, RelayCommand::AddRule(r) if r == rule));

        // Verify DP worker received the command
        let dp_cmd = dp_rx.recv().await.unwrap();
        assert!(matches!(dp_cmd, RelayCommand::AddRule(r) if r == rule));
    }

    #[tokio::test]
    async fn test_dispatch_remove_rule() {
        let mut dispatcher = RuleDispatcher::new();
        let (cp_tx, mut cp_rx) = mpsc::channel(10);
        let (dp_tx, mut dp_rx) = mpsc::channel(10);

        dispatcher
            .register_worker(1, cp_tx, WorkerType::ControlPlane)
            .unwrap();
        dispatcher
            .register_worker(2, dp_tx, WorkerType::DataPlane { core_id: 0 })
            .unwrap();

        let rule = dummy_rule("rule1");
        dispatcher.dispatch_add_rule(rule).await.unwrap();
        dispatcher.dispatch_remove_rule("rule1").await.unwrap();

        assert!(!dispatcher.has_rule("rule1"));
        assert_eq!(dispatcher.active_rule_count(), 0);

        // Verify CP worker received the command
        cp_rx.recv().await; // Consume the add
        let cp_cmd = cp_rx.recv().await.unwrap();
        assert!(matches!(cp_cmd, RelayCommand::RemoveRule(id) if id == "rule1"));

        // Verify DP worker received the command
        dp_rx.recv().await; // Consume the add
        let dp_cmd = dp_rx.recv().await.unwrap();
        assert!(matches!(dp_cmd, RelayCommand::RemoveRule(id) if id == "rule1"));
    }

    #[tokio::test]
    async fn test_resync_worker() {
        let mut dispatcher = RuleDispatcher::new();
        let (worker1_tx, mut worker1_rx) = mpsc::channel(10);

        // Pre-populate with rules
        dispatcher
            .active_rules
            .insert("rule1".to_string(), dummy_rule("rule1"));
        dispatcher
            .active_rules
            .insert("rule2".to_string(), dummy_rule("rule2"));

        // Register a new worker
        dispatcher
            .register_worker(1, worker1_tx, WorkerType::DataPlane { core_id: 0 })
            .unwrap();

        // Resync the new worker
        dispatcher.resync_worker(1).await.unwrap();

        // Verify the worker received all active rules
        let mut received_rules = std::collections::HashSet::new();
        received_rules.insert(worker1_rx.recv().await.unwrap().rule_id().unwrap());
        received_rules.insert(worker1_rx.recv().await.unwrap().rule_id().unwrap());

        assert!(received_rules.contains("rule1"));
        assert!(received_rules.contains("rule2"));
        assert_eq!(received_rules.len(), 2);
    }
}
