// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::ForwardingRule;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    ListRules,
    // Future requests can be added here, e.g.:
    // GetStats,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Rules(Vec<ForwardingRule>),
    // Future responses can be added here, e.g.:
    // Stats(Vec<FlowStats>),
    Error(String),
}
