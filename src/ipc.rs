// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{FlowStats, ForwardingRule};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    ListRules,
    GetStats,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Rules(Vec<ForwardingRule>),
    Stats(Vec<FlowStats>),
    Error(String),
}
