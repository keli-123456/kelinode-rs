use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct MachineStatusPayload {
    pub machine_id: u32,
    pub status: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MachineStatusResponse {
    #[serde(default)]
    pub reload: bool,
    #[serde(default)]
    pub upgrade: Option<MachineUpgradeCommand>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MachineUpgradeCommand {
    pub id: String,
    pub target_version: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct NodeFailurePayload {
    pub api_host: String,
    pub node_id: u32,
    pub machine_id: u32,
    pub node_type: String,
    pub error: String,
}

impl NodeFailurePayload {
    pub fn v2node(
        api_host: impl Into<String>,
        node_id: u32,
        machine_id: u32,
        error: impl Into<String>,
    ) -> Self {
        Self {
            api_host: api_host.into(),
            node_id,
            machine_id,
            node_type: "v2node".to_string(),
            error: error.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NodeFailurePayload;

    #[test]
    fn node_failure_uses_v2node_type() {
        let failure = NodeFailurePayload::v2node("https://panel.example.test", 5, 7, "boom");

        assert_eq!(failure.node_type, "v2node");
        assert_eq!(failure.node_id, 5);
        assert_eq!(failure.machine_id, 7);
    }
}
