use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::panel::types::RealtimeBaseConfig;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct MachinePanelNode {
    pub id: u32,
    #[serde(default)]
    pub code: String,
    #[serde(default, rename = "type")]
    pub node_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub updated_at: Value,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct MachineNodesResponse {
    #[serde(default)]
    pub nodes: Vec<MachinePanelNode>,
    #[serde(default)]
    pub base_config: Option<MachineProfileBaseConfig>,
    #[serde(default)]
    pub agent: Option<MachineAgentConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct MachineNodesEnvelope {
    #[serde(default)]
    pub nodes: Vec<MachinePanelNode>,
    #[serde(default)]
    pub base_config: Option<MachineProfileBaseConfig>,
    #[serde(default)]
    pub agent: Option<MachineAgentConfig>,
    #[serde(default)]
    pub data: Option<MachineNodesResponse>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct MachineProfileBaseConfig {
    #[serde(default)]
    pub realtime: Option<RealtimeBaseConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MachineAgentConfig {
    #[serde(default)]
    pub subscription_proxy: Option<SubscriptionProxyConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SubscriptionProxyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub https_listen: String,
    #[serde(default)]
    pub http_listen: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default)]
    pub certificate_domain: String,
    #[serde(default)]
    pub challenge_dir: String,
    #[serde(default)]
    pub site_id: String,
    #[serde(default)]
    pub upstream_base_url: String,
    #[serde(default)]
    pub subscribe_path: String,
    #[serde(default)]
    pub allow_http_fallback: bool,
    #[serde(default)]
    pub max_response_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct MachineStatusPayload {
    pub machine_id: u32,
    pub status: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
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

impl MachineNodesEnvelope {
    pub fn into_response(self) -> MachineNodesResponse {
        if let Some(data) = self.data {
            return data;
        }

        MachineNodesResponse {
            nodes: self.nodes,
            base_config: self.base_config,
            agent: self.agent,
        }
    }
}

impl MachineStatusPayload {
    pub fn new(machine_id: u32) -> Self {
        Self {
            machine_id,
            status: BTreeMap::new(),
        }
    }

    pub fn insert_status(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        self.status.insert(key.into(), value.into());
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{MachineNodesEnvelope, MachineStatusPayload, NodeFailurePayload};

    #[test]
    fn node_failure_uses_v2node_type() {
        let failure = NodeFailurePayload::v2node("https://panel.example.test", 5, 7, "boom");

        assert_eq!(failure.node_type, "v2node");
        assert_eq!(failure.node_id, 5);
        assert_eq!(failure.machine_id, 7);
    }

    #[test]
    fn machine_nodes_response_accepts_nested_data_shape() {
        let envelope: MachineNodesEnvelope = serde_json::from_value(json!({
            "data": {
                "nodes": [
                    {"id": 10, "type": "vless", "name": "node-a"}
                ],
                "base_config": {
                    "realtime": {
                        "enabled": true,
                        "url": "wss://panel.example.test/ws/node",
                        "ping_interval": 15
                    }
                },
                "agent": {
                    "subscription_proxy": {
                        "enabled": true,
                        "site_id": "site-a",
                        "upstream_base_url": "https://panel.example.test",
                        "subscribe_path": "s"
                    }
                }
            }
        }))
        .unwrap();

        let response = envelope.into_response();

        assert_eq!(response.nodes.len(), 1);
        assert_eq!(response.nodes[0].id, 10);
        assert_eq!(response.nodes[0].node_type, "vless");
        assert!(response.base_config.unwrap().realtime.unwrap().enabled);
        assert_eq!(
            response.agent.unwrap().subscription_proxy.unwrap().site_id,
            "site-a"
        );
    }

    #[test]
    fn machine_status_payload_collects_dynamic_status() {
        let mut payload = MachineStatusPayload::new(7);
        payload.insert_status("version", "v0.1.0");
        payload.insert_status("cpu", 12.5);

        assert_eq!(payload.machine_id, 7);
        assert_eq!(payload.status["version"], json!("v0.1.0"));
        assert_eq!(payload.status["cpu"], json!(12.5));
    }
}
