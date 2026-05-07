use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{
    AgentConfig, MachineProfileConfig, NodeConfig, SubscriptionProxyConfig as RuntimeSubscriptionProxyConfig,
    SubscriptionProxyProfile, DEFAULT_CONFIG_DIR,
};
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachineResolveResult {
    pub nodes: Vec<NodeConfig>,
    pub agent: AgentConfig,
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

pub fn resolve_machine_profile_result(
    profile: &MachineProfileConfig,
    response: &MachineNodesResponse,
) -> MachineResolveResult {
    let nodes = response
        .nodes
        .iter()
        .filter(|node| node.id > 0)
        .map(|node| NodeConfig {
            url: profile.url.trim_end_matches('/').to_string(),
            token: profile.token.clone(),
            node_id: node.id,
            machine_id: profile.machine_id,
            timeout: profile.timeout,
            config_dir: machine_profile_node_config_dir(profile, node.id),
        })
        .collect();

    let mut agent = AgentConfig::default();
    if let Some(machine_agent) = &response.agent {
        if let Some(proxy) = &machine_agent.subscription_proxy {
            merge_subscription_proxy(&mut agent.subscription_proxy, profile, proxy);
        }
    }

    MachineResolveResult { nodes, agent }
}

pub fn merge_subscription_proxy(
    target: &mut RuntimeSubscriptionProxyConfig,
    profile: &MachineProfileConfig,
    source: &SubscriptionProxyConfig,
) {
    if !source.enabled {
        return;
    }

    let mut proxy_profile = SubscriptionProxyProfile {
        site_id: first_non_empty(source.site_id.trim(), &machine_profile_label(profile)),
        upstream_base_url: first_non_empty(
            source.upstream_base_url.trim_end_matches('/'),
            profile.url.trim_end_matches('/'),
        ),
        subscribe_path: first_non_empty(source.subscribe_path.trim_matches('/'), "s"),
    };
    proxy_profile.site_id = sanitize_machine_profile_name(&proxy_profile.site_id);
    if proxy_profile.site_id.is_empty() || proxy_profile.upstream_base_url.is_empty() {
        return;
    }

    if !target.enabled {
        target.enabled = true;
        target.https_listen = source.https_listen.trim().to_string();
        target.http_listen = source.http_listen.trim().to_string();
        target.cert_file = source.cert_file.trim().to_string();
        target.key_file = source.key_file.trim().to_string();
        target.certificate_domain = source.certificate_domain.trim().to_string();
        target.challenge_dir = source.challenge_dir.trim().to_string();
        target.allow_http_fallback = source.allow_http_fallback;
        target.max_response_bytes = source.max_response_bytes;
    } else {
        fill_if_empty(&mut target.https_listen, &source.https_listen);
        fill_if_empty(&mut target.http_listen, &source.http_listen);
        fill_if_empty(&mut target.cert_file, &source.cert_file);
        fill_if_empty(&mut target.key_file, &source.key_file);
        fill_if_empty(&mut target.certificate_domain, &source.certificate_domain);
        fill_if_empty(&mut target.challenge_dir, &source.challenge_dir);
        if target.max_response_bytes == 0 {
            target.max_response_bytes = source.max_response_bytes;
        }
    }

    if target
        .profiles
        .iter()
        .any(|existing| existing.site_id.eq_ignore_ascii_case(&proxy_profile.site_id))
    {
        return;
    }
    target.profiles.push(proxy_profile);
}

pub fn machine_profile_node_config_dir(profile: &MachineProfileConfig, node_id: u32) -> String {
    let label = sanitize_machine_profile_name(&machine_profile_label(profile));
    let root = if profile.config_dir.trim().is_empty() {
        format!("{DEFAULT_CONFIG_DIR}/{label}")
    } else {
        profile
            .config_dir
            .trim_end_matches(|character| character == '/' || character == '\\')
            .to_string()
    };

    format!("{root}/node-{node_id}")
}

pub fn machine_profile_label(profile: &MachineProfileConfig) -> String {
    if !profile.name.trim().is_empty() {
        return profile.name.trim().to_string();
    }
    if profile.machine_id > 0 {
        return format!("machine-{}", profile.machine_id);
    }
    profile.url.trim_end_matches('/').to_string()
}

pub fn sanitize_machine_profile_name(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    let mut last_dash = false;
    for character in name.trim().chars() {
        let allowed = character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-');
        if allowed {
            output.push(character);
            last_dash = false;
        } else if !last_dash {
            output.push('-');
            last_dash = true;
        }
    }
    let trimmed = output.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "machine".to_string()
    } else {
        trimmed
    }
}

fn first_non_empty(first: &str, fallback: &str) -> String {
    if first.trim().is_empty() {
        fallback.trim().to_string()
    } else {
        first.trim().to_string()
    }
}

fn fill_if_empty(target: &mut String, value: &str) {
    if target.trim().is_empty() {
        *target = value.trim().to_string();
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

    use super::{
        machine_profile_node_config_dir, resolve_machine_profile_result, sanitize_machine_profile_name,
        MachineNodesEnvelope, MachineNodesResponse, MachinePanelNode, MachineStatusPayload,
        NodeFailurePayload, SubscriptionProxyConfig,
    };
    use crate::config::MachineProfileConfig;

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

    #[test]
    fn resolves_machine_nodes_into_node_configs() {
        let profile = MachineProfileConfig {
            name: "site-a".to_string(),
            url: "https://panel.example.test/".to_string(),
            token: "machine-token".to_string(),
            machine_id: 3,
            timeout: 5,
            ..MachineProfileConfig::default()
        };
        let response = MachineNodesResponse {
            nodes: vec![MachinePanelNode {
                id: 10,
                code: String::new(),
                node_type: "vless".to_string(),
                name: "node-a".to_string(),
                updated_at: json!(null),
            }],
            agent: Some(super::MachineAgentConfig {
                subscription_proxy: Some(SubscriptionProxyConfig {
                    enabled: true,
                    site_id: "site-one".to_string(),
                    upstream_base_url: "https://panel.example.test/".to_string(),
                    subscribe_path: "answer/land".to_string(),
                    https_listen: "0.0.0.0:443".to_string(),
                    ..SubscriptionProxyConfig::default()
                }),
            }),
            ..MachineNodesResponse::default()
        };

        let result = resolve_machine_profile_result(&profile, &response);

        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].url, "https://panel.example.test");
        assert_eq!(result.nodes[0].node_id, 10);
        assert_eq!(result.nodes[0].machine_id, 3);
        assert_eq!(result.nodes[0].config_dir, "/etc/v2node/site-a/node-10");
        assert!(result.agent.subscription_proxy.enabled);
        assert_eq!(result.agent.subscription_proxy.profiles[0].site_id, "site-one");
        assert_eq!(
            result.agent.subscription_proxy.profiles[0].subscribe_path,
            "answer/land"
        );
    }

    #[test]
    fn machine_node_config_dir_uses_override_root() {
        let profile = MachineProfileConfig {
            config_dir: "/srv/keli".to_string(),
            ..MachineProfileConfig::default()
        };

        assert_eq!(
            machine_profile_node_config_dir(&profile, 21),
            "/srv/keli/node-21"
        );
    }

    #[test]
    fn sanitizes_machine_profile_names() {
        assert_eq!(sanitize_machine_profile_name("Site A / Prod"), "Site-A-Prod");
        assert_eq!(sanitize_machine_profile_name("///"), "machine");
    }
}
