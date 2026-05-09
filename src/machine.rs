use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{
    AgentConfig, MachineProfileConfig, NodeConfig,
    SubscriptionProxyConfig as RuntimeSubscriptionProxyConfig, SubscriptionProxyProfile,
    SubscriptionProxyZeroSslConfig, DEFAULT_CONFIG_DIR, DEFAULT_TIMEOUT_SECS,
};
use crate::panel::types::RealtimeBaseConfig;
use crate::panel::{PanelClient, PanelClientOptions};

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
    pub zerossl: SubscriptionProxyZeroSslConfig,
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MachineUpgradeCommand {
    pub id: String,
    pub target_version: String,
    #[serde(default)]
    pub component: String,
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
    pub realtime: Option<MachineProfileRealtime>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MachineProfileInput {
    pub profile: MachineProfileConfig,
    pub result: Result<MachineNodesResponse, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachineResolveSummary {
    pub nodes: Vec<NodeConfig>,
    pub agent: AgentConfig,
    pub realtime: Vec<MachineProfileRealtime>,
    pub failures: Vec<MachineResolveFailure>,
    pub subscription_proxy_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineResolveFailure {
    pub profile: String,
    pub machine_id: u32,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineProfileRealtime {
    pub profile: String,
    pub machine_id: u32,
    pub enabled: bool,
    pub url: String,
    pub ping_interval: u64,
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

    MachineResolveResult {
        nodes,
        agent,
        realtime: machine_profile_realtime(profile, response),
    }
}

pub fn resolve_machine_profiles(
    inputs: Vec<MachineProfileInput>,
    continue_on_error: bool,
) -> Result<MachineResolveSummary, String> {
    let mut summary = MachineResolveSummary::default();
    let mut seen_nodes = BTreeSet::new();
    let mut successes = 0usize;

    for input in inputs {
        let profile_label = machine_profile_label(&input.profile);
        let response = match input.result {
            Ok(response) => {
                successes += 1;
                response
            }
            Err(error) => {
                let failure = MachineResolveFailure {
                    profile: profile_label,
                    machine_id: input.profile.machine_id,
                    error,
                };
                if !continue_on_error {
                    return Err(failure.error);
                }
                summary.failures.push(failure);
                continue;
            }
        };

        let resolved = resolve_machine_profile_result(&input.profile, &response);
        merge_runtime_agent(&mut summary.agent, resolved.agent);
        if let Some(realtime) = resolved.realtime {
            summary.realtime.push(realtime);
        }

        for node in resolved.nodes {
            let key = machine_node_key(&node);
            if !seen_nodes.insert(key.clone()) {
                let failure = MachineResolveFailure {
                    profile: profile_label.clone(),
                    machine_id: input.profile.machine_id,
                    error: format!("duplicate machine profile node: {key}"),
                };
                if !continue_on_error {
                    return Err(failure.error);
                }
                summary.failures.push(failure);
                continue;
            }
            summary.nodes.push(node);
        }
    }

    if summary.nodes.is_empty() {
        if successes > 0 && can_run_subscription_proxy_only(&summary.agent) {
            summary.subscription_proxy_only = true;
            return Ok(summary);
        }
        if !summary.failures.is_empty() {
            let details = summary
                .failures
                .iter()
                .map(|failure| format!("{}: {}", failure.profile, failure.error))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("no machine nodes resolved: {details}"));
        }
        return Err("no machine nodes resolved".to_string());
    }

    Ok(summary)
}

pub async fn fetch_machine_profile_input(profile: MachineProfileConfig) -> MachineProfileInput {
    let result = fetch_machine_nodes_for_profile(&profile).await;
    MachineProfileInput { profile, result }
}

pub async fn resolve_machine_profiles_from_panel(
    profiles: &[MachineProfileConfig],
    continue_on_error: bool,
) -> Result<MachineResolveSummary, String> {
    let mut inputs = Vec::with_capacity(profiles.len());
    for profile in profiles {
        inputs.push(fetch_machine_profile_input(profile.clone()).await);
    }
    resolve_machine_profiles(inputs, continue_on_error)
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
        target.zerossl = source.zerossl.clone();
        target.allow_http_fallback = source.allow_http_fallback;
        target.max_response_bytes = source.max_response_bytes;
    } else {
        fill_if_empty(&mut target.https_listen, &source.https_listen);
        fill_if_empty(&mut target.http_listen, &source.http_listen);
        fill_if_empty(&mut target.cert_file, &source.cert_file);
        fill_if_empty(&mut target.key_file, &source.key_file);
        fill_if_empty(&mut target.certificate_domain, &source.certificate_domain);
        fill_if_empty(&mut target.challenge_dir, &source.challenge_dir);
        merge_subscription_proxy_zerossl(&mut target.zerossl, &source.zerossl);
        if target.max_response_bytes == 0 {
            target.max_response_bytes = source.max_response_bytes;
        }
    }

    if target.profiles.iter().any(|existing| {
        existing
            .site_id
            .eq_ignore_ascii_case(&proxy_profile.site_id)
    }) {
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

pub fn machine_profile_realtime(
    profile: &MachineProfileConfig,
    response: &MachineNodesResponse,
) -> Option<MachineProfileRealtime> {
    let realtime = response.base_config.as_ref()?.realtime.as_ref()?;
    Some(MachineProfileRealtime {
        profile: machine_profile_label(profile),
        machine_id: profile.machine_id,
        enabled: realtime.enabled,
        url: realtime.url.trim().to_string(),
        ping_interval: machine_realtime_interval_seconds(&realtime.ping_interval),
    })
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

fn merge_runtime_agent(target: &mut AgentConfig, source: AgentConfig) {
    let source_proxy = source.subscription_proxy;
    if !source_proxy.enabled {
        return;
    }

    if !target.subscription_proxy.enabled {
        target.subscription_proxy = source_proxy;
        return;
    }

    fill_if_empty(
        &mut target.subscription_proxy.https_listen,
        &source_proxy.https_listen,
    );
    fill_if_empty(
        &mut target.subscription_proxy.http_listen,
        &source_proxy.http_listen,
    );
    fill_if_empty(
        &mut target.subscription_proxy.cert_file,
        &source_proxy.cert_file,
    );
    fill_if_empty(
        &mut target.subscription_proxy.key_file,
        &source_proxy.key_file,
    );
    fill_if_empty(
        &mut target.subscription_proxy.certificate_domain,
        &source_proxy.certificate_domain,
    );
    fill_if_empty(
        &mut target.subscription_proxy.challenge_dir,
        &source_proxy.challenge_dir,
    );
    merge_subscription_proxy_zerossl(
        &mut target.subscription_proxy.zerossl,
        &source_proxy.zerossl,
    );
    if target.subscription_proxy.max_response_bytes == 0 {
        target.subscription_proxy.max_response_bytes = source_proxy.max_response_bytes;
    }

    for profile in source_proxy.profiles {
        if target
            .subscription_proxy
            .profiles
            .iter()
            .any(|existing| existing.site_id.eq_ignore_ascii_case(&profile.site_id))
        {
            continue;
        }
        target.subscription_proxy.profiles.push(profile);
    }
}

fn merge_subscription_proxy_zerossl(
    target: &mut crate::config::SubscriptionProxyZeroSslConfig,
    source: &crate::config::SubscriptionProxyZeroSslConfig,
) {
    fill_if_empty(&mut target.status, &source.status);
    fill_if_empty(&mut target.certificate_id, &source.certificate_id);
    fill_if_empty(&mut target.validation_path, &source.validation_path);
    fill_if_empty(&mut target.validation_content, &source.validation_content);
    fill_if_empty(&mut target.certificate_pem, &source.certificate_pem);
    fill_if_empty(&mut target.ca_bundle_pem, &source.ca_bundle_pem);
    fill_if_empty(&mut target.expires_at, &source.expires_at);
}

async fn fetch_machine_nodes_for_profile(
    profile: &MachineProfileConfig,
) -> Result<MachineNodesResponse, String> {
    let timeout = if profile.timeout == 0 {
        DEFAULT_TIMEOUT_SECS
    } else {
        profile.timeout
    };
    let client = PanelClient::new(PanelClientOptions {
        api_host: profile.url.clone(),
        token: profile.token.clone(),
        node_id: 0,
        machine_id: profile.machine_id,
        timeout: Duration::from_secs(timeout),
        config_dir: profile.config_dir.clone(),
    })
    .map_err(|err| err.to_string())?;

    client
        .get_machine_nodes()
        .await
        .map_err(|err| err.to_string())
}

fn can_run_subscription_proxy_only(agent: &AgentConfig) -> bool {
    if !agent.subscription_proxy.enabled {
        return false;
    }
    if valid_subscription_proxy_profile(
        &agent.subscription_proxy.site_id,
        &agent.subscription_proxy.upstream_base_url,
    ) {
        return true;
    }
    agent.subscription_proxy.profiles.iter().any(|profile| {
        valid_subscription_proxy_profile(&profile.site_id, &profile.upstream_base_url)
    })
}

fn valid_subscription_proxy_profile(site_id: &str, upstream_base_url: &str) -> bool {
    let site_id = site_id.trim();
    let upstream = upstream_base_url.trim_end_matches('/');
    if site_id.is_empty() || upstream.is_empty() {
        return false;
    }
    let Some((scheme, rest)) = upstream.split_once("://") else {
        return false;
    };
    !scheme.is_empty() && !rest.trim_matches('/').is_empty()
}

fn machine_realtime_interval_seconds(value: &Value) -> u64 {
    match value {
        Value::Number(number) => number.as_u64().unwrap_or_default(),
        Value::String(text) => text.trim().parse::<u64>().unwrap_or_default(),
        _ => 0,
    }
}

fn machine_node_key(node: &NodeConfig) -> String {
    format!(
        "{}#{}#{}",
        node.url.trim_end_matches('/'),
        node.machine_id,
        node.node_id
    )
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
        machine_profile_node_config_dir, resolve_machine_profile_result, resolve_machine_profiles,
        sanitize_machine_profile_name, MachineNodesEnvelope, MachineNodesResponse,
        MachinePanelNode, MachineProfileBaseConfig, MachineProfileInput, MachineStatusPayload,
        MachineStatusResponse, NodeFailurePayload, SubscriptionProxyConfig,
    };
    use crate::config::{MachineProfileConfig, SubscriptionProxyZeroSslConfig};
    use crate::panel::types::RealtimeBaseConfig;

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
    fn machine_status_response_accepts_legacy_and_component_upgrade_commands() {
        let legacy: MachineStatusResponse = serde_json::from_value(json!({
            "reload": false,
            "upgrade": {
                "id": "upgrade-node",
                "target_version": "v0.1.3"
            }
        }))
        .unwrap();
        let core: MachineStatusResponse = serde_json::from_value(json!({
            "upgrade": {
                "id": "upgrade-core",
                "target_version": "v0.1.1",
                "component": "core"
            }
        }))
        .unwrap();

        assert_eq!(legacy.upgrade.unwrap().component, "");
        assert_eq!(core.upgrade.unwrap().component, "core");
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
                    zerossl: SubscriptionProxyZeroSslConfig {
                        certificate_id: "cert-1".to_string(),
                        ..SubscriptionProxyZeroSslConfig::default()
                    },
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
        assert_eq!(
            result.agent.subscription_proxy.profiles[0].site_id,
            "site-one"
        );
        assert_eq!(
            result.agent.subscription_proxy.profiles[0].subscribe_path,
            "answer/land"
        );
        assert_eq!(
            result.agent.subscription_proxy.zerossl.certificate_id,
            "cert-1"
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
        assert_eq!(
            sanitize_machine_profile_name("Site A / Prod"),
            "Site-A-Prod"
        );
        assert_eq!(sanitize_machine_profile_name("///"), "machine");
    }

    #[test]
    fn aggregates_multiple_machine_profiles() {
        let first = MachineProfileConfig {
            name: "site-a".to_string(),
            url: "https://site-a.example.test".to_string(),
            token: "token-a".to_string(),
            machine_id: 1,
            ..MachineProfileConfig::default()
        };
        let second = MachineProfileConfig {
            name: "site-b".to_string(),
            url: "https://site-b.example.test".to_string(),
            token: "token-b".to_string(),
            machine_id: 2,
            ..MachineProfileConfig::default()
        };

        let summary = resolve_machine_profiles(
            vec![
                MachineProfileInput {
                    profile: first,
                    result: Ok(machine_response(10, "site-a")),
                },
                MachineProfileInput {
                    profile: second,
                    result: Ok(machine_response(20, "site-b")),
                },
            ],
            true,
        )
        .unwrap();

        assert_eq!(summary.nodes.len(), 2);
        assert_eq!(summary.agent.subscription_proxy.profiles.len(), 2);
        assert!(summary.failures.is_empty());
        assert_eq!(summary.realtime.len(), 2);
    }

    #[test]
    fn continues_after_profile_error_when_allowed() {
        let ok = MachineProfileConfig {
            name: "ok".to_string(),
            url: "https://ok.example.test".to_string(),
            token: "ok-token".to_string(),
            machine_id: 2,
            ..MachineProfileConfig::default()
        };
        let failed = MachineProfileConfig {
            name: "failed".to_string(),
            url: "https://failed.example.test".to_string(),
            token: "bad-token".to_string(),
            machine_id: 1,
            ..MachineProfileConfig::default()
        };

        let summary = resolve_machine_profiles(
            vec![
                MachineProfileInput {
                    profile: failed,
                    result: Err("unauthorized".to_string()),
                },
                MachineProfileInput {
                    profile: ok,
                    result: Ok(machine_response(21, "ok")),
                },
            ],
            true,
        )
        .unwrap();

        assert_eq!(summary.nodes.len(), 1);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].profile, "failed");
    }

    #[test]
    fn rejects_duplicate_machine_nodes_without_continue_on_error() {
        let first = MachineProfileConfig {
            name: "first".to_string(),
            url: "https://same.example.test/".to_string(),
            token: "token".to_string(),
            machine_id: 9,
            ..MachineProfileConfig::default()
        };
        let second = MachineProfileConfig {
            name: "second".to_string(),
            url: "https://same.example.test".to_string(),
            token: "token".to_string(),
            machine_id: 9,
            ..MachineProfileConfig::default()
        };

        let err = resolve_machine_profiles(
            vec![
                MachineProfileInput {
                    profile: first,
                    result: Ok(machine_response(30, "one")),
                },
                MachineProfileInput {
                    profile: second,
                    result: Ok(machine_response(30, "two")),
                },
            ],
            false,
        )
        .unwrap_err();

        assert!(err.contains("duplicate machine profile node"));
    }

    #[test]
    fn allows_subscription_proxy_only_when_no_nodes_returned() {
        let profile = MachineProfileConfig {
            name: "site-only".to_string(),
            url: "https://site-only.example.test".to_string(),
            token: "token".to_string(),
            machine_id: 6,
            ..MachineProfileConfig::default()
        };
        let response = MachineNodesResponse {
            nodes: Vec::new(),
            agent: Some(super::MachineAgentConfig {
                subscription_proxy: Some(SubscriptionProxyConfig {
                    enabled: true,
                    site_id: "site-only".to_string(),
                    upstream_base_url: "https://site-only.example.test".to_string(),
                    subscribe_path: "s".to_string(),
                    ..SubscriptionProxyConfig::default()
                }),
            }),
            ..MachineNodesResponse::default()
        };

        let summary = resolve_machine_profiles(
            vec![MachineProfileInput {
                profile,
                result: Ok(response),
            }],
            true,
        )
        .unwrap();

        assert!(summary.nodes.is_empty());
        assert!(summary.subscription_proxy_only);
        assert_eq!(summary.agent.subscription_proxy.profiles.len(), 1);
    }

    fn machine_response(node_id: u32, site_id: &str) -> MachineNodesResponse {
        MachineNodesResponse {
            nodes: vec![MachinePanelNode {
                id: node_id,
                code: String::new(),
                node_type: "vless".to_string(),
                name: format!("node-{node_id}"),
                updated_at: json!(null),
            }],
            base_config: Some(MachineProfileBaseConfig {
                realtime: Some(RealtimeBaseConfig {
                    enabled: true,
                    url: "wss://panel.example.test/ws/node".to_string(),
                    ping_interval: json!(15),
                }),
            }),
            agent: Some(super::MachineAgentConfig {
                subscription_proxy: Some(SubscriptionProxyConfig {
                    enabled: true,
                    site_id: site_id.to_string(),
                    upstream_base_url: format!("https://{site_id}.example.test"),
                    subscribe_path: "s".to_string(),
                    ..SubscriptionProxyConfig::default()
                }),
            }),
        }
    }
}
