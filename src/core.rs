use std::path::PathBuf;

use crate::panel::types::{NodeInfo, Protocol, Security};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreKind {
    Xray,
    SingBox,
    Mihomo,
    Sidecar(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorePlan {
    pub kind: CoreKind,
    pub config_path: PathBuf,
    pub listen_tags: Vec<String>,
    pub inbounds: Vec<InboundPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundPlan {
    pub tag: String,
    pub protocol: String,
    pub listen: String,
    pub port: u16,
    pub security: String,
    pub network: String,
    pub alpn: Vec<String>,
    pub fallback_to_ipv4: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreApplyResult {
    pub restarted: bool,
    pub changed_tags: Vec<String>,
}

pub trait CoreAdapter {
    fn apply(&mut self, plan: CorePlan) -> Result<CoreApplyResult, CoreError>;
    fn stop(&mut self) -> Result<(), CoreError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreError {
    pub message: String,
}

impl CoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl CorePlan {
    pub fn from_nodes(
        kind: CoreKind,
        config_path: PathBuf,
        nodes: &[NodeInfo],
    ) -> Result<Self, CoreError> {
        let inbounds = nodes
            .iter()
            .map(build_inbound_plan)
            .collect::<Result<Vec<_>, _>>()?;
        let listen_tags = inbounds.iter().map(|inbound| inbound.tag.clone()).collect();

        Ok(Self {
            kind,
            config_path,
            listen_tags,
            inbounds,
        })
    }
}

pub fn build_inbound_plan(node: &NodeInfo) -> Result<InboundPlan, CoreError> {
    if node.common.server_port == 0 {
        return Err(CoreError::new(format!(
            "node {} has empty server port",
            node.tag
        )));
    }

    Ok(InboundPlan {
        tag: node.tag.clone(),
        protocol: core_protocol_name(node.protocol),
        listen: resolve_node_listen_ip(&node.common.listen_ip),
        port: node.common.server_port,
        security: security_name(node.security),
        network: core_network_name(node),
        alpn: resolve_tls_alpn(node),
        fallback_to_ipv4: should_fallback_node_listen_ip(&node.common.listen_ip),
    })
}

pub fn normalize_node_listen_ip(raw: &str) -> String {
    let listen_ip = raw.trim();
    if listen_ip.starts_with('[') && listen_ip.ends_with(']') {
        listen_ip
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    } else {
        listen_ip.to_string()
    }
}

pub fn resolve_node_listen_ip(raw: &str) -> String {
    match normalize_node_listen_ip(raw).as_str() {
        "" | "0.0.0.0" => "::".to_string(),
        value => value.to_string(),
    }
}

pub fn should_fallback_node_listen_ip(raw: &str) -> bool {
    matches!(
        normalize_node_listen_ip(raw).as_str(),
        "" | "0.0.0.0" | "::"
    )
}

pub fn resolve_tls_alpn(node: &NodeInfo) -> Vec<String> {
    let mut alpn = Vec::new();
    for value in &node.common.tls_settings.alpn {
        let text = value.trim();
        if text.is_empty() || alpn.iter().any(|existing| existing.as_str() == text) {
            continue;
        }
        alpn.push(text.to_string());
    }

    if alpn.is_empty() && matches!(node.protocol, Protocol::Hysteria2 | Protocol::Tuic) {
        alpn.push("h3".to_string());
    }
    alpn
}

fn core_protocol_name(protocol: Protocol) -> String {
    match protocol {
        Protocol::Hysteria2 => "hysteria".to_string(),
        other => other.as_str().to_string(),
    }
}

fn core_network_name(node: &NodeInfo) -> String {
    if !node.common.network.trim().is_empty() {
        return node.common.network.trim().to_string();
    }

    match node.protocol {
        Protocol::Trojan => "tcp".to_string(),
        Protocol::Hysteria2 => "hysteria".to_string(),
        Protocol::Tuic => "tuic".to_string(),
        _ => String::new(),
    }
}

fn security_name(security: Security) -> String {
    match security {
        Security::None => "none".to_string(),
        Security::Tls => "tls".to_string(),
        Security::Reality => "reality".to_string(),
        Security::Other(value) => format!("other-{value}"),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::{
        build_inbound_plan, resolve_node_listen_ip, should_fallback_node_listen_ip, CoreKind,
        CorePlan,
    };
    use crate::panel::types::{CommonNode, NodeInfo};

    #[test]
    fn core_plan_can_represent_external_xray() {
        let plan = CorePlan {
            kind: CoreKind::Xray,
            config_path: PathBuf::from("/etc/v2node/config.json"),
            listen_tags: vec!["[panel]-vless:1".to_string()],
            inbounds: Vec::new(),
        };

        assert_eq!(plan.listen_tags.len(), 1);
    }

    #[test]
    fn core_plan_builds_inbounds_from_nodes() {
        let node = test_node("vless", 1, "0.0.0.0");

        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/etc/v2node/config.json"),
            &[node],
        )
        .unwrap();

        assert_eq!(plan.listen_tags.len(), 1);
        assert_eq!(plan.inbounds[0].listen, "::");
        assert!(plan.inbounds[0].fallback_to_ipv4);
    }

    #[test]
    fn resolve_node_listen_ip_defaults_wildcard_to_dual_stack() {
        assert_eq!(resolve_node_listen_ip("0.0.0.0"), "::");
        assert_eq!(resolve_node_listen_ip(" "), "::");
        assert_eq!(resolve_node_listen_ip("[::]"), "::");
        assert_eq!(resolve_node_listen_ip("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn fallback_only_applies_to_wildcard_listeners() {
        assert!(should_fallback_node_listen_ip(""));
        assert!(should_fallback_node_listen_ip("0.0.0.0"));
        assert!(should_fallback_node_listen_ip("[::]"));
        assert!(!should_fallback_node_listen_ip("2001:db8::1"));
    }

    #[test]
    fn inbound_plan_maps_hysteria2_and_default_alpn() {
        let node = test_node("hysteria2", 7, "");
        let inbound = build_inbound_plan(&node).unwrap();

        assert_eq!(inbound.protocol, "hysteria");
        assert_eq!(inbound.network, "hysteria");
        assert_eq!(inbound.alpn, vec!["h3".to_string()]);
    }

    #[test]
    fn inbound_plan_deduplicates_custom_alpn() {
        let mut node = test_node("tuic", 8, "");
        node.common.tls_settings.alpn = vec![
            " h3 ".to_string(),
            "h3".to_string(),
            "h2".to_string(),
        ];
        let inbound = build_inbound_plan(&node).unwrap();

        assert_eq!(inbound.alpn, vec!["h3".to_string(), "h2".to_string()]);
    }

    fn test_node(protocol: &str, node_id: u32, listen_ip: &str) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": protocol,
            "listen_ip": listen_ip,
            "server_port": 10000 + node_id
        }))
        .unwrap();

        NodeInfo::from_common("https://panel.example.test", node_id, common).unwrap()
    }
}
