use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::panel::types::{CertInfo, NodeInfo, Protocol, Security, UserInfo};

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
    pub cert_file: String,
    pub key_file: String,
    pub server_name: String,
    pub reality_dest: String,
    pub reality_private_key: String,
    pub reality_short_id: String,
    pub users: Vec<InboundUserPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundUserPlan {
    pub id: u32,
    pub uuid: String,
    pub email: String,
    pub speed_limit: u32,
    pub device_limit: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreFileLayout {
    pub config_path: PathBuf,
    pub config_dir: PathBuf,
    pub temp_config_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreConfigWriteResult {
    pub path: PathBuf,
    pub bytes: usize,
    pub inbound_count: usize,
    pub changed: bool,
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
        Self::from_nodes_with_users(kind, config_path, nodes, &BTreeMap::new())
    }

    pub fn from_nodes_with_users(
        kind: CoreKind,
        config_path: PathBuf,
        nodes: &[NodeInfo],
        users_by_node_id: &BTreeMap<u32, Vec<UserInfo>>,
    ) -> Result<Self, CoreError> {
        let inbounds = nodes
            .iter()
            .map(|node| {
                let users = users_by_node_id
                    .get(&node.id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                build_inbound_plan_with_users(node, users)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let listen_tags = inbounds.iter().map(|inbound| inbound.tag.clone()).collect();

        Ok(Self {
            kind,
            config_path,
            listen_tags,
            inbounds,
        })
    }

    pub fn file_layout(&self) -> CoreFileLayout {
        core_file_layout(&self.config_path)
    }
}

pub fn core_file_layout(config_path: impl AsRef<Path>) -> CoreFileLayout {
    let config_path = config_path.as_ref().to_path_buf();
    let config_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let temp_config_path = config_path.with_extension("json.tmp");

    CoreFileLayout {
        config_path,
        config_dir,
        temp_config_path,
    }
}

pub fn render_core_config(plan: &CorePlan) -> Result<Value, CoreError> {
    match &plan.kind {
        CoreKind::Xray => Ok(render_xray_config(plan)),
        CoreKind::SingBox => Err(CoreError::new(
            "sing-box core config rendering is not implemented yet",
        )),
        CoreKind::Mihomo => Err(CoreError::new(
            "mihomo core config rendering is not implemented yet",
        )),
        CoreKind::Sidecar(name) => Err(CoreError::new(format!(
            "sidecar core config rendering is not implemented for {name}",
        ))),
    }
}

pub fn write_core_config(plan: &CorePlan) -> Result<CoreConfigWriteResult, CoreError> {
    let value = render_core_config(plan)?;
    write_core_config_value(&plan.config_path, &value, plan.inbounds.len())
}

pub fn write_core_config_value(
    path: impl AsRef<Path>,
    value: &Value,
    inbound_count: usize,
) -> Result<CoreConfigWriteResult, CoreError> {
    let path = path.as_ref();
    let layout = core_file_layout(path);
    fs::create_dir_all(&layout.config_dir).map_err(|err| {
        CoreError::new(format!(
            "create core config dir {}: {err}",
            layout.config_dir.display()
        ))
    })?;

    let mut content = serde_json::to_vec_pretty(value).map_err(|err| {
        CoreError::new(format!("encode core config {}: {err}", path.display()))
    })?;
    content.push(b'\n');

    if fs::read(path).ok().as_deref() == Some(content.as_slice()) {
        return Ok(CoreConfigWriteResult {
            path: path.to_path_buf(),
            bytes: content.len(),
            inbound_count,
            changed: false,
        });
    }

    fs::write(&layout.temp_config_path, &content).map_err(|err| {
        CoreError::new(format!(
            "write core config temp {}: {err}",
            layout.temp_config_path.display()
        ))
    })?;
    replace_file(&layout.temp_config_path, path).map_err(|err| {
        CoreError::new(format!("replace core config {}: {err}", path.display()))
    })?;

    Ok(CoreConfigWriteResult {
        path: path.to_path_buf(),
        bytes: content.len(),
        inbound_count,
        changed: true,
    })
}

pub fn build_inbound_plan(node: &NodeInfo) -> Result<InboundPlan, CoreError> {
    build_inbound_plan_with_users(node, &[])
}

pub fn build_inbound_plan_with_users(
    node: &NodeInfo,
    users: &[UserInfo],
) -> Result<InboundPlan, CoreError> {
    if node.common.server_port == 0 {
        return Err(CoreError::new(format!(
            "node {} has empty server port",
            node.tag
        )));
    }

    let cert = node.common.cert_info.as_ref();

    Ok(InboundPlan {
        tag: node.tag.clone(),
        protocol: core_protocol_name(node.protocol),
        listen: resolve_node_listen_ip(&node.common.listen_ip),
        port: node.common.server_port,
        security: security_name(node.security),
        network: core_network_name(node),
        alpn: resolve_tls_alpn(node),
        fallback_to_ipv4: should_fallback_node_listen_ip(&node.common.listen_ip),
        cert_file: cert.map(cert_file).unwrap_or_default(),
        key_file: cert.map(key_file).unwrap_or_default(),
        server_name: cert.map(cert_domain).unwrap_or_else(|| {
            first_non_empty(
                node.common.tls_settings.server_name.trim(),
                node.common.server_name.trim(),
            )
        }),
        reality_dest: node.common.tls_settings.dest.trim().to_string(),
        reality_private_key: node.common.tls_settings.private_key.trim().to_string(),
        reality_short_id: node.common.tls_settings.short_id.trim().to_string(),
        users: users
            .iter()
            .filter(|user| !user.uuid.trim().is_empty())
            .map(inbound_user_plan)
            .collect(),
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

fn render_xray_config(plan: &CorePlan) -> Value {
    let inbounds = plan
        .inbounds
        .iter()
        .map(render_xray_inbound)
        .collect::<Vec<_>>();

    json!({
        "log": {
            "loglevel": "warning"
        },
        "inbounds": inbounds,
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom"
            },
            {
                "tag": "blocked",
                "protocol": "blackhole"
            }
        ]
    })
}

fn render_xray_inbound(inbound: &InboundPlan) -> Value {
    let mut item = Map::new();
    item.insert("tag".to_string(), json!(&inbound.tag));
    item.insert("listen".to_string(), json!(&inbound.listen));
    item.insert("port".to_string(), json!(inbound.port));
    item.insert("protocol".to_string(), json!(&inbound.protocol));
    item.insert(
        "settings".to_string(),
        render_xray_inbound_settings(inbound),
    );

    let stream_settings = render_xray_stream_settings(inbound);
    if !stream_settings.is_empty() {
        item.insert("streamSettings".to_string(), Value::Object(stream_settings));
    }

    Value::Object(item)
}

fn render_xray_inbound_settings(inbound: &InboundPlan) -> Value {
    let clients = render_xray_clients(inbound);
    match inbound.protocol.as_str() {
        "vless" => json!({
            "clients": clients,
            "decryption": "none"
        }),
        "vmess" | "trojan" => json!({
            "clients": clients
        }),
        "shadowsocks" => json!({
            "clients": clients,
            "network": "tcp,udp"
        }),
        "hysteria" | "tuic" => json!({
            "clients": clients
        }),
        _ => json!({}),
    }
}

fn render_xray_clients(inbound: &InboundPlan) -> Vec<Value> {
    inbound
        .users
        .iter()
        .map(|user| match inbound.protocol.as_str() {
            "trojan" | "shadowsocks" | "hysteria" | "tuic" => json!({
                "password": &user.uuid,
                "email": &user.email
            }),
            "vmess" => json!({
                "id": &user.uuid,
                "email": &user.email,
                "alterId": 0
            }),
            _ => json!({
                "id": &user.uuid,
                "email": &user.email
            }),
        })
        .collect()
}

fn render_xray_stream_settings(inbound: &InboundPlan) -> Map<String, Value> {
    let mut stream = Map::new();
    if !inbound.network.trim().is_empty() {
        stream.insert("network".to_string(), json!(&inbound.network));
    }
    if inbound.security != "none" {
        stream.insert("security".to_string(), json!(&inbound.security));
    }

    match inbound.security.as_str() {
        "tls" => {
            stream.insert("tlsSettings".to_string(), render_xray_tls_settings(inbound));
        }
        "reality" => {
            stream.insert(
                "realitySettings".to_string(),
                render_xray_reality_settings(inbound),
            );
        }
        _ => {}
    }

    stream
}

fn render_xray_tls_settings(inbound: &InboundPlan) -> Value {
    let mut settings = Map::new();
    if !inbound.server_name.trim().is_empty() {
        settings.insert("serverName".to_string(), json!(&inbound.server_name));
    }
    if !inbound.alpn.is_empty() {
        settings.insert("alpn".to_string(), json!(&inbound.alpn));
    }
    if !inbound.cert_file.trim().is_empty() && !inbound.key_file.trim().is_empty() {
        settings.insert(
            "certificates".to_string(),
            json!([{
                "certificateFile": &inbound.cert_file,
                "keyFile": &inbound.key_file
            }]),
        );
    }

    Value::Object(settings)
}

fn render_xray_reality_settings(inbound: &InboundPlan) -> Value {
    let mut settings = Map::new();
    if !inbound.reality_dest.trim().is_empty() {
        settings.insert("dest".to_string(), json!(&inbound.reality_dest));
    }
    if !inbound.server_name.trim().is_empty() {
        settings.insert("serverNames".to_string(), json!([&inbound.server_name]));
    }
    if !inbound.reality_private_key.trim().is_empty() {
        settings.insert(
            "privateKey".to_string(),
            json!(&inbound.reality_private_key),
        );
    }
    if !inbound.reality_short_id.trim().is_empty() {
        settings.insert("shortIds".to_string(), json!([&inbound.reality_short_id]));
    }

    Value::Object(settings)
}

fn replace_file(from: &Path, to: &Path) -> Result<(), std::io::Error> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(err) if cfg!(windows) && to.exists() => {
            fs::remove_file(to)?;
            fs::rename(from, to).map_err(|_| err)
        }
        Err(err) => Err(err),
    }
}

fn cert_file(cert: &CertInfo) -> String {
    cert.cert_file.clone()
}

fn key_file(cert: &CertInfo) -> String {
    cert.key_file.clone()
}

fn cert_domain(cert: &CertInfo) -> String {
    cert.cert_domain.clone()
}

fn first_non_empty(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn inbound_user_plan(user: &UserInfo) -> InboundUserPlan {
    InboundUserPlan {
        id: user.id,
        uuid: user.uuid.trim().to_string(),
        email: format!("user-{}", user.id),
        speed_limit: user.speed_limit,
        device_limit: user.device_limit,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::{
        build_inbound_plan, core_file_layout, render_core_config, resolve_node_listen_ip,
        should_fallback_node_listen_ip, write_core_config, CoreKind, CorePlan,
    };
    use crate::panel::types::{CommonNode, NodeInfo, Security, UserInfo};

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

    #[test]
    fn core_file_layout_tracks_config_dir_and_temp_file() {
        let layout = core_file_layout("/srv/v2node/config.json");

        assert_eq!(layout.config_dir, PathBuf::from("/srv/v2node"));
        assert_eq!(layout.temp_config_path, PathBuf::from("/srv/v2node/config.json.tmp"));
    }

    #[test]
    fn renders_xray_config_with_tls_certificate_metadata() {
        let mut node = test_node("vless", 9, "0.0.0.0");
        node.common.tls = 1;
        node.security = Security::Tls;
        node.common.tls_settings.server_name = "node.example.test".to_string();
        node.common.tls_settings.cert_file = "/srv/v2node/node.cer".to_string();
        node.common.tls_settings.key_file = "/srv/v2node/node.key".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "node.example.test".to_string();
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/node.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/node.key".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["listen"], "::");
        assert_eq!(config["inbounds"][0]["streamSettings"]["security"], "tls");
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]
                ["certificateFile"],
            "/srv/v2node/node.cer"
        );
    }

    #[test]
    fn renders_xray_clients_from_users_by_node_id() {
        let node = test_node("vless", 9, "0.0.0.0");
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            9,
            vec![UserInfo {
                id: 12,
                uuid: "11111111-1111-1111-1111-111111111111".to_string(),
                speed_limit: 0,
                device_limit: 2,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["settings"]["clients"][0]["id"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["clients"][0]["email"],
            "user-12"
        );
    }

    #[test]
    fn renders_password_based_clients_for_trojan() {
        let node = test_node("trojan", 3, "");
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            3,
            vec![UserInfo {
                id: 5,
                uuid: "password-value".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["settings"]["clients"][0]["password"],
            "password-value"
        );
    }

    #[test]
    fn writes_core_config_atomically_and_detects_unchanged_content() {
        let dir = temp_test_dir("core-config-write");
        let path = dir.join("runtime").join("config.json");
        let node = test_node("vless", 10, "");
        let plan = CorePlan::from_nodes(CoreKind::Xray, path.clone(), &[node]).unwrap();

        let first = write_core_config(&plan).unwrap();
        let second = write_core_config(&plan).unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(first.inbound_count, 1);
        assert!(saved.contains("\"inbounds\""));
        assert!(!path.with_extension("json.tmp").exists());

        let _ = fs::remove_dir_all(dir);
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

    fn temp_test_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("kelinode-rs-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
