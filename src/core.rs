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
    pub network_settings: Value,
    pub flow: String,
    pub cipher: String,
    pub server_key: String,
    pub vless_decryption: String,
    pub padding_scheme: Vec<String>,
    pub congestion_control: String,
    pub zero_rtt_handshake: bool,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub obfs: String,
    pub obfs_password: String,
    pub ignore_client_bandwidth: bool,
    pub alpn: Vec<String>,
    pub fallback_to_ipv4: bool,
    pub cert_file: String,
    pub key_file: String,
    pub server_name: String,
    pub reality_dest: String,
    pub reality_private_key: String,
    pub reality_short_id: String,
    pub users: Vec<InboundUserPlan>,
    pub routes: Vec<RoutePlan>,
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
pub struct RoutePlan {
    pub id: u32,
    pub action: String,
    pub match_rules: Vec<String>,
    pub action_value: Option<String>,
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
        users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
    ) -> Result<Self, CoreError> {
        let inbounds = nodes
            .iter()
            .map(|node| {
                let users = users_by_node_tag
                    .get(&node.tag)
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
        network_settings: node.common.network_settings.clone(),
        flow: node.common.flow.trim().to_string(),
        cipher: node.common.cipher.trim().to_string(),
        server_key: node.common.server_key.trim().to_string(),
        vless_decryption: resolve_vless_decryption(node)?,
        padding_scheme: node
            .common
            .padding_scheme
            .iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect(),
        congestion_control: node.common.congestion_control.trim().to_string(),
        zero_rtt_handshake: node.common.zero_rtt_handshake,
        up_mbps: node.common.up_mbps,
        down_mbps: node.common.down_mbps,
        obfs: node.common.obfs.trim().to_string(),
        obfs_password: node.common.obfs_password.trim().to_string(),
        ignore_client_bandwidth: node.common.ignore_client_bandwidth,
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
            .map(|user| inbound_user_plan(&node.tag, user))
            .collect(),
        routes: node
            .common
            .routes
            .iter()
            .map(route_plan)
            .filter(|route| !route.action.is_empty())
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

fn resolve_vless_decryption(node: &NodeInfo) -> Result<String, CoreError> {
    if node.protocol != Protocol::Vless {
        return Ok(String::new());
    }

    let encryption = node.common.encryption.trim();
    if encryption.is_empty() {
        return Ok("none".to_string());
    }

    match encryption {
        "mlkem768x25519plus" => {
            let settings = &node.common.encryption_settings;
            let mut parts = vec![
                encryption.to_string(),
                settings.mode.trim().to_string(),
                settings.ticket.trim().to_string(),
            ];
            if !settings.server_padding.trim().is_empty() {
                parts.push(settings.server_padding.trim().to_string());
            }
            parts.push(settings.private_key.trim().to_string());
            Ok(parts.join("."))
        }
        _ => Err(CoreError::new(format!(
            "vless decryption method {encryption} is not support"
        ))),
    }
}

fn render_xray_config(plan: &CorePlan) -> Value {
    let inbounds = plan
        .inbounds
        .iter()
        .map(render_xray_inbound)
        .collect::<Vec<_>>();

    let mut config = Map::new();
    config.insert(
        "log".to_string(),
        json!({
            "loglevel": "warning"
        }),
    );
    config.insert("inbounds".to_string(), Value::Array(inbounds));
    config.insert(
        "outbounds".to_string(),
        Value::Array(render_xray_outbounds(plan)),
    );
    config.insert("routing".to_string(), render_xray_routing(plan));
    if let Some(dns) = render_xray_dns(plan) {
        config.insert("dns".to_string(), dns);
    }

    Value::Object(config)
}

fn render_xray_outbounds(plan: &CorePlan) -> Vec<Value> {
    let mut outbounds = vec![
        json!({
            "tag": "direct",
            "protocol": "freedom"
        }),
        json!({
            "tag": "block",
            "protocol": "blackhole"
        }),
        json!({
            "tag": "dns_out",
            "protocol": "dns"
        }),
    ];

    for inbound in &plan.inbounds {
        for route in &inbound.routes {
            if !matches!(
                route.action.as_str(),
                "route" | "route_ip" | "default_out"
            ) {
                continue;
            }
            let Some((tag, outbound)) = parse_route_outbound(route) else {
                continue;
            };
            if outbounds
                .iter()
                .any(|item| item.get("tag").and_then(Value::as_str) == Some(tag.as_str()))
            {
                continue;
            }
            outbounds.push(outbound);
        }
    }

    outbounds
}

fn render_xray_routing(plan: &CorePlan) -> Value {
    let mut rules = vec![json!({
        "port": "53",
        "network": "udp",
        "outboundTag": "dns_out"
    })];

    for inbound in &plan.inbounds {
        for route in &inbound.routes {
            if let Some(rule) = render_xray_route_rule(&inbound.tag, route) {
                rules.push(rule);
            }
        }
    }

    json!({
        "domainStrategy": "AsIs",
        "rules": rules
    })
}

fn render_xray_route_rule(inbound_tag: &str, route: &RoutePlan) -> Option<Value> {
    if route.match_rules.is_empty() && route.action != "default_out" {
        return None;
    }

    match route.action.as_str() {
        "block" => Some(json!({
            "inboundTag": inbound_tag,
            "domain": &route.match_rules,
            "outboundTag": "block"
        })),
        "block_ip" => Some(json!({
            "inboundTag": inbound_tag,
            "ip": &route.match_rules,
            "outboundTag": "block"
        })),
        "block_port" => Some(json!({
            "inboundTag": inbound_tag,
            "port": route.match_rules.join(","),
            "outboundTag": "block"
        })),
        "protocol" => Some(json!({
            "inboundTag": inbound_tag,
            "protocol": &route.match_rules,
            "outboundTag": "block"
        })),
        "route" => route_outbound_tag(route).map(|tag| {
            json!({
                "inboundTag": inbound_tag,
                "domain": &route.match_rules,
                "outboundTag": tag
            })
        }),
        "route_ip" => route_outbound_tag(route).map(|tag| {
            json!({
                "inboundTag": inbound_tag,
                "ip": &route.match_rules,
                "outboundTag": tag
            })
        }),
        "default_out" => route_outbound_tag(route).map(|tag| {
            json!({
                "inboundTag": inbound_tag,
                "network": "tcp,udp",
                "outboundTag": tag
            })
        }),
        _ => None,
    }
}

fn render_xray_dns(plan: &CorePlan) -> Option<Value> {
    let mut servers = Vec::new();
    for inbound in &plan.inbounds {
        for route in &inbound.routes {
            if route.action != "dns" {
                continue;
            }
            let Some(address) = route.action_value.as_deref().map(str::trim) else {
                continue;
            };
            if address.is_empty() {
                continue;
            }
            let mut server = Map::new();
            server.insert("address".to_string(), json!(address));
            if !route.match_rules.is_empty() {
                server.insert("domains".to_string(), json!(&route.match_rules));
            }
            servers.push(Value::Object(server));
        }
    }

    if servers.is_empty() {
        None
    } else {
        Some(json!({
            "servers": servers
        }))
    }
}

fn route_outbound_tag(route: &RoutePlan) -> Option<String> {
    parse_route_outbound(route).map(|(tag, _)| tag)
}

fn parse_route_outbound(route: &RoutePlan) -> Option<(String, Value)> {
    let raw = route.action_value.as_deref()?.trim();
    if raw.is_empty() {
        return None;
    }
    let outbound: Value = serde_json::from_str(raw).ok()?;
    let tag = outbound.get("tag").and_then(Value::as_str)?.trim();
    if tag.is_empty() {
        return None;
    }
    Some((tag.to_string(), outbound))
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
            "decryption": render_vless_decryption(inbound)
        }),
        "vmess" | "trojan" => json!({
            "clients": clients
        }),
        "shadowsocks" => render_xray_shadowsocks_settings(inbound, clients),
        "socks" => render_xray_socks_settings(inbound),
        "http" => render_xray_http_settings(inbound),
        "anytls" => render_xray_anytls_settings(inbound, clients),
        "hysteria" => render_xray_hysteria_settings(clients),
        "tuic" => render_xray_tuic_settings(inbound, clients),
        _ => json!({}),
    }
}

fn render_vless_decryption(inbound: &InboundPlan) -> &str {
    if inbound.vless_decryption.trim().is_empty() {
        "none"
    } else {
        inbound.vless_decryption.as_str()
    }
}

fn render_xray_clients(inbound: &InboundPlan) -> Vec<Value> {
    inbound
        .users
        .iter()
        .map(|user| match inbound.protocol.as_str() {
            "shadowsocks" => render_xray_shadowsocks_client(inbound, user),
            "trojan" | "hysteria" | "tuic" | "anytls" => json!({
                "password": &user.uuid,
                "email": &user.email
            }),
            "vmess" => json!({
                "id": &user.uuid,
                "email": &user.email,
                "alterId": 0
            }),
            "vless" => render_xray_vless_client(inbound, user),
            _ => render_xray_id_client(user),
        })
        .collect()
}

fn render_xray_vless_client(inbound: &InboundPlan, user: &InboundUserPlan) -> Value {
    let mut client = Map::new();
    client.insert("id".to_string(), json!(&user.uuid));
    client.insert("email".to_string(), json!(&user.email));
    if !inbound.flow.trim().is_empty() {
        client.insert("flow".to_string(), json!(&inbound.flow));
    }
    Value::Object(client)
}

fn render_xray_id_client(user: &InboundUserPlan) -> Value {
    json!({
        "id": &user.uuid,
        "email": &user.email
    })
}

fn render_xray_shadowsocks_client(inbound: &InboundPlan, user: &InboundUserPlan) -> Value {
    let mut client = Map::new();
    if inbound.server_key.trim().is_empty() {
        client.insert("password".to_string(), json!(&user.uuid));
        if !inbound.cipher.trim().is_empty() {
            client.insert("method".to_string(), json!(&inbound.cipher));
        }
    } else {
        client.insert(
            "password".to_string(),
            json!(shadowsocks_2022_user_key(&user.uuid, &inbound.cipher)),
        );
    }
    client.insert("email".to_string(), json!(&user.email));
    Value::Object(client)
}

fn render_xray_shadowsocks_settings(inbound: &InboundPlan, clients: Vec<Value>) -> Value {
    let mut settings = Map::new();
    settings.insert("clients".to_string(), Value::Array(clients));
    settings.insert("network".to_string(), json!("tcp,udp"));
    if !inbound.cipher.trim().is_empty() {
        settings.insert("method".to_string(), json!(&inbound.cipher));
    }
    if !inbound.server_key.trim().is_empty() {
        settings.insert("password".to_string(), json!(&inbound.server_key));
    }
    Value::Object(settings)
}

fn shadowsocks_2022_user_key(uuid: &str, cipher: &str) -> String {
    let key_length = match cipher.trim() {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => 0,
    };
    let bytes = uuid.as_bytes();
    base64_standard_encode(&bytes[..bytes.len().min(key_length)])
}

fn base64_standard_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(((bytes.len() + 2) / 3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        output.push(TABLE[(b0 >> 2) as usize] as char);
        output.push(TABLE[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn render_xray_socks_settings(inbound: &InboundPlan) -> Value {
    let accounts = inbound
        .users
        .iter()
        .map(|user| {
            json!({
                "user": &user.uuid,
                "pass": &user.uuid
            })
        })
        .collect::<Vec<_>>();

    json!({
        "auth": "password",
        "accounts": accounts,
        "udp": true
    })
}

fn render_xray_http_settings(inbound: &InboundPlan) -> Value {
    let accounts = inbound
        .users
        .iter()
        .map(|user| {
            json!({
                "user": &user.uuid,
                "pass": &user.uuid
            })
        })
        .collect::<Vec<_>>();

    json!({
        "accounts": accounts
    })
}

fn render_xray_anytls_settings(inbound: &InboundPlan, clients: Vec<Value>) -> Value {
    let mut settings = Map::new();
    settings.insert("clients".to_string(), Value::Array(clients));
    if !inbound.padding_scheme.is_empty() {
        settings.insert("paddingScheme".to_string(), json!(&inbound.padding_scheme));
    }
    Value::Object(settings)
}

fn render_xray_hysteria_settings(clients: Vec<Value>) -> Value {
    json!({
        "version": 2,
        "clients": clients
    })
}

fn render_xray_tuic_settings(inbound: &InboundPlan, clients: Vec<Value>) -> Value {
    let mut settings = Map::new();
    settings.insert("clients".to_string(), Value::Array(clients));
    if !inbound.congestion_control.trim().is_empty() {
        settings.insert(
            "congestionControl".to_string(),
            json!(&inbound.congestion_control),
        );
    }
    if inbound.zero_rtt_handshake {
        settings.insert("zeroRttHandshake".to_string(), json!(true));
    }
    Value::Object(settings)
}

fn render_xray_stream_settings(inbound: &InboundPlan) -> Map<String, Value> {
    let mut stream = Map::new();
    if !inbound.network.trim().is_empty() {
        stream.insert("network".to_string(), json!(&inbound.network));
        if let Some((key, value)) =
            render_xray_network_settings(&inbound.network, &inbound.network_settings)
        {
            stream.insert(key.to_string(), value);
        }
    }
    if accepts_proxy_protocol(&inbound.network_settings) {
        stream.insert(
            "sockopt".to_string(),
            json!({
                "acceptProxyProtocol": true
            }),
        );
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
    if inbound.protocol == "hysteria" {
        stream.insert(
            "hysteriaSettings".to_string(),
            render_xray_hysteria_stream_settings(inbound),
        );
    }

    stream
}

fn render_xray_hysteria_stream_settings(inbound: &InboundPlan) -> Value {
    let mut settings = Map::new();
    settings.insert("version".to_string(), json!(2));

    let mut final_mask = Map::new();
    if !inbound.ignore_client_bandwidth && (inbound.up_mbps > 0 || inbound.down_mbps > 0) {
        final_mask.insert(
            "quicParams".to_string(),
            json!({
                "congestion": "force-brutal",
                "brutalUp": format!("{}mbps", inbound.up_mbps),
                "brutalDown": format!("{}mbps", inbound.down_mbps)
            }),
        );
    }
    if !inbound.obfs.is_empty() && !inbound.obfs_password.is_empty() {
        final_mask.insert(
            "udp".to_string(),
            json!([
                {
                    "type": &inbound.obfs,
                    "settings": {
                        "password": &inbound.obfs_password
                    }
                }
            ]),
        );
    }
    if !final_mask.is_empty() {
        settings.insert("finalMask".to_string(), Value::Object(final_mask));
    }

    Value::Object(settings)
}

fn render_xray_network_settings(
    network: &str,
    settings: &Value,
) -> Option<(&'static str, Value)> {
    if settings.is_null() || settings.as_object().map(|value| value.is_empty()).unwrap_or(false) {
        return None;
    }

    let key = match network.trim().to_ascii_lowercase().as_str() {
        "tcp" => "tcpSettings",
        "kcp" => "kcpSettings",
        "ws" | "websocket" => "wsSettings",
        "http" | "h2" => "httpSettings",
        "quic" => "quicSettings",
        "grpc" => "grpcSettings",
        "httpupgrade" => "httpupgradeSettings",
        "xhttp" => "xhttpSettings",
        _ => return None,
    };
    Some((key, settings.clone()))
}

fn accepts_proxy_protocol(settings: &Value) -> bool {
    settings
        .get("acceptProxyProtocol")
        .and_then(Value::as_bool)
        .unwrap_or(false)
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

fn inbound_user_plan(tag: &str, user: &UserInfo) -> InboundUserPlan {
    let uuid = user.uuid.trim().to_string();
    InboundUserPlan {
        id: user.id,
        email: user_tag(tag, &uuid),
        uuid,
        speed_limit: user.speed_limit,
        device_limit: user.device_limit,
    }
}

fn user_tag(tag: &str, uuid: &str) -> String {
    format!("{}|{}", tag, uuid)
}

fn route_plan(route: &crate::panel::types::Route) -> RoutePlan {
    RoutePlan {
        id: route.id,
        action: route.action.trim().to_string(),
        match_rules: route
            .match_rules
            .iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect(),
        action_value: route.action_value.as_ref().and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }),
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
    use crate::panel::types::{CommonNode, NodeInfo, Route, Security, UserInfo};

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
    fn renders_xray_clients_from_users_by_node_tag() {
        let node = test_node("vless", 9, "0.0.0.0");
        let tag = node.tag.clone();
        let uuid = "11111111-1111-1111-1111-111111111111";
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag.clone(),
            vec![UserInfo {
                id: 12,
                uuid: uuid.to_string(),
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
            format!("{}|{}", tag, uuid)
        );
    }

    #[test]
    fn renders_vless_flow_for_users() {
        let mut node = test_node("vless", 13, "");
        node.common.flow = "xtls-rprx-vision".to_string();
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 13,
                uuid: "22222222-2222-2222-2222-222222222222".to_string(),
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
            config["inbounds"][0]["settings"]["clients"][0]["flow"],
            "xtls-rprx-vision"
        );
    }

    #[test]
    fn renders_supported_vless_encryption_decryption() {
        let mut node = test_node("vless", 15, "");
        node.common.encryption = "mlkem768x25519plus".to_string();
        node.common.encryption_settings.mode = "0rtt".to_string();
        node.common.encryption_settings.ticket = "ticket-value".to_string();
        node.common.encryption_settings.server_padding = "padding".to_string();
        node.common.encryption_settings.private_key = "private-key".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["settings"]["decryption"],
            "mlkem768x25519plus.0rtt.ticket-value.padding.private-key"
        );
    }

    #[test]
    fn rejects_unsupported_vless_encryption() {
        let mut node = test_node("vless", 16, "");
        node.common.encryption = "unsupported".to_string();

        let err = build_inbound_plan(&node).unwrap_err();

        assert!(err
            .message
            .contains("vless decryption method unsupported is not support"));
    }

    #[test]
    fn renders_password_based_clients_for_trojan() {
        let node = test_node("trojan", 3, "");
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
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
    fn renders_shadowsocks_cipher_method() {
        let mut node = test_node("shadowsocks", 14, "");
        node.common.cipher = "aes-128-gcm".to_string();
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 14,
                uuid: "ss-password".to_string(),
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
            config["inbounds"][0]["settings"]["method"],
            "aes-128-gcm"
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["clients"][0]["method"],
            "aes-128-gcm"
        );
    }

    #[test]
    fn renders_shadowsocks_2022_server_key_and_user_key() {
        let mut node = test_node("shadowsocks", 25, "");
        node.common.cipher = "2022-blake3-aes-128-gcm".to_string();
        node.common.server_key = "server-secret".to_string();
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 25,
                uuid: "0123456789abcdef0123456789abcdef".to_string(),
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
            config["inbounds"][0]["settings"]["method"],
            "2022-blake3-aes-128-gcm"
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["password"],
            "server-secret"
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["clients"][0]["password"],
            "MDEyMzQ1Njc4OWFiY2RlZg=="
        );
        assert!(config["inbounds"][0]["settings"]["clients"][0]["method"].is_null());
    }

    #[test]
    fn renders_socks_accounts_from_users() {
        let node = test_node("socks", 20, "");
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 20,
                uuid: "socks-secret".to_string(),
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

        assert_eq!(config["inbounds"][0]["settings"]["auth"], "password");
        assert_eq!(
            config["inbounds"][0]["settings"]["accounts"][0]["user"],
            "socks-secret"
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["accounts"][0]["pass"],
            "socks-secret"
        );
        assert_eq!(config["inbounds"][0]["settings"]["udp"], true);
    }

    #[test]
    fn renders_http_accounts_from_users() {
        let node = test_node("http", 21, "");
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 21,
                uuid: "http-secret".to_string(),
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
            config["inbounds"][0]["settings"]["accounts"][0]["user"],
            "http-secret"
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["accounts"][0]["pass"],
            "http-secret"
        );
    }

    #[test]
    fn renders_anytls_padding_and_clients() {
        let mut node = test_node("anytls", 22, "");
        node.common.padding_scheme = vec!["stop=8".to_string(), " ".to_string()];
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 22,
                uuid: "anytls-password".to_string(),
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
            "anytls-password"
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["paddingScheme"][0],
            "stop=8"
        );
    }

    #[test]
    fn renders_hysteria2_bandwidth_and_obfs_settings() {
        let mut node = test_node("hysteria2", 23, "");
        node.common.up_mbps = 100;
        node.common.down_mbps = 200;
        node.common.obfs = "salamander".to_string();
        node.common.obfs_password = "obfs-secret".to_string();
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 23,
                uuid: "hy2-password".to_string(),
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

        assert_eq!(config["inbounds"][0]["settings"]["version"], 2);
        assert_eq!(
            config["inbounds"][0]["settings"]["clients"][0]["password"],
            "hy2-password"
        );
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["hysteriaSettings"]["finalMask"]
                ["quicParams"]["brutalUp"],
            "100mbps"
        );
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["hysteriaSettings"]["finalMask"]["udp"]
                [0]["settings"]["password"],
            "obfs-secret"
        );
    }

    #[test]
    fn renders_tuic_congestion_and_zero_rtt_settings() {
        let mut node = test_node("tuic", 24, "");
        node.common.congestion_control = "bbr".to_string();
        node.common.zero_rtt_handshake = true;
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 24,
                uuid: "tuic-password".to_string(),
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
            config["inbounds"][0]["settings"]["congestionControl"],
            "bbr"
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["zeroRttHandshake"],
            true
        );
        assert_eq!(
            config["inbounds"][0]["settings"]["clients"][0]["password"],
            "tuic-password"
        );
    }

    #[test]
    fn renders_stream_network_settings_for_websocket() {
        let mut node = test_node("vless", 11, "");
        node.common.network = "ws".to_string();
        node.common.network_settings = json!({
            "path": "/ws",
            "headers": {
                "Host": "node.example.test"
            }
        });
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["streamSettings"]["wsSettings"]["path"],
            "/ws"
        );
    }

    #[test]
    fn renders_proxy_protocol_socket_option() {
        let mut node = test_node("vless", 26, "");
        node.common.network = "ws".to_string();
        node.common.network_settings = json!({
            "path": "/ws",
            "acceptProxyProtocol": true
        });
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["streamSettings"]["sockopt"]["acceptProxyProtocol"],
            true
        );
    }

    #[test]
    fn renders_block_route_rules() {
        let mut node = test_node("vless", 17, "");
        node.common.routes = vec![Route {
            id: 1,
            action: "block".to_string(),
            match_rules: vec!["domain:example.com".to_string()],
            action_value: None,
        }];
        let tag = node.tag.clone();
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "block");
        assert_eq!(config["routing"]["rules"][1]["inboundTag"], tag);
        assert_eq!(
            config["routing"]["rules"][1]["domain"][0],
            "domain:example.com"
        );
        assert_eq!(config["routing"]["rules"][1]["outboundTag"], "block");
    }

    #[test]
    fn renders_custom_route_outbound_once() {
        let mut node = test_node("vless", 18, "");
        node.common.routes = vec![
            Route {
                id: 1,
                action: "default_out".to_string(),
                match_rules: Vec::new(),
                action_value: Some(r#"{"tag":"warp","protocol":"freedom"}"#.to_string()),
            },
            Route {
                id: 2,
                action: "route_ip".to_string(),
                match_rules: vec!["geoip:private".to_string()],
                action_value: Some(r#"{"tag":"warp","protocol":"freedom"}"#.to_string()),
            },
        ];
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        assert_eq!(
            outbounds
                .iter()
                .filter(|outbound| outbound["tag"] == "warp")
                .count(),
            1
        );
        assert_eq!(config["routing"]["rules"][1]["outboundTag"], "warp");
        assert_eq!(config["routing"]["rules"][2]["ip"][0], "geoip:private");
    }

    #[test]
    fn renders_dns_route_servers() {
        let mut node = test_node("vless", 19, "");
        node.common.routes = vec![Route {
            id: 1,
            action: "dns".to_string(),
            match_rules: vec!["geosite:openai".to_string()],
            action_value: Some("1.1.1.1".to_string()),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["dns"]["servers"][0]["address"], "1.1.1.1");
        assert_eq!(
            config["dns"]["servers"][0]["domains"][0],
            "geosite:openai"
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
