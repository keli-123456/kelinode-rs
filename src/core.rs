use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::panel::types::{CertInfo, NodeInfo, Protocol, Security, TlsSettings, UserInfo};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreKind {
    Xray,
    SingBox,
    Mihomo,
    KeliCoreRs,
    Sidecar(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorePlan {
    pub kind: CoreKind,
    pub config_path: PathBuf,
    pub listen_tags: Vec<String>,
    pub inbounds: Vec<InboundPlan>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CorePlanBundle {
    pub xray: Option<CorePlan>,
    pub sidecars: Vec<CorePlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundPlan {
    pub tag: String,
    pub protocol: String,
    pub listen: String,
    pub port: u16,
    pub port_range: String,
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
    pub reject_unknown_sni: bool,
    pub server_name: String,
    pub reality_dest: String,
    pub reality_xver: u64,
    pub reality_private_key: String,
    pub reality_short_id: String,
    pub reality_mldsa65_seed: String,
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
        reject_sidecar_protocols_for_core(&kind, nodes)?;
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

pub fn core_kind_from_name(value: &str) -> Result<CoreKind, CoreError> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "" | "xray" => Ok(CoreKind::Xray),
        "sing-box" | "singbox" => Ok(CoreKind::SingBox),
        "mihomo" | "clash-meta" => Ok(CoreKind::Mihomo),
        "keli-core-rs" | "kelicore-rs" | "kelicorers" => Ok(CoreKind::KeliCoreRs),
        other => Err(CoreError::new(format!("unsupported core type {other}"))),
    }
}

pub fn split_core_plans_for_nodes(
    config_path: PathBuf,
    nodes: &[NodeInfo],
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
) -> Result<CorePlanBundle, CoreError> {
    split_core_plans_for_nodes_with_kind(
        CoreKind::Xray,
        config_path,
        nodes,
        users_by_node_tag,
    )
}

pub fn split_core_plans_for_nodes_with_kind(
    core_kind: CoreKind,
    config_path: PathBuf,
    nodes: &[NodeInfo],
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
) -> Result<CorePlanBundle, CoreError> {
    let core_nodes = nodes
        .iter()
        .filter(|node| sidecar_protocol_name(node.protocol).is_none())
        .cloned()
        .collect::<Vec<_>>();
    let xray = if core_nodes.is_empty() {
        None
    } else {
        Some(CorePlan::from_nodes_with_users(
            core_kind,
            config_path.clone(),
            &core_nodes,
            users_by_node_tag,
        )?)
    };

    let mut sidecars = Vec::new();
    for node in nodes {
        let Some(protocol) = sidecar_protocol_name(node.protocol) else {
            continue;
        };
        sidecars.push(CorePlan::from_nodes_with_users(
            CoreKind::Sidecar(protocol.to_string()),
            sidecar_config_path(&config_path, protocol, node.id),
            std::slice::from_ref(node),
            users_by_node_tag,
        )?);
    }

    Ok(CorePlanBundle { xray, sidecars })
}

pub fn sidecar_protocol_name(protocol: Protocol) -> Option<&'static str> {
    match protocol {
        Protocol::Naive => Some("naive"),
        Protocol::Mieru => Some("mieru"),
        _ => None,
    }
}

pub fn sidecar_config_path(
    base_config_path: impl AsRef<Path>,
    protocol: &str,
    node_id: u32,
) -> PathBuf {
    let base = base_config_path.as_ref();
    let dir = base.parent().unwrap_or_else(|| Path::new("."));
    let extension = if protocol == "naive" { "Caddyfile" } else { "json" };
    dir.join(format!("sidecar-{protocol}-{node_id}.{extension}"))
}

fn reject_sidecar_protocols_for_core(
    kind: &CoreKind,
    nodes: &[NodeInfo],
) -> Result<(), CoreError> {
    if !matches!(kind, CoreKind::Xray) {
        return Ok(());
    }
    let Some((node, protocol)) = nodes
        .iter()
        .find_map(|node| sidecar_protocol_name(node.protocol).map(|protocol| (node, protocol)))
    else {
        return Ok(());
    };
    Err(CoreError::new(format!(
        "protocol {protocol} for node {} requires a sidecar runtime and cannot be rendered into Xray",
        node.tag
    )))
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
        CoreKind::KeliCoreRs => render_keli_core_rs_config(plan),
        CoreKind::SingBox => Err(CoreError::new(
            "sing-box core config rendering is not implemented yet",
        )),
        CoreKind::Mihomo => Err(CoreError::new(
            "mihomo core config rendering is not implemented yet",
        )),
        CoreKind::Sidecar(name) => render_sidecar_config(plan, name),
    }
}

fn render_sidecar_config(plan: &CorePlan, name: &str) -> Result<Value, CoreError> {
    match name {
        "mieru" => render_mieru_sidecar_config(plan),
        "naive" => Ok(Value::String(render_naive_sidecar_config(plan)?)),
        value => Err(CoreError::new(format!(
            "sidecar core config rendering is not implemented for {value}",
        ))),
    }
}

fn render_naive_sidecar_config(plan: &CorePlan) -> Result<String, CoreError> {
    if plan.inbounds.len() != 1 {
        return Err(CoreError::new(
            "naive sidecar config must contain exactly one inbound",
        ));
    }
    let inbound = &plan.inbounds[0];
    if inbound.protocol != "naive" {
        return Err(CoreError::new(format!(
            "naive sidecar cannot render protocol {}",
            inbound.protocol
        )));
    }

    let listen = naive_caddy_listen(inbound);
    let server_name = inbound.server_name.trim();
    let site = if server_name.is_empty() {
        listen
    } else {
        format!("{listen}, {server_name}")
    };
    let tls = if !inbound.cert_file.trim().is_empty() && !inbound.key_file.trim().is_empty() {
        format!(
            "    tls {} {}\n",
            caddy_token(&inbound.cert_file),
            caddy_token(&inbound.key_file)
        )
    } else {
        String::new()
    };
    let users = inbound
        .users
        .iter()
        .map(|user| {
            format!(
                "            basic_auth {} {}\n",
                caddy_token(&user.uuid),
                caddy_token(&user.uuid)
            )
        })
        .collect::<String>();

    Ok(format!(
        "{{\n    order forward_proxy first\n}}\n\n{} {{\n{}    route {{\n        forward_proxy {{\n{}            hide_ip\n            hide_via\n        }}\n        respond \"OK\" 200\n    }}\n}}\n",
        site, tls, users
    ))
}

fn render_mieru_sidecar_config(plan: &CorePlan) -> Result<Value, CoreError> {
    let mut port_bindings = Vec::new();
    let mut users = Vec::new();

    for inbound in &plan.inbounds {
        if inbound.protocol != "mieru" {
            return Err(CoreError::new(format!(
                "mieru sidecar cannot render protocol {}",
                inbound.protocol
            )));
        }

        let mut binding = Map::new();
        if inbound.port_range.is_empty() {
            binding.insert("port".to_string(), json!(inbound.port));
        } else {
            binding.insert("portRange".to_string(), json!(&inbound.port_range));
        }
        binding.insert(
            "protocol".to_string(),
            json!(resolve_mieru_transport(&inbound.network)?),
        );
        port_bindings.push(Value::Object(binding));

        for user in &inbound.users {
            let credential = user.uuid.trim();
            if credential.is_empty() {
                continue;
            }
            users.push(json!({
                "name": credential,
                "password": credential
            }));
        }
    }

    Ok(json!({
        "portBindings": port_bindings,
        "users": users,
        "loggingLevel": "INFO",
        "mtu": 1400
    }))
}

fn render_keli_core_rs_config(plan: &CorePlan) -> Result<Value, CoreError> {
    let mut routes = Vec::new();
    for inbound in &plan.inbounds {
        validate_keli_core_rs_inbound(inbound)?;

        for route in &inbound.routes {
            if route.match_rules.is_empty() {
                continue;
            }
            match route.action.as_str() {
                "block" => routes.push(json!({
                    "targets": &route.match_rules,
                    "action": "block"
                })),
                value => {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route action {value} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            }
        }
    }

    Ok(json!({
        "instance_id": keli_core_rs_instance_id(plan),
        "log_level": "info",
        "inbounds": plan
            .inbounds
            .iter()
            .map(render_keli_core_rs_inbound)
            .collect::<Vec<_>>(),
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "address": null,
                "port": null
            }
        ],
        "routes": routes,
        "stats": {
            "enabled": true,
            "per_user": true
        }
    }))
}

fn validate_keli_core_rs_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    match inbound.protocol.as_str() {
        "socks" | "http" => Ok(()),
        "shadowsocks" => {
            validate_keli_core_rs_plain_tcp_inbound(inbound)?;
            if !is_keli_core_rs_shadowsocks_cipher(&inbound.cipher) {
                return Err(CoreError::new(format!(
                    "keli-core-rs shadowsocks cipher {} on inbound {} is not supported yet",
                    inbound.cipher, inbound.tag
                )));
            }
            Ok(())
        }
        "anytls" => {
            validate_keli_core_rs_plain_tcp_inbound(inbound)?;
            if !inbound.padding_scheme.is_empty() {
                return Err(CoreError::new(format!(
                    "keli-core-rs anytls currently does not support padding scheme on inbound {}",
                    inbound.tag
                )));
            }
            Ok(())
        }
        "vless" | "trojan" | "vmess" => {
            validate_keli_core_rs_tcp_or_ws_inbound(inbound)?;
            Ok(())
        }
        "tuic" => validate_keli_core_rs_tuic_inbound(inbound),
        "hysteria" => validate_keli_core_rs_hysteria2_inbound(inbound),
        value => Err(CoreError::new(format!(
            "keli-core-rs native renderer only supports socks/http/shadowsocks/vmess/vless/trojan/anytls tcp, vmess/vless/trojan ws, tuic tcp/udp relay, and hysteria2 tcp/udp relay today; inbound {} uses {}",
            inbound.tag, value
        ))),
    }
}

fn validate_keli_core_rs_plain_tcp_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let protocol = inbound.protocol.as_str();
    let network = first_non_empty(inbound.network.trim(), "tcp");
    if network != "tcp" {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only tcp transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if inbound.security != "none" {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only security none; inbound {} uses {}",
            inbound.tag, inbound.security
        )));
    }
    if !inbound.flow.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently does not support flow {}; inbound {}",
            inbound.flow, inbound.tag
        )));
    }
    if !json_value_is_empty(&inbound.network_settings) {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently does not support transport settings on inbound {}",
            inbound.tag
        )));
    }
    Ok(())
}

fn validate_keli_core_rs_tcp_or_ws_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let protocol = inbound.protocol.as_str();
    let network = keli_core_rs_transport_network(inbound);
    if !matches!(network.as_str(), "tcp" | "ws") {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only tcp/ws transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if !matches!(inbound.security.as_str(), "none" | "tls") {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only security none/tls; inbound {} uses {}",
            inbound.tag, inbound.security
        )));
    }
    if inbound.security == "tls" {
        validate_keli_core_rs_tls_inbound(inbound)?;
    }
    if !inbound.flow.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently does not support flow {}; inbound {}",
            inbound.flow, inbound.tag
        )));
    }
    if network == "tcp" {
        if !json_value_is_empty(&inbound.network_settings) {
            return Err(CoreError::new(format!(
                "keli-core-rs {protocol} currently does not support transport settings on tcp inbound {}",
                inbound.tag
            )));
        }
        return Ok(());
    }

    validate_keli_core_rs_websocket_settings(inbound)
}

fn validate_keli_core_rs_tls_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let protocol = inbound.protocol.as_str();
    let network = keli_core_rs_transport_network(inbound);
    if !matches!(network.as_str(), "tcp" | "ws") {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} tls currently supports only tcp/ws transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if inbound.cert_file.trim().is_empty() || inbound.key_file.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} tls requires cert_file and key_file on inbound {}",
            inbound.tag
        )));
    }
    if inbound.reject_unknown_sni {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} reject_unknown_sni is not supported yet on inbound {}",
            inbound.tag
        )));
    }
    Ok(())
}

fn validate_keli_core_rs_tuic_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    if keli_core_rs_transport_network(inbound) != "tuic" {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic currently requires tuic transport; inbound {} uses {}",
            inbound.tag, inbound.network
        )));
    }
    if inbound.security != "tls" {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic currently requires tls security; inbound {} uses {}",
            inbound.tag, inbound.security
        )));
    }
    if inbound.cert_file.trim().is_empty() || inbound.key_file.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic tls requires cert_file and key_file on inbound {}",
            inbound.tag
        )));
    }
    if inbound.reject_unknown_sni {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic reject_unknown_sni is not supported yet on inbound {}",
            inbound.tag
        )));
    }
    if !inbound.flow.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic currently does not support flow {}; inbound {}",
            inbound.flow, inbound.tag
        )));
    }
    if !json_value_is_empty(&inbound.network_settings) {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic currently does not support transport settings on inbound {}",
            inbound.tag
        )));
    }
    if !inbound.congestion_control.trim().is_empty() || inbound.zero_rtt_handshake {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic currently does not support custom congestion or zero-rtt on inbound {}",
            inbound.tag
        )));
    }
    if inbound.users.iter().any(|user| !is_uuid_like(&user.uuid)) {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic currently requires UUID users on inbound {}",
            inbound.tag
        )));
    }
    Ok(())
}

fn validate_keli_core_rs_hysteria2_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let network = keli_core_rs_transport_network(inbound);
    if !matches!(network.as_str(), "hysteria" | "hysteria2") {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 currently requires hysteria transport; inbound {} uses {}",
            inbound.tag, inbound.network
        )));
    }
    if inbound.security != "tls" {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 currently requires tls security; inbound {} uses {}",
            inbound.tag, inbound.security
        )));
    }
    if inbound.cert_file.trim().is_empty() || inbound.key_file.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 tls requires cert_file and key_file on inbound {}",
            inbound.tag
        )));
    }
    if inbound.reject_unknown_sni {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 reject_unknown_sni is not supported yet on inbound {}",
            inbound.tag
        )));
    }
    if !inbound.flow.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 currently does not support flow {}; inbound {}",
            inbound.flow, inbound.tag
        )));
    }
    if !json_value_is_empty(&inbound.network_settings) {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 currently does not support transport settings on inbound {}",
            inbound.tag
        )));
    }
    if !inbound.obfs.trim().is_empty() || !inbound.obfs_password.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 currently does not support obfs on inbound {}",
            inbound.tag
        )));
    }
    Ok(())
}

fn validate_keli_core_rs_websocket_settings(inbound: &InboundPlan) -> Result<(), CoreError> {
    if json_value_is_empty(&inbound.network_settings) {
        return Ok(());
    }
    let Some(settings) = inbound.network_settings.as_object() else {
        return Err(CoreError::new(format!(
            "keli-core-rs websocket settings on inbound {} must be an object",
            inbound.tag
        )));
    };
    for (key, value) in settings {
        match key.as_str() {
            "path" | "Host" | "host" => {
                if !value.is_string() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs websocket setting {key} on inbound {} must be a string",
                        inbound.tag
                    )));
                }
            }
            "headers" => validate_keli_core_rs_websocket_headers(inbound, value)?,
            _ => {
                return Err(CoreError::new(format!(
                    "keli-core-rs websocket setting {key} on inbound {} is not supported yet",
                    inbound.tag
                )));
            }
        }
    }
    Ok(())
}

fn validate_keli_core_rs_websocket_headers(
    inbound: &InboundPlan,
    headers: &Value,
) -> Result<(), CoreError> {
    let Some(headers) = headers.as_object() else {
        return Err(CoreError::new(format!(
            "keli-core-rs websocket headers on inbound {} must be an object",
            inbound.tag
        )));
    };
    for (key, value) in headers {
        if !matches!(key.as_str(), "Host" | "host") {
            return Err(CoreError::new(format!(
                "keli-core-rs websocket header {key} on inbound {} is not supported yet",
                inbound.tag
            )));
        }
        if !value.is_string() {
            return Err(CoreError::new(format!(
                "keli-core-rs websocket header {key} on inbound {} must be a string",
                inbound.tag
            )));
        }
    }
    Ok(())
}

fn json_value_is_empty(value: &Value) -> bool {
    value.is_null()
        || value
            .as_object()
            .map(|object| object.is_empty())
            .unwrap_or(false)
}

fn is_uuid_like(value: &str) -> bool {
    let compact = value
        .trim()
        .chars()
        .filter(|value| *value != '-')
        .collect::<String>();
    compact.len() == 32 && compact.chars().all(|value| value.is_ascii_hexdigit())
}

fn is_keli_core_rs_shadowsocks_cipher(cipher: &str) -> bool {
    matches!(
        cipher.trim().to_ascii_lowercase().replace('_', "-").as_str(),
        "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
    )
}

fn keli_core_rs_instance_id(plan: &CorePlan) -> String {
    plan.config_path
        .file_stem()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("kelinode-rs")
        .to_string()
}

fn render_keli_core_rs_inbound(inbound: &InboundPlan) -> Value {
    json!({
        "tag": &inbound.tag,
        "protocol": keli_core_rs_protocol_name(inbound),
        "listen": &inbound.listen,
        "port": inbound.port,
        "cipher": if inbound.protocol == "shadowsocks" {
            Value::String(inbound.cipher.clone())
        } else {
            Value::Null
        },
        "users": inbound
            .users
            .iter()
            .map(render_keli_core_rs_user)
            .collect::<Vec<_>>(),
        "transport": render_keli_core_rs_transport(inbound),
        "tls": render_keli_core_rs_tls(inbound),
        "sniffing": {
            "enabled": true,
            "dest_override": ["http", "tls"]
        }
    })
}

fn keli_core_rs_protocol_name(inbound: &InboundPlan) -> &str {
    if inbound.protocol == "hysteria" {
        "hysteria2"
    } else {
        &inbound.protocol
    }
}

fn render_keli_core_rs_tls(inbound: &InboundPlan) -> Value {
    if inbound.security != "tls" {
        return Value::Null;
    }
    json!({
        "server_name": &inbound.server_name,
        "cert_file": &inbound.cert_file,
        "key_file": &inbound.key_file,
        "alpn": &inbound.alpn,
        "reject_unknown_sni": inbound.reject_unknown_sni,
        "reality": null
    })
}

fn render_keli_core_rs_transport(inbound: &InboundPlan) -> Value {
    let network = keli_core_rs_transport_network(inbound);
    let mut transport = Map::new();
    transport.insert("network".to_string(), Value::String(network.clone()));
    transport.insert(
        "path".to_string(),
        if network == "ws" {
            websocket_path_setting(&inbound.network_settings)
                .map(Value::String)
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    transport.insert(
        "host".to_string(),
        if network == "ws" {
            websocket_host_setting(&inbound.network_settings)
                .map(Value::String)
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    transport.insert("service_name".to_string(), Value::Null);
    transport.insert("proxy_protocol".to_string(), Value::Bool(false));

    if inbound.protocol == "hysteria" {
        if inbound.ignore_client_bandwidth {
            transport.insert("ignore_client_bandwidth".to_string(), Value::Bool(true));
        } else {
            if inbound.up_mbps > 0 {
                transport.insert("up_mbps".to_string(), json!(inbound.up_mbps));
            }
            if inbound.down_mbps > 0 {
                transport.insert("down_mbps".to_string(), json!(inbound.down_mbps));
            }
        }
    }

    Value::Object(transport)
}

fn keli_core_rs_transport_network(inbound: &InboundPlan) -> String {
    match first_non_empty(inbound.network.trim(), "tcp")
        .to_ascii_lowercase()
        .as_str()
    {
        "websocket" => "ws".to_string(),
        value => value.to_string(),
    }
}

fn websocket_path_setting(settings: &Value) -> Option<String> {
    network_setting_string(settings, &["path"])
}

fn websocket_host_setting(settings: &Value) -> Option<String> {
    network_setting_string(settings, &["Host", "host"]).or_else(|| {
        settings
            .get("headers")
            .and_then(|headers| network_setting_string(headers, &["Host", "host"]))
    })
}

fn render_keli_core_rs_user(user: &InboundUserPlan) -> Value {
    json!({
        "id": user.id,
        "uuid": &user.uuid,
        "password": null,
        "email": &user.email,
        "speed_limit": user.speed_limit,
        "device_limit": user.device_limit
    })
}

pub fn write_core_config(plan: &CorePlan) -> Result<CoreConfigWriteResult, CoreError> {
    if matches!(&plan.kind, CoreKind::Sidecar(name) if name == "naive") {
        let content = render_naive_sidecar_config(plan)?;
        return write_core_config_bytes(&plan.config_path, content.into_bytes(), plan.inbounds.len());
    }
    let value = render_core_config(plan)?;
    write_core_config_value(&plan.config_path, &value, plan.inbounds.len())
}

pub fn write_core_config_value(
    path: impl AsRef<Path>,
    value: &Value,
    inbound_count: usize,
) -> Result<CoreConfigWriteResult, CoreError> {
    let path = path.as_ref();
    let mut content = serde_json::to_vec_pretty(value).map_err(|err| {
        CoreError::new(format!("encode core config {}: {err}", path.display()))
    })?;
    content.push(b'\n');

    write_core_config_bytes(path, content, inbound_count)
}

fn write_core_config_bytes(
    path: impl AsRef<Path>,
    content: Vec<u8>,
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
        port_range: resolve_node_port_range(node),
        security: security_name(node.security),
        network: core_network_name(node)?,
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
        reject_unknown_sni: cert.map(|cert| cert.reject_unknown_sni).unwrap_or(false),
        server_name: cert.map(cert_domain).unwrap_or_else(|| {
            first_non_empty(
                node.common.tls_settings.server_name.trim(),
                node.common.server_name.trim(),
            )
        }),
        reality_dest: resolve_reality_dest(&node.common.tls_settings),
        reality_xver: value_to_u64(&node.common.tls_settings.xver),
        reality_private_key: node.common.tls_settings.private_key.trim().to_string(),
        reality_short_id: node.common.tls_settings.short_id.trim().to_string(),
        reality_mldsa65_seed: node.common.tls_settings.mldsa65_seed.trim().to_string(),
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
    let mut alpn: Vec<String> = Vec::new();
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

fn core_network_name(node: &NodeInfo) -> Result<String, CoreError> {
    if !node.common.network.trim().is_empty() {
        return Ok(node.common.network.trim().to_string());
    }

    Ok(match node.protocol {
        Protocol::Trojan => "tcp".to_string(),
        Protocol::Hysteria2 => "hysteria".to_string(),
        Protocol::Tuic => "tuic".to_string(),
        Protocol::Mieru => resolve_mieru_transport(&node.common.transport)?,
        _ => String::new(),
    })
}

fn resolve_node_port_range(node: &NodeInfo) -> String {
    let ports = node.common.ports.0.trim();
    if !ports.is_empty() {
        return ports.to_string();
    }

    let port = node.common.port.0.trim();
    if port.contains('-') {
        port.to_string()
    } else {
        String::new()
    }
}

fn resolve_mieru_transport(value: &str) -> Result<String, CoreError> {
    let transport = value.trim();
    if transport.is_empty() {
        return Ok("TCP".to_string());
    }

    let transport = transport.to_ascii_uppercase();
    match transport.as_str() {
        "TCP" | "UDP" => Ok(transport),
        _ => Err(CoreError::new(format!(
            "mieru transport {transport} is not supported"
        ))),
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

fn resolve_reality_dest(settings: &TlsSettings) -> String {
    let host = first_non_empty(settings.dest.trim(), settings.server_name.trim());
    let port = settings.server_port.trim();
    if host.is_empty() || port.is_empty() {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn value_to_u64(value: &Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        .unwrap_or(0)
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
    config.insert("stats".to_string(), json!({}));
    config.insert("policy".to_string(), render_xray_policy());
    config.insert("routing".to_string(), render_xray_routing(plan));
    if let Some(dns) = render_xray_dns(plan) {
        config.insert("dns".to_string(), dns);
    }

    Value::Object(config)
}

fn render_xray_policy() -> Value {
    json!({
        "levels": {
            "0": {
                "statsUserUplink": true,
                "statsUserDownlink": true,
                "handshake": 4,
                "connIdle": 120,
                "uplinkOnly": 2,
                "downlinkOnly": 4,
                "bufferSize": 128
            }
        }
    })
}

fn render_xray_outbounds(plan: &CorePlan) -> Vec<Value> {
    let mut outbounds = vec![
        json!({
            "tag": "Default",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4"
            }
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
    let mut servers = vec![
        json!({
            "address": "1.1.1.1"
        }),
        json!({
            "address": "8.8.8.8"
        }),
    ];
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

    Some(json!({
        "servers": servers,
        "queryStrategy": "UseIPv4"
    }))
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
    item.insert("sniffing".to_string(), render_xray_sniffing());

    let stream_settings = render_xray_stream_settings(inbound);
    if !stream_settings.is_empty() {
        item.insert("streamSettings".to_string(), Value::Object(stream_settings));
    }

    Value::Object(item)
}

fn render_xray_sniffing() -> Value {
    json!({
        "enabled": true,
        "destOverride": ["http", "tls"]
    })
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
    settings.insert(
        "network".to_string(),
        if shadowsocks_has_http_obfs(inbound) {
            json!("tcp")
        } else {
            json!("tcp,udp")
        },
    );
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
    if let Some(tcp_settings) = render_shadowsocks_tcp_stream_settings(inbound) {
        stream.insert("network".to_string(), json!("tcp"));
        stream.insert("tcpSettings".to_string(), tcp_settings);
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

fn render_shadowsocks_tcp_stream_settings(inbound: &InboundPlan) -> Option<Value> {
    if inbound.protocol != "shadowsocks" {
        return None;
    }

    let accept_proxy_protocol = accepts_proxy_protocol(&inbound.network_settings);
    let path = network_setting_string(&inbound.network_settings, &["path"]);
    let host = network_setting_string(&inbound.network_settings, &["Host", "host"]);
    if !accept_proxy_protocol && path.is_none() && host.is_none() {
        return None;
    }

    let mut settings = Map::new();
    if accept_proxy_protocol {
        settings.insert("acceptProxyProtocol".to_string(), json!(true));
    }
    if path.is_some() || host.is_some() {
        let path = path.unwrap_or_else(|| "/".to_string());
        let mut request = Map::new();
        request.insert("path".to_string(), json!([path]));
        if let Some(host) = host {
            request.insert(
                "headers".to_string(),
                json!({
                    "Host": [host]
                }),
            );
        }
        settings.insert(
            "header".to_string(),
            json!({
                "type": "http",
                "request": request
            }),
        );
    }

    Some(Value::Object(settings))
}

fn shadowsocks_has_http_obfs(inbound: &InboundPlan) -> bool {
    inbound.protocol == "shadowsocks"
        && (network_setting_string(&inbound.network_settings, &["path"]).is_some()
            || network_setting_string(&inbound.network_settings, &["Host", "host"]).is_some())
}

fn accepts_proxy_protocol(settings: &Value) -> bool {
    settings
        .get("acceptProxyProtocol")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn network_setting_string(settings: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| settings.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn render_xray_tls_settings(inbound: &InboundPlan) -> Value {
    let mut settings = Map::new();
    if !inbound.server_name.trim().is_empty() {
        settings.insert("serverName".to_string(), json!(&inbound.server_name));
    }
    if !inbound.alpn.is_empty() {
        settings.insert("alpn".to_string(), json!(&inbound.alpn));
    }
    if inbound.reject_unknown_sni {
        settings.insert("rejectUnknownSni".to_string(), json!(true));
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
    if inbound.reality_xver > 0 {
        settings.insert("xver".to_string(), json!(inbound.reality_xver));
    }
    if !inbound.reality_short_id.trim().is_empty() {
        settings.insert("shortIds".to_string(), json!([&inbound.reality_short_id]));
    }
    if !inbound.reality_mldsa65_seed.trim().is_empty() {
        settings.insert(
            "mldsa65Seed".to_string(),
            json!(&inbound.reality_mldsa65_seed),
        );
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

fn naive_caddy_listen(inbound: &InboundPlan) -> String {
    let listen = inbound.listen.trim();
    if listen.is_empty() || listen == "::" || listen == "0.0.0.0" {
        return format!(":{}", inbound.port);
    }
    if listen.contains(':') && !listen.starts_with('[') {
        format!("[{}]:{}", listen, inbound.port)
    } else {
        format!("{}:{}", listen, inbound.port)
    }
}

fn caddy_token(value: &str) -> String {
    if value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/' | ':' | '$')
    }) {
        return value.to_string();
    }

    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
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
        build_inbound_plan, core_file_layout, core_kind_from_name, render_core_config,
        resolve_node_listen_ip, should_fallback_node_listen_ip, sidecar_config_path,
        split_core_plans_for_nodes, write_core_config, CoreKind, CorePlan,
    };
    use crate::panel::types::{CommonNode, NodeInfo, PortValue, Route, Security, UserInfo};

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
    fn parses_kernel_core_kind_names() {
        assert_eq!(core_kind_from_name(" xray ").unwrap(), CoreKind::Xray);
        assert_eq!(
            core_kind_from_name("keli_core_rs").unwrap(),
            CoreKind::KeliCoreRs
        );
        assert!(core_kind_from_name("unknown").is_err());
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
    fn xray_plan_rejects_sidecar_only_protocols() {
        let node = test_node("naive", 33, "");

        let err = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap_err();

        assert!(err.message.contains("protocol naive"));
        assert!(err.message.contains("requires a sidecar runtime"));
    }

    #[test]
    fn splits_xray_and_sidecar_protocol_plans() {
        let nodes = vec![test_node("vless", 34, ""), test_node("mieru", 35, "")];
        let bundle = split_core_plans_for_nodes(
            PathBuf::from("/srv/v2node/config.json"),
            &nodes,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();

        let xray = bundle.xray.unwrap();
        assert_eq!(xray.inbounds.len(), 1);
        assert_eq!(xray.inbounds[0].protocol, "vless");
        assert_eq!(bundle.sidecars.len(), 1);
        assert_eq!(bundle.sidecars[0].kind, CoreKind::Sidecar("mieru".to_string()));
        assert_eq!(bundle.sidecars[0].inbounds[0].protocol, "mieru");
        assert_eq!(
            bundle.sidecars[0].config_path,
            PathBuf::from("/srv/v2node/sidecar-mieru-35.json")
        );
    }

    #[test]
    fn derives_sidecar_config_path_next_to_core_config() {
        assert_eq!(
            sidecar_config_path("/srv/v2node/config.json", "naive", 36),
            PathBuf::from("/srv/v2node/sidecar-naive-36.Caddyfile")
        );
    }

    #[test]
    fn renders_mieru_sidecar_server_config_from_users() {
        let mut node = test_node("mieru", 37, "");
        node.common.transport = "udp".to_string();
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 37,
                uuid: "mieru-secret".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::Sidecar("mieru".to_string()),
            PathBuf::from("/srv/v2node/sidecar-mieru-37.json"),
            &[node],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["portBindings"][0]["port"], 10037);
        assert_eq!(config["portBindings"][0]["protocol"], "UDP");
        assert_eq!(config["users"][0]["name"], "mieru-secret");
        assert_eq!(config["users"][0]["password"], "mieru-secret");
        assert_eq!(config["loggingLevel"], "INFO");
    }

    #[test]
    fn renders_mieru_sidecar_port_range_when_present() {
        let mut node = test_node("mieru", 38, "");
        node.common.ports = PortValue("2100-2200".to_string());
        let plan = CorePlan::from_nodes(
            CoreKind::Sidecar("mieru".to_string()),
            PathBuf::from("/srv/v2node/sidecar-mieru-38.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["portBindings"][0]["portRange"], "2100-2200");
        assert!(config["portBindings"][0]["port"].is_null());
    }

    #[test]
    fn renders_naive_sidecar_caddyfile_from_users() {
        let node = test_node("naive", 39, "");
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 39,
                uuid: "naive-secret".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::Sidecar("naive".to_string()),
            PathBuf::from("/srv/v2node/sidecar-naive-39.Caddyfile"),
            &[node],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();
        let caddyfile = config.as_str().unwrap();

        assert!(caddyfile.contains("forward_proxy"));
        assert!(caddyfile.contains("basic_auth naive-secret naive-secret"));

        let dir = temp_test_dir("naive-caddyfile-write");
        let path = dir.join("sidecar-naive-39.Caddyfile");
        let mut plan = plan;
        plan.config_path = path.clone();
        let written = write_core_config(&plan).unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        assert!(written.changed);
        assert!(saved.starts_with("{\n    order forward_proxy first"));
        assert!(!saved.starts_with('"'));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn renders_keli_core_rs_native_socks_http_shadowsocks_vmess_vless_trojan_anytls_config_from_panel_users() {
        let socks = test_node("socks", 40, "");
        let http = test_node("http", 41, "127.0.0.1");
        let mut shadowsocks = test_node("shadowsocks", 54, "127.0.0.1");
        shadowsocks.common.cipher = "aes-128-gcm".to_string();
        let vmess = test_node("vmess", 43, "127.0.0.1");
        let vless = test_node("vless", 45, "127.0.0.1");
        let trojan = test_node("trojan", 50, "127.0.0.1");
        let anytls = test_node("anytls", 58, "127.0.0.1");
        let socks_tag = socks.tag.clone();
        let http_tag = http.tag.clone();
        let shadowsocks_tag = shadowsocks.tag.clone();
        let vmess_tag = vmess.tag.clone();
        let vless_tag = vless.tag.clone();
        let trojan_tag = trojan.tag.clone();
        let anytls_tag = anytls.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            socks_tag.clone(),
            vec![UserInfo {
                id: 40,
                uuid: "socks-user".to_string(),
                speed_limit: 1024,
                device_limit: 2,
            }],
        );
        users.insert(
            http_tag.clone(),
            vec![UserInfo {
                id: 41,
                uuid: "http-user".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        users.insert(
            vless_tag.clone(),
            vec![UserInfo {
                id: 45,
                uuid: "11111111-1111-1111-1111-111111111111".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        users.insert(
            vmess_tag.clone(),
            vec![UserInfo {
                id: 43,
                uuid: "33333333-3333-3333-3333-333333333333".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        users.insert(
            shadowsocks_tag,
            vec![UserInfo {
                id: 54,
                uuid: "ss-password".to_string(),
                speed_limit: 3072,
                device_limit: 4,
            }],
        );
        users.insert(
            trojan_tag,
            vec![UserInfo {
                id: 50,
                uuid: "trojan-password".to_string(),
                speed_limit: 2048,
                device_limit: 3,
            }],
        );
        users.insert(
            anytls_tag,
            vec![UserInfo {
                id: 58,
                uuid: "anytls-password".to_string(),
                speed_limit: 4096,
                device_limit: 5,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[socks, http, shadowsocks, vmess, vless, trojan, anytls],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["instance_id"], "keli-core-rs");
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
        assert_eq!(config["inbounds"][0]["listen"], "::");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "tcp");
        assert_eq!(config["inbounds"][0]["users"][0]["uuid"], "socks-user");
        assert_eq!(
            config["inbounds"][0]["users"][0]["email"],
            format!("{socks_tag}|socks-user")
        );
        assert_eq!(config["inbounds"][0]["users"][0]["speed_limit"], 1024);
        assert_eq!(config["inbounds"][0]["users"][0]["device_limit"], 2);
        assert_eq!(config["inbounds"][1]["protocol"], "http");
        assert_eq!(config["inbounds"][1]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][2]["protocol"], "shadowsocks");
        assert_eq!(config["inbounds"][2]["cipher"], "aes-128-gcm");
        assert_eq!(config["inbounds"][2]["users"][0]["uuid"], "ss-password");
        assert_eq!(config["inbounds"][2]["users"][0]["speed_limit"], 3072);
        assert_eq!(config["inbounds"][2]["users"][0]["device_limit"], 4);
        assert_eq!(config["inbounds"][3]["protocol"], "vmess");
        assert_eq!(config["inbounds"][3]["listen"], "127.0.0.1");
        assert_eq!(
            config["inbounds"][3]["users"][0]["uuid"],
            "33333333-3333-3333-3333-333333333333"
        );
        assert_eq!(config["inbounds"][4]["protocol"], "vless");
        assert_eq!(config["inbounds"][4]["listen"], "127.0.0.1");
        assert_eq!(
            config["inbounds"][4]["users"][0]["uuid"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(config["inbounds"][5]["protocol"], "trojan");
        assert_eq!(config["inbounds"][5]["listen"], "127.0.0.1");
        assert_eq!(
            config["inbounds"][5]["users"][0]["uuid"],
            "trojan-password"
        );
        assert_eq!(config["inbounds"][5]["users"][0]["speed_limit"], 2048);
        assert_eq!(config["inbounds"][5]["users"][0]["device_limit"], 3);
        assert_eq!(config["inbounds"][6]["protocol"], "anytls");
        assert_eq!(
            config["inbounds"][6]["users"][0]["uuid"],
            "anytls-password"
        );
        assert_eq!(config["inbounds"][6]["users"][0]["speed_limit"], 4096);
        assert_eq!(config["inbounds"][6]["users"][0]["device_limit"], 5);
        assert_eq!(config["outbounds"][0]["tag"], "direct");
        assert_eq!(config["stats"]["per_user"], true);
    }

    #[test]
    fn renders_keli_core_rs_block_routes() {
        let mut node = test_node("http", 42, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["*.blocked.example".to_string()],
            action: "block".to_string(),
            action_value: None,
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["routes"][0]["targets"][0], "*.blocked.example");
        assert_eq!(config["routes"][0]["action"], "block");
    }

    #[test]
    fn keli_core_rs_rejects_unimplemented_protocols() {
        let node = test_node("naive", 43, "");
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err
            .message
            .contains("only supports socks/http/shadowsocks/vmess/vless/trojan/anytls"));
    }

    #[test]
    fn keli_core_rs_rejects_vless_reality_until_core_supports_it() {
        let mut node = test_node("vless", 46, "");
        node.security = Security::Reality;
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("security none/tls"));
    }

    #[test]
    fn keli_core_rs_rejects_vless_unsupported_transport_until_core_supports_it() {
        let mut node = test_node("vless", 47, "");
        node.common.network = "grpc".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("tcp/ws transport"));
    }

    #[test]
    fn keli_core_rs_rejects_vless_flow_until_core_supports_it() {
        let mut node = test_node("vless", 48, "");
        node.common.flow = "xtls-rprx-vision".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("does not support flow"));
    }

    #[test]
    fn keli_core_rs_rejects_vless_transport_settings_until_core_supports_it() {
        let mut node = test_node("vless", 49, "");
        node.common.network_settings = json!({
            "header": {
                "type": "http"
            }
        });
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("transport settings"));
    }

    #[test]
    fn renders_keli_core_rs_vmess_vless_and_trojan_websocket_transport_settings() {
        let mut vless = test_node("vless", 60, "");
        vless.common.network = "ws".to_string();
        vless.common.network_settings = json!({
            "path": "/vless",
            "headers": {
                "Host": "vless.example.test"
            }
        });
        let mut vmess = test_node("vmess", 63, "");
        vmess.common.network = "ws".to_string();
        vmess.common.network_settings = json!({
            "path": "/vmess",
            "headers": {
                "Host": "vmess.example.test"
            }
        });
        let mut trojan = test_node("trojan", 61, "");
        trojan.common.network = "websocket".to_string();
        trojan.common.network_settings = json!({
            "path": "/trojan",
            "Host": "trojan.example.test"
        });
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[vless, vmess, trojan],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["transport"]["network"], "ws");
        assert_eq!(config["inbounds"][0]["transport"]["path"], "/vless");
        assert_eq!(
            config["inbounds"][0]["transport"]["host"],
            "vless.example.test"
        );
        assert_eq!(config["inbounds"][1]["transport"]["network"], "ws");
        assert_eq!(config["inbounds"][1]["transport"]["path"], "/vmess");
        assert_eq!(
            config["inbounds"][1]["transport"]["host"],
            "vmess.example.test"
        );
        assert_eq!(config["inbounds"][2]["transport"]["network"], "ws");
        assert_eq!(config["inbounds"][2]["transport"]["path"], "/trojan");
        assert_eq!(
            config["inbounds"][2]["transport"]["host"],
            "trojan.example.test"
        );
    }

    #[test]
    fn renders_keli_core_rs_vmess_tls_settings() {
        let mut node = test_node("vmess", 64, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/vmess.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/vmess.key".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "vmess.example.test".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "vmess");
        assert_eq!(config["inbounds"][0]["tls"]["server_name"], "vmess.example.test");
        assert_eq!(config["inbounds"][0]["tls"]["cert_file"], "/srv/v2node/vmess.cer");
        assert_eq!(config["inbounds"][0]["tls"]["key_file"], "/srv/v2node/vmess.key");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "tcp");
    }

    #[test]
    fn renders_keli_core_rs_tuic_tls_settings() {
        let mut node = test_node("tuic", 65, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/tuic.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/tuic.key".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "tuic.example.test".to_string();
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 65,
                uuid: "11111111-1111-1111-1111-111111111111".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "tuic");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "tuic");
        assert_eq!(config["inbounds"][0]["tls"]["server_name"], "tuic.example.test");
        assert_eq!(config["inbounds"][0]["tls"]["cert_file"], "/srv/v2node/tuic.cer");
        assert_eq!(config["inbounds"][0]["tls"]["key_file"], "/srv/v2node/tuic.key");
        assert_eq!(config["inbounds"][0]["tls"]["alpn"][0], "h3");
        assert_eq!(
            config["inbounds"][0]["users"][0]["uuid"],
            "11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn renders_keli_core_rs_hysteria2_tls_settings() {
        let mut node = test_node("hysteria2", 66, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/hy2.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/hy2.key".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "hy2.example.test".to_string();
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 66,
                uuid: "hy2-password".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "hysteria2");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "hysteria");
        assert_eq!(config["inbounds"][0]["tls"]["server_name"], "hy2.example.test");
        assert_eq!(config["inbounds"][0]["tls"]["cert_file"], "/srv/v2node/hy2.cer");
        assert_eq!(config["inbounds"][0]["tls"]["key_file"], "/srv/v2node/hy2.key");
        assert_eq!(config["inbounds"][0]["tls"]["alpn"][0], "h3");
        assert_eq!(config["inbounds"][0]["users"][0]["uuid"], "hy2-password");
    }

    #[test]
    fn keli_core_rs_rejects_hysteria2_obfs_until_core_supports_it() {
        let mut node = test_node("hysteria2", 67, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/hy2.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/hy2.key".to_string();
        node.common.obfs = "salamander".to_string();
        node.common.obfs_password = "obfs-secret".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("does not support obfs"));
    }

    #[test]
    fn renders_keli_core_rs_hysteria2_bandwidth_options() {
        let mut node = test_node("hysteria2", 68, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/hy2.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/hy2.key".to_string();
        node.common.up_mbps = 100;
        node.common.down_mbps = 200;
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 68,
                uuid: "hy2-password".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["transport"]["up_mbps"], 100);
        assert_eq!(config["inbounds"][0]["transport"]["down_mbps"], 200);
        assert!(config["inbounds"][0]["transport"]["ignore_client_bandwidth"].is_null());
    }

    #[test]
    fn renders_keli_core_rs_hysteria2_ignore_client_bandwidth() {
        let mut node = test_node("hysteria2", 69, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/hy2.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/hy2.key".to_string();
        node.common.up_mbps = 100;
        node.common.down_mbps = 200;
        node.common.ignore_client_bandwidth = true;
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["transport"]["ignore_client_bandwidth"],
            true
        );
        assert!(config["inbounds"][0]["transport"]["up_mbps"].is_null());
        assert!(config["inbounds"][0]["transport"]["down_mbps"].is_null());
    }

    #[test]
    fn keli_core_rs_rejects_shadowsocks_unsupported_cipher_until_core_supports_it() {
        let mut node = test_node("shadowsocks", 55, "");
        node.common.cipher = "2022-blake3-aes-128-gcm".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("shadowsocks cipher"));
    }

    #[test]
    fn keli_core_rs_rejects_shadowsocks_non_tcp_transport_until_core_supports_it() {
        let mut node = test_node("shadowsocks", 56, "");
        node.common.cipher = "aes-128-gcm".to_string();
        node.common.network = "ws".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("tcp transport"));
    }

    #[test]
    fn keli_core_rs_rejects_shadowsocks_transport_settings_until_core_supports_it() {
        let mut node = test_node("shadowsocks", 57, "");
        node.common.cipher = "aes-128-gcm".to_string();
        node.common.network_settings = json!({
            "path": "/ss"
        });
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("transport settings"));
    }

    #[test]
    fn renders_keli_core_rs_vless_and_trojan_tls_settings() {
        let mut vless = test_node("vless", 51, "");
        vless.security = Security::Tls;
        vless.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/vless.cer".to_string();
        vless.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/vless.key".to_string();
        vless.common.cert_info.as_mut().unwrap().cert_domain = "vless.example.test".to_string();
        vless.common.network = "ws".to_string();
        vless.common.network_settings = json!({
            "path": "/vless-tls"
        });
        let mut trojan = test_node("trojan", 62, "");
        trojan.security = Security::Tls;
        trojan.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/trojan.cer".to_string();
        trojan.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/trojan.key".to_string();
        trojan.common.cert_info.as_mut().unwrap().cert_domain = "trojan.example.test".to_string();
        trojan.common.tls_settings.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[vless, trojan],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["tls"]["server_name"], "vless.example.test");
        assert_eq!(config["inbounds"][0]["tls"]["cert_file"], "/srv/v2node/vless.cer");
        assert_eq!(config["inbounds"][0]["tls"]["key_file"], "/srv/v2node/vless.key");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "ws");
        assert_eq!(config["inbounds"][0]["transport"]["path"], "/vless-tls");
        assert_eq!(
            config["inbounds"][1]["tls"]["server_name"],
            "trojan.example.test"
        );
        assert_eq!(config["inbounds"][1]["tls"]["cert_file"], "/srv/v2node/trojan.cer");
        assert_eq!(config["inbounds"][1]["tls"]["key_file"], "/srv/v2node/trojan.key");
        assert_eq!(config["inbounds"][1]["tls"]["alpn"][0], "h2");
        assert_eq!(config["inbounds"][1]["tls"]["alpn"][1], "http/1.1");
    }

    #[test]
    fn keli_core_rs_rejects_trojan_unsupported_transport_until_core_supports_it() {
        let mut node = test_node("trojan", 52, "");
        node.common.network = "grpc".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("tcp/ws transport"));
    }

    #[test]
    fn keli_core_rs_rejects_trojan_transport_settings_until_core_supports_it() {
        let mut node = test_node("trojan", 53, "");
        node.common.network_settings = json!({
            "path": "/trojan"
        });
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("transport settings"));
    }

    #[test]
    fn keli_core_rs_rejects_anytls_padding_until_core_supports_it() {
        let mut node = test_node("anytls", 59, "");
        node.common.padding_scheme = vec!["stop=8".to_string()];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("padding scheme"));
    }

    #[test]
    fn keli_core_rs_rejects_unsupported_route_actions() {
        let mut node = test_node("socks", 44, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["10.0.0.0/8".to_string()],
            action: "block_ip".to_string(),
            action_value: None,
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("route action block_ip"));
    }

    #[test]
    fn renders_default_sniffing_for_inbounds() {
        let node = test_node("vless", 28, "");
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["sniffing"]["enabled"], true);
        assert_eq!(
            config["inbounds"][0]["sniffing"]["destOverride"],
            json!(["http", "tls"])
        );
    }

    #[test]
    fn renders_go_default_dns_and_outbound() {
        let node = test_node("vless", 30, "");
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][0]["tag"], "Default");
        assert_eq!(
            config["outbounds"][0]["settings"]["domainStrategy"],
            "UseIPv4"
        );
        assert_eq!(config["dns"]["queryStrategy"], "UseIPv4");
        assert_eq!(config["dns"]["servers"][0]["address"], "1.1.1.1");
        assert_eq!(config["dns"]["servers"][1]["address"], "8.8.8.8");
    }

    #[test]
    fn renders_stats_policy_for_user_traffic() {
        let node = test_node("vless", 31, "");
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert!(config["stats"].is_object());
        assert_eq!(config["policy"]["levels"]["0"]["statsUserUplink"], true);
        assert_eq!(config["policy"]["levels"]["0"]["statsUserDownlink"], true);
        assert_eq!(config["policy"]["levels"]["0"]["connIdle"], 120);
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
        node.common.cert_info.as_mut().unwrap().reject_unknown_sni = true;
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
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["tlsSettings"]["rejectUnknownSni"],
            true
        );
    }

    #[test]
    fn renders_reality_dest_xver_and_mldsa_seed() {
        let mut node = test_node("vless", 29, "");
        node.common.tls = 2;
        node.security = Security::Reality;
        node.common.tls_settings.server_name = "reality.example.test".to_string();
        node.common.tls_settings.server_port = "443".to_string();
        node.common.tls_settings.private_key = "private-key".to_string();
        node.common.tls_settings.short_id = "abcd".to_string();
        node.common.tls_settings.mldsa65_seed = "seed-value".to_string();
        node.common.tls_settings.xver = json!("1");
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["streamSettings"]["realitySettings"]["dest"],
            "reality.example.test:443"
        );
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["realitySettings"]["xver"],
            1
        );
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["realitySettings"]["mldsa65Seed"],
            "seed-value"
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
    fn renders_shadowsocks_http_obfs_as_tcp_header() {
        let mut node = test_node("shadowsocks", 27, "");
        node.common.network_settings = json!({
            "path": "/ss",
            "Host": "edge.example.test"
        });
        let plan = CorePlan::from_nodes(
            CoreKind::Xray,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["settings"]["network"], "tcp");
        assert_eq!(config["inbounds"][0]["streamSettings"]["network"], "tcp");
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["tcpSettings"]["header"]["type"],
            "http"
        );
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["tcpSettings"]["header"]["request"]["path"][0],
            "/ss"
        );
        assert_eq!(
            config["inbounds"][0]["streamSettings"]["tcpSettings"]["header"]["request"]
                ["headers"]["Host"][0],
            "edge.example.test"
        );
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

        assert_eq!(config["dns"]["servers"][2]["address"], "1.1.1.1");
        assert_eq!(
            config["dns"]["servers"][2]["domains"][0],
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
