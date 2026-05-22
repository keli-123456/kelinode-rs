use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::config::KernelConfig;
use crate::logging;
use crate::panel::types::{CertInfo, NodeInfo, Protocol, Security, TlsSettings, UserInfo};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreKind {
    KeliCoreRs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorePlan {
    pub kind: CoreKind,
    pub config_path: PathBuf,
    pub listen_tags: Vec<String>,
    pub inbounds: Vec<InboundPlan>,
    pub dns: CorePlanDnsOptions,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CorePlanDnsOptions {
    pub servers: Vec<String>,
    pub block_private_ips: bool,
    pub private_ip_allowlist: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CorePlanBundle {
    pub core: Option<CorePlan>,
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
    pub multiplexing: String,
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
        let mut inbounds = nodes
            .iter()
            .map(|node| {
                let users = users_by_node_tag
                    .get(&node.tag)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                build_inbound_plan_with_users(node, users)
            })
            .collect::<Result<Vec<_>, _>>()?;
        strip_native_user_emails(&mut inbounds);
        let listen_tags = inbounds.iter().map(|inbound| inbound.tag.clone()).collect();

        Ok(Self {
            kind,
            config_path,
            listen_tags,
            inbounds,
            dns: CorePlanDnsOptions::default(),
        })
    }

    pub fn file_layout(&self) -> CoreFileLayout {
        core_file_layout(&self.config_path)
    }

    pub fn apply_kernel_dns_options(&mut self, kernel: &KernelConfig) {
        self.dns = CorePlanDnsOptions {
            servers: kernel.dns_servers.clone(),
            block_private_ips: kernel.dns_block_private_ips,
            private_ip_allowlist: kernel.dns_private_ip_allowlist.clone(),
        };
    }
}

fn strip_native_user_emails(inbounds: &mut [InboundPlan]) {
    for inbound in inbounds {
        for user in &mut inbound.users {
            user.email.clear();
        }
    }
}

pub fn core_kind_from_name(value: &str) -> Result<CoreKind, CoreError> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "" => Ok(CoreKind::KeliCoreRs),
        "keli-core-rs" | "kelicore-rs" | "kelicorers" => Ok(CoreKind::KeliCoreRs),
        "xray" | "sing-box" | "singbox" | "mihomo" | "clash-meta" => Err(CoreError::new(
            "legacy external core types are no longer supported; use keli-core-rs",
        )),
        other => Err(CoreError::new(format!(
            "unsupported core type {other}; use keli-core-rs"
        ))),
    }
}

pub fn split_core_plans_for_nodes(
    config_path: PathBuf,
    nodes: &[NodeInfo],
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
) -> Result<CorePlanBundle, CoreError> {
    split_core_plans_for_nodes_with_kind(
        CoreKind::KeliCoreRs,
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
        .filter(|node| {
            match node_supported_by_keli_core_rs(&config_path, node, users_by_node_tag) {
                Ok(()) => true,
                Err(error) => {
                    logging::warn(
                        "core",
                        format!(
                            "skipping unsupported native inbound tag={} error={}",
                            node.tag, error.message
                        ),
                    );
                    false
                }
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    let core = if core_nodes.is_empty() {
        None
    } else {
        Some(CorePlan::from_nodes_with_users(
            core_kind.clone(),
            config_path.clone(),
            &core_nodes,
            users_by_node_tag,
        )?)
    };

    Ok(CorePlanBundle { core })
}

fn node_supported_by_keli_core_rs(
    config_path: &Path,
    node: &NodeInfo,
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
) -> Result<(), CoreError> {
    if keli_core_rs_protocol_requires_users(node.protocol)
        && !node_has_keli_core_rs_users(&node.tag, users_by_node_tag)
    {
        return Err(CoreError::new(format!(
            "keli-core-rs {} inbound {} requires panel users before rendering",
            core_protocol_name(node.protocol),
            node.tag
        )));
    }
    let probe = CorePlan::from_nodes_with_users(
        CoreKind::KeliCoreRs,
        config_path.to_path_buf(),
        std::slice::from_ref(node),
        users_by_node_tag,
    )?;
    for inbound in &probe.inbounds {
        validate_keli_core_rs_inbound(inbound)?;
    }
    Ok(())
}

fn keli_core_rs_protocol_requires_users(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Vmess
            | Protocol::Shadowsocks
            | Protocol::Anytls
            | Protocol::Mieru
            | Protocol::Naive
    )
}

fn node_has_keli_core_rs_users(
    node_tag: &str,
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
) -> bool {
    users_by_node_tag
        .get(node_tag)
        .map(|users| users.iter().any(|user| !user.uuid.trim().is_empty()))
        .unwrap_or(false)
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
        CoreKind::KeliCoreRs => render_keli_core_rs_config(plan),
    }
}

fn render_keli_core_rs_config(plan: &CorePlan) -> Result<Value, CoreError> {
    let mut outbounds = vec![json!({
        "tag": "direct",
        "protocol": "freedom",
        "address": null,
        "port": null
    })];
    for inbound in &plan.inbounds {
        validate_keli_core_rs_inbound(inbound)?;
        collect_keli_core_rs_route_outbounds(inbound, &mut outbounds)?;
    }

    Ok(json!({
        "instance_id": keli_core_rs_instance_id(plan),
        "log_level": "info",
        "policy": render_keli_core_rs_policy(),
        "dns": render_keli_core_rs_dns(plan)?,
        "inbounds": render_keli_core_rs_inbounds(&plan.inbounds)?,
        "outbounds": outbounds,
        "routes": [],
        "stats": {
            "enabled": true,
            "per_user": true
        }
    }))
}

fn render_keli_core_rs_policy() -> Value {
    json!({
        "handshake_secs": 4,
        "connection_idle_secs": 120,
        "uplink_only_secs": 2,
        "downlink_only_secs": 4,
        "buffer_size_kib": 128,
        "sniffing_cache_millis": 200,
        "connect_timeout_secs": 15
    })
}

fn collect_keli_core_rs_route_outbounds(
    inbound: &InboundPlan,
    outbounds: &mut Vec<Value>,
) -> Result<(), CoreError> {
    for route in &inbound.routes {
        if route.match_rules.is_empty() && route.action != "default_out" {
            continue;
        }
        if !matches!(route.action.as_str(), "route" | "route_ip" | "default_out") {
            continue;
        }
        if keli_core_rs_route_outbound_is_blackhole(route) {
            continue;
        }
        if let Some((tag, outbound)) = keli_core_rs_route_outbound(inbound, route)? {
            push_keli_core_rs_outbound_once(outbounds, tag.as_str(), outbound);
        }
    }
    Ok(())
}

fn render_keli_core_rs_routes_for_inbound(inbound: &InboundPlan) -> Result<Vec<Value>, CoreError> {
    let mut routes = Vec::new();
    for route in &inbound.routes {
        if route.match_rules.is_empty() && route.action != "default_out" {
            continue;
        }
        match route.action.as_str() {
            "block" => routes.push(json!({
                "targets": keli_core_rs_block_route_targets(inbound, route)?,
                "action": "block"
            })),
            "block_ip" => routes.push(json!({
                "targets": prefixed_keli_core_rs_ip_route_targets(inbound, route)?,
                "action": "block"
            })),
            "block_port" => routes.push(json!({
                "targets": prefixed_keli_core_rs_port_route_targets(inbound, route)?,
                "action": "block"
            })),
            "route" => {
                if keli_core_rs_route_outbound_is_blackhole(route) {
                    routes.push(json!({
                        "targets": keli_core_rs_route_targets(inbound, route)?,
                        "action": "block"
                    }));
                    continue;
                }
                if let Some((tag, outbound)) = keli_core_rs_route_outbound(inbound, route)? {
                    routes.push(json!({
                        "targets": keli_core_rs_route_targets(inbound, route)?,
                        "action": {
                            "outbound": tag
                        },
                        "outbound": outbound
                    }));
                }
            }
            "route_ip" => {
                if keli_core_rs_route_outbound_is_blackhole(route) {
                    routes.push(json!({
                        "targets": prefixed_keli_core_rs_ip_route_targets(inbound, route)?,
                        "action": "block"
                    }));
                    continue;
                }
                if let Some((tag, outbound)) = keli_core_rs_route_outbound(inbound, route)? {
                    routes.push(json!({
                        "targets": prefixed_keli_core_rs_ip_route_targets(inbound, route)?,
                        "action": {
                            "outbound": tag
                        },
                        "outbound": outbound
                    }));
                }
            }
            "default_out" => {
                if keli_core_rs_route_outbound_is_blackhole(route) {
                    routes.push(json!({
                        "targets": ["*"],
                        "action": "block"
                    }));
                    continue;
                }
                if let Some((tag, outbound)) = keli_core_rs_route_outbound(inbound, route)? {
                    routes.push(json!({
                        "targets": ["*"],
                        "action": {
                            "outbound": tag
                        },
                        "outbound": outbound
                    }));
                }
            }
            "protocol" => routes.push(json!({
                "targets": prefixed_keli_core_rs_protocol_route_targets(inbound, route)?,
                "action": "block"
            })),
            "dns" => {}
            value => {
                return Err(CoreError::new(format!(
                    "keli-core-rs route action {value} on inbound {} is not supported yet",
                    inbound.tag
                )));
            }
        }
    }
    Ok(routes)
}

fn render_keli_core_rs_dns(plan: &CorePlan) -> Result<Value, CoreError> {
    let mut servers = if plan.dns.servers.is_empty() {
        vec![
            json!({
                "address": "1.1.1.1"
            }),
            json!({
                "address": "8.8.8.8"
            }),
        ]
    } else {
        plan.dns
            .servers
            .iter()
            .map(|address| {
                json!({
                    "address": address
                })
            })
            .collect()
    };
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
                server.insert(
                    "domains".to_string(),
                    json!(keli_core_rs_route_targets(inbound, route)?),
                );
            }
            servers.push(Value::Object(server));
        }
    }

    let mut dns = Map::new();
    dns.insert("servers".to_string(), json!(servers));
    dns.insert("query_strategy".to_string(), json!("UseIPv4"));
    if plan.dns.block_private_ips {
        dns.insert("block_private_ips".to_string(), json!(true));
    }
    if !plan.dns.private_ip_allowlist.is_empty() {
        dns.insert(
            "private_ip_allowlist".to_string(),
            json!(plan.dns.private_ip_allowlist),
        );
    }
    Ok(Value::Object(dns))
}

fn push_keli_core_rs_outbound_once(outbounds: &mut Vec<Value>, tag: &str, outbound: Value) {
    if outbounds
        .iter()
        .any(|item| item.get("tag").and_then(Value::as_str) == Some(tag))
    {
        return;
    }
    outbounds.push(outbound);
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

fn keli_core_rs_route_outbound_is_blackhole(route: &RoutePlan) -> bool {
    parse_route_outbound(route)
        .and_then(|(_, outbound)| {
            outbound
                .get("protocol")
                .and_then(Value::as_str)
                .map(|protocol| protocol.trim().eq_ignore_ascii_case("blackhole"))
        })
        .unwrap_or(false)
}

fn keli_core_rs_route_outbound(
    inbound: &InboundPlan,
    route: &RoutePlan,
) -> Result<Option<(String, Value)>, CoreError> {
    let Some((tag, outbound)) = parse_route_outbound(route) else {
        return Ok(None);
    };
    let protocol = outbound
        .get("protocol")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let protocol = protocol.to_ascii_lowercase();
    if !matches!(
        protocol.as_str(),
        "freedom" | "socks" | "socks5" | "http" | "shadowsocks" | "trojan" | "vless" | "vmess"
    ) {
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} protocol {protocol} on inbound {} is not supported yet",
            inbound.tag
        )));
    }
    let (tls, transport) = match protocol.as_str() {
        "trojan" | "vmess" => keli_core_rs_route_outbound_stream(inbound, &tag, &outbound)?,
        "vless" => keli_core_rs_route_outbound_vless_stream(inbound, &tag, &outbound)?,
        _ => (None, None),
    };

    let (address, port, username, password, method, alter_id) =
        keli_core_rs_route_outbound_endpoint(&outbound);
    if protocol == "vless" {
        if address
            .as_deref()
            .map(str::trim)
            .map(str::is_empty)
            .unwrap_or(true)
            || port.is_none()
        {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} requires vless address and port",
                inbound.tag
            )));
        }
        if username
            .as_deref()
            .map(str::trim)
            .map(str::is_empty)
            .unwrap_or(true)
        {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} requires vless users[0].id",
                inbound.tag
            )));
        }
        if method
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
        {
            let flow = method.as_deref().unwrap_or_default().trim();
            if flow != "xtls-rprx-vision" {
                return Err(CoreError::new(format!(
                    "keli-core-rs route outbound {tag} on inbound {} supports only vless xtls-rprx-vision flow; flow {flow} is not supported yet",
                    inbound.tag
                )));
            }
            if tls.is_none() || transport.is_some() {
                return Err(CoreError::new(format!(
                    "keli-core-rs route outbound {tag} on inbound {} supports vless flow only on tcp tls",
                    inbound.tag
                )));
            }
        }
    }
    if protocol == "vmess" {
        if address
            .as_deref()
            .map(str::trim)
            .map(str::is_empty)
            .unwrap_or(true)
            || port.is_none()
        {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} requires vmess address and port",
                inbound.tag
            )));
        }
        if username
            .as_deref()
            .map(str::trim)
            .map(str::is_empty)
            .unwrap_or(true)
        {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} requires vmess users[0].id",
                inbound.tag
            )));
        }
    }

    Ok(Some((
        tag.clone(),
        json!({
            "tag": tag,
            "protocol": protocol,
            "method": method,
            "alter_id": alter_id,
            "address": address,
            "port": port,
            "username": username,
            "password": password,
            "tls": tls,
            "transport": transport
        }),
    )))
}

fn keli_core_rs_route_outbound_stream(
    inbound: &InboundPlan,
    tag: &str,
    outbound: &Value,
) -> Result<(Option<Value>, Option<Value>), CoreError> {
    let Some(stream_settings) = outbound
        .get("streamSettings")
        .filter(|value| !value.is_null())
    else {
        return Ok((None, None));
    };
    let network = stream_settings
        .get("network")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("tcp");
    if !matches!(
        network,
        "tcp" | "ws" | "httpupgrade" | "grpc" | "h2" | "http" | "xhttp" | "splithttp" | "quic"
    ) {
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} on inbound {} supports only tcp/ws/httpupgrade/grpc/h2/xhttp stream-one/quic today; network {network} is not supported yet",
            inbound.tag
        )));
    }
    let security = stream_settings
        .get("security")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("none");
    if !matches!(security, "none" | "tls") {
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} on inbound {} supports only security none/tls today; security {security} is not supported yet",
            inbound.tag
        )));
    }
    if let Some(object) = stream_settings.as_object() {
        for (key, value) in object {
            if matches!(key.as_str(), "network" | "security" | "sockopt" | "mux")
                || (security == "tls" && key == "tlsSettings")
                || (network == "ws" && key == "wsSettings")
                || (network == "httpupgrade" && key == "httpupgradeSettings")
                || (network == "grpc" && key == "grpcSettings")
                || (matches!(network, "h2" | "http") && key == "httpSettings")
                || (network == "xhttp" && key == "xhttpSettings")
                || (network == "splithttp" && key == "splithttpSettings")
                || (network == "quic" && key == "quicSettings")
                || is_empty_json(value)
            {
                continue;
            }
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} does not support streamSettings.{key} yet",
                inbound.tag
            )));
        }
    }
    validate_ignored_object_if_present(inbound, tag, "sockopt", stream_settings.get("sockopt"))?;
    validate_ignored_object_if_present(inbound, tag, "mux", stream_settings.get("mux"))?;
    validate_ignored_object_if_present(inbound, tag, "mux", outbound.get("mux"))?;
    let tls_settings = stream_settings.get("tlsSettings").unwrap_or(&Value::Null);
    let tls = if security == "tls" {
        Some(json!({
            "server_name": outbound_string(tls_settings, "serverName"),
            "allow_insecure": tls_settings
                .get("allowInsecure")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            "alpn": outbound_string_array(tls_settings, "alpn")
        }))
    } else {
        None
    };
    let transport_settings = match network {
        "ws" => stream_settings.get("wsSettings").unwrap_or(&Value::Null),
        "httpupgrade" => stream_settings
            .get("httpupgradeSettings")
            .unwrap_or(&Value::Null),
        "grpc" => stream_settings.get("grpcSettings").unwrap_or(&Value::Null),
        "h2" | "http" => stream_settings.get("httpSettings").unwrap_or(&Value::Null),
        "xhttp" => stream_settings.get("xhttpSettings").unwrap_or(&Value::Null),
        "splithttp" => stream_settings
            .get("splithttpSettings")
            .unwrap_or(&Value::Null),
        "quic" => stream_settings.get("quicSettings").unwrap_or(&Value::Null),
        _ => &Value::Null,
    };
    let xhttp_stream_one = if matches!(network, "xhttp" | "splithttp") {
        validate_xhttp_stream_one_settings(inbound, tag, network, transport_settings)?;
        let mode = outbound_string(transport_settings, "mode").unwrap_or_default();
        if !mode.eq_ignore_ascii_case("stream-one") {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} supports xhttp only in stream-one mode today",
                inbound.tag
            )));
        }
        if security != "tls" {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} supports xhttp stream-one only with tls/h2 today",
                inbound.tag
            )));
        }
        true
    } else {
        false
    };
    let quic_supported = if network == "quic" {
        validate_quic_settings(inbound, tag, transport_settings)?;
        true
    } else {
        false
    };
    let transport_host = outbound_string_or_first_array(transport_settings, "host")
        .or_else(|| {
            transport_settings
                .get("headers")
                .and_then(|headers| outbound_string(headers, "Host"))
        })
        .or_else(|| {
            transport_settings
                .get("headers")
                .and_then(|headers| outbound_string(headers, "host"))
        });
    let transport_service_name = outbound_string(transport_settings, "serviceName")
        .or_else(|| outbound_string(transport_settings, "service_name"));
    let transport_method = outbound_string(transport_settings, "method")
        .or_else(|| outbound_string(transport_settings, "uplinkHTTPMethod"));
    let transport_network = if xhttp_stream_one { "h2" } else { network };
    let transport_path = if matches!(
        network,
        "ws" | "httpupgrade" | "h2" | "http" | "xhttp" | "splithttp"
    ) {
        outbound_string(transport_settings, "path").map(|path| {
            if xhttp_stream_one {
                normalize_xhttp_stream_one_path(&path)
            } else {
                path
            }
        })
    } else {
        None
    };
    let transport_headers = if xhttp_stream_one {
        xhttp_stream_one_headers(
            transport_settings,
            transport_host.as_deref(),
            transport_path.as_deref(),
        )?
    } else {
        BTreeMap::new()
    };
    let quic_security = if quic_supported {
        outbound_string(transport_settings, "security").or_else(|| Some("none".to_string()))
    } else {
        None
    };
    let quic_key = if quic_supported {
        outbound_string(transport_settings, "key")
    } else {
        None
    };
    let quic_header_type = if quic_supported {
        transport_settings
            .get("header")
            .and_then(|header| outbound_string(header, "type"))
            .or_else(|| Some("none".to_string()))
    } else {
        None
    };
    let transport = if matches!(
        network,
        "ws" | "httpupgrade" | "grpc" | "h2" | "http" | "xhttp" | "splithttp" | "quic"
    ) {
        Some(json!({
            "network": transport_network,
            "path": if matches!(network, "ws" | "httpupgrade" | "h2" | "http" | "xhttp" | "splithttp") {
                transport_path
            } else {
                None
            },
            "host": if matches!(network, "ws" | "httpupgrade" | "h2" | "http" | "xhttp" | "splithttp") {
                transport_host
            } else {
                None
            },
            "service_name": if network == "grpc" {
                transport_service_name
            } else {
                None
            },
            "method": if xhttp_stream_one {
                Some(transport_method.unwrap_or_else(|| "POST".to_string()))
            } else if matches!(network, "h2" | "http") {
                transport_method
            } else {
                None
            },
            "headers": transport_headers,
            "quic_security": quic_security,
            "quic_key": quic_key,
            "quic_header_type": quic_header_type
        }))
    } else {
        None
    };
    Ok((tls, transport))
}

fn keli_core_rs_route_outbound_vless_stream(
    inbound: &InboundPlan,
    tag: &str,
    outbound: &Value,
) -> Result<(Option<Value>, Option<Value>), CoreError> {
    keli_core_rs_route_outbound_stream(inbound, tag, outbound)
}

fn is_empty_json(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => value.trim().is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        _ => false,
    }
}

fn validate_ignored_object_if_present(
    inbound: &InboundPlan,
    tag: &str,
    key: &str,
    value: Option<&Value>,
) -> Result<(), CoreError> {
    let Some(value) = value.filter(|value| !is_empty_json(value)) else {
        return Ok(());
    };
    if value.is_object() {
        return Ok(());
    }
    Err(CoreError::new(format!(
        "keli-core-rs route outbound {tag} on inbound {} {key} must be an object",
        inbound.tag
    )))
}

fn keli_core_rs_route_outbound_endpoint(
    outbound: &Value,
) -> (
    Option<String>,
    Option<u16>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<u16>,
) {
    let address = outbound
        .get("address")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let port = outbound
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok());
    if address.is_some() || port.is_some() {
        return (
            address,
            port,
            outbound_string(outbound, "username").or_else(|| outbound_string(outbound, "user")),
            outbound_string(outbound, "password").or_else(|| outbound_string(outbound, "pass")),
            outbound_string(outbound, "method").or_else(|| outbound_string(outbound, "cipher")),
            outbound_u16(outbound, "alter_id").or_else(|| outbound_u16(outbound, "alterId")),
        );
    }

    let settings = outbound.get("settings");
    let redirect = outbound
        .get("settings")
        .and_then(|settings| settings.get("redirect"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(redirect) = redirect {
        let (address, port) = parse_route_redirect_endpoint(redirect);
        return (address, port, None, None, None, None);
    }

    let settings_method = settings
        .and_then(|settings| outbound_string(settings, "method"))
        .or_else(|| settings.and_then(|settings| outbound_string(settings, "cipher")));
    let settings_alter_id = settings
        .and_then(|settings| outbound_u16(settings, "alter_id"))
        .or_else(|| settings.and_then(|settings| outbound_u16(settings, "alterId")));
    if let Some(endpoint) = outbound
        .get("settings")
        .and_then(|settings| settings.get("servers"))
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .map(|server| {
            let (address, port, username, password, method, alter_id) =
                keli_core_rs_route_outbound_server_endpoint(server);
            (
                address,
                port,
                username,
                password,
                method.or_else(|| settings_method.clone()),
                alter_id.or(settings_alter_id),
            )
        })
    {
        return endpoint;
    }

    outbound
        .get("settings")
        .and_then(|settings| settings.get("vnext"))
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .map(|server| {
            let (address, port, username, password, method, alter_id) =
                keli_core_rs_route_outbound_server_endpoint(server);
            (
                address,
                port,
                username,
                password,
                method.or_else(|| settings_method.clone()),
                alter_id.or(settings_alter_id),
            )
        })
        .unwrap_or((None, None, None, None, settings_method, settings_alter_id))
}

fn outbound_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn outbound_string_or_first_array(value: &Value, key: &str) -> Option<String> {
    outbound_string(value, key).or_else(|| {
        value
            .get(key)
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn outbound_u16(value: &Value, key: &str) -> Option<u16> {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.trim().parse().ok()))
        })
        .and_then(|value| u16::try_from(value).ok())
}

fn outbound_string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn validate_xhttp_stream_one_settings(
    inbound: &InboundPlan,
    tag: &str,
    network: &str,
    settings: &Value,
) -> Result<(), CoreError> {
    let Some(object) = settings.as_object() else {
        if settings.is_null() {
            return Ok(());
        }
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} on inbound {} {network} settings must be an object",
            inbound.tag
        )));
    };
    for (key, value) in object {
        if matches!(
            key.as_str(),
            "path"
                | "host"
                | "mode"
                | "headers"
                | "noGRPCHeader"
                | "noGrpcHeader"
                | "method"
                | "uplinkHTTPMethod"
        ) || is_empty_json(value)
        {
            continue;
        }
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} on inbound {} does not support {network}Settings.{key} yet",
            inbound.tag
        )));
    }
    if let Some(value) = settings
        .get("headers")
        .filter(|value| !is_empty_json(value))
    {
        let Some(headers) = value.as_object() else {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} {network}Settings.headers must be an object",
                inbound.tag
            )));
        };
        for (name, value) in headers {
            if name.trim().is_empty() {
                return Err(CoreError::new(format!(
                    "keli-core-rs route outbound {tag} on inbound {} {network}Settings.headers contains an empty header name",
                    inbound.tag
                )));
            }
            if !value.is_string() && !is_empty_json(value) {
                return Err(CoreError::new(format!(
                    "keli-core-rs route outbound {tag} on inbound {} {network}Settings.headers.{name} must be a string",
                    inbound.tag
                )));
            }
        }
    }
    for key in ["noGRPCHeader", "noGrpcHeader"] {
        if let Some(value) = settings.get(key).filter(|value| !is_empty_json(value)) {
            if !value.is_boolean() {
                return Err(CoreError::new(format!(
                    "keli-core-rs route outbound {tag} on inbound {} {network}Settings.{key} must be a boolean",
                    inbound.tag
                )));
            }
        }
    }
    Ok(())
}

fn validate_quic_settings(
    inbound: &InboundPlan,
    tag: &str,
    settings: &Value,
) -> Result<(), CoreError> {
    let Some(object) = settings.as_object() else {
        if settings.is_null() {
            return Ok(());
        }
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} on inbound {} quicSettings must be an object",
            inbound.tag
        )));
    };
    for (key, value) in object {
        if matches!(key.as_str(), "security" | "key" | "header") || is_empty_json(value) {
            continue;
        }
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} on inbound {} does not support quicSettings.{key} yet",
            inbound.tag
        )));
    }
    let security = outbound_string(settings, "security").unwrap_or_else(|| "none".to_string());
    let security_lc = security.to_ascii_lowercase();
    if !matches!(
        security_lc.as_str(),
        "none" | "aes-128-gcm" | "aes128-gcm" | "chacha20-poly1305" | "chacha20-ietf-poly1305"
    ) {
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} on inbound {} supports only quicSettings.security none/aes-128-gcm/chacha20-poly1305 today",
            inbound.tag
        )));
    }
    if security_lc == "none"
        && outbound_string(settings, "key")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    {
        return Err(CoreError::new(format!(
            "keli-core-rs route outbound {tag} on inbound {} supports quicSettings.key only with encrypted quic security",
            inbound.tag
        )));
    }
    if let Some(header) = settings.get("header").filter(|value| !is_empty_json(value)) {
        let Some(header) = header.as_object() else {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} quicSettings.header must be an object",
                inbound.tag
            )));
        };
        for (key, value) in header {
            if key == "type" || is_empty_json(value) {
                continue;
            }
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} does not support quicSettings.header.{key} yet",
                inbound.tag
            )));
        }
        let header_type = header
            .get("type")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("none");
        if !header_type.eq_ignore_ascii_case("none") {
            return Err(CoreError::new(format!(
                "keli-core-rs route outbound {tag} on inbound {} supports quicSettings.header.type none only today",
                inbound.tag
            )));
        }
    }
    Ok(())
}

fn normalize_xhttp_stream_one_path(value: &str) -> String {
    let value = value.trim();
    let (path, query) = value.split_once('?').unwrap_or((value, ""));
    let mut path = path.trim().to_string();
    if path.is_empty() {
        path = "/".to_string();
    } else if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    if query.is_empty() {
        path
    } else {
        format!("{path}?{query}")
    }
}

fn xhttp_stream_one_headers(
    settings: &Value,
    _host: Option<&str>,
    path: Option<&str>,
) -> Result<BTreeMap<String, String>, CoreError> {
    let mut headers = BTreeMap::new();
    if let Some(object) = settings
        .get("headers")
        .filter(|value| !is_empty_json(value))
        .and_then(Value::as_object)
    {
        for (name, value) in object {
            if name.eq_ignore_ascii_case("host") || is_empty_json(value) {
                continue;
            }
            let Some(value) = value.as_str() else {
                continue;
            };
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let path = path.unwrap_or("/");
    let separator = if path.contains('?') { '&' } else { '?' };
    headers.insert(
        "referer".to_string(),
        format!(
            "https://keli.local{path}{separator}x_padding={}",
            "X".repeat(128)
        ),
    );
    let no_grpc_header = settings
        .get("noGRPCHeader")
        .or_else(|| settings.get("noGrpcHeader"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !no_grpc_header {
        headers.insert("content-type".to_string(), "application/grpc".to_string());
    }
    Ok(headers)
}

fn keli_core_rs_route_outbound_server_endpoint(
    server: &Value,
) -> (
    Option<String>,
    Option<u16>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<u16>,
) {
    let address = outbound_string(server, "address");
    let port = server
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok());
    let user = server
        .get("users")
        .and_then(Value::as_array)
        .and_then(|users| users.first());
    let username = outbound_string(server, "username")
        .or_else(|| outbound_string(server, "user"))
        .or_else(|| user.and_then(|user| outbound_string(user, "user")))
        .or_else(|| user.and_then(|user| outbound_string(user, "username")))
        .or_else(|| user.and_then(|user| outbound_string(user, "id")));
    let password = outbound_string(server, "password")
        .or_else(|| outbound_string(server, "pass"))
        .or_else(|| user.and_then(|user| outbound_string(user, "pass")))
        .or_else(|| user.and_then(|user| outbound_string(user, "password")));
    let method = outbound_string(server, "method")
        .or_else(|| outbound_string(server, "cipher"))
        .or_else(|| outbound_string(server, "security"))
        .or_else(|| user.and_then(|user| outbound_string(user, "method")))
        .or_else(|| user.and_then(|user| outbound_string(user, "cipher")))
        .or_else(|| user.and_then(|user| outbound_string(user, "security")))
        .or_else(|| user.and_then(|user| outbound_string(user, "flow")));
    let alter_id = outbound_u16(server, "alter_id")
        .or_else(|| outbound_u16(server, "alterId"))
        .or_else(|| user.and_then(|user| outbound_u16(user, "alter_id")))
        .or_else(|| user.and_then(|user| outbound_u16(user, "alterId")));
    (address, port, username, password, method, alter_id)
}

fn parse_route_redirect_endpoint(value: &str) -> (Option<String>, Option<u16>) {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].trim();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|port| port.parse::<u16>().ok());
            return ((!host.is_empty()).then(|| host.to_string()), port);
        }
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            let host = host.trim().trim_matches(['[', ']']);
            return ((!host.is_empty()).then(|| host.to_string()), Some(port));
        }
    }
    (Some(value.trim_matches(['[', ']']).to_string()), None)
}

fn keli_core_rs_route_targets(
    inbound: &InboundPlan,
    route: &RoutePlan,
) -> Result<Vec<String>, CoreError> {
    route
        .match_rules
        .iter()
        .map(|rule| {
            let rule = rule.trim();
            if rule.is_empty() {
                return Err(CoreError::new(format!(
                    "keli-core-rs empty route rule on inbound {} is not supported",
                    inbound.tag
                )));
            }
            let normalized = rule.to_ascii_lowercase();
            if let Some(value) = normalized.strip_prefix("ip:") {
                if !is_keli_core_rs_ip_route_rule(value) {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("port:") {
                if !is_keli_core_rs_port_route_rule(value) {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("network:") {
                if !matches!(value.trim(), "tcp" | "udp") {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("domain:") {
                if value.trim().trim_start_matches('.').is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("full:") {
                if value.trim().trim_matches(['[', ']']).is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("keyword:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("geoip:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("geosite:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("regexp:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("protocol:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs route rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            }
            Ok(rule.to_string())
        })
        .collect()
}

fn keli_core_rs_block_route_targets(
    inbound: &InboundPlan,
    route: &RoutePlan,
) -> Result<Vec<String>, CoreError> {
    route
        .match_rules
        .iter()
        .map(|rule| {
            let rule = rule.trim();
            if rule.is_empty() {
                return Err(CoreError::new(format!(
                    "keli-core-rs empty block rule on inbound {} is not supported",
                    inbound.tag
                )));
            }
            let normalized = rule.to_ascii_lowercase();
            if let Some(value) = normalized.strip_prefix("ip:") {
                if !is_keli_core_rs_ip_route_rule(value) {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("port:") {
                if !is_keli_core_rs_port_route_rule(value) {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("network:") {
                if !matches!(value.trim(), "tcp" | "udp") {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("domain:") {
                if value.trim().trim_start_matches('.').is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("full:") {
                if value.trim().trim_matches(['[', ']']).is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("keyword:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("geoip:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("geosite:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("regexp:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            } else if let Some(value) = normalized.strip_prefix("protocol:") {
                if value.trim().is_empty() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs block rule {rule} on inbound {} is not supported yet",
                        inbound.tag
                    )));
                }
            }
            Ok(rule.to_string())
        })
        .collect()
}

fn prefixed_keli_core_rs_ip_route_targets(
    inbound: &InboundPlan,
    route: &RoutePlan,
) -> Result<Vec<String>, CoreError> {
    route
        .match_rules
        .iter()
        .map(|rule| {
            let rule = rule.trim();
            if !is_keli_core_rs_ip_route_rule(rule) {
                return Err(CoreError::new(format!(
                    "keli-core-rs block_ip rule {rule} on inbound {} is not supported yet",
                    inbound.tag
                )));
            }
            let normalized = rule.to_ascii_lowercase();
            if normalized.starts_with("geoip:") || normalized.starts_with("ip:geoip:") {
                Ok(rule.to_string())
            } else {
                Ok(format!("ip:{rule}"))
            }
        })
        .collect()
}

fn prefixed_keli_core_rs_protocol_route_targets(
    inbound: &InboundPlan,
    route: &RoutePlan,
) -> Result<Vec<String>, CoreError> {
    route
        .match_rules
        .iter()
        .map(|rule| {
            let rule = rule.trim();
            if rule.is_empty() {
                return Err(CoreError::new(format!(
                    "keli-core-rs protocol rule on inbound {} is not supported yet",
                    inbound.tag
                )));
            }
            Ok(format!("protocol:{rule}"))
        })
        .collect()
}

fn prefixed_keli_core_rs_port_route_targets(
    inbound: &InboundPlan,
    route: &RoutePlan,
) -> Result<Vec<String>, CoreError> {
    route
        .match_rules
        .iter()
        .map(|rule| {
            let rule = rule.trim();
            if !is_keli_core_rs_port_route_rule(rule) {
                return Err(CoreError::new(format!(
                    "keli-core-rs block_port rule {rule} on inbound {} is not supported yet",
                    inbound.tag
                )));
            }
            Ok(format!("port:{rule}"))
        })
        .collect()
}

fn is_keli_core_rs_ip_route_rule(rule: &str) -> bool {
    let rule = rule.trim().trim_matches(['[', ']']);
    if rule
        .to_ascii_lowercase()
        .strip_prefix("ip:")
        .is_some_and(|value| value.starts_with("geoip:"))
        || rule.to_ascii_lowercase().starts_with("geoip:")
    {
        return true;
    }
    if rule.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some((ip, prefix)) = rule.split_once('/') else {
        return false;
    };
    let Ok(ip) = ip.trim().parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.trim().parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

fn is_keli_core_rs_port_route_rule(rule: &str) -> bool {
    rule.split(',').all(|item| {
        let item = item.trim();
        if item.is_empty() {
            return false;
        }
        if let Some((start, end)) = item.split_once('-') {
            let Ok(start) = start.trim().parse::<u16>() else {
                return false;
            };
            let Ok(end) = end.trim().parse::<u16>() else {
                return false;
            };
            return start <= end;
        }
        item.parse::<u16>().is_ok()
    })
}

fn validate_keli_core_rs_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    validate_keli_core_rs_protocol_scoped_fields(inbound)?;
    match inbound.protocol.as_str() {
        "socks" | "http" => validate_keli_core_rs_plain_tcp_inbound(inbound),
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
            if inbound.security == "tls" {
                validate_keli_core_rs_tls_inbound(inbound)?;
            }
            Ok(())
        }
        "mieru" => {
            validate_keli_core_rs_plain_tcp_inbound(inbound)?;
            Ok(())
        }
        "naive" => validate_keli_core_rs_naive_inbound(inbound),
        "vless" | "trojan" | "vmess" => {
            validate_keli_core_rs_tcp_or_ws_inbound(inbound)?;
            Ok(())
        }
        "tuic" => validate_keli_core_rs_tuic_inbound(inbound),
        "hysteria" => validate_keli_core_rs_hysteria2_inbound(inbound),
        value => Err(CoreError::new(format!(
            "keli-core-rs native renderer only supports socks/http/shadowsocks/vmess/vless/trojan/anytls/mieru tcp, naive h2/h3 tls, vmess/vless/trojan ws/httpupgrade/grpc, tuic tcp/udp relay, and hysteria2 tcp/udp relay today; inbound {} uses {}",
            inbound.tag, value
        ))),
    }
}

fn validate_keli_core_rs_protocol_scoped_fields(inbound: &InboundPlan) -> Result<(), CoreError> {
    let protocol = inbound.protocol.as_str();
    if protocol != "shadowsocks" && !inbound.cipher.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} does not support cipher on inbound {}",
            inbound.tag
        )));
    }
    if protocol != "anytls" && !inbound.padding_scheme.is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} does not support paddingScheme on inbound {}",
            inbound.tag
        )));
    }

    let has_hysteria2_options = inbound.up_mbps > 0
        || inbound.down_mbps > 0
        || inbound.ignore_client_bandwidth
        || !inbound.obfs.trim().is_empty()
        || !inbound.obfs_password.trim().is_empty();
    if protocol != "hysteria" && has_hysteria2_options {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} does not support hysteria2 bandwidth/obfs options on inbound {}",
            inbound.tag
        )));
    }

    if !inbound.congestion_control.trim().is_empty() && !matches!(protocol, "tuic" | "hysteria") {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} does not support congestion_control on inbound {}",
            inbound.tag
        )));
    }
    if protocol != "tuic" && inbound.zero_rtt_handshake {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} does not support tuic zero-rtt options on inbound {}",
            inbound.tag
        )));
    }

    Ok(())
}

fn validate_keli_core_rs_plain_tcp_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let protocol = inbound.protocol.as_str();
    let network = first_non_empty(inbound.network.trim(), "tcp").to_ascii_lowercase();
    let network_supported = if protocol == "shadowsocks" {
        matches!(network.as_str(), "tcp" | "tcp,udp")
    } else {
        network == "tcp"
    };
    if !network_supported {
        let expected = if protocol == "shadowsocks" {
            "tcp or tcp,udp"
        } else {
            "tcp"
        };
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only {expected} transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if inbound.security != "none" && !(protocol == "anytls" && inbound.security == "tls") {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only security none{}; inbound {} uses {}",
            if protocol == "anytls" { "/tls" } else { "" },
            inbound.tag,
            inbound.security
        )));
    }
    if protocol != "mieru" && !inbound.port_range.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only a single port; inbound {} uses port range {}",
            inbound.tag, inbound.port_range
        )));
    }
    validate_keli_core_rs_flow(inbound, &network)?;
    if !json_value_is_empty(&inbound.network_settings) {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently does not support transport settings on inbound {}",
            inbound.tag
        )));
    }
    Ok(())
}

fn validate_keli_core_rs_naive_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let network = first_non_empty(inbound.network.trim(), "tcp").to_ascii_lowercase();
    if !matches!(network.as_str(), "tcp" | "quic") {
        return Err(CoreError::new(format!(
            "keli-core-rs naive currently supports only tcp or quic transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if inbound.security != "tls" {
        return Err(CoreError::new(format!(
            "keli-core-rs naive currently requires tls security; inbound {} uses {}",
            inbound.tag, inbound.security
        )));
    }
    validate_keli_core_rs_tls_inbound(inbound)?;
    if !inbound.port_range.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs naive currently supports only a single port; inbound {} uses port range {}",
            inbound.tag, inbound.port_range
        )));
    }
    if !inbound.flow.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs naive does not support flow; inbound {} uses {}",
            inbound.tag, inbound.flow
        )));
    }
    if !json_value_is_empty(&inbound.network_settings) {
        return Err(CoreError::new(format!(
            "keli-core-rs naive currently does not support transport settings on inbound {}",
            inbound.tag
        )));
    }
    Ok(())
}

fn validate_keli_core_rs_tcp_or_ws_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let protocol = inbound.protocol.as_str();
    let network = keli_core_rs_transport_network(inbound);
    if !matches!(network.as_str(), "tcp" | "ws" | "httpupgrade" | "grpc") {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only tcp/ws/httpupgrade/grpc transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if !matches!(inbound.security.as_str(), "none" | "tls" | "reality") {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} currently supports only security none/tls/reality; inbound {} uses {}",
            inbound.tag, inbound.security
        )));
    }
    if inbound.security == "reality" {
        validate_keli_core_rs_reality_inbound(inbound)?;
    } else if inbound.security == "tls" {
        validate_keli_core_rs_tls_inbound(inbound)?;
    }
    validate_keli_core_rs_flow(inbound, &network)?;
    if network == "tcp" {
        if !json_value_is_empty(&inbound.network_settings) {
            return Err(CoreError::new(format!(
                "keli-core-rs {protocol} currently does not support transport settings on tcp inbound {}",
                inbound.tag
            )));
        }
        return Ok(());
    }

    if network == "grpc" {
        validate_keli_core_rs_grpc_transport_settings(inbound)
    } else {
        validate_keli_core_rs_http_transport_settings(inbound, &network)
    }
}

fn validate_keli_core_rs_flow(inbound: &InboundPlan, network: &str) -> Result<(), CoreError> {
    let flow = inbound.flow.trim();
    if flow.is_empty() {
        return Ok(());
    }
    if inbound.protocol != "vless" {
        return Err(CoreError::new(format!(
            "keli-core-rs {} currently does not support flow {}; inbound {}",
            inbound.protocol, inbound.flow, inbound.tag
        )));
    }
    if flow != "xtls-rprx-vision" {
        return Err(CoreError::new(format!(
            "keli-core-rs vless currently supports only xtls-rprx-vision flow; inbound {} uses {}",
            inbound.tag, inbound.flow
        )));
    }
    if network != "tcp" {
        return Err(CoreError::new(format!(
            "keli-core-rs vless vision currently requires tcp transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if !matches!(inbound.security.as_str(), "tls" | "reality") {
        return Err(CoreError::new(format!(
            "keli-core-rs vless vision currently requires tls or reality security; inbound {} uses {}",
            inbound.tag, inbound.security
        )));
    }
    Ok(())
}

fn validate_keli_core_rs_reality_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let network = keli_core_rs_transport_network(inbound);
    if inbound.protocol != "vless" {
        return Err(CoreError::new(format!(
            "keli-core-rs reality currently supports only vless; inbound {} uses {}",
            inbound.tag, inbound.protocol
        )));
    }
    if network != "tcp" {
        return Err(CoreError::new(format!(
            "keli-core-rs vless reality currently requires tcp transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if inbound.server_name.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs vless reality requires server_name on inbound {}",
            inbound.tag
        )));
    }
    if inbound.reality_dest.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs vless reality requires dest on inbound {}",
            inbound.tag
        )));
    }
    if inbound.reality_private_key.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs vless reality requires private_key on inbound {}",
            inbound.tag
        )));
    }
    if inbound.reality_short_id.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs vless reality requires short_id on inbound {}",
            inbound.tag
        )));
    }
    if !inbound.reality_mldsa65_seed.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs vless reality mldsa65Seed is not supported yet on inbound {}",
            inbound.tag
        )));
    }
    Ok(())
}

fn validate_keli_core_rs_tls_inbound(inbound: &InboundPlan) -> Result<(), CoreError> {
    let protocol = inbound.protocol.as_str();
    let network = keli_core_rs_transport_network(inbound);
    let supports_transport = matches!(network.as_str(), "tcp" | "ws" | "httpupgrade" | "grpc")
        || (protocol == "naive" && network == "quic");
    if !supports_transport {
        let expected = if protocol == "naive" {
            "tcp/quic"
        } else {
            "tcp/ws/httpupgrade/grpc"
        };
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} tls currently supports only {expected} transport; inbound {} uses {}",
            inbound.tag, network
        )));
    }
    if inbound.cert_file.trim().is_empty() || inbound.key_file.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} tls requires cert_file and key_file on inbound {}",
            inbound.tag
        )));
    }
    if inbound.reject_unknown_sni && inbound.server_name.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs {protocol} reject_unknown_sni requires server_name on inbound {}",
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
    if inbound.reject_unknown_sni && inbound.server_name.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic reject_unknown_sni requires server_name on inbound {}",
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
    let congestion = inbound.congestion_control.trim();
    if !congestion.is_empty() && !is_keli_core_rs_quic_congestion_supported(congestion) {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic congestion_control {} is not supported on inbound {}",
            inbound.congestion_control, inbound.tag
        )));
    }
    if inbound.zero_rtt_handshake {
        return Err(CoreError::new(format!(
            "keli-core-rs tuic currently does not support zero-rtt on inbound {}",
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

fn is_keli_core_rs_quic_congestion_supported(value: &str) -> bool {
    matches!(
        value
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_")
            .as_str(),
        "" | "cubic" | "bbr" | "new_reno" | "newreno" | "reno"
    )
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
    if inbound.reject_unknown_sni && inbound.server_name.trim().is_empty() {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 reject_unknown_sni requires server_name on inbound {}",
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
    let congestion = inbound.congestion_control.trim();
    if !congestion.is_empty() && !is_keli_core_rs_quic_congestion_supported(congestion) {
        return Err(CoreError::new(format!(
            "keli-core-rs hysteria2 congestion_control {} is not supported on inbound {}",
            inbound.congestion_control, inbound.tag
        )));
    }
    let obfs = inbound.obfs.trim();
    let obfs_password = inbound.obfs_password.trim();
    if !obfs.is_empty() || !obfs_password.is_empty() {
        if !obfs.eq_ignore_ascii_case("salamander") {
            return Err(CoreError::new(format!(
                "keli-core-rs hysteria2 only supports salamander obfs on inbound {}",
                inbound.tag
            )));
        }
        if obfs_password.len() < 4 {
            return Err(CoreError::new(format!(
                "keli-core-rs hysteria2 salamander obfs password must be at least 4 bytes on inbound {}",
                inbound.tag
            )));
        }
    }
    Ok(())
}

fn validate_keli_core_rs_http_transport_settings(
    inbound: &InboundPlan,
    network: &str,
) -> Result<(), CoreError> {
    if json_value_is_empty(&inbound.network_settings) {
        return Ok(());
    }
    let Some(settings) = inbound.network_settings.as_object() else {
        return Err(CoreError::new(format!(
            "keli-core-rs {network} settings on inbound {} must be an object",
            inbound.tag,
        )));
    };
    for (key, value) in settings {
        match key.as_str() {
            "path" | "Host" | "host" => {
                if !value.is_string() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs {network} setting {key} on inbound {} must be a string",
                        inbound.tag,
                    )));
                }
            }
            "headers" => validate_keli_core_rs_http_transport_headers(inbound, network, value)?,
            "ipaddress" | "ipAddress" | "ip_address" => {}
            _ => {
                return Err(CoreError::new(format!(
                    "keli-core-rs {network} setting {key} on inbound {} is not supported yet",
                    inbound.tag,
                )));
            }
        }
    }
    Ok(())
}

fn validate_keli_core_rs_http_transport_headers(
    inbound: &InboundPlan,
    network: &str,
    headers: &Value,
) -> Result<(), CoreError> {
    let Some(headers) = headers.as_object() else {
        return Err(CoreError::new(format!(
            "keli-core-rs {network} headers on inbound {} must be an object",
            inbound.tag,
        )));
    };
    for (key, value) in headers {
        if !matches!(key.as_str(), "Host" | "host") {
            return Err(CoreError::new(format!(
                "keli-core-rs {network} header {key} on inbound {} is not supported yet",
                inbound.tag,
            )));
        }
        if !value.is_string() {
            return Err(CoreError::new(format!(
                "keli-core-rs {network} header {key} on inbound {} must be a string",
                inbound.tag,
            )));
        }
    }
    Ok(())
}

fn validate_keli_core_rs_grpc_transport_settings(inbound: &InboundPlan) -> Result<(), CoreError> {
    if json_value_is_empty(&inbound.network_settings) {
        return Ok(());
    }
    let Some(settings) = inbound.network_settings.as_object() else {
        return Err(CoreError::new(format!(
            "keli-core-rs grpc settings on inbound {} must be an object",
            inbound.tag
        )));
    };
    for (key, value) in settings {
        match key.as_str() {
            "serviceName" | "service_name" => {
                if !value.is_string() {
                    return Err(CoreError::new(format!(
                        "keli-core-rs grpc setting {key} on inbound {} must be a string",
                        inbound.tag
                    )));
                }
            }
            "multiMode" | "multi_mode" => {
                if value.as_bool().unwrap_or(false) {
                    return Err(CoreError::new(format!(
                        "keli-core-rs grpc TunMulti is not supported yet on inbound {}",
                        inbound.tag
                    )));
                }
            }
            _ => {
                return Err(CoreError::new(format!(
                    "keli-core-rs grpc setting {key} on inbound {} is not supported yet",
                    inbound.tag
                )));
            }
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
        cipher
            .trim()
            .to_ascii_lowercase()
            .replace('_', "-")
            .as_str(),
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

fn render_keli_core_rs_inbound(inbound: &InboundPlan) -> Result<Value, CoreError> {
    Ok(json!({
        "tag": &inbound.tag,
        "protocol": keli_core_rs_protocol_name(inbound),
        "listen": &inbound.listen,
        "port": inbound.port,
        "cipher": if inbound.protocol == "shadowsocks" {
            Value::String(inbound.cipher.clone())
        } else {
            Value::Null
        },
        "flow": &inbound.flow,
        "padding_scheme": &inbound.padding_scheme,
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
        },
        "routes": render_keli_core_rs_routes_for_inbound(inbound)?
    }))
}

fn render_keli_core_rs_inbounds(inbounds: &[InboundPlan]) -> Result<Vec<Value>, CoreError> {
    let mut rendered = Vec::new();
    for inbound in inbounds {
        for expanded in expand_keli_core_rs_inbound(inbound)? {
            rendered.push(render_keli_core_rs_inbound(&expanded)?);
        }
    }
    Ok(rendered)
}

fn expand_keli_core_rs_inbound(inbound: &InboundPlan) -> Result<Vec<InboundPlan>, CoreError> {
    if inbound.protocol != "mieru" || inbound.port_range.trim().is_empty() {
        return Ok(vec![inbound.clone()]);
    }
    let ports = parse_keli_core_rs_port_range(&inbound.port_range).map_err(|message| {
        CoreError::new(format!(
            "keli-core-rs mieru port range on inbound {} is invalid: {message}",
            inbound.tag
        ))
    })?;
    Ok(ports
        .into_iter()
        .map(|port| {
            let mut expanded = inbound.clone();
            expanded.tag = format!("{}|port:{port}", inbound.tag);
            expanded.port = port;
            expanded.port_range.clear();
            expanded
        })
        .collect())
}

pub(crate) fn parse_keli_core_rs_port_range(raw: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    let mut seen = BTreeSet::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (start, end) = if let Some((start, end)) = token.split_once('-') {
            let start = start
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("bad port range start {token}"))?;
            let end = end
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("bad port range end {token}"))?;
            if start > end {
                return Err(format!("range start is greater than end in {token}"));
            }
            (start, end)
        } else {
            let port = token
                .parse::<u16>()
                .map_err(|_| format!("bad port {token}"))?;
            (port, port)
        };
        for port in start..=end {
            if seen.insert(port) {
                ports.push(port);
            }
            if ports.len() > 2048 {
                return Err("port range expands to more than 2048 ports".to_string());
            }
        }
    }
    if ports.is_empty() {
        return Err("empty port range".to_string());
    }
    Ok(ports)
}

fn keli_core_rs_protocol_name(inbound: &InboundPlan) -> &str {
    if inbound.protocol == "hysteria" {
        "hysteria2"
    } else {
        &inbound.protocol
    }
}

fn render_keli_core_rs_tls(inbound: &InboundPlan) -> Value {
    if !matches!(inbound.security.as_str(), "tls" | "reality") {
        return Value::Null;
    }
    let reality = if inbound.security == "reality" {
        json!({
            "dest": &inbound.reality_dest,
            "server_port": null,
            "private_key": &inbound.reality_private_key,
            "short_id": &inbound.reality_short_id,
            "xver": inbound.reality_xver,
            "mldsa65_seed": if inbound.reality_mldsa65_seed.trim().is_empty() {
                Value::Null
            } else {
                Value::String(inbound.reality_mldsa65_seed.clone())
            }
        })
    } else {
        Value::Null
    };
    json!({
        "server_name": &inbound.server_name,
        "cert_file": if inbound.security == "tls" {
            Value::String(inbound.cert_file.clone())
        } else {
            Value::Null
        },
        "key_file": if inbound.security == "tls" {
            Value::String(inbound.key_file.clone())
        } else {
            Value::Null
        },
        "alpn": &inbound.alpn,
        "reject_unknown_sni": inbound.reject_unknown_sni,
        "reality": reality
    })
}

fn render_keli_core_rs_transport(inbound: &InboundPlan) -> Value {
    let network = keli_core_rs_transport_network(inbound);
    let mut transport = Map::new();
    transport.insert("network".to_string(), Value::String(network.clone()));
    transport.insert(
        "path".to_string(),
        if matches!(network.as_str(), "ws" | "httpupgrade") {
            websocket_path_setting(&inbound.network_settings)
                .map(Value::String)
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    transport.insert(
        "host".to_string(),
        if matches!(network.as_str(), "ws" | "httpupgrade") {
            websocket_host_setting(&inbound.network_settings)
                .map(Value::String)
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    transport.insert(
        "service_name".to_string(),
        if network == "grpc" {
            grpc_service_name_setting(&inbound.network_settings)
                .map(Value::String)
                .unwrap_or_else(|| Value::String("GunService".to_string()))
        } else {
            Value::Null
        },
    );
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
        if !inbound.obfs.trim().is_empty() {
            transport.insert(
                "obfs".to_string(),
                Value::String(inbound.obfs.trim().to_string()),
            );
        }
        if !inbound.obfs_password.trim().is_empty() {
            transport.insert(
                "obfs_password".to_string(),
                Value::String(inbound.obfs_password.trim().to_string()),
            );
        }
    }

    if matches!(inbound.protocol.as_str(), "tuic" | "hysteria")
        && !inbound.congestion_control.trim().is_empty()
    {
        transport.insert(
            "congestion_control".to_string(),
            Value::String(inbound.congestion_control.trim().to_string()),
        );
    }

    Value::Object(transport)
}

fn keli_core_rs_transport_network(inbound: &InboundPlan) -> String {
    if inbound.protocol == "shadowsocks" && inbound.network.trim().is_empty() {
        return "tcp,udp".to_string();
    }
    match first_non_empty(inbound.network.trim(), "tcp")
        .to_ascii_lowercase()
        .as_str()
    {
        "websocket" => "ws".to_string(),
        "http_upgrade" | "http-upgrade" | "httpupgrade" => "httpupgrade".to_string(),
        "gun" => "grpc".to_string(),
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

fn grpc_service_name_setting(settings: &Value) -> Option<String> {
    network_setting_string(settings, &["serviceName", "service_name"])
}

fn network_setting_string(settings: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| settings.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn render_keli_core_rs_user(user: &InboundUserPlan) -> Value {
    json!({
        "id": user.id,
        "uuid": &user.uuid,
        "password": null,
        "email": null,
        "speed_limit": user.speed_limit,
        "device_limit": user.device_limit
    })
}

pub fn write_core_config(plan: &CorePlan) -> Result<CoreConfigWriteResult, CoreError> {
    ensure_core_plan_certificates(plan)?;

    let content = render_keli_core_rs_config_bytes(plan)?;
    write_core_config_bytes(&plan.config_path, content, plan.inbounds.len())
}

#[derive(Serialize)]
struct KeliCoreRsUserRef<'a> {
    id: u32,
    uuid: &'a str,
    password: Option<&'a str>,
    email: Option<&'a str>,
    speed_limit: u32,
    device_limit: u32,
}

fn render_keli_core_rs_config_bytes(plan: &CorePlan) -> Result<Vec<u8>, CoreError> {
    let mut outbounds = vec![json!({
        "tag": "direct",
        "protocol": "freedom",
        "address": null,
        "port": null
    })];
    for inbound in &plan.inbounds {
        validate_keli_core_rs_inbound(inbound)?;
        collect_keli_core_rs_route_outbounds(inbound, &mut outbounds)?;
    }

    let mut content = Vec::new();
    content.extend_from_slice(b"{");
    write_json_field(
        &mut content,
        "instance_id",
        &keli_core_rs_instance_id(plan),
        true,
    )?;
    write_json_field(&mut content, "log_level", &"info", false)?;
    write_json_field(&mut content, "policy", &render_keli_core_rs_policy(), false)?;
    write_json_field(&mut content, "dns", &render_keli_core_rs_dns(plan)?, false)?;
    content.extend_from_slice(br#","inbounds":["#);
    let mut first_inbound = true;
    for inbound in &plan.inbounds {
        for expanded in expand_keli_core_rs_inbound(inbound)? {
            if !first_inbound {
                content.push(b',');
            }
            write_keli_core_rs_inbound(&mut content, &expanded)?;
            first_inbound = false;
        }
    }
    content.push(b']');
    write_json_field(&mut content, "outbounds", &outbounds, false)?;
    write_json_field(&mut content, "routes", &Vec::<Value>::new(), false)?;
    write_json_field(
        &mut content,
        "stats",
        &json!({
            "enabled": true,
            "per_user": true
        }),
        false,
    )?;
    content.extend_from_slice(b"}\n");
    Ok(content)
}

fn write_keli_core_rs_inbound<W: Write>(
    writer: &mut W,
    inbound: &InboundPlan,
) -> Result<(), CoreError> {
    writer
        .write_all(b"{")
        .map_err(|err| CoreError::new(format!("encode keli-core-rs inbound: {err}")))?;
    write_json_field(writer, "tag", &inbound.tag, true)?;
    write_json_field(
        writer,
        "protocol",
        &keli_core_rs_protocol_name(inbound),
        false,
    )?;
    write_json_field(writer, "listen", &inbound.listen, false)?;
    write_json_field(writer, "port", &inbound.port, false)?;
    let cipher = if inbound.protocol == "shadowsocks" {
        Value::String(inbound.cipher.clone())
    } else {
        Value::Null
    };
    write_json_field(writer, "cipher", &cipher, false)?;
    write_json_field(writer, "flow", &inbound.flow, false)?;
    write_json_field(writer, "padding_scheme", &inbound.padding_scheme, false)?;
    writer
        .write_all(br#","users":["#)
        .map_err(|err| CoreError::new(format!("encode keli-core-rs users: {err}")))?;
    for (idx, user) in inbound.users.iter().enumerate() {
        if idx > 0 {
            writer
                .write_all(b",")
                .map_err(|err| CoreError::new(format!("encode keli-core-rs users: {err}")))?;
        }
        let user = KeliCoreRsUserRef {
            id: user.id,
            uuid: &user.uuid,
            password: None,
            email: None,
            speed_limit: user.speed_limit,
            device_limit: user.device_limit,
        };
        serde_json::to_writer(&mut *writer, &user)
            .map_err(|err| CoreError::new(format!("encode keli-core-rs user: {err}")))?;
    }
    writer
        .write_all(b"]")
        .map_err(|err| CoreError::new(format!("encode keli-core-rs users: {err}")))?;
    write_json_field(
        writer,
        "transport",
        &render_keli_core_rs_transport(inbound),
        false,
    )?;
    write_json_field(writer, "tls", &render_keli_core_rs_tls(inbound), false)?;
    write_json_field(
        writer,
        "sniffing",
        &json!({
            "enabled": true,
            "dest_override": ["http", "tls"]
        }),
        false,
    )?;
    write_json_field(
        writer,
        "routes",
        &render_keli_core_rs_routes_for_inbound(inbound)?,
        false,
    )?;
    writer
        .write_all(b"}")
        .map_err(|err| CoreError::new(format!("encode keli-core-rs inbound: {err}")))?;
    Ok(())
}

fn write_json_field<W, T>(
    writer: &mut W,
    name: &str,
    value: &T,
    first: bool,
) -> Result<(), CoreError>
where
    W: Write,
    T: Serialize + ?Sized,
{
    if !first {
        writer
            .write_all(b",")
            .map_err(|err| CoreError::new(format!("encode core config field {name}: {err}")))?;
    }
    serde_json::to_writer(&mut *writer, name)
        .map_err(|err| CoreError::new(format!("encode core config field {name}: {err}")))?;
    writer
        .write_all(b":")
        .map_err(|err| CoreError::new(format!("encode core config field {name}: {err}")))?;
    serde_json::to_writer(writer, value)
        .map_err(|err| CoreError::new(format!("encode core config field {name}: {err}")))
}

fn ensure_core_plan_certificates(plan: &CorePlan) -> Result<(), CoreError> {
    for inbound in &plan.inbounds {
        ensure_inbound_certificate_pair(inbound)?;
    }
    Ok(())
}

fn ensure_inbound_certificate_pair(inbound: &InboundPlan) -> Result<(), CoreError> {
    if !inbound.security.eq_ignore_ascii_case("tls") {
        return Ok(());
    }

    let cert_file = inbound.cert_file.trim();
    let key_file = inbound.key_file.trim();
    if cert_file.is_empty() || key_file.is_empty() {
        return Ok(());
    }

    let cert_path = Path::new(cert_file);
    let key_path = Path::new(key_file);
    if certificate_pair_looks_usable(cert_path, key_path) {
        return Ok(());
    }

    let domain = self_signed_certificate_name(inbound);
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![domain.clone()])
        .map_err(|err| {
            CoreError::new(format!(
                "generate self-signed certificate for inbound {} domain {domain}: {err}",
                inbound.tag
            ))
        })?;
    write_certificate_file(cert_path, cert.pem().as_bytes(), false)?;
    write_certificate_file(key_path, key_pair.serialize_pem().as_bytes(), true)?;
    logging::warn(
        "core",
        format!(
            "generated fallback self-signed certificate inbound={} domain={}",
            inbound.tag, domain
        ),
    );

    Ok(())
}

fn self_signed_certificate_name(inbound: &InboundPlan) -> String {
    normalize_certificate_name(&inbound.server_name)
        .or_else(|| normalize_certificate_name(&inbound.reality_dest))
        .unwrap_or_else(|| "localhost".to_string())
}

fn normalize_certificate_name(value: &str) -> Option<String> {
    let mut name = value.trim().trim_matches('"').trim_matches('\'').trim();
    if name.is_empty() {
        return None;
    }

    if let Some(rest) = name.strip_prefix('[') {
        if let Some((inside, _)) = rest.split_once(']') {
            name = inside.trim();
        }
    } else if name.matches(':').count() == 1 {
        if let Some((host, port)) = name.rsplit_once(':') {
            if !host.trim().is_empty() && port.chars().all(|character| character.is_ascii_digit()) {
                name = host.trim();
            }
        }
    }

    let name = name.trim_end_matches('.').trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn certificate_pair_looks_usable(cert_path: &Path, key_path: &Path) -> bool {
    certificate_file_looks_usable(cert_path) && private_key_file_looks_usable(key_path)
}

fn certificate_file_looks_usable(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut reader = std::io::BufReader::new(file);
    let Ok(certs) = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>() else {
        return false;
    };
    !certs.is_empty()
}

fn private_key_file_looks_usable(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .ok()
        .flatten()
        .is_some()
}

fn write_certificate_file(path: &Path, content: &[u8], private: bool) -> Result<(), CoreError> {
    #[cfg(not(unix))]
    let _ = private;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            CoreError::new(format!(
                "create certificate dir {}: {err}",
                parent.display()
            ))
        })?;
    }

    let temp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("pem")
    ));
    fs::write(&temp_path, content).map_err(|err| {
        CoreError::new(format!(
            "write certificate temp {}: {err}",
            temp_path.display()
        ))
    })?;
    replace_file(&temp_path, path)
        .map_err(|err| CoreError::new(format!("replace certificate {}: {err}", path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private { 0o600 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|err| {
            CoreError::new(format!(
                "set certificate permissions {}: {err}",
                path.display()
            ))
        })?;
    }

    Ok(())
}

pub fn write_core_config_value(
    path: impl AsRef<Path>,
    value: &Value,
    inbound_count: usize,
) -> Result<CoreConfigWriteResult, CoreError> {
    let path = path.as_ref();
    let mut content = serde_json::to_vec_pretty(value)
        .map_err(|err| CoreError::new(format!("encode core config {}: {err}", path.display())))?;
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
    replace_file(&layout.temp_config_path, path)
        .map_err(|err| CoreError::new(format!("replace core config {}: {err}", path.display())))?;

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
        multiplexing: node.common.multiplexing.trim().to_string(),
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
        "" => "0.0.0.0".to_string(),
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
    } else if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
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
        build_inbound_plan, core_file_layout, core_kind_from_name, render_core_config,
        resolve_node_listen_ip, should_fallback_node_listen_ip, split_core_plans_for_nodes,
        split_core_plans_for_nodes_with_kind, write_core_config, CoreKind, CorePlan,
    };
    use crate::panel::types::{
        CertInfo, CommonNode, NodeInfo, PortValue, Route, Security, UserInfo,
    };

    #[test]
    fn parses_kernel_core_kind_names() {
        assert_eq!(core_kind_from_name("").unwrap(), CoreKind::KeliCoreRs);
        assert_eq!(
            core_kind_from_name("keli_core_rs").unwrap(),
            CoreKind::KeliCoreRs
        );
        assert!(core_kind_from_name(" xray ").is_err());
        assert!(core_kind_from_name("unknown").is_err());
    }

    #[test]
    fn core_plan_builds_inbounds_from_nodes() {
        let node = test_node("vless", 1, "0.0.0.0");

        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/etc/v2node/config.json"),
            &[node],
        )
        .unwrap();

        assert_eq!(plan.listen_tags.len(), 1);
        assert_eq!(plan.inbounds[0].listen, "0.0.0.0");
        assert!(plan.inbounds[0].fallback_to_ipv4);
    }

    #[test]
    fn default_split_uses_native_core_plan() {
        let mieru = test_node("mieru", 35, "");
        let mieru_tag = mieru.tag.clone();
        let nodes = vec![test_node("vless", 34, ""), mieru];
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            mieru_tag,
            vec![UserInfo {
                id: 35,
                uuid: "mieru-secret".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let bundle =
            split_core_plans_for_nodes(PathBuf::from("/srv/v2node/config.json"), &nodes, &users)
                .unwrap();

        let core = bundle.core.unwrap();
        assert_eq!(core.kind, CoreKind::KeliCoreRs);
        assert_eq!(core.inbounds.len(), 2);
        assert_eq!(core.inbounds[0].protocol, "vless");
        assert_eq!(core.inbounds[1].protocol, "mieru");
    }

    #[test]
    fn keeps_mieru_and_naive_native_for_keli_core_rs() {
        let mieru = test_node("mieru", 35, "");
        let mieru_tag = mieru.tag.clone();
        let mut naive = test_node("naive", 36, "");
        let naive_tag = naive.tag.clone();
        naive.security = Security::Tls;
        naive.common.tls = 1;
        naive.common.cert_info = Some(CertInfo {
            cert_mode: "file".to_string(),
            cert_file: "/tmp/naive.crt".to_string(),
            key_file: "/tmp/naive.key".to_string(),
            cert_domain: "naive.example.test".to_string(),
            dns_env: Default::default(),
            provider: String::new(),
            reject_unknown_sni: false,
        });
        let nodes = vec![test_node("vless", 34, ""), mieru, naive];
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            mieru_tag,
            vec![UserInfo {
                id: 35,
                uuid: "mieru-secret".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        users.insert(
            naive_tag,
            vec![UserInfo {
                id: 36,
                uuid: "naive-password".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let bundle = split_core_plans_for_nodes_with_kind(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/config.json"),
            &nodes,
            &users,
        )
        .unwrap();

        let core = bundle.core.unwrap();
        assert_eq!(core.kind, CoreKind::KeliCoreRs);
        assert_eq!(core.inbounds.len(), 3);
        assert_eq!(core.inbounds[0].protocol, "vless");
        assert_eq!(core.inbounds[1].protocol, "mieru");
        assert_eq!(core.inbounds[2].protocol, "naive");
    }

    #[test]
    fn keli_core_rs_skips_unsupported_native_inbounds_without_dropping_supported_nodes() {
        let supported = test_node("vless", 41, "");
        let mut unsupported = test_node("anytls", 42, "");
        unsupported.common.network = "ws".to_string();

        let nodes = vec![supported, unsupported];
        let bundle = split_core_plans_for_nodes_with_kind(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/config.json"),
            &nodes,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();

        let core = bundle.core.unwrap();
        assert_eq!(core.kind, CoreKind::KeliCoreRs);
        assert_eq!(core.inbounds.len(), 1);
        assert_eq!(core.inbounds[0].protocol, "vless");
    }

    #[test]
    fn keli_core_rs_waits_for_users_before_rendering_user_required_inbounds() {
        let supported_without_users = test_node("vless", 43, "");
        let mut anytls = test_node("anytls", 44, "");
        anytls.security = Security::Tls;
        anytls.common.tls = 1;
        anytls.common.cert_info = Some(CertInfo {
            cert_mode: "file".to_string(),
            cert_file: "/tmp/anytls.crt".to_string(),
            key_file: "/tmp/anytls.key".to_string(),
            cert_domain: "anytls.example.test".to_string(),
            dns_env: Default::default(),
            provider: String::new(),
            reject_unknown_sni: false,
        });
        let anytls_tag = anytls.tag.clone();
        let nodes = vec![supported_without_users, anytls.clone()];

        let cold_bundle = split_core_plans_for_nodes_with_kind(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/config.json"),
            &nodes,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();

        let cold_core = cold_bundle.core.unwrap();
        assert_eq!(cold_core.inbounds.len(), 1);
        assert_eq!(cold_core.inbounds[0].protocol, "vless");

        let mut users = std::collections::BTreeMap::new();
        users.insert(
            anytls_tag,
            vec![UserInfo {
                id: 44,
                uuid: "anytls-password".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let warm_bundle = split_core_plans_for_nodes_with_kind(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/config.json"),
            &nodes,
            &users,
        )
        .unwrap();

        let warm_core = warm_bundle.core.unwrap();
        assert_eq!(warm_core.inbounds.len(), 2);
        assert_eq!(warm_core.inbounds[0].protocol, "vless");
        assert_eq!(warm_core.inbounds[1].protocol, "anytls");
    }

    #[test]
    fn renders_keli_core_rs_mieru_inbound() {
        let node = test_node("mieru", 40, "");
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 40,
                uuid: "mieru-secret".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "mieru");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "tcp");
        assert_eq!(config["inbounds"][0]["users"][0]["uuid"], "mieru-secret");
        assert!(config["inbounds"][0]["users"][0]["password"].is_null());
    }

    #[test]
    fn renders_keli_core_rs_mieru_default_out_as_wildcard_http_outbound() {
        let mut node = test_node("mieru", 42, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: Vec::new(),
            action: "default_out".to_string(),
            action_value: Some(
                r#"{"tag":"http-out","protocol":"http","address":"127.0.0.1","port":8080}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "mieru");
        assert_eq!(config["inbounds"][0]["routes"][0]["targets"][0], "*");
        assert_eq!(
            config["inbounds"][0]["routes"][0]["action"]["outbound"],
            "http-out"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["protocol"],
            "http"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["address"],
            "127.0.0.1"
        );
        assert_eq!(config["inbounds"][0]["routes"][0]["outbound"]["port"], 8080);
    }

    #[test]
    fn keli_core_rs_expands_mieru_port_range_inbounds() {
        let mut node = test_node("mieru", 41, "");
        node.common.ports = PortValue("2100-2102".to_string());
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"].as_array().unwrap().len(), 3);
        assert_eq!(config["inbounds"][0]["port"], 2100);
        assert_eq!(
            config["inbounds"][0]["tag"],
            "[https://panel.example.test]-mieru:41|port:2100"
        );
        assert_eq!(config["inbounds"][2]["port"], 2102);
    }

    #[test]
    fn keli_core_rs_accepts_mieru_multiplexing_modes() {
        let mut node = test_node("mieru", 43, "");
        node.common.multiplexing = "MULTIPLEXING_HIGH".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/config.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "mieru");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "tcp");
    }

    #[test]
    fn renders_keli_core_rs_native_socks_http_shadowsocks_vmess_vless_trojan_anytls_naive_config_from_panel_users(
    ) {
        let socks = test_node("socks", 40, "");
        let http = test_node("http", 41, "127.0.0.1");
        let mut shadowsocks = test_node("shadowsocks", 54, "127.0.0.1");
        shadowsocks.common.cipher = "aes-128-gcm".to_string();
        let vmess = test_node("vmess", 43, "127.0.0.1");
        let vless = test_node("vless", 45, "127.0.0.1");
        let trojan = test_node("trojan", 50, "127.0.0.1");
        let anytls = test_node("anytls", 58, "127.0.0.1");
        let mut naive = test_node("naive", 61, "127.0.0.1");
        naive.security = Security::Tls;
        naive.common.tls = 1;
        naive.common.cert_info = Some(CertInfo {
            cert_mode: "file".to_string(),
            cert_file: "/srv/v2node/naive.cer".to_string(),
            key_file: "/srv/v2node/naive.key".to_string(),
            cert_domain: "naive.example.test".to_string(),
            dns_env: Default::default(),
            provider: String::new(),
            reject_unknown_sni: false,
        });
        let socks_tag = socks.tag.clone();
        let http_tag = http.tag.clone();
        let shadowsocks_tag = shadowsocks.tag.clone();
        let vmess_tag = vmess.tag.clone();
        let vless_tag = vless.tag.clone();
        let trojan_tag = trojan.tag.clone();
        let anytls_tag = anytls.tag.clone();
        let naive_tag = naive.tag.clone();
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
        users.insert(
            naive_tag,
            vec![UserInfo {
                id: 61,
                uuid: "naive-password".to_string(),
                speed_limit: 5120,
                device_limit: 6,
            }],
        );
        let plan = CorePlan::from_nodes_with_users(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[
                socks,
                http,
                shadowsocks,
                vmess,
                vless,
                trojan,
                anytls,
                naive,
            ],
            &users,
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["instance_id"], "keli-core-rs");
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
        assert_eq!(config["inbounds"][0]["listen"], "0.0.0.0");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "tcp");
        assert_eq!(config["inbounds"][0]["users"][0]["uuid"], "socks-user");
        assert_eq!(config["inbounds"][0]["users"][0]["email"], json!(null));
        assert_eq!(plan.inbounds[0].users[0].email, "");
        assert_eq!(config["inbounds"][0]["users"][0]["speed_limit"], 1024);
        assert_eq!(config["inbounds"][0]["users"][0]["device_limit"], 2);
        assert_eq!(config["inbounds"][1]["protocol"], "http");
        assert_eq!(config["inbounds"][1]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][2]["protocol"], "shadowsocks");
        assert_eq!(config["inbounds"][2]["cipher"], "aes-128-gcm");
        assert_eq!(config["inbounds"][2]["transport"]["network"], "tcp,udp");
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
        assert_eq!(config["inbounds"][5]["users"][0]["uuid"], "trojan-password");
        assert_eq!(config["inbounds"][5]["users"][0]["speed_limit"], 2048);
        assert_eq!(config["inbounds"][5]["users"][0]["device_limit"], 3);
        assert_eq!(config["inbounds"][6]["protocol"], "anytls");
        assert_eq!(config["inbounds"][6]["users"][0]["uuid"], "anytls-password");
        assert_eq!(config["inbounds"][6]["users"][0]["speed_limit"], 4096);
        assert_eq!(config["inbounds"][6]["users"][0]["device_limit"], 5);
        assert_eq!(config["inbounds"][7]["protocol"], "naive");
        assert_eq!(config["inbounds"][7]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][7]["transport"]["network"], "tcp");
        assert_eq!(config["inbounds"][7]["users"][0]["uuid"], "naive-password");
        assert_eq!(config["inbounds"][7]["users"][0]["speed_limit"], 5120);
        assert_eq!(config["inbounds"][7]["users"][0]["device_limit"], 6);
        assert_eq!(
            config["inbounds"][7]["tls"]["server_name"],
            "naive.example.test"
        );
        assert_eq!(
            config["inbounds"][7]["tls"]["cert_file"],
            "/srv/v2node/naive.cer"
        );
        assert_eq!(
            config["inbounds"][7]["tls"]["key_file"],
            "/srv/v2node/naive.key"
        );
        assert_eq!(config["outbounds"][0]["tag"], "direct");
        assert_eq!(config["stats"]["per_user"], true);
    }

    #[test]
    fn renders_keli_core_rs_block_routes() {
        let mut node = test_node("http", 42, "");
        node.common.routes = vec![
            Route {
                id: 1,
                match_rules: vec![
                    "*.blocked.example".to_string(),
                    "domain:example.com".to_string(),
                    "keyword:tracker".to_string(),
                    "network:udp".to_string(),
                ],
                action: "block".to_string(),
                action_value: None,
            },
            Route {
                id: 2,
                match_rules: vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
                action: "block_ip".to_string(),
                action_value: None,
            },
            Route {
                id: 3,
                match_rules: vec!["6881-6889,6969".to_string()],
                action: "block_port".to_string(),
                action_value: None,
            },
        ];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][0],
            "*.blocked.example"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][1],
            "domain:example.com"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][2],
            "keyword:tracker"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][3],
            "network:udp"
        );
        assert_eq!(config["inbounds"][0]["routes"][0]["action"], "block");
        assert_eq!(
            config["inbounds"][0]["routes"][1]["targets"][0],
            "ip:10.0.0.0/8"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][1]["targets"][1],
            "ip:2001:db8::/32"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][2]["targets"][0],
            "port:6881-6889,6969"
        );
    }

    #[test]
    fn renders_keli_core_rs_routes_on_owning_inbound_only() {
        let mut socks = test_node("socks", 28, "");
        socks.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geoip:private".to_string()],
            action: "block_ip".to_string(),
            action_value: None,
        }];
        let vless = test_node("vless", 32, "");
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[socks, vless],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["routes"].as_array().unwrap().len(), 0);
        let socks_inbound = config["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|inbound| inbound["protocol"] == "socks")
            .expect("socks inbound");
        let vless_inbound = config["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|inbound| inbound["protocol"] == "vless")
            .expect("vless inbound");
        assert_eq!(socks_inbound["routes"][0]["targets"][0], "geoip:private");
        assert_eq!(vless_inbound["routes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn renders_keli_core_rs_dns_routes() {
        let mut node = test_node("vless", 43, "");
        node.common.routes = vec![Route {
            id: 1,
            action: "dns".to_string(),
            match_rules: vec![
                "geosite:openai".to_string(),
                "domain:example.com".to_string(),
            ],
            action_value: Some("1.1.1.1".to_string()),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["dns"]["query_strategy"], "UseIPv4");
        assert_eq!(config["dns"]["servers"][0]["address"], "1.1.1.1");
        assert_eq!(config["dns"]["servers"][1]["address"], "8.8.8.8");
        assert_eq!(config["dns"]["servers"][2]["address"], "1.1.1.1");
        assert_eq!(config["dns"]["servers"][2]["domains"][0], "geosite:openai");
        assert_eq!(
            config["dns"]["servers"][2]["domains"][1],
            "domain:example.com"
        );
    }

    #[test]
    fn renders_keli_core_rs_dns_private_ip_guard() {
        let node = test_node("socks", 44, "");
        let mut plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();
        plan.dns.servers = vec![
            "9.9.9.9".to_string(),
            "https://dns.example/dns-query".to_string(),
        ];
        plan.dns.block_private_ips = true;
        plan.dns.private_ip_allowlist = vec![
            "domain:internal.example".to_string(),
            "ip:10.0.0.0/8".to_string(),
        ];

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["dns"]["servers"][0]["address"], "9.9.9.9");
        assert_eq!(
            config["dns"]["servers"][1]["address"],
            "https://dns.example/dns-query"
        );
        assert_eq!(config["dns"]["block_private_ips"], true);
        assert_eq!(
            config["dns"]["private_ip_allowlist"][0],
            "domain:internal.example"
        );
        assert_eq!(config["dns"]["private_ip_allowlist"][1], "ip:10.0.0.0/8");
    }

    #[test]
    fn renders_keli_core_rs_freedom_route_outbounds() {
        let mut node = test_node("http", 82, "");
        node.common.routes = vec![
            Route {
                id: 1,
                match_rules: vec!["domain:example.com".to_string()],
                action: "route".to_string(),
                action_value: Some(
                    r#"{"tag":"warp","protocol":"freedom","settings":{"redirect":"127.0.0.1:40000"}}"#
                        .to_string(),
                ),
            },
            Route {
                id: 2,
                match_rules: vec!["10.0.0.0/8".to_string()],
                action: "route_ip".to_string(),
                action_value: Some(r#"{"tag":"warp","protocol":"freedom"}"#.to_string()),
            },
            Route {
                id: 3,
                match_rules: Vec::new(),
                action: "default_out".to_string(),
                action_value: Some(r#"{"tag":"warp","protocol":"freedom"}"#.to_string()),
            },
        ];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
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
        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][0],
            "domain:example.com"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["action"]["outbound"],
            "warp"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["address"],
            "127.0.0.1"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["port"],
            40000
        );
        assert_eq!(
            config["inbounds"][0]["routes"][1]["targets"][0],
            "ip:10.0.0.0/8"
        );
        assert_eq!(config["inbounds"][0]["routes"][2]["targets"][0], "*");
    }

    #[test]
    fn renders_keli_core_rs_xray_policy_defaults() {
        let node = test_node("vless", 45, "");
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["policy"]["handshake_secs"], 4);
        assert_eq!(config["policy"]["connection_idle_secs"], 120);
        assert_eq!(config["policy"]["uplink_only_secs"], 2);
        assert_eq!(config["policy"]["downlink_only_secs"], 4);
        assert_eq!(config["policy"]["buffer_size_kib"], 128);
        assert_eq!(config["policy"]["sniffing_cache_millis"], 200);
        assert_eq!(config["policy"]["connect_timeout_secs"], 15);
    }

    #[test]
    fn renders_keli_core_rs_route_outbound_with_xray_noop_keys() {
        let mut node = test_node("http", 107, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-ws","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","sockopt":{"tcpFastOpen":true},"tlsSettings":{"serverName":"sni.example.com"},"wsSettings":{"path":"/vless","headers":{"Host":"cdn.example.com"}}},"mux":{"enabled":false}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-ws");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "ws");
        assert_eq!(config["outbounds"][1]["transport"]["path"], "/vless");
    }

    #[test]
    fn renders_keli_core_rs_blackhole_route_outbound_as_block_rule() {
        let mut node = test_node("http", 108, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:ads.example".to_string()],
            action: "route".to_string(),
            action_value: Some(r#"{"tag":"blocked","protocol":"blackhole"}"#.to_string()),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"].as_array().unwrap().len(), 1);
        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][0],
            "domain:ads.example"
        );
        assert_eq!(config["inbounds"][0]["routes"][0]["action"], "block");
    }

    #[test]
    fn renders_keli_core_rs_proxy_route_outbounds() {
        let mut node = test_node("http", 83, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1080,"users":[{"user":"alice","pass":"secret"}]}]}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "proxy");
        assert_eq!(config["outbounds"][1]["protocol"], "socks");
        assert_eq!(config["outbounds"][1]["address"], "127.0.0.1");
        assert_eq!(config["outbounds"][1]["port"], 1080);
        assert_eq!(config["outbounds"][1]["username"], "alice");
        assert_eq!(config["outbounds"][1]["password"], "secret");
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["protocol"],
            "socks"
        );
    }

    #[test]
    fn renders_keli_core_rs_shadowsocks_route_outbounds() {
        let mut node = test_node("http", 84, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"ss-out","protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":8388,"method":"aes-128-gcm","password":"secret"}]}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "ss-out");
        assert_eq!(config["outbounds"][1]["protocol"], "shadowsocks");
        assert_eq!(config["outbounds"][1]["method"], "aes-128-gcm");
        assert_eq!(config["outbounds"][1]["address"], "127.0.0.1");
        assert_eq!(config["outbounds"][1]["port"], 8388);
        assert_eq!(config["outbounds"][1]["password"], "secret");
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["method"],
            "aes-128-gcm"
        );
    }

    #[test]
    fn renders_keli_core_rs_trojan_route_outbounds() {
        let mut node = test_node("http", 85, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"trojan-out","protocol":"trojan","settings":{"servers":[{"address":"proxy.example.com","port":443,"password":"secret"}]}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "trojan-out");
        assert_eq!(config["outbounds"][1]["protocol"], "trojan");
        assert_eq!(config["outbounds"][1]["address"], "proxy.example.com");
        assert_eq!(config["outbounds"][1]["port"], 443);
        assert_eq!(config["outbounds"][1]["password"], "secret");
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["protocol"],
            "trojan"
        );
    }

    #[test]
    fn renders_keli_core_rs_trojan_tls_route_outbounds() {
        let mut node = test_node("http", 86, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"trojan-out","protocol":"trojan","settings":{"servers":[{"address":"proxy.example.com","port":443,"password":"secret"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true,"alpn":["h2","http/1.1"]}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "trojan-out");
        assert_eq!(config["outbounds"][1]["protocol"], "trojan");
        assert_eq!(config["outbounds"][1]["address"], "proxy.example.com");
        assert_eq!(config["outbounds"][1]["port"], 443);
        assert_eq!(config["outbounds"][1]["password"], "secret");
        assert_eq!(
            config["outbounds"][1]["tls"]["server_name"],
            "sni.example.com"
        );
        assert_eq!(config["outbounds"][1]["tls"]["allow_insecure"], true);
        assert_eq!(config["outbounds"][1]["tls"]["alpn"][0], "h2");
        assert_eq!(config["outbounds"][1]["tls"]["alpn"][1], "http/1.1");
    }

    #[test]
    fn renders_keli_core_rs_trojan_websocket_route_outbounds() {
        let mut node = test_node("http", 92, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"trojan-ws","protocol":"trojan","settings":{"servers":[{"address":"proxy.example.com","port":443,"password":"secret"}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"wsSettings":{"path":"/trojan","headers":{"Host":"cdn.example.com"}}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "trojan-ws");
        assert_eq!(config["outbounds"][1]["protocol"], "trojan");
        assert_eq!(config["outbounds"][1]["password"], "secret");
        assert_eq!(
            config["outbounds"][1]["tls"]["server_name"],
            "sni.example.com"
        );
        assert_eq!(config["outbounds"][1]["transport"]["network"], "ws");
        assert_eq!(config["outbounds"][1]["transport"]["path"], "/trojan");
        assert_eq!(
            config["outbounds"][1]["transport"]["host"],
            "cdn.example.com"
        );
    }

    #[test]
    fn renders_keli_core_rs_trojan_httpupgrade_route_outbounds() {
        let mut node = test_node("http", 93, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"trojan-httpupgrade","protocol":"trojan","settings":{"servers":[{"address":"proxy.example.com","port":443,"password":"secret"}]},"streamSettings":{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"httpupgradeSettings":{"path":"/trojan","host":"cdn.example.com"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "trojan-httpupgrade");
        assert_eq!(config["outbounds"][1]["protocol"], "trojan");
        assert_eq!(
            config["outbounds"][1]["tls"]["server_name"],
            "sni.example.com"
        );
        assert_eq!(
            config["outbounds"][1]["transport"]["network"],
            "httpupgrade"
        );
        assert_eq!(config["outbounds"][1]["transport"]["path"], "/trojan");
        assert_eq!(
            config["outbounds"][1]["transport"]["host"],
            "cdn.example.com"
        );
    }

    #[test]
    fn renders_keli_core_rs_trojan_grpc_route_outbounds() {
        let mut node = test_node("http", 95, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"trojan-grpc","protocol":"trojan","settings":{"servers":[{"address":"proxy.example.com","port":443,"password":"secret"}]},"streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true,"alpn":["h2"]},"grpcSettings":{"serviceName":"GunService"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "trojan-grpc");
        assert_eq!(config["outbounds"][1]["protocol"], "trojan");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "grpc");
        assert_eq!(
            config["outbounds"][1]["transport"]["service_name"],
            "GunService"
        );
        assert!(config["outbounds"][1]["transport"]["path"].is_null());
        assert!(config["outbounds"][1]["transport"]["host"].is_null());
    }

    #[test]
    fn renders_keli_core_rs_vless_route_outbounds() {
        let mut node = test_node("http", 87, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-out","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-out");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(config["outbounds"][1]["address"], "proxy.example.com");
        assert_eq!(config["outbounds"][1]["port"], 443);
        assert_eq!(
            config["outbounds"][1]["username"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["protocol"],
            "vless"
        );
    }

    #[test]
    fn renders_keli_core_rs_vless_tls_route_outbounds() {
        let mut node = test_node("http", 90, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-tls","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true,"alpn":["h2","http/1.1"]}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-tls");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(config["outbounds"][1]["address"], "proxy.example.com");
        assert_eq!(config["outbounds"][1]["port"], 443);
        assert_eq!(
            config["outbounds"][1]["username"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(
            config["outbounds"][1]["tls"]["server_name"],
            "sni.example.com"
        );
        assert_eq!(config["outbounds"][1]["tls"]["allow_insecure"], true);
        assert_eq!(config["outbounds"][1]["tls"]["alpn"][0], "h2");
        assert_eq!(config["outbounds"][1]["tls"]["alpn"][1], "http/1.1");
    }

    #[test]
    fn renders_keli_core_rs_vless_vision_route_outbounds() {
        let mut node = test_node("http", 98, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-vision","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-vision");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(config["outbounds"][1]["method"], "xtls-rprx-vision");
        assert_eq!(
            config["outbounds"][1]["tls"]["server_name"],
            "sni.example.com"
        );
        assert!(config["outbounds"][1]["transport"].is_null());
    }

    #[test]
    fn renders_keli_core_rs_vless_websocket_route_outbounds() {
        let mut node = test_node("http", 91, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-ws","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"wsSettings":{"path":"/vless","headers":{"Host":"cdn.example.com"}}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-ws");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(
            config["outbounds"][1]["tls"]["server_name"],
            "sni.example.com"
        );
        assert_eq!(config["outbounds"][1]["transport"]["network"], "ws");
        assert_eq!(config["outbounds"][1]["transport"]["path"], "/vless");
        assert_eq!(
            config["outbounds"][1]["transport"]["host"],
            "cdn.example.com"
        );
    }

    #[test]
    fn renders_keli_core_rs_vless_httpupgrade_route_outbounds() {
        let mut node = test_node("http", 94, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-httpupgrade","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"httpupgradeSettings":{"path":"/vless","host":"cdn.example.com"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-httpupgrade");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(
            config["outbounds"][1]["tls"]["server_name"],
            "sni.example.com"
        );
        assert_eq!(
            config["outbounds"][1]["transport"]["network"],
            "httpupgrade"
        );
        assert_eq!(config["outbounds"][1]["transport"]["path"], "/vless");
        assert_eq!(
            config["outbounds"][1]["transport"]["host"],
            "cdn.example.com"
        );
    }

    #[test]
    fn renders_keli_core_rs_vless_grpc_route_outbounds() {
        let mut node = test_node("http", 96, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-grpc","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"grpcSettings":{"serviceName":"GunService"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-grpc");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "grpc");
        assert_eq!(
            config["outbounds"][1]["transport"]["service_name"],
            "GunService"
        );
        assert!(config["outbounds"][1]["transport"]["path"].is_null());
        assert!(config["outbounds"][1]["transport"]["host"].is_null());
    }

    #[test]
    fn renders_keli_core_rs_vmess_websocket_route_outbounds() {
        let mut node = test_node("http", 97, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vmess-ws","protocol":"vmess","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","security":"aes-128-gcm"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"wsSettings":{"path":"/vmess","headers":{"Host":"cdn.example.com"}}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vmess-ws");
        assert_eq!(config["outbounds"][1]["protocol"], "vmess");
        assert_eq!(config["outbounds"][1]["method"], "aes-128-gcm");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "ws");
        assert_eq!(config["outbounds"][1]["transport"]["path"], "/vmess");
        assert_eq!(
            config["outbounds"][1]["transport"]["host"],
            "cdn.example.com"
        );
    }

    #[test]
    fn renders_keli_core_rs_vmess_httpupgrade_route_outbounds() {
        let mut node = test_node("http", 98, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vmess-httpupgrade","protocol":"vmess","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","security":"chacha20-poly1305"}]}]},"streamSettings":{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"httpupgradeSettings":{"path":"/vmess","host":"cdn.example.com"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vmess-httpupgrade");
        assert_eq!(config["outbounds"][1]["protocol"], "vmess");
        assert_eq!(config["outbounds"][1]["method"], "chacha20-poly1305");
        assert_eq!(
            config["outbounds"][1]["transport"]["network"],
            "httpupgrade"
        );
        assert_eq!(config["outbounds"][1]["transport"]["path"], "/vmess");
        assert_eq!(
            config["outbounds"][1]["transport"]["host"],
            "cdn.example.com"
        );
    }

    #[test]
    fn renders_keli_core_rs_vmess_grpc_route_outbounds() {
        let mut node = test_node("http", 99, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vmess-grpc","protocol":"vmess","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","security":"auto"}]}]},"streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"grpcSettings":{"serviceName":"GunService"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vmess-grpc");
        assert_eq!(config["outbounds"][1]["protocol"], "vmess");
        assert_eq!(config["outbounds"][1]["method"], "auto");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "grpc");
        assert_eq!(
            config["outbounds"][1]["transport"]["service_name"],
            "GunService"
        );
        assert!(config["outbounds"][1]["transport"]["path"].is_null());
        assert!(config["outbounds"][1]["transport"]["host"].is_null());
    }

    #[test]
    fn renders_keli_core_rs_vmess_h2_route_outbounds() {
        let mut node = test_node("http", 100, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vmess-h2","protocol":"vmess","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","security":"auto"}]}]},"streamSettings":{"network":"h2","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true,"alpn":["h2"]},"httpSettings":{"path":"/vmess","host":["cdn.example.com"],"method":"PUT"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vmess-h2");
        assert_eq!(config["outbounds"][1]["protocol"], "vmess");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "h2");
        assert_eq!(config["outbounds"][1]["transport"]["path"], "/vmess");
        assert_eq!(
            config["outbounds"][1]["transport"]["host"],
            "cdn.example.com"
        );
        assert_eq!(config["outbounds"][1]["transport"]["method"], "PUT");
    }

    #[test]
    fn renders_keli_core_rs_vless_xhttp_stream_one_route_outbounds() {
        let mut node = test_node("http", 104, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["geosite:openai".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-xhttp","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true,"alpn":["h2"]},"xhttpSettings":{"path":"/xhttp?ed=2048","host":"cdn.example.com","mode":"stream-one","headers":{"X-Keli":"ok"}}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-xhttp");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "h2");
        assert_eq!(
            config["outbounds"][1]["transport"]["path"],
            "/xhttp/?ed=2048"
        );
        assert_eq!(
            config["outbounds"][1]["transport"]["host"],
            "cdn.example.com"
        );
        assert_eq!(config["outbounds"][1]["transport"]["method"], "POST");
        assert_eq!(
            config["outbounds"][1]["transport"]["headers"]["content-type"],
            "application/grpc"
        );
        assert_eq!(
            config["outbounds"][1]["transport"]["headers"]["x-keli"],
            "ok"
        );
        assert!(config["outbounds"][1]["transport"]["headers"]["referer"]
            .as_str()
            .unwrap()
            .contains("/xhttp/?ed=2048&x_padding="));
    }

    #[test]
    fn renders_keli_core_rs_vless_plain_quic_route_outbounds() {
        let mut node = test_node("http", 105, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-quic","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"quic","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"quicSettings":{"security":"none","header":{"type":"none"}}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-quic");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "quic");
        assert_eq!(config["outbounds"][1]["transport"]["quic_security"], "none");
        assert_eq!(
            config["outbounds"][1]["transport"]["quic_header_type"],
            "none"
        );
        assert!(config["outbounds"][1]["transport"]["quic_key"].is_null());
    }

    #[test]
    fn renders_keli_core_rs_vless_encrypted_quic_route_outbounds() {
        let mut node = test_node("http", 106, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-quic","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"quic","security":"tls","tlsSettings":{"serverName":"sni.example.com","allowInsecure":true},"quicSettings":{"security":"aes-128-gcm","key":"secret","header":{"type":"none"}}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vless-quic");
        assert_eq!(config["outbounds"][1]["transport"]["network"], "quic");
        assert_eq!(
            config["outbounds"][1]["transport"]["quic_security"],
            "aes-128-gcm"
        );
        assert_eq!(config["outbounds"][1]["transport"]["quic_key"], "secret");
        assert_eq!(
            config["outbounds"][1]["transport"]["quic_header_type"],
            "none"
        );
    }

    #[test]
    fn renders_keli_core_rs_vmess_alter_id_route_outbounds() {
        let mut node = test_node("http", 101, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:legacy.example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vmess-legacy","protocol":"vmess","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","security":"aes-128-gcm","alterId":8}]}]}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["outbounds"][1]["tag"], "vmess-legacy");
        assert_eq!(config["outbounds"][1]["protocol"], "vmess");
        assert_eq!(config["outbounds"][1]["method"], "aes-128-gcm");
        assert_eq!(config["outbounds"][1]["alter_id"], 8);
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["alter_id"],
            8
        );
    }

    #[test]
    fn renders_keli_core_rs_vmess_udp_route_outbounds() {
        let mut node = test_node("vmess", 76, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["network:udp".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vmess-udp","protocol":"vmess","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","security":"auto"}]}]}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][0],
            "network:udp"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][0]["outbound"]["tag"],
            "vmess-udp"
        );
        assert_eq!(config["outbounds"][1]["protocol"], "vmess");
        assert_eq!(config["outbounds"][1]["address"], "proxy.example.com");
    }

    #[test]
    fn keli_core_rs_rejects_unsupported_route_outbound() {
        let mut node = test_node("http", 83, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(r#"{"tag":"proxy","protocol":"naive"}"#.to_string()),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("protocol naive"));
    }

    #[test]
    fn keli_core_rs_rejects_invalid_ignored_route_outbound_shape() {
        let mut node = test_node("http", 109, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-ws","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","mux":true,"tlsSettings":{"serverName":"sni.example.com"},"wsSettings":{"path":"/vless"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("mux must be an object"));
    }

    #[test]
    fn keli_core_rs_rejects_unsupported_vless_route_outbound_options() {
        let mut node = test_node("http", 88, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-out","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/vless"}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();
        let err = render_core_config(&plan).unwrap_err();
        assert!(err
            .message
            .contains("supports xhttp only in stream-one mode today"));

        let mut node = test_node("http", 89, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-out","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","encryption":"none"}]}]}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();
        let err = render_core_config(&plan).unwrap_err();
        assert!(err.message.contains("vless flow only on tcp tls"));

        let mut node = test_node("http", 90, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-quic","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"quic","quicSettings":{"security":"aes-128-gcm","key":"secret","header":{"type":"none"}}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();
        assert!(render_core_config(&plan).is_ok());

        let mut node = test_node("http", 91, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["domain:example.com".to_string()],
            action: "route".to_string(),
            action_value: Some(
                r#"{"tag":"vless-quic","protocol":"vless","settings":{"vnext":[{"address":"proxy.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"quic","quicSettings":{"security":"aes-128-gcm","key":"secret","header":{"type":"srtp"}}}}"#
                    .to_string(),
            ),
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();
        let err = render_core_config(&plan).unwrap_err();
        assert!(err.message.contains("quicSettings.header.type none"));
    }

    #[test]
    fn keli_core_rs_rejects_naive_without_tls() {
        let node = test_node("naive", 43, "");
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("naive currently requires tls"));
    }

    #[test]
    fn renders_keli_core_rs_naive_quic_inbound() {
        let mut node = test_node("naive", 74, "");
        node.security = Security::Tls;
        node.common.tls = 1;
        node.common.network = "quic".to_string();
        node.common.tls_settings.alpn = vec!["h3".to_string()];
        node.common.cert_info = Some(CertInfo {
            cert_mode: "file".to_string(),
            cert_file: "/srv/v2node/naive-h3.cer".to_string(),
            key_file: "/srv/v2node/naive-h3.key".to_string(),
            cert_domain: "naive-h3.example.test".to_string(),
            dns_env: Default::default(),
            provider: String::new(),
            reject_unknown_sni: false,
        });
        let node_tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            node_tag,
            vec![UserInfo {
                id: 74,
                uuid: "naive-h3-password".to_string(),
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

        assert_eq!(config["inbounds"][0]["protocol"], "naive");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "quic");
        assert_eq!(config["inbounds"][0]["tls"]["alpn"], json!(["h3"]));
        assert_eq!(
            config["inbounds"][0]["tls"]["server_name"],
            "naive-h3.example.test"
        );
    }

    #[test]
    fn keli_core_rs_rejects_plain_proxy_non_tcp_and_tls() {
        let mut node = test_node("socks", 72, "");
        node.common.network = "ws".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("supports only tcp transport"));

        let mut node = test_node("http", 73, "");
        node.security = Security::Tls;
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("supports only security none"));
    }

    #[test]
    fn keli_core_rs_rejects_protocol_scoped_options_that_core_would_ignore() {
        let mut node = test_node("vless", 74, "");
        node.common.cipher = "aes-128-gcm".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("does not support cipher"));

        let mut node = test_node("trojan", 75, "");
        node.common.padding_scheme = vec!["stop=8".to_string()];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("paddingScheme"));

        let mut node = test_node("vmess", 76, "");
        node.common.up_mbps = 100;
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("bandwidth/obfs"));

        let mut node = test_node("vmess", 77, "");
        node.common.congestion_control = "bbr".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("congestion_control"));
    }

    #[test]
    fn renders_keli_core_rs_vless_reality_settings() {
        let mut node = test_node("vless", 46, "");
        node.security = Security::Reality;
        let private_key = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
        node.common.tls_settings.server_name = "reality.example.test".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "reality.example.test".to_string();
        node.common.tls_settings.server_port = "443".to_string();
        node.common.tls_settings.private_key = private_key.to_string();
        node.common.tls_settings.short_id = "6ba85179e30d4fc2".to_string();
        node.common.flow = "xtls-rprx-vision".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "vless");
        assert_eq!(
            config["inbounds"][0]["tls"]["server_name"],
            "reality.example.test"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["reality"]["dest"],
            "reality.example.test:443"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["reality"]["private_key"],
            private_key
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["reality"]["short_id"],
            "6ba85179e30d4fc2"
        );
    }

    #[test]
    fn keli_core_rs_rejects_vless_unsupported_transport_until_core_supports_it() {
        let mut node = test_node("vless", 47, "");
        node.common.network = "kcp".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("tcp/ws/httpupgrade/grpc transport"));
    }

    #[test]
    fn renders_keli_core_rs_vless_vision_flow() {
        let mut node = test_node("vless", 48, "");
        node.common.flow = "xtls-rprx-vision".to_string();
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/vless.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/vless.key".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "vless.example.test".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(
            config["inbounds"][0]["tls"]["cert_file"],
            "/srv/v2node/vless.cer"
        );
    }

    #[test]
    fn keli_core_rs_rejects_vless_vision_without_tls() {
        let mut node = test_node("vless", 48, "");
        node.common.flow = "xtls-rprx-vision".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("requires tls or reality security"));
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
    fn renders_keli_core_rs_trojan_websocket_with_legacy_panel_ipaddress_setting() {
        let mut trojan = test_node("trojan", 66, "");
        trojan.common.network = "ws".to_string();
        trojan.common.network_settings = json!({
            "path": "/trojan",
            "headers": {
                "Host": "trojan.example.test"
            },
            "ipaddress": "127.0.0.1"
        });
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[trojan],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "trojan");
        assert_eq!(config["inbounds"][0]["transport"]["network"], "ws");
        assert_eq!(config["inbounds"][0]["transport"]["path"], "/trojan");
        assert_eq!(
            config["inbounds"][0]["transport"]["host"],
            "trojan.example.test"
        );
    }

    #[test]
    fn renders_keli_core_rs_httpupgrade_transport_settings() {
        let mut vless = test_node("vless", 62, "");
        vless.common.network = "httpupgrade".to_string();
        vless.common.network_settings = json!({
            "path": "/edge",
            "headers": {
                "Host": "edge.example.test"
            }
        });
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[vless],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["transport"]["network"], "httpupgrade");
        assert_eq!(config["inbounds"][0]["transport"]["path"], "/edge");
        assert_eq!(
            config["inbounds"][0]["transport"]["host"],
            "edge.example.test"
        );
    }

    #[test]
    fn renders_keli_core_rs_grpc_transport_settings() {
        let mut vless = test_node("vless", 65, "");
        vless.common.network = "grpc".to_string();
        vless.common.network_settings = json!({
            "serviceName": "KeliService",
            "multiMode": false
        });
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[vless],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["transport"]["network"], "grpc");
        assert_eq!(
            config["inbounds"][0]["transport"]["service_name"],
            "KeliService"
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
        assert_eq!(
            config["inbounds"][0]["tls"]["server_name"],
            "vmess.example.test"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["cert_file"],
            "/srv/v2node/vmess.cer"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["key_file"],
            "/srv/v2node/vmess.key"
        );
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
        assert_eq!(
            config["inbounds"][0]["tls"]["server_name"],
            "tuic.example.test"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["cert_file"],
            "/srv/v2node/tuic.cer"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["key_file"],
            "/srv/v2node/tuic.key"
        );
        assert_eq!(config["inbounds"][0]["tls"]["alpn"][0], "h3");
        assert_eq!(
            config["inbounds"][0]["users"][0]["uuid"],
            "11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn renders_keli_core_rs_tuic_congestion_control() {
        let mut node = test_node("tuic", 68, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/tuic.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/tuic.key".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "tuic.example.test".to_string();
        node.common.congestion_control = "bbr".to_string();
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 68,
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

        assert_eq!(
            config["inbounds"][0]["transport"]["congestion_control"],
            "bbr"
        );
    }

    #[test]
    fn rejects_keli_core_rs_tuic_zero_rtt_until_core_supports_it() {
        let mut node = test_node("tuic", 69, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/tuic.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/tuic.key".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "tuic.example.test".to_string();
        node.common.zero_rtt_handshake = true;
        let tag = node.tag.clone();
        let mut users = std::collections::BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 69,
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

        let error = render_core_config(&plan).unwrap_err();

        assert!(error.message.contains("does not support zero-rtt"));
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
        assert_eq!(
            config["inbounds"][0]["tls"]["server_name"],
            "hy2.example.test"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["cert_file"],
            "/srv/v2node/hy2.cer"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["key_file"],
            "/srv/v2node/hy2.key"
        );
        assert_eq!(config["inbounds"][0]["tls"]["alpn"][0], "h3");
        assert_eq!(config["inbounds"][0]["users"][0]["uuid"], "hy2-password");
    }

    #[test]
    fn renders_keli_core_rs_hysteria2_salamander_obfs() {
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

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["transport"]["obfs"], "salamander");
        assert_eq!(
            config["inbounds"][0]["transport"]["obfs_password"],
            "obfs-secret"
        );
    }

    #[test]
    fn renders_keli_core_rs_hysteria2_congestion_control() {
        let mut node = test_node("hysteria2", 72, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/hy2.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/hy2.key".to_string();
        node.common.congestion_control = "bbr".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["transport"]["congestion_control"],
            "bbr"
        );
    }

    #[test]
    fn keli_core_rs_rejects_unsupported_hysteria2_obfs() {
        let mut node = test_node("hysteria2", 70, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/hy2.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/hy2.key".to_string();
        node.common.obfs = "unknown".to_string();
        node.common.obfs_password = "obfs-secret".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("only supports salamander obfs"));
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

        assert!(err.message.contains("tcp or tcp,udp"));
    }

    #[test]
    fn renders_keli_core_rs_shadowsocks_explicit_tcp_transport() {
        let mut node = test_node("shadowsocks", 71, "");
        node.common.cipher = "aes-128-gcm".to_string();
        node.common.network = "tcp".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["transport"]["network"], "tcp");
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
        vless.common.cert_info.as_mut().unwrap().reject_unknown_sni = true;
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

        assert_eq!(
            config["inbounds"][0]["tls"]["server_name"],
            "vless.example.test"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["cert_file"],
            "/srv/v2node/vless.cer"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["key_file"],
            "/srv/v2node/vless.key"
        );
        assert_eq!(config["inbounds"][0]["tls"]["reject_unknown_sni"], true);
        assert_eq!(config["inbounds"][0]["transport"]["network"], "ws");
        assert_eq!(config["inbounds"][0]["transport"]["path"], "/vless-tls");
        assert_eq!(
            config["inbounds"][1]["tls"]["server_name"],
            "trojan.example.test"
        );
        assert_eq!(
            config["inbounds"][1]["tls"]["cert_file"],
            "/srv/v2node/trojan.cer"
        );
        assert_eq!(
            config["inbounds"][1]["tls"]["key_file"],
            "/srv/v2node/trojan.key"
        );
        assert_eq!(config["inbounds"][1]["tls"]["alpn"][0], "h2");
        assert_eq!(config["inbounds"][1]["tls"]["alpn"][1], "http/1.1");
    }

    #[test]
    fn keli_core_rs_rejects_trojan_unsupported_transport_until_core_supports_it() {
        let mut node = test_node("trojan", 52, "");
        node.common.network = "kcp".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("tcp/ws/httpupgrade/grpc transport"));
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
    fn renders_keli_core_rs_anytls_padding_scheme() {
        let mut node = test_node("anytls", 59, "");
        node.common.padding_scheme = vec!["stop=8".to_string(), "0=30-30".to_string()];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "anytls");
        assert_eq!(config["inbounds"][0]["padding_scheme"][0], "stop=8");
        assert_eq!(config["inbounds"][0]["padding_scheme"][1], "0=30-30");
    }

    #[test]
    fn renders_keli_core_rs_anytls_tls_settings() {
        let mut node = test_node("anytls", 60, "");
        node.security = Security::Tls;
        node.common.cert_info.as_mut().unwrap().cert_file = "/srv/v2node/anytls.cer".to_string();
        node.common.cert_info.as_mut().unwrap().key_file = "/srv/v2node/anytls.key".to_string();
        node.common.cert_info.as_mut().unwrap().cert_domain = "anytls.example.test".to_string();
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(config["inbounds"][0]["protocol"], "anytls");
        assert_eq!(
            config["inbounds"][0]["tls"]["server_name"],
            "anytls.example.test"
        );
        assert_eq!(
            config["inbounds"][0]["tls"]["cert_file"],
            "/srv/v2node/anytls.cer"
        );
    }

    #[test]
    fn renders_keli_core_rs_protocol_route_action() {
        let mut node = test_node("socks", 44, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["bittorrent".to_string()],
            action: "protocol".to_string(),
            action_value: None,
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][0],
            "protocol:bittorrent"
        );
        assert_eq!(config["inbounds"][0]["routes"][0]["action"], "block");
    }

    #[test]
    fn keli_core_rs_rejects_unsupported_ip_and_port_route_rules() {
        let mut node = test_node("socks", 79, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["70000".to_string()],
            action: "block_port".to_string(),
            action_value: None,
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("block_port rule 70000"));

        let mut node = test_node("socks", 80, "");
        node.common.routes = vec![Route {
            id: 1,
            match_rules: vec!["keyword:".to_string()],
            action: "block".to_string(),
            action_value: None,
        }];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let err = render_core_config(&plan).unwrap_err();

        assert!(err.message.contains("block rule keyword:"));
    }

    #[test]
    fn renders_keli_core_rs_advanced_route_rules() {
        let mut node = test_node("socks", 81, "");
        node.common.routes = vec![
            Route {
                id: 1,
                match_rules: vec!["geoip:private".to_string()],
                action: "block_ip".to_string(),
                action_value: None,
            },
            Route {
                id: 2,
                match_rules: vec![
                    "geosite:private".to_string(),
                    "regexp:^api\\.".to_string(),
                    "protocol:udp".to_string(),
                ],
                action: "block".to_string(),
                action_value: None,
            },
        ];
        let plan = CorePlan::from_nodes(
            CoreKind::KeliCoreRs,
            PathBuf::from("/srv/v2node/keli-core-rs.json"),
            &[node],
        )
        .unwrap();

        let config = render_core_config(&plan).unwrap();

        assert_eq!(
            config["inbounds"][0]["routes"][0]["targets"][0],
            "geoip:private"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][1]["targets"][0],
            "geosite:private"
        );
        assert_eq!(
            config["inbounds"][0]["routes"][1]["targets"][1],
            "regexp:^api\\."
        );
        assert_eq!(
            config["inbounds"][0]["routes"][1]["targets"][2],
            "protocol:udp"
        );
    }

    #[test]
    fn resolve_node_listen_ip_preserves_ipv4_wildcard() {
        assert_eq!(resolve_node_listen_ip("0.0.0.0"), "0.0.0.0");
        assert_eq!(resolve_node_listen_ip(" "), "0.0.0.0");
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
        node.common.tls_settings.alpn =
            vec![" h3 ".to_string(), "h3".to_string(), "h2".to_string()];
        let inbound = build_inbound_plan(&node).unwrap();

        assert_eq!(inbound.alpn, vec!["h3".to_string(), "h2".to_string()]);
    }

    #[test]
    fn core_file_layout_tracks_config_dir_and_temp_file() {
        let layout = core_file_layout("/srv/v2node/config.json");

        assert_eq!(layout.config_dir, PathBuf::from("/srv/v2node"));
        assert_eq!(
            layout.temp_config_path,
            PathBuf::from("/srv/v2node/config.json.tmp")
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
    fn writes_core_config_atomically_and_detects_unchanged_content() {
        let dir = temp_test_dir("core-config-write");
        let path = dir.join("runtime").join("config.json");
        let node = test_node("vless", 10, "");
        let plan = CorePlan::from_nodes(CoreKind::KeliCoreRs, path.clone(), &[node]).unwrap();

        let first = write_core_config(&plan).unwrap();
        let second = write_core_config(&plan).unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(first.inbound_count, 1);
        assert!(saved.contains("\"inbounds\""));
        assert!(saved.contains("\"policy\""));
        assert!(saved.contains("\"connect_timeout_secs\":15"));
        assert!(!path.with_extension("json.tmp").exists());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn write_core_config_generates_self_signed_cert_when_tls_files_are_missing() {
        let dir = temp_test_dir("core-config-self-signed");
        let path = dir.join("runtime").join("config.json");
        let cert_path = dir.join("certs").join("node.cer");
        let key_path = dir.join("certs").join("node.key");
        let mut node = test_node("vless", 80, "");
        node.security = Security::Tls;
        {
            let cert = node.common.cert_info.as_mut().unwrap();
            cert.cert_file = cert_path.to_string_lossy().to_string();
            cert.key_file = key_path.to_string_lossy().to_string();
            cert.cert_domain = "node.example.test".to_string();
        }
        let plan = CorePlan::from_nodes(CoreKind::KeliCoreRs, path, &[node]).unwrap();

        let written = write_core_config(&plan).unwrap();
        let cert_content = fs::read_to_string(&cert_path).unwrap();
        let key_content = fs::read_to_string(&key_path).unwrap();

        assert!(written.changed);
        assert!(cert_content.contains("-----BEGIN CERTIFICATE-----"));
        assert!(key_content.contains("-----BEGIN PRIVATE KEY-----"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn write_core_config_preserves_existing_tls_cert_files() {
        let dir = temp_test_dir("core-config-preserve-cert");
        let path = dir.join("runtime").join("config.json");
        let cert_path = dir.join("certs").join("node.cer");
        let key_path = dir.join("certs").join("node.key");
        fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        let generated =
            rcgen::generate_simple_self_signed(vec!["node.example.test".to_string()]).unwrap();
        let cert_content = generated.cert.pem();
        let key_content = generated.key_pair.serialize_pem();
        fs::write(&cert_path, &cert_content).unwrap();
        fs::write(&key_path, &key_content).unwrap();

        let mut node = test_node("vless", 81, "");
        node.security = Security::Tls;
        {
            let cert = node.common.cert_info.as_mut().unwrap();
            cert.cert_file = cert_path.to_string_lossy().to_string();
            cert.key_file = key_path.to_string_lossy().to_string();
            cert.cert_domain = "node.example.test".to_string();
        }
        let plan = CorePlan::from_nodes(CoreKind::KeliCoreRs, path, &[node]).unwrap();

        write_core_config(&plan).unwrap();

        assert_eq!(fs::read_to_string(&cert_path).unwrap(), cert_content);
        assert_eq!(fs::read_to_string(&key_path).unwrap(), key_content);

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
