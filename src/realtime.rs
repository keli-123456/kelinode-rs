use std::time::Duration;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{NodeConfig, RealtimeConfig};
use crate::panel::types::NodeInfo;

pub const REASON_SUBSCRIPTION_PROXY_CERT_STATE_CHANGED: &str =
    "subscription_proxy.cert_state_changed";
pub const REASON_SERVER_MACHINE_BOUND: &str = "admin.server_machine.bound";

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct RealtimeMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub topic: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub revision: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub ts: i64,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub server_id: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_id: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub machine_id: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeOptions {
    pub url: String,
    pub token: String,
    pub node_id: u32,
    pub machine_id: u32,
    pub node_type: String,
    pub ping_interval: Duration,
    pub reconnect_delay: Duration,
    pub log_tag: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RealtimeUserSummary {
    pub deleted: usize,
    pub added: usize,
    pub updated: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealtimeInboundAction {
    Ignore,
    Pong,
    ConfigCheck,
    ForceReload,
    UserSync,
    Error(String),
    HelloAck,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RealtimeRuntimeTask {
    Ignore,
    Pong(RealtimeMessage),
    ConfigCheck,
    ForceReload,
    UserSync,
    Error(String),
    HelloAck,
}

impl Default for RealtimeOptions {
    fn default() -> Self {
        Self {
            url: String::new(),
            token: String::new(),
            node_id: 0,
            machine_id: 0,
            node_type: "v2node".to_string(),
            ping_interval: Duration::from_secs(30),
            reconnect_delay: Duration::from_secs(5),
            log_tag: String::new(),
        }
    }
}

pub fn resolve_realtime_options(
    local: &RealtimeConfig,
    node_config: &NodeConfig,
    node_info: &NodeInfo,
) -> Option<RealtimeOptions> {
    let panel_realtime = node_info
        .common
        .base_config
        .as_ref()
        .and_then(|config| config.realtime.as_ref());

    let panel_enabled = panel_realtime.map(|config| config.enabled).unwrap_or(false);
    let panel_url = panel_realtime
        .map(|config| config.url.trim())
        .unwrap_or_default();
    let panel_ping = panel_realtime
        .map(|config| realtime_interval_to_duration(&config.ping_interval))
        .unwrap_or_default();

    let mut url = local.url.trim().to_string();
    let enabled = local.enabled || !url.is_empty() || panel_enabled;
    if !enabled {
        return None;
    }

    if url.is_empty() {
        url = panel_url.to_string();
    }
    if url.is_empty() {
        url = derive_realtime_url(&node_config.url);
    }
    if url.is_empty() {
        return None;
    }

    let mut ping_interval = panel_ping;
    if local.ping_interval > 0 {
        ping_interval = Duration::from_secs(local.ping_interval);
    }
    if ping_interval.is_zero() {
        ping_interval = Duration::from_secs(30);
    }

    let reconnect_delay = if local.reconnect_interval > 0 {
        Duration::from_secs(local.reconnect_interval)
    } else {
        Duration::from_secs(5)
    };

    Some(RealtimeOptions {
        url,
        token: node_config.token.trim().to_string(),
        node_id: node_config.node_id,
        machine_id: node_config.machine_id,
        node_type: "v2node".to_string(),
        ping_interval,
        reconnect_delay,
        log_tag: node_info.tag.clone(),
    })
}

impl RealtimeMessage {
    pub fn ping(options: &RealtimeOptions, ts: i64, health: Option<Value>) -> Self {
        Self {
            message_type: "ping".to_string(),
            ts,
            token: options.token.clone(),
            node_id: options.node_id.to_string(),
            machine_id: options.machine_id,
            node_type: options.node_type.clone(),
            health,
            ..Self::default()
        }
    }

    pub fn pong(ts: i64) -> Self {
        Self {
            message_type: "pong".to_string(),
            ts,
            ..Self::default()
        }
    }
}

pub fn realtime_runtime_task(message: &RealtimeMessage, now_ts: i64) -> RealtimeRuntimeTask {
    match realtime_inbound_action(message) {
        RealtimeInboundAction::Ignore => RealtimeRuntimeTask::Ignore,
        RealtimeInboundAction::Pong => RealtimeRuntimeTask::Pong(RealtimeMessage::pong(now_ts)),
        RealtimeInboundAction::ConfigCheck => RealtimeRuntimeTask::ConfigCheck,
        RealtimeInboundAction::ForceReload => RealtimeRuntimeTask::ForceReload,
        RealtimeInboundAction::UserSync => RealtimeRuntimeTask::UserSync,
        RealtimeInboundAction::Error(message) => RealtimeRuntimeTask::Error(message),
        RealtimeInboundAction::HelloAck => RealtimeRuntimeTask::HelloAck,
    }
}

pub fn realtime_inbound_action(message: &RealtimeMessage) -> RealtimeInboundAction {
    match message.message_type.as_str() {
        "hello_ack" => RealtimeInboundAction::HelloAck,
        "ping" => RealtimeInboundAction::Pong,
        "error" => RealtimeInboundAction::Error(message.message.clone()),
        "invalidate" => realtime_invalidate_action(message),
        _ => RealtimeInboundAction::Ignore,
    }
}

pub fn realtime_invalidate_action(message: &RealtimeMessage) -> RealtimeInboundAction {
    match message.topic.as_str() {
        "config" if should_force_realtime_config_reload(message) => {
            RealtimeInboundAction::ForceReload
        }
        "config" => RealtimeInboundAction::ConfigCheck,
        "users" => RealtimeInboundAction::UserSync,
        _ => RealtimeInboundAction::Ignore,
    }
}

pub fn should_force_realtime_config_reload(message: &RealtimeMessage) -> bool {
    matches!(
        message.reason.as_str(),
        REASON_SUBSCRIPTION_PROXY_CERT_STATE_CHANGED | REASON_SERVER_MACHINE_BOUND
    )
}

pub fn build_realtime_receipt(
    topic: &str,
    source: &RealtimeMessage,
    status: &str,
    message: &str,
    ts: i64,
) -> RealtimeMessage {
    RealtimeMessage {
        message_type: "receipt".to_string(),
        topic: topic.to_string(),
        event_id: source.event_id.clone(),
        reason: source.reason.clone(),
        status: status.to_string(),
        message: truncate_realtime_receipt_message(message),
        ts,
        ..RealtimeMessage::default()
    }
}

pub fn format_realtime_user_summary(summary: RealtimeUserSummary) -> String {
    format!(
        "deleted={} added={} updated={}",
        summary.deleted, summary.added, summary.updated
    )
}

pub fn truncate_realtime_receipt_message(message: &str) -> String {
    let message = message.trim();
    if message.chars().count() <= 240 {
        return message.to_string();
    }

    let mut output = message.chars().take(237).collect::<String>();
    output.push_str("...");
    output
}

pub fn derive_realtime_url(api_host: &str) -> String {
    let Ok(mut parsed) = Url::parse(api_host.trim()) else {
        return String::new();
    };
    match parsed.scheme() {
        "http" => {
            let _ = parsed.set_scheme("ws");
        }
        "https" => {
            let _ = parsed.set_scheme("wss");
        }
        "ws" | "wss" => {}
        _ => {
            let _ = parsed.set_scheme("ws");
        }
    }
    parsed.set_path("/ws/node");
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

pub fn build_realtime_dial_url(options: &RealtimeOptions) -> Result<String, String> {
    let mut parsed =
        Url::parse(options.url.trim()).map_err(|err| format!("parse realtime url: {err}"))?;
    {
        let mut query = parsed.query_pairs_mut();
        query.append_pair("token", &options.token);
        query.append_pair("node_id", &options.node_id.to_string());
        query.append_pair("node_type", &options.node_type);
        if options.machine_id > 0 {
            query.append_pair("machine_id", &options.machine_id.to_string());
        }
    }
    Ok(parsed.to_string())
}

pub fn realtime_interval_to_duration(value: &Value) -> Duration {
    match value {
        Value::Number(number) => number.as_u64().map(Duration::from_secs).unwrap_or_default(),
        Value::String(text) => text
            .trim()
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
            .unwrap_or_default(),
        _ => Duration::from_secs(0),
    }
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{NodeConfig, RealtimeConfig};
    use crate::panel::types::{CommonNode, NodeInfo};

    use super::{
        build_realtime_dial_url, build_realtime_receipt, derive_realtime_url,
        format_realtime_user_summary, realtime_inbound_action, realtime_interval_to_duration,
        realtime_runtime_task, resolve_realtime_options, should_force_realtime_config_reload,
        truncate_realtime_receipt_message, RealtimeInboundAction, RealtimeMessage, RealtimeOptions,
        RealtimeRuntimeTask, RealtimeUserSummary, REASON_SERVER_MACHINE_BOUND,
        REASON_SUBSCRIPTION_PROXY_CERT_STATE_CHANGED,
    };

    #[test]
    fn parses_invalidate_actions_like_go_worker() {
        assert_eq!(
            realtime_inbound_action(&RealtimeMessage {
                message_type: "invalidate".to_string(),
                topic: "config".to_string(),
                reason: "admin.server.saved".to_string(),
                ..RealtimeMessage::default()
            }),
            RealtimeInboundAction::ConfigCheck
        );
        assert_eq!(
            realtime_inbound_action(&RealtimeMessage {
                message_type: "invalidate".to_string(),
                topic: "users".to_string(),
                reason: "user.delta".to_string(),
                ..RealtimeMessage::default()
            }),
            RealtimeInboundAction::UserSync
        );
    }

    #[test]
    fn forces_reload_for_machine_binding_and_subscription_proxy_cert_events() {
        for reason in [
            REASON_SUBSCRIPTION_PROXY_CERT_STATE_CHANGED,
            REASON_SERVER_MACHINE_BOUND,
        ] {
            let message = RealtimeMessage {
                reason: reason.to_string(),
                ..RealtimeMessage::default()
            };

            assert!(should_force_realtime_config_reload(&message));
        }
    }

    #[test]
    fn builds_realtime_receipt_with_truncated_message() {
        let source = RealtimeMessage {
            event_id: "evt-1".to_string(),
            reason: "user.delta".to_string(),
            ..RealtimeMessage::default()
        };
        let receipt = build_realtime_receipt("users", &source, "applied", &"x".repeat(300), 123);

        assert_eq!(receipt.message_type, "receipt");
        assert_eq!(receipt.topic, "users");
        assert_eq!(receipt.event_id, "evt-1");
        assert_eq!(receipt.status, "applied");
        assert_eq!(receipt.ts, 123);
        assert_eq!(receipt.message.chars().count(), 240);
        assert!(receipt.message.ends_with("..."));
    }

    #[test]
    fn derives_realtime_url_from_panel_host() {
        assert_eq!(
            derive_realtime_url("https://panel.example.com/base"),
            "wss://panel.example.com/ws/node"
        );
        assert_eq!(
            derive_realtime_url("http://panel.example.com"),
            "ws://panel.example.com/ws/node"
        );
        assert_eq!(derive_realtime_url("://bad"), "");
    }

    #[test]
    fn builds_realtime_dial_url_with_identity_query() {
        let url = build_realtime_dial_url(&RealtimeOptions {
            url: "wss://panel.example.test/ws/node?existing=1".to_string(),
            token: "token".to_string(),
            node_id: 7,
            machine_id: 3,
            node_type: "v2node".to_string(),
            ..RealtimeOptions::default()
        })
        .unwrap();

        assert!(url.contains("existing=1"));
        assert!(url.contains("token=token"));
        assert!(url.contains("node_id=7"));
        assert!(url.contains("machine_id=3"));
        assert!(url.contains("node_type=v2node"));
    }

    #[test]
    fn resolves_realtime_options_from_panel_base_config() {
        let node_config = test_node_config();
        let node_info = test_node_info(json!({
            "protocol": "vless",
            "base_config": {
                "realtime": {
                    "enabled": true,
                    "url": "wss://panel.example.test/custom/ws",
                    "ping_interval": "18"
                }
            }
        }));

        let options =
            resolve_realtime_options(&RealtimeConfig::default(), &node_config, &node_info).unwrap();

        assert_eq!(options.url, "wss://panel.example.test/custom/ws");
        assert_eq!(options.token, "token");
        assert_eq!(options.node_id, 7);
        assert_eq!(options.machine_id, 3);
        assert_eq!(options.ping_interval.as_secs(), 18);
        assert_eq!(options.reconnect_delay.as_secs(), 5);
        assert_eq!(options.log_tag, node_info.tag);
    }

    #[test]
    fn local_realtime_config_overrides_panel_url_and_intervals() {
        let node_config = test_node_config();
        let node_info = test_node_info(json!({
            "protocol": "vless",
            "base_config": {
                "realtime": {
                    "enabled": true,
                    "url": "wss://panel.example.test/custom/ws",
                    "ping_interval": 18
                }
            }
        }));
        let local = RealtimeConfig {
            url: "wss://local.example.test/ws/node".to_string(),
            ping_interval: 9,
            reconnect_interval: 4,
            ..RealtimeConfig::default()
        };

        let options = resolve_realtime_options(&local, &node_config, &node_info).unwrap();

        assert_eq!(options.url, "wss://local.example.test/ws/node");
        assert_eq!(options.ping_interval.as_secs(), 9);
        assert_eq!(options.reconnect_delay.as_secs(), 4);
    }

    #[test]
    fn derives_realtime_options_from_panel_api_host_when_enabled_locally() {
        let node_config = test_node_config();
        let node_info = test_node_info(json!({
            "protocol": "vless"
        }));
        let local = RealtimeConfig {
            enabled: true,
            ..RealtimeConfig::default()
        };

        let options = resolve_realtime_options(&local, &node_config, &node_info).unwrap();

        assert_eq!(options.url, "wss://panel.example.test/ws/node");
        assert_eq!(options.ping_interval.as_secs(), 30);
    }

    #[test]
    fn realtime_options_stay_disabled_without_local_or_panel_enablement() {
        let node_config = test_node_config();
        let node_info = test_node_info(json!({
            "protocol": "vless"
        }));

        assert!(
            resolve_realtime_options(&RealtimeConfig::default(), &node_config, &node_info)
                .is_none()
        );
    }

    #[test]
    fn maps_realtime_messages_to_runtime_tasks() {
        assert_eq!(
            realtime_runtime_task(
                &RealtimeMessage {
                    message_type: "ping".to_string(),
                    ..RealtimeMessage::default()
                },
                123
            ),
            RealtimeRuntimeTask::Pong(RealtimeMessage::pong(123))
        );
        assert_eq!(
            realtime_runtime_task(
                &RealtimeMessage {
                    message_type: "invalidate".to_string(),
                    topic: "config".to_string(),
                    reason: REASON_SERVER_MACHINE_BOUND.to_string(),
                    ..RealtimeMessage::default()
                },
                123
            ),
            RealtimeRuntimeTask::ForceReload
        );
        assert_eq!(
            realtime_runtime_task(
                &RealtimeMessage {
                    message_type: "invalidate".to_string(),
                    topic: "users".to_string(),
                    ..RealtimeMessage::default()
                },
                123
            ),
            RealtimeRuntimeTask::UserSync
        );
    }

    #[test]
    fn formats_user_summary_and_intervals() {
        assert_eq!(
            format_realtime_user_summary(RealtimeUserSummary {
                deleted: 1,
                added: 2,
                updated: 3,
            }),
            "deleted=1 added=2 updated=3"
        );
        assert_eq!(realtime_interval_to_duration(&json!("45")).as_secs(), 45);
        assert_eq!(realtime_interval_to_duration(&json!(30)).as_secs(), 30);
        assert_eq!(truncate_realtime_receipt_message(" ok "), "ok");
    }

    fn test_node_config() -> NodeConfig {
        NodeConfig {
            url: "https://panel.example.test/base".to_string(),
            token: "token".to_string(),
            node_id: 7,
            machine_id: 3,
            ..NodeConfig::default()
        }
    }

    fn test_node_info(value: serde_json::Value) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(value).unwrap();
        NodeInfo::from_common("https://panel.example.test", 7, common).unwrap()
    }
}
