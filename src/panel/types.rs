use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
pub struct NodeInfo {
    pub id: u32,
    pub protocol: Protocol,
    pub security: Security,
    pub push_interval: Duration,
    pub pull_interval: Duration,
    pub tag: String,
    pub common: CommonNode,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CommonNode {
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub listen_ip: String,
    #[serde(default)]
    pub server_port: u16,
    #[serde(default)]
    pub port: PortValue,
    #[serde(default)]
    pub ports: PortValue,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub base_config: Option<BaseConfig>,
    #[serde(default)]
    pub tls: u8,
    #[serde(default)]
    pub tls_settings: TlsSettings,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub network_settings: Value,
    #[serde(default)]
    pub encryption: String,
    #[serde(default)]
    pub encryption_settings: EncSettings,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub server_key: String,
    #[serde(default)]
    pub congestion_control: String,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default)]
    pub padding_scheme: Vec<String>,
    #[serde(default)]
    pub up_mbps: u32,
    #[serde(default)]
    pub down_mbps: u32,
    #[serde(default)]
    pub obfs: String,
    #[serde(default, rename = "obfs-password")]
    pub obfs_password: String,
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Route {
    #[serde(default)]
    pub id: u32,
    #[serde(default, rename = "match")]
    pub match_rules: Vec<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub action_value: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BaseConfig {
    #[serde(default)]
    pub push_interval: Value,
    #[serde(default)]
    pub pull_interval: Value,
    #[serde(default)]
    pub device_online_min_traffic: u64,
    #[serde(default)]
    pub node_report_min_traffic: u64,
    #[serde(default)]
    pub device_limit_fallback: u32,
    #[serde(default)]
    pub realtime: Option<RealtimeBaseConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct RealtimeBaseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub ping_interval: Value,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct TlsSettings {
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub dest: String,
    #[serde(default)]
    pub server_port: String,
    #[serde(default)]
    pub short_id: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default, rename = "mldsa65Seed")]
    pub mldsa65_seed: String,
    #[serde(default)]
    pub xver: Value,
    #[serde(default)]
    pub cert_mode: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub dns_env: String,
    #[serde(default)]
    pub reject_unknown_sni: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct EncSettings {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub ticket: String,
    #[serde(default)]
    pub server_padding: String,
    #[serde(default)]
    pub private_key: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortValue(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    Vmess,
    Vless,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
    Anytls,
    Socks,
    Http,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    None,
    Tls,
    Reality,
    Other(u8),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserInfo {
    pub id: u32,
    pub uuid: String,
    #[serde(default)]
    pub speed_limit: u32,
    #[serde(default)]
    pub device_limit: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct UserListBody {
    #[serde(default)]
    pub users: Vec<UserInfo>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct UserDeltaBody {
    #[serde(default)]
    pub full: bool,
    #[serde(default)]
    pub revision: i64,
    #[serde(default)]
    pub users: Vec<UserInfo>,
    #[serde(default)]
    pub deleted: Vec<UserInfo>,
    #[serde(default)]
    pub upsert: Vec<UserInfo>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AliveMap {
    #[serde(default)]
    pub alive: BTreeMap<u32, u32>,
    #[serde(default)]
    pub alive_ips: BTreeMap<u32, Vec<String>>,
    #[serde(default)]
    pub mode: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserTraffic {
    pub uid: u32,
    pub upload: i64,
    pub download: i64,
}

impl NodeInfo {
    pub fn from_common(api_host: &str, node_id: u32, common: CommonNode) -> Result<Self, String> {
        let protocol = Protocol::parse(&common.protocol)
            .ok_or_else(|| format!("unsupported protocol: {}", common.protocol))?;
        let security = Security::from_tls_value(common.tls);
        let push_interval = common
            .base_config
            .as_ref()
            .and_then(|config| interval_to_duration(&config.push_interval))
            .unwrap_or_else(|| Duration::from_secs(60));
        let pull_interval = common
            .base_config
            .as_ref()
            .and_then(|config| interval_to_duration(&config.pull_interval))
            .unwrap_or_else(|| Duration::from_secs(60));
        let tag = format!("[{}]-{}:{}", api_host.trim_end_matches('/'), protocol.as_str(), node_id);

        Ok(Self {
            id: node_id,
            protocol,
            security,
            push_interval,
            pull_interval,
            tag,
            common,
        })
    }
}

impl Protocol {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "vmess" => Some(Self::Vmess),
            "vless" => Some(Self::Vless),
            "trojan" => Some(Self::Trojan),
            "shadowsocks" => Some(Self::Shadowsocks),
            "hysteria2" => Some(Self::Hysteria2),
            "tuic" => Some(Self::Tuic),
            "anytls" => Some(Self::Anytls),
            "socks" => Some(Self::Socks),
            "http" => Some(Self::Http),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Anytls => "anytls",
            Self::Socks => "socks",
            Self::Http => "http",
        }
    }
}

impl Security {
    pub fn from_tls_value(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Tls,
            2 => Self::Reality,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for PortValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PortValueVisitor;

        impl<'de> Visitor<'de> for PortValueVisitor {
            type Value = PortValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("null, a string port, or a numeric port")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PortValue::default())
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PortValue::default())
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PortValue(value.to_string()))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PortValue(value.to_string()))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PortValue(value.to_string()))
            }
        }

        deserializer.deserialize_any(PortValueVisitor)
    }
}

fn interval_to_duration(value: &Value) -> Option<Duration> {
    match value {
        Value::Number(number) => number.as_u64().map(Duration::from_secs),
        Value::String(text) => text.parse::<u64>().ok().map(Duration::from_secs),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CommonNode, NodeInfo, PortValue, Protocol, Security};

    #[test]
    fn parses_protocols_supported_by_go_kelinode() {
        for protocol in [
            "vmess",
            "vless",
            "trojan",
            "shadowsocks",
            "hysteria2",
            "tuic",
            "anytls",
            "socks",
            "http",
        ] {
            assert!(Protocol::parse(protocol).is_some(), "{protocol}");
        }
        assert!(Protocol::parse("naive").is_none());
    }

    #[test]
    fn port_value_accepts_string_number_and_null() {
        let text: PortValue = serde_json::from_value(json!("1000-2000")).unwrap();
        let number: PortValue = serde_json::from_value(json!(443)).unwrap();
        let null: PortValue = serde_json::from_value(json!(null)).unwrap();

        assert_eq!(text.0, "1000-2000");
        assert_eq!(number.0, "443");
        assert_eq!(null.0, "");
    }

    #[test]
    fn node_info_derives_tag_and_intervals() {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "vless",
            "tls": 2,
            "base_config": {
                "push_interval": "30",
                "pull_interval": 45
            }
        }))
        .unwrap();

        let node = NodeInfo::from_common("https://panel.example.test/", 9, common).unwrap();

        assert_eq!(node.protocol, Protocol::Vless);
        assert_eq!(node.security, Security::Reality);
        assert_eq!(node.push_interval.as_secs(), 30);
        assert_eq!(node.pull_interval.as_secs(), 45);
        assert_eq!(node.tag, "[https://panel.example.test]-vless:9");
    }
}
