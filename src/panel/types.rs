use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::config::normalize_config_dir;

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
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub protocol: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub listen_ip: String,
    #[serde(default, deserialize_with = "deserialize_u16_from_any")]
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
    #[serde(skip)]
    pub cert_info: Option<CertInfo>,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub network: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub transport: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub multiplexing: String,
    #[serde(default)]
    pub network_settings: Value,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub encryption: String,
    #[serde(default)]
    pub encryption_settings: EncSettings,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub server_name: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub flow: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub cipher: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub server_key: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub congestion_control: String,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default, deserialize_with = "deserialize_string_vec_from_any")]
    pub padding_scheme: Vec<String>,
    #[serde(default)]
    pub up_mbps: u32,
    #[serde(default)]
    pub down_mbps: u32,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub obfs: String,
    #[serde(
        default,
        rename = "obfs-password",
        deserialize_with = "deserialize_string_from_any"
    )]
    pub obfs_password: String,
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Route {
    #[serde(default)]
    pub id: u32,
    #[serde(
        default,
        rename = "match",
        deserialize_with = "deserialize_string_vec_from_any"
    )]
    pub match_rules: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub action: String,
    #[serde(default, deserialize_with = "deserialize_option_string_from_any")]
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealtimeBootstrap {
    pub enabled: bool,
    pub url: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct TlsSettings {
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub server_name: String,
    #[serde(default, deserialize_with = "deserialize_string_vec_from_any")]
    pub alpn: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub dest: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub server_port: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub short_id: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub private_key: String,
    #[serde(
        default,
        rename = "mldsa65Seed",
        deserialize_with = "deserialize_string_from_any"
    )]
    pub mldsa65_seed: String,
    #[serde(default)]
    pub xver: Value,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub cert_mode: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub cert_file: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub key_file: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub provider: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub dns_env: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub reject_unknown_sni: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertInfo {
    pub cert_mode: String,
    pub cert_file: String,
    pub key_file: String,
    pub cert_domain: String,
    pub dns_env: BTreeMap<String, String>,
    pub provider: String,
    pub reject_unknown_sni: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct EncSettings {
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub mode: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub ticket: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub server_padding: String,
    #[serde(default, deserialize_with = "deserialize_string_from_any")]
    pub private_key: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortValue(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    Naive,
    Mieru,
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

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserListBody {
    #[serde(default)]
    pub users: Vec<UserInfo>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
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
        Self::from_common_with_config_dir(api_host, node_id, "/etc/v2node", common)
    }

    pub fn from_common_with_config_dir(
        api_host: &str,
        node_id: u32,
        config_dir: &str,
        mut common: CommonNode,
    ) -> Result<Self, String> {
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
        let tag = format!(
            "[{}]-{}:{}",
            api_host.trim_end_matches('/'),
            protocol.as_str(),
            node_id
        );
        common.cert_info = Some(build_cert_info(&common, protocol, node_id, config_dir));

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
            "naive" => Some(Self::Naive),
            "mieru" => Some(Self::Mieru),
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
            Self::Naive => "naive",
            Self::Mieru => "mieru",
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

fn deserialize_u16_from_any<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<Value>::deserialize(deserializer)? else {
        return Ok(0);
    };

    match value {
        Value::Number(number) => number
            .as_u64()
            .filter(|value| *value <= u16::MAX as u64)
            .map(|value| value as u16)
            .ok_or_else(|| de::Error::custom("port number is out of range")),
        Value::String(text) => {
            let text = text.trim();
            if text.is_empty() {
                Ok(0)
            } else {
                text.parse::<u16>()
                    .map_err(|_| de::Error::custom("port string is not a valid u16"))
            }
        }
        _ => Err(de::Error::custom("port must be a string or number")),
    }
}

fn deserialize_string_from_any<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value,
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(_) => {
            return Err(de::Error::custom(
                "value must be a string, number, bool, or null",
            ))
        }
    })
}

fn deserialize_option_string_from_any<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_string_from_any(deserializer)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn deserialize_string_vec_from_any<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<Value>::deserialize(deserializer)? else {
        return Ok(Vec::new());
    };
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(value) => {
            if value.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![value])
            }
        }
        Value::Array(values) => values
            .into_iter()
            .filter(|value| !value.is_null())
            .map(|value| match value {
                Value::String(value) => Ok(value),
                Value::Number(value) => Ok(value.to_string()),
                Value::Bool(value) => Ok(value.to_string()),
                _ => Err(de::Error::custom(
                    "array values must be strings, numbers, bools, or null",
                )),
            })
            .collect(),
        _ => Err(de::Error::custom("value must be an array, string, or null")),
    }
}

fn interval_to_duration(value: &Value) -> Option<Duration> {
    match value {
        Value::Number(number) => number.as_u64().map(Duration::from_secs),
        Value::String(text) => text.parse::<u64>().ok().map(Duration::from_secs),
        _ => None,
    }
}

fn build_cert_info(
    common: &CommonNode,
    protocol: Protocol,
    node_id: u32,
    config_dir: &str,
) -> CertInfo {
    let config_dir = normalize_config_dir(config_dir);
    let default_prefix = format!(
        "{}/{}{}",
        config_dir.trim_end_matches('/'),
        protocol.as_str(),
        node_id
    );
    let cert_file = first_non_empty(
        common.tls_settings.cert_file.trim(),
        &format!("{default_prefix}.cer"),
    );
    let key_file = first_non_empty(
        common.tls_settings.key_file.trim(),
        &format!("{default_prefix}.key"),
    );

    CertInfo {
        cert_mode: common.tls_settings.cert_mode.trim().to_string(),
        cert_file,
        key_file,
        cert_domain: common.tls_settings.server_name.trim().to_string(),
        dns_env: parse_dns_env(&common.tls_settings.dns_env),
        provider: common.tls_settings.provider.trim().to_string(),
        reject_unknown_sni: common.tls_settings.reject_unknown_sni.trim() == "1",
    }
}

fn first_non_empty(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn parse_dns_env(value: &str) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for item in value.split(',') {
        let Some((key, value)) = item.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        env.insert(key.to_string(), value.trim().to_string());
    }
    env
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
            "naive",
            "mieru",
        ] {
            assert!(Protocol::parse(protocol).is_some(), "{protocol}");
        }
        assert!(Protocol::parse("unknown").is_none());
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
    fn common_node_accepts_string_server_port_and_mieru_fields() {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "mieru",
            "server_port": "2999",
            "transport": "udp",
            "multiplexing": "MULTIPLEXING_HIGH"
        }))
        .unwrap();

        assert_eq!(common.server_port, 2999);
        assert_eq!(common.transport, "udp");
        assert_eq!(common.multiplexing, "MULTIPLEXING_HIGH");
    }

    #[test]
    fn common_node_accepts_nullable_panel_fields() {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "hysteria2",
            "listen_ip": "0.0.0.0",
            "server_port": 19009,
            "network": null,
            "networkSettings": null,
            "obfs": null,
            "obfs-password": null,
            "tls": 1,
            "tls_settings": {
                "server_name": "example.test",
                "alpn": null,
                "cert_mode": "file"
            }
        }))
        .unwrap();

        assert_eq!(common.protocol, "hysteria2");
        assert_eq!(common.network, "");
        assert_eq!(common.obfs, "");
        assert_eq!(common.obfs_password, "");
        assert_eq!(common.tls_settings.alpn, Vec::<String>::new());
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

    #[test]
    fn node_info_defaults_certificate_paths_from_config_dir() {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "hysteria2",
            "tls": 1,
            "tls_settings": {
                "server_name": "node.example.test",
                "cert_mode": "dns",
                "dns_env": "A=1,B=2",
                "provider": "cloudflare",
                "reject_unknown_sni": "1"
            }
        }))
        .unwrap();

        let node = NodeInfo::from_common_with_config_dir(
            "https://panel.example.test/",
            10,
            "/srv/v2node",
            common,
        )
        .unwrap();
        let cert = node.common.cert_info.unwrap();

        assert_eq!(cert.cert_file, "/srv/v2node/hysteria210.cer");
        assert_eq!(cert.key_file, "/srv/v2node/hysteria210.key");
        assert_eq!(cert.cert_domain, "node.example.test");
        assert_eq!(cert.dns_env["A"], "1");
        assert_eq!(cert.dns_env["B"], "2");
        assert!(cert.reject_unknown_sni);
    }
}
