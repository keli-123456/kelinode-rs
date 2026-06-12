use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/kelinode";
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    #[serde(default)]
    pub panel: PanelConfig,
    #[serde(default)]
    pub kernel: KernelConfig,
    #[serde(default)]
    pub realtime: RealtimeConfig,
    #[serde(default)]
    pub machine: MachineConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PanelConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub node_id: u32,
    #[serde(default)]
    pub machine_id: u32,
    #[serde(default)]
    pub timeout: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct KernelConfig {
    #[serde(default = "default_core_type")]
    pub r#type: String,
    #[serde(default)]
    pub core_command: String,
    #[serde(default = "default_config_dir")]
    pub config_dir: String,
    #[serde(default)]
    pub log_level: String,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default = "default_dns_block_private_ips")]
    pub dns_block_private_ips: bool,
    #[serde(default)]
    pub dns_private_ip_allowlist: Vec<String>,
    #[serde(default)]
    pub ip_strategy: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct RealtimeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub ping_interval: u64,
    #[serde(default)]
    pub reconnect_interval: u64,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MachineConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub continue_on_error: Option<bool>,
    #[serde(default)]
    pub profiles: Vec<MachineProfileConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MachineProfileConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub machine_id: u32,
    #[serde(default)]
    pub timeout: u64,
    #[serde(default)]
    pub config_dir: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct AgentConfig {
    #[serde(default)]
    pub subscription_proxy: SubscriptionProxyConfig,
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
    #[serde(default)]
    pub profiles: Vec<SubscriptionProxyProfile>,
    #[serde(default)]
    pub website_profiles: Vec<WebsiteProxyProfile>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SubscriptionProxyZeroSslConfig {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub certificate_id: String,
    #[serde(default)]
    pub validation_path: String,
    #[serde(default, deserialize_with = "deserialize_validation_content")]
    pub validation_content: String,
    #[serde(default)]
    pub certificate_pem: String,
    #[serde(default)]
    pub ca_bundle_pem: String,
    #[serde(default)]
    pub expires_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SubscriptionProxyProfile {
    #[serde(default)]
    pub site_id: String,
    #[serde(default)]
    pub upstream_base_url: String,
    #[serde(default)]
    pub subscribe_path: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct WebsiteProxyProfile {
    #[serde(default)]
    pub site_id: String,
    #[serde(default)]
    pub upstream_base_url: String,
    #[serde(default)]
    pub path_prefix: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct NodeConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub node_id: u32,
    #[serde(default)]
    pub machine_id: u32,
    #[serde(default)]
    pub timeout: u64,
    #[serde(default)]
    pub config_dir: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ValidationContentInput {
    Text(String),
    Lines(Vec<String>),
    Bool(bool),
    Signed(i64),
    Unsigned(u64),
    Float(f64),
}

impl ValidationContentInput {
    fn into_normalized_string(self) -> String {
        match self {
            Self::Text(value) => value.trim().to_string(),
            Self::Lines(values) => values
                .into_iter()
                .map(|value| value.trim().to_string())
                .collect::<Vec<_>>()
                .join("\n"),
            Self::Bool(value) => value.to_string(),
            Self::Signed(value) => value.to_string(),
            Self::Unsigned(value) => value.to_string(),
            Self::Float(value) => value.to_string(),
        }
    }
}

fn deserialize_validation_content<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<ValidationContentInput>::deserialize(deserializer)?
        .map(ValidationContentInput::into_normalized_string)
        .unwrap_or_default())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub kernel: KernelConfig,
    pub realtime: RealtimeConfig,
    pub machine: ResolvedMachineConfig,
    pub agent: AgentConfig,
    pub nodes: Vec<NodeConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedMachineConfig {
    pub enabled: bool,
    pub continue_on_error: bool,
    pub profiles: Vec<MachineProfileConfig>,
}

impl AppConfig {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let resolved_path = resolve_config_path(path);
        let content = fs::read_to_string(&resolved_path)
            .map_err(|err| format!("read config file {}: {err}", resolved_path.display()))?;

        match config_extension(&resolved_path).as_deref() {
            Some("yml") | Some("yaml") => serde_yaml::from_str(&content)
                .map_err(|err| format!("decode yaml config {}: {err}", resolved_path.display())),
            Some("json") => serde_json::from_str(&content)
                .map_err(|err| format!("decode json config {}: {err}", resolved_path.display())),
            _ => match serde_json::from_str(&content) {
                Ok(config) => Ok(config),
                Err(json_err) => serde_yaml::from_str(&content).map_err(|yaml_err| {
                    format!(
                        "decode config {}: json: {json_err}; yaml: {yaml_err}",
                        resolved_path.display()
                    )
                }),
            },
        }
    }

    pub fn direct_node(&self) -> Option<NodeConfig> {
        if !self.nodes.is_empty() || !self.machine.profiles.is_empty() {
            return None;
        }
        let api_host = self.panel.url.trim();
        let token = self.panel.token.trim();
        if api_host.is_empty() || token.is_empty() || self.panel.node_id == 0 {
            return None;
        }
        Some(NodeConfig {
            url: api_host.to_string(),
            token: token.to_string(),
            node_id: self.panel.node_id,
            machine_id: self.panel.machine_id,
            timeout: self.panel.timeout,
            config_dir: normalize_config_dir(&self.kernel.config_dir),
        })
    }

    pub fn machine_mode_enabled(&self) -> bool {
        self.machine.enabled || !self.machine.profiles.is_empty()
    }

    pub fn resolve_runtime(&self) -> Result<ResolvedConfig, String> {
        let mut kernel = self.kernel.clone();
        kernel.r#type = kernel.r#type.trim().to_string();
        kernel.core_command = kernel.core_command.trim().to_string();
        kernel.config_dir = normalize_config_dir(&kernel.config_dir);
        kernel.dns_servers = normalize_string_list(&kernel.dns_servers);
        kernel.dns_private_ip_allowlist = normalize_string_list(&kernel.dns_private_ip_allowlist);
        kernel.ip_strategy = kernel.ip_strategy.trim().to_string();
        kernel.log_level = kernel.log_level.trim().to_string();

        let mut realtime = self.realtime.clone();
        realtime.url = realtime.url.trim().to_string();

        let base_api_host = self.panel.url.trim().to_string();
        let base_token = self.panel.token.trim().to_string();
        let base_timeout = self.panel.timeout;
        let base_config_dir = kernel.config_dir.clone();

        let machine_enabled = self.machine_mode_enabled();
        let mut machine = ResolvedMachineConfig {
            enabled: machine_enabled,
            continue_on_error: self.machine.continue_on_error.unwrap_or(machine_enabled),
            profiles: Vec::with_capacity(self.machine.profiles.len()),
        };

        for row in &self.machine.profiles {
            let api_host = first_non_empty(row.url.trim(), &base_api_host);
            let token = first_non_empty(row.token.trim(), &base_token);
            let timeout = first_positive_u64(row.timeout, base_timeout);
            let mut name = row.name.trim().to_string();
            if name.is_empty() && row.machine_id > 0 {
                name = format!("machine-{}", row.machine_id);
            }
            if api_host.is_empty() || token.is_empty() || row.machine_id == 0 {
                return Err(
                    "config v2 machine profiles require url, token and machine_id".to_string(),
                );
            }
            machine.profiles.push(MachineProfileConfig {
                name,
                url: api_host,
                token,
                machine_id: row.machine_id,
                timeout,
                config_dir: normalize_optional_config_dir(&row.config_dir),
            });
        }

        let agent = AgentConfig {
            subscription_proxy: normalize_subscription_proxy(&self.agent.subscription_proxy),
        };

        let nodes = if self.nodes.is_empty() {
            if !machine.profiles.is_empty() {
                Vec::new()
            } else {
                if base_api_host.is_empty() || base_token.is_empty() || self.panel.node_id == 0 {
                    return Err(
                        "config v2 requires panel.url, panel.token and panel.node_id when nodes is empty"
                            .to_string(),
                    );
                }
                vec![NodeConfig {
                    url: base_api_host,
                    token: base_token,
                    node_id: self.panel.node_id,
                    machine_id: self.panel.machine_id,
                    timeout: base_timeout,
                    config_dir: base_config_dir,
                }]
            }
        } else {
            let multi_node = self.nodes.len() > 1;
            let mut nodes = Vec::with_capacity(self.nodes.len());
            for row in &self.nodes {
                let api_host = first_non_empty(row.url.trim(), &base_api_host);
                let token = first_non_empty(row.token.trim(), &base_token);
                let timeout = first_positive_u64(row.timeout, base_timeout);
                if api_host.is_empty() || token.is_empty() || row.node_id == 0 {
                    return Err(
                        "config v2 nodes entries require node_id and inherit or define url/token"
                            .to_string(),
                    );
                }
                nodes.push(NodeConfig {
                    url: api_host,
                    token,
                    node_id: row.node_id,
                    machine_id: first_positive_u32(row.machine_id, self.panel.machine_id),
                    timeout,
                    config_dir: resolve_node_config_dir(
                        &base_config_dir,
                        &row.config_dir,
                        row.node_id,
                        multi_node,
                    ),
                });
            }
            nodes
        };

        Ok(ResolvedConfig {
            kernel,
            realtime,
            machine,
            agent,
            nodes,
        })
    }
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            r#type: default_core_type(),
            core_command: String::new(),
            config_dir: default_config_dir(),
            log_level: String::new(),
            dns_servers: Vec::new(),
            dns_block_private_ips: default_dns_block_private_ips(),
            dns_private_ip_allowlist: Vec::new(),
            ip_strategy: String::new(),
        }
    }
}

fn default_core_type() -> String {
    "keli-core-rs".to_string()
}

fn default_config_dir() -> String {
    DEFAULT_CONFIG_DIR.to_string()
}

fn default_dns_block_private_ips() -> bool {
    true
}

pub fn resolve_config_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    if path.as_os_str().is_empty() || path.exists() {
        return path.to_path_buf();
    }

    let Some(extension) = config_extension(path) else {
        return path.to_path_buf();
    };
    let candidates: &[&str] = match extension.as_str() {
        "json" => &["yml", "yaml"],
        "yml" | "yaml" => &["json"],
        _ => &[],
    };
    if candidates.is_empty() {
        return path.to_path_buf();
    }

    for candidate_extension in candidates {
        let candidate = path.with_extension(candidate_extension);
        if candidate.exists() {
            return candidate;
        }
    }
    path.to_path_buf()
}

pub fn normalize_config_dir(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return DEFAULT_CONFIG_DIR.to_string();
    }

    clean_posix_path(path)
}

pub fn resolve_node_config_dir(
    base_dir: &str,
    override_dir: &str,
    node_id: u32,
    multi_node: bool,
) -> String {
    if !override_dir.trim().is_empty() {
        return normalize_config_dir(override_dir);
    }

    let root = normalize_config_dir(base_dir);
    if multi_node {
        join_posix_path(&root, &format!("node-{node_id}"))
    } else {
        root
    }
}

fn normalize_subscription_proxy(src: &SubscriptionProxyConfig) -> SubscriptionProxyConfig {
    let profiles = src
        .profiles
        .iter()
        .map(|row| SubscriptionProxyProfile {
            site_id: row.site_id.trim().to_string(),
            upstream_base_url: trim_trailing_slashes(row.upstream_base_url.trim()),
            subscribe_path: row.subscribe_path.trim().trim_matches('/').to_string(),
        })
        .collect::<Vec<_>>();
    let website_profiles = src
        .website_profiles
        .iter()
        .map(|row| WebsiteProxyProfile {
            site_id: row.site_id.trim().to_string(),
            upstream_base_url: trim_trailing_slashes(row.upstream_base_url.trim()),
            path_prefix: normalize_proxy_path_prefix(&row.path_prefix),
        })
        .collect::<Vec<_>>();

    SubscriptionProxyConfig {
        enabled: src.enabled || !profiles.is_empty() || !website_profiles.is_empty(),
        https_listen: src.https_listen.trim().to_string(),
        http_listen: src.http_listen.trim().to_string(),
        cert_file: src.cert_file.trim().to_string(),
        key_file: src.key_file.trim().to_string(),
        certificate_domain: src.certificate_domain.trim().to_string(),
        challenge_dir: src.challenge_dir.trim().to_string(),
        zerossl: normalize_subscription_proxy_zerossl(&src.zerossl),
        site_id: src.site_id.trim().to_string(),
        upstream_base_url: trim_trailing_slashes(src.upstream_base_url.trim()),
        subscribe_path: src.subscribe_path.trim().trim_matches('/').to_string(),
        allow_http_fallback: src.allow_http_fallback,
        max_response_bytes: src.max_response_bytes,
        profiles,
        website_profiles,
    }
}

fn normalize_subscription_proxy_zerossl(
    src: &SubscriptionProxyZeroSslConfig,
) -> SubscriptionProxyZeroSslConfig {
    SubscriptionProxyZeroSslConfig {
        status: src.status.trim().to_string(),
        certificate_id: src.certificate_id.trim().to_string(),
        validation_path: src.validation_path.trim().to_string(),
        validation_content: src.validation_content.trim().to_string(),
        certificate_pem: src.certificate_pem.trim().to_string(),
        ca_bundle_pem: src.ca_bundle_pem.trim().to_string(),
        expires_at: src.expires_at.trim().to_string(),
    }
}

fn normalize_string_list(values: &[String]) -> Vec<String> {
    let mut output: Vec<String> = Vec::new();
    for value in values {
        let cleaned = value.trim();
        if cleaned.is_empty() || output.iter().any(|existing| existing.as_str() == cleaned) {
            continue;
        }
        output.push(cleaned.to_string());
    }
    output
}

fn first_non_empty(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.trim().to_string()
    } else {
        value.trim().to_string()
    }
}

fn first_positive_u32(value: u32, fallback: u32) -> u32 {
    if value > 0 {
        value
    } else {
        fallback
    }
}

fn first_positive_u64(value: u64, fallback: u64) -> u64 {
    if value > 0 {
        value
    } else {
        fallback
    }
}

fn join_posix_path(root: &str, child: &str) -> String {
    format!(
        "{}/{}",
        root.trim_end_matches('/'),
        child.trim_start_matches('/')
    )
}

fn trim_trailing_slashes(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

fn normalize_proxy_path_prefix(value: &str) -> String {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() || value == "/" {
        return "/".to_string();
    }
    if value.starts_with('/') {
        value.to_string()
    } else {
        format!("/{value}")
    }
}

fn clean_posix_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let absolute = path.starts_with('/');
    let mut parts = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if !parts.is_empty() && parts.last() != Some(&"..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(part);
                }
            }
            value => parts.push(value),
        }
    }

    if absolute {
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

fn normalize_optional_config_dir(path: &str) -> String {
    if path.trim().is_empty() {
        String::new()
    } else {
        normalize_config_dir(path)
    }
}

fn config_extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        normalize_config_dir, resolve_config_path, resolve_node_config_dir, AppConfig,
        KernelConfig, MachineProfileConfig, NodeConfig, SubscriptionProxyProfile,
        DEFAULT_CONFIG_DIR,
    };

    #[test]
    fn kernel_defaults_match_binary_layout() {
        let kernel = KernelConfig::default();

        assert_eq!(kernel.r#type, "keli-core-rs");
        assert!(kernel.core_command.is_empty());
        assert_eq!(kernel.config_dir, DEFAULT_CONFIG_DIR);
        assert!(kernel.dns_block_private_ips);
        assert!(kernel.dns_private_ip_allowlist.is_empty());
    }

    #[test]
    fn direct_node_requires_panel_identity() {
        let mut config = AppConfig::default();
        assert!(config.direct_node().is_none());

        config.panel.url = "https://panel.example.test".to_string();
        config.panel.token = "token".to_string();
        config.panel.node_id = 7;

        assert_eq!(config.direct_node().unwrap().node_id, 7);
    }

    #[test]
    fn subscription_proxy_defaults_to_disabled() {
        let config = AppConfig::default();

        assert!(!config.agent.subscription_proxy.enabled);
        assert!(config.agent.subscription_proxy.profiles.is_empty());
    }

    #[test]
    fn resolve_runtime_direct_node_inherits_panel() {
        let mut config = AppConfig::default();
        config.panel.url = " https://panel.example.test ".to_string();
        config.panel.token = " token ".to_string();
        config.panel.node_id = 7;
        config.panel.machine_id = 3;
        config.panel.timeout = 18;
        config.kernel.config_dir = "/var/lib/v2node/./".to_string();

        let resolved = config.resolve_runtime().unwrap();

        assert_eq!(resolved.nodes.len(), 1);
        assert_eq!(resolved.nodes[0].url, "https://panel.example.test");
        assert_eq!(resolved.nodes[0].token, "token");
        assert_eq!(resolved.nodes[0].node_id, 7);
        assert_eq!(resolved.nodes[0].machine_id, 3);
        assert_eq!(resolved.nodes[0].timeout, 18);
        assert_eq!(resolved.nodes[0].config_dir, "/var/lib/v2node");
    }

    #[test]
    fn resolve_runtime_multi_node_config_dirs() {
        let mut config = AppConfig::default();
        config.panel.url = "https://panel.example.test".to_string();
        config.panel.token = "shared-token".to_string();
        config.panel.machine_id = 9;
        config.kernel.config_dir = "/var/lib/v2node".to_string();
        config.nodes = vec![
            NodeConfig {
                node_id: 1,
                ..NodeConfig::default()
            },
            NodeConfig {
                node_id: 2,
                config_dir: "/srv/v2node/custom-2//".to_string(),
                ..NodeConfig::default()
            },
        ];

        let resolved = config.resolve_runtime().unwrap();

        assert_eq!(resolved.nodes.len(), 2);
        assert_eq!(resolved.nodes[0].config_dir, "/var/lib/v2node/node-1");
        assert_eq!(resolved.nodes[0].machine_id, 9);
        assert_eq!(resolved.nodes[1].config_dir, "/srv/v2node/custom-2");
    }

    #[test]
    fn resolve_runtime_machine_profiles_defer_nodes() {
        let mut config = AppConfig::default();
        config.panel.url = "https://panel.example.test".to_string();
        config.panel.token = "shared-token".to_string();
        config.panel.timeout = 12;
        config.machine.profiles.push(MachineProfileConfig {
            machine_id: 11,
            ..MachineProfileConfig::default()
        });

        let resolved = config.resolve_runtime().unwrap();

        assert!(resolved.nodes.is_empty());
        assert!(resolved.machine.enabled);
        assert!(resolved.machine.continue_on_error);
        assert_eq!(resolved.machine.profiles[0].name, "machine-11");
        assert_eq!(
            resolved.machine.profiles[0].url,
            "https://panel.example.test"
        );
        assert_eq!(resolved.machine.profiles[0].timeout, 12);
    }

    #[test]
    fn resolve_runtime_respects_explicit_machine_continue_on_error_false() {
        let mut config = AppConfig::default();
        config.panel.url = "https://panel.example.test".to_string();
        config.panel.token = "shared-token".to_string();
        config.machine.continue_on_error = Some(false);
        config.machine.profiles.push(MachineProfileConfig {
            url: "https://panel-b.example.test".to_string(),
            token: "machine-token".to_string(),
            machine_id: 22,
            timeout: 20,
            config_dir: " /srv/site-b ".to_string(),
            ..MachineProfileConfig::default()
        });

        let resolved = config.resolve_runtime().unwrap();

        assert!(!resolved.machine.continue_on_error);
        assert_eq!(resolved.machine.profiles[0].config_dir, "/srv/site-b");
    }

    #[test]
    fn resolve_runtime_rejects_node_without_url_token() {
        let mut config = AppConfig::default();
        config.nodes.push(NodeConfig {
            node_id: 1,
            ..NodeConfig::default()
        });

        let err = config.resolve_runtime().unwrap_err();

        assert!(err.contains("nodes entries require"));
    }

    #[test]
    fn resolve_runtime_trims_subscription_proxy_profiles() {
        let mut config = AppConfig::default();
        config.panel.url = "https://panel.example.test".to_string();
        config.panel.token = "token".to_string();
        config.panel.node_id = 1;
        config.agent.subscription_proxy.upstream_base_url =
            " https://panel.example.test/ ".to_string();
        config.agent.subscription_proxy.subscribe_path = " /s/ ".to_string();
        config.agent.subscription_proxy.zerossl.certificate_id = " cert-1 ".to_string();
        config.agent.subscription_proxy.zerossl.validation_path =
            " /.well-known/acme-challenge/token ".to_string();
        config.agent.subscription_proxy.zerossl.validation_content = " challenge ".to_string();
        config
            .agent
            .subscription_proxy
            .profiles
            .push(SubscriptionProxyProfile {
                site_id: " site-a ".to_string(),
                upstream_base_url: " https://site-a.example.test/ ".to_string(),
                subscribe_path: "/sub/".to_string(),
            });

        let resolved = config.resolve_runtime().unwrap();
        let proxy = resolved.agent.subscription_proxy;

        assert!(proxy.enabled);
        assert_eq!(proxy.upstream_base_url, "https://panel.example.test");
        assert_eq!(proxy.subscribe_path, "s");
        assert_eq!(proxy.profiles[0].site_id, "site-a");
        assert_eq!(
            proxy.profiles[0].upstream_base_url,
            "https://site-a.example.test"
        );
        assert_eq!(proxy.profiles[0].subscribe_path, "sub");
        assert_eq!(proxy.zerossl.certificate_id, "cert-1");
        assert_eq!(
            proxy.zerossl.validation_path,
            "/.well-known/acme-challenge/token"
        );
        assert_eq!(proxy.zerossl.validation_content, "challenge");
    }

    #[test]
    fn resolve_runtime_normalizes_core_command() {
        let mut config = AppConfig::default();
        config.panel.url = "https://panel.example.test".to_string();
        config.panel.token = "token".to_string();
        config.panel.node_id = 1;
        config.kernel.r#type = " keli-core-rs ".to_string();
        config.kernel.core_command = " /usr/local/bin/keli-core-rs ".to_string();

        let resolved = config.resolve_runtime().unwrap();

        assert_eq!(resolved.kernel.r#type, "keli-core-rs");
        assert_eq!(resolved.kernel.core_command, "/usr/local/bin/keli-core-rs");
    }

    #[test]
    fn resolve_runtime_normalizes_dns_security_options() {
        let mut config = AppConfig::default();
        config.panel.url = "https://panel.example.test".to_string();
        config.panel.token = "token".to_string();
        config.panel.node_id = 1;
        config.kernel.dns_servers = vec![
            " 9.9.9.9 ".to_string(),
            "".to_string(),
            " https://dns.example/dns-query ".to_string(),
        ];
        config.kernel.dns_block_private_ips = true;
        config.kernel.dns_private_ip_allowlist = vec![
            " domain:internal.example ".to_string(),
            "".to_string(),
            " ip:10.0.0.0/8 ".to_string(),
        ];

        let resolved = config.resolve_runtime().unwrap();

        assert_eq!(
            resolved.kernel.dns_servers,
            vec![
                "9.9.9.9".to_string(),
                "https://dns.example/dns-query".to_string()
            ]
        );
        assert!(resolved.kernel.dns_block_private_ips);
        assert_eq!(
            resolved.kernel.dns_private_ip_allowlist,
            vec![
                "domain:internal.example".to_string(),
                "ip:10.0.0.0/8".to_string()
            ]
        );
    }

    #[test]
    fn normalizes_config_dir_with_posix_semantics() {
        assert_eq!(normalize_config_dir(""), DEFAULT_CONFIG_DIR);
        assert_eq!(
            normalize_config_dir("/var/lib/v2node/../v2node"),
            "/var/lib/v2node"
        );
        assert_eq!(
            resolve_node_config_dir("/var/lib/v2node", "", 5, true),
            "/var/lib/v2node/node-5"
        );
    }

    #[test]
    fn resolve_config_path_switches_between_json_and_yaml() {
        let dir = temp_test_dir("resolve-config-path");
        let json_path = dir.join("config.json");
        let yaml_path = dir.join("config.yml");
        fs::write(&yaml_path, "panel:\n  url: https://panel.example.test\n").unwrap();

        assert_eq!(resolve_config_path(&json_path), yaml_path);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_from_path_decodes_yaml_config() {
        let dir = temp_test_dir("load-yaml-config");
        let path = dir.join("config.yml");
        fs::write(
            &path,
            r#"
panel:
  url: "https://panel.example.test"
  token: "token"
  node_id: 7
kernel:
  config_dir: "/var/lib/v2node"
"#,
        )
        .unwrap();

        let config = AppConfig::load_from_path(&path).unwrap();
        let resolved = config.resolve_runtime().unwrap();

        assert_eq!(resolved.nodes[0].node_id, 7);
        assert_eq!(resolved.nodes[0].config_dir, "/var/lib/v2node");
        assert!(resolved.kernel.dns_block_private_ips);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_from_path_decodes_subscription_proxy_zerossl_content() {
        let dir = temp_test_dir("load-zerossl-config");
        let path = dir.join("config.yml");
        fs::write(
            &path,
            r#"
agent:
  subscription_proxy:
    zerossl:
      certificate_id: " cert-1 "
      validation_path: " /.well-known/acme-challenge/token "
      validation_content:
        - " line-a "
        - "line-b"
      certificate_pem: " -----BEGIN CERTIFICATE----- "
      ca_bundle_pem: " -----BEGIN CA----- "
"#,
        )
        .unwrap();

        let config = AppConfig::load_from_path(&path).unwrap();
        let proxy = config.agent.subscription_proxy;

        assert_eq!(proxy.zerossl.validation_content, "line-a\nline-b");
        assert_eq!(proxy.zerossl.certificate_id, " cert-1 ");

        let _ = fs::remove_dir_all(dir);
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
