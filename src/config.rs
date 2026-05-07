use serde::Deserialize;

pub const DEFAULT_CONFIG_DIR: &str = "/etc/v2node";
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
    #[serde(default = "default_config_dir")]
    pub config_dir: String,
    #[serde(default)]
    pub log_level: String,
    #[serde(default)]
    pub dns_servers: Vec<String>,
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
    pub continue_on_error: bool,
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

impl AppConfig {
    pub fn direct_node(&self) -> Option<NodeConfig> {
        if !self.nodes.is_empty() {
            return None;
        }
        if self.panel.url.is_empty() || self.panel.token.is_empty() || self.panel.node_id == 0 {
            return None;
        }
        Some(NodeConfig {
            url: self.panel.url.clone(),
            token: self.panel.token.clone(),
            node_id: self.panel.node_id,
            machine_id: self.panel.machine_id,
            timeout: self.panel.timeout,
            config_dir: self.kernel.config_dir.clone(),
        })
    }

    pub fn machine_mode_enabled(&self) -> bool {
        self.machine.enabled || !self.machine.profiles.is_empty()
    }
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            r#type: default_core_type(),
            config_dir: default_config_dir(),
            log_level: String::new(),
            dns_servers: Vec::new(),
            ip_strategy: String::new(),
        }
    }
}

fn default_core_type() -> String {
    "xray".to_string()
}

fn default_config_dir() -> String {
    DEFAULT_CONFIG_DIR.to_string()
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, KernelConfig, DEFAULT_CONFIG_DIR};

    #[test]
    fn kernel_defaults_match_binary_layout() {
        let kernel = KernelConfig::default();

        assert_eq!(kernel.r#type, "xray");
        assert_eq!(kernel.config_dir, DEFAULT_CONFIG_DIR);
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
}
