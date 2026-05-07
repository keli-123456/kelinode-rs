use crate::config::AppConfig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeMode {
    DirectNode,
    MachineBinding,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bootstrap {
    pub mode: RuntimeMode,
    pub node_count: usize,
    pub machine_profile_count: usize,
}

impl Bootstrap {
    pub fn from_config(config: &AppConfig) -> Self {
        let Ok(resolved) = config.resolve_runtime() else {
            return Self {
                mode: RuntimeMode::Invalid,
                node_count: 0,
                machine_profile_count: 0,
            };
        };

        let mode = if resolved.machine.enabled {
            RuntimeMode::MachineBinding
        } else if !resolved.nodes.is_empty() {
            RuntimeMode::DirectNode
        } else {
            RuntimeMode::Invalid
        };

        Self {
            mode,
            node_count: resolved.nodes.len(),
            machine_profile_count: resolved.machine.profiles.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{AppConfig, MachineProfileConfig};

    use super::{Bootstrap, RuntimeMode};

    #[test]
    fn detects_machine_mode_before_direct_node() {
        let mut config = AppConfig::default();
        config.panel.url = "https://panel.example.test".to_string();
        config.panel.token = "token".to_string();
        config.panel.node_id = 9;
        config.machine.profiles.push(MachineProfileConfig {
            url: "https://panel.example.test".to_string(),
            token: "token".to_string(),
            machine_id: 1,
            ..MachineProfileConfig::default()
        });

        let bootstrap = Bootstrap::from_config(&config);

        assert_eq!(bootstrap.mode, RuntimeMode::MachineBinding);
        assert_eq!(bootstrap.machine_profile_count, 1);
    }
}
