use crate::config::{NodeConfig, RealtimeConfig};
use crate::panel::types::NodeInfo;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeManagerOptions {
    pub continue_on_error: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeRuntime {
    pub config: NodeConfig,
    pub info: NodeInfo,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeFailure {
    pub config: NodeConfig,
    pub error: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodeManager {
    runtimes: Vec<NodeRuntime>,
    failures: Vec<NodeFailure>,
    realtime: RealtimeConfig,
    continue_on_error: bool,
}

impl NodeManager {
    pub fn build_with_loader<F>(
        nodes: &[NodeConfig],
        realtime: RealtimeConfig,
        options: NodeManagerOptions,
        mut load_node_info: F,
    ) -> Result<Self, String>
    where
        F: FnMut(&NodeConfig) -> Result<Option<NodeInfo>, String>,
    {
        let mut manager = Self {
            runtimes: Vec::with_capacity(nodes.len()),
            failures: Vec::new(),
            realtime,
            continue_on_error: options.continue_on_error,
        };

        for config in nodes {
            match load_node_info(config) {
                Ok(Some(info)) => manager.runtimes.push(NodeRuntime {
                    config: config.clone(),
                    info,
                }),
                Ok(None) => {
                    let error = "received empty node info".to_string();
                    if !options.continue_on_error {
                        return Err(format_node_error("get node info", config, &error));
                    }
                    manager.record_failure(config, error);
                }
                Err(error) => {
                    if !options.continue_on_error {
                        return Err(format_node_error("get node info", config, &error));
                    }
                    manager.record_failure(config, error);
                }
            }
        }

        Ok(manager)
    }

    pub fn active_configs(&self) -> Vec<NodeConfig> {
        self.runtimes
            .iter()
            .map(|runtime| runtime.config.clone())
            .collect()
    }

    pub fn node_infos(&self) -> Vec<NodeInfo> {
        self.runtimes
            .iter()
            .map(|runtime| runtime.info.clone())
            .collect()
    }

    pub fn failures(&self) -> &[NodeFailure] {
        &self.failures
    }

    pub fn realtime(&self) -> &RealtimeConfig {
        &self.realtime
    }

    pub fn continue_on_error(&self) -> bool {
        self.continue_on_error
    }

    pub fn len(&self) -> usize {
        self.runtimes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.runtimes.is_empty()
    }

    fn record_failure(&mut self, config: &NodeConfig, error: String) {
        self.failures.push(NodeFailure {
            config: config.clone(),
            error,
        });
    }
}

fn format_node_error(action: &str, config: &NodeConfig, error: &str) -> String {
    format!(
        "{} [{}-{}] error: {}",
        action,
        config.url.trim_end_matches('/'),
        config.node_id,
        error
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{NodeManager, NodeManagerOptions};
    use crate::config::{NodeConfig, RealtimeConfig};
    use crate::panel::types::{CommonNode, NodeInfo};

    #[test]
    fn continues_after_node_info_error_when_allowed() {
        let nodes = vec![
            node_config("https://panel-a.example.test", 1),
            node_config("https://panel-b.example.test", 2),
        ];

        let manager = NodeManager::build_with_loader(
            &nodes,
            RealtimeConfig::default(),
            NodeManagerOptions {
                continue_on_error: true,
            },
            |config| {
                if config.node_id == 1 {
                    Err("panel unavailable".to_string())
                } else {
                    Ok(Some(test_node_info(config)))
                }
            },
        )
        .unwrap();

        assert_eq!(manager.len(), 1);
        assert_eq!(manager.active_configs()[0].node_id, 2);
        assert_eq!(manager.failures().len(), 1);
        assert_eq!(manager.failures()[0].config.node_id, 1);
    }

    #[test]
    fn keeps_fail_fast_behavior() {
        let nodes = vec![
            node_config("https://panel-a.example.test", 1),
            node_config("https://panel-b.example.test", 2),
        ];

        let err = NodeManager::build_with_loader(
            &nodes,
            RealtimeConfig::default(),
            NodeManagerOptions::default(),
            |config| {
                if config.node_id == 1 {
                    Err("panel unavailable".to_string())
                } else {
                    Ok(Some(test_node_info(config)))
                }
            },
        )
        .unwrap_err();

        assert!(err.contains("get node info [https://panel-a.example.test-1]"));
    }

    #[test]
    fn treats_empty_node_info_as_failure() {
        let nodes = vec![node_config("https://panel.example.test", 7)];

        let manager = NodeManager::build_with_loader(
            &nodes,
            RealtimeConfig::default(),
            NodeManagerOptions {
                continue_on_error: true,
            },
            |_| Ok(None),
        )
        .unwrap();

        assert!(manager.is_empty());
        assert_eq!(manager.failures()[0].error, "received empty node info");
    }

    fn node_config(url: &str, node_id: u32) -> NodeConfig {
        NodeConfig {
            url: url.to_string(),
            token: "token".to_string(),
            node_id,
            ..NodeConfig::default()
        }
    }

    fn test_node_info(config: &NodeConfig) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "vless",
            "server_port": 10000 + config.node_id
        }))
        .unwrap();

        NodeInfo::from_common(&config.url, config.node_id, common).unwrap()
    }
}
