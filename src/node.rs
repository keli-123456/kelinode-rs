use std::collections::{BTreeMap, BTreeSet};

use crate::config::{NodeConfig, RealtimeConfig};
use crate::panel::client::{PanelClient, PanelClientOptions};
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileResult {
    pub added: usize,
    pub removed: usize,
    pub restarted: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub full_reload_required: bool,
    pub failures: Vec<NodeFailure>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodeManager {
    runtimes: Vec<NodeRuntime>,
    failures: Vec<NodeFailure>,
    realtime: RealtimeConfig,
    continue_on_error: bool,
}

impl NodeManager {
    pub async fn build_from_panel(
        nodes: &[NodeConfig],
        realtime: RealtimeConfig,
        options: NodeManagerOptions,
    ) -> Result<Self, String> {
        let mut manager = Self {
            runtimes: Vec::with_capacity(nodes.len()),
            failures: Vec::new(),
            realtime,
            continue_on_error: options.continue_on_error,
        };

        for config in nodes {
            match load_panel_node_info(config).await {
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

    pub fn reconcile_with_loader<F>(
        &mut self,
        desired: &[NodeConfig],
        realtime: RealtimeConfig,
        options: NodeManagerOptions,
        mut load_node_info: F,
    ) -> Result<ReconcileResult, String>
    where
        F: FnMut(&NodeConfig) -> Result<Option<NodeInfo>, String>,
    {
        let mut result = ReconcileResult::default();
        let current = self.current_slots()?;
        let mut desired_keys = BTreeSet::new();
        let mut candidates = BTreeMap::new();
        let mut ordered_keys = Vec::with_capacity(desired.len());

        for config in desired {
            let key = machine_node_key(config);
            if key.is_empty() {
                handle_reconcile_failure(
                    &mut result,
                    config,
                    "node config requires api host and node id".to_string(),
                    options,
                )?;
                continue;
            }
            if !desired_keys.insert(key.clone()) {
                handle_reconcile_failure(
                    &mut result,
                    config,
                    format!("duplicate node config: {key}"),
                    options,
                )?;
                continue;
            }
            ordered_keys.push(key.clone());

            match load_node_info(config) {
                Ok(Some(info)) => {
                    candidates.insert(
                        key,
                        NodeRuntime {
                            config: config.clone(),
                            info,
                        },
                    );
                }
                Ok(None) => {
                    if current.contains_key(&key) {
                        result.skipped += 1;
                    } else {
                        handle_reconcile_failure(
                            &mut result,
                            config,
                            "received empty node info".to_string(),
                            options,
                        )?;
                    }
                }
                Err(error) => {
                    handle_reconcile_failure(&mut result, config, error, options)?;
                }
            }
        }

        if candidates.is_empty() && !result.failures.is_empty() && options.continue_on_error {
            self.failures = result.failures.clone();
            return Ok(result);
        }

        if machine_reconcile_needs_full_reload(&current, &desired_keys, &candidates) {
            result.full_reload_required = true;
            return Ok(result);
        }

        for key in current.keys() {
            if !desired_keys.contains(key) {
                result.removed += 1;
            }
        }

        let mut next = Vec::with_capacity(desired.len());
        for key in ordered_keys {
            let candidate = candidates.get(&key);
            let slot = current.get(&key);

            match (candidate, slot) {
                (None, Some(existing)) => {
                    next.push(existing.clone());
                    result.unchanged += 1;
                }
                (None, None) => {}
                (Some(candidate), Some(existing)) if candidate == existing => {
                    next.push(existing.clone());
                    result.unchanged += 1;
                }
                (Some(candidate), Some(_)) => {
                    next.push(candidate.clone());
                    result.restarted += 1;
                }
                (Some(candidate), None) => {
                    next.push(candidate.clone());
                    result.added += 1;
                }
            }
        }

        self.runtimes = next;
        self.failures = result.failures.clone();
        self.realtime = realtime;
        self.continue_on_error = options.continue_on_error;

        Ok(result)
    }

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

    fn current_slots(&self) -> Result<BTreeMap<String, NodeRuntime>, String> {
        let mut current = BTreeMap::new();
        for runtime in &self.runtimes {
            let key = machine_node_key(&runtime.config);
            if key.is_empty() {
                return Err(format!(
                    "current node config requires api host and node id: {:?}",
                    runtime.config
                ));
            }
            if current.insert(key.clone(), runtime.clone()).is_some() {
                return Err(format!("duplicate current node config: {key}"));
            }
        }
        Ok(current)
    }
}

async fn load_panel_node_info(config: &NodeConfig) -> Result<Option<NodeInfo>, String> {
    let options = PanelClientOptions::from(config);
    let mut client = PanelClient::new(options).map_err(|err| err.to_string())?;
    client
        .get_node_info()
        .await
        .map_err(|err| err.to_string())
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

fn handle_reconcile_failure(
    result: &mut ReconcileResult,
    config: &NodeConfig,
    error: String,
    options: NodeManagerOptions,
) -> Result<(), String> {
    result.skipped += 1;
    result.failures.push(NodeFailure {
        config: config.clone(),
        error: error.clone(),
    });
    if options.continue_on_error {
        Ok(())
    } else {
        Err(error)
    }
}

fn machine_reconcile_needs_full_reload(
    current: &BTreeMap<String, NodeRuntime>,
    desired_keys: &BTreeSet<String>,
    candidates: &BTreeMap<String, NodeRuntime>,
) -> bool {
    for (key, slot) in current {
        if !desired_keys.contains(key) && node_has_custom_routes(&slot.info) {
            return true;
        }
    }

    for (key, candidate) in candidates {
        let Some(slot) = current.get(key) else {
            if node_has_custom_routes(&candidate.info) {
                return true;
            }
            continue;
        };
        if slot != candidate
            && (node_has_custom_routes(&slot.info) || node_has_custom_routes(&candidate.info))
        {
            return true;
        }
    }

    false
}

fn node_has_custom_routes(info: &NodeInfo) -> bool {
    !info.common.routes.is_empty()
}

fn machine_node_key(config: &NodeConfig) -> String {
    let api_host = config.url.trim().trim_end_matches('/');
    if api_host.is_empty() || config.node_id == 0 {
        String::new()
    } else {
        format!("{}#{}", api_host, config.node_id)
    }
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

    #[test]
    fn reconcile_adds_and_removes_nodes() {
        let initial = vec![
            node_config("https://panel-a.example.test", 1),
            node_config("https://panel-b.example.test", 2),
        ];
        let mut manager = NodeManager::build_with_loader(
            &initial,
            RealtimeConfig::default(),
            NodeManagerOptions::default(),
            |config| Ok(Some(test_node_info(config))),
        )
        .unwrap();

        let desired = vec![
            node_config("https://panel-b.example.test", 2),
            node_config("https://panel-c.example.test", 3),
        ];
        let result = manager
            .reconcile_with_loader(
                &desired,
                RealtimeConfig::default(),
                NodeManagerOptions {
                    continue_on_error: true,
                },
                |config| Ok(Some(test_node_info(config))),
            )
            .unwrap();

        assert_eq!(result.added, 1);
        assert_eq!(result.removed, 1);
        assert_eq!(result.unchanged, 1);
        assert_eq!(manager.active_configs()[0].node_id, 2);
        assert_eq!(manager.active_configs()[1].node_id, 3);
    }

    #[test]
    fn reconcile_requires_full_reload_for_route_changes() {
        let initial = vec![node_config("https://panel-a.example.test", 1)];
        let mut manager = NodeManager::build_with_loader(
            &initial,
            RealtimeConfig::default(),
            NodeManagerOptions::default(),
            |config| Ok(Some(test_node_info(config))),
        )
        .unwrap();

        let desired = vec![
            node_config("https://panel-a.example.test", 1),
            node_config("https://panel-b.example.test", 2),
        ];
        let result = manager
            .reconcile_with_loader(
                &desired,
                RealtimeConfig::default(),
                NodeManagerOptions {
                    continue_on_error: true,
                },
                |config| {
                    if config.node_id == 2 {
                        Ok(Some(test_node_info_with_routes(config)))
                    } else {
                        Ok(Some(test_node_info(config)))
                    }
                },
            )
            .unwrap();

        assert!(result.full_reload_required);
        assert_eq!(manager.active_configs().len(), 1);
        assert_eq!(manager.active_configs()[0].node_id, 1);
    }

    #[test]
    fn reconcile_keeps_existing_when_refresh_fails() {
        let initial = vec![node_config("https://panel.example.test", 1)];
        let mut manager = NodeManager::build_with_loader(
            &initial,
            RealtimeConfig::default(),
            NodeManagerOptions::default(),
            |config| Ok(Some(test_node_info(config))),
        )
        .unwrap();

        let result = manager
            .reconcile_with_loader(
                &initial,
                RealtimeConfig::default(),
                NodeManagerOptions {
                    continue_on_error: true,
                },
                |_| Err("temporary panel error".to_string()),
            )
            .unwrap();

        assert_eq!(result.skipped, 1);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(manager.active_configs().len(), 1);
        assert_eq!(manager.active_configs()[0].node_id, 1);
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

    fn test_node_info_with_routes(config: &NodeConfig) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "vless",
            "server_port": 10000 + config.node_id,
            "routes": [
                {"id": 1, "action": "block", "match": ["example.com"]}
            ]
        }))
        .unwrap();

        NodeInfo::from_common(&config.url, config.node_id, common).unwrap()
    }
}
