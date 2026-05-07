use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::config::{AgentConfig, AppConfig, ResolvedConfig, SubscriptionProxyConfig};
use crate::core::{CoreKind, CorePlan};
use crate::machine::{resolve_machine_profiles_from_panel, MachineResolveSummary};
use crate::node::{users_by_node_tag, NodeFailure, NodeManager, NodeManagerOptions};
use crate::panel::types::{NodeInfo, UserInfo};
use crate::port_forward::{
    build_hysteria_port_forward_rules, new_hysteria_port_forward_status,
    HysteriaPortForwardStatus,
};

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

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeBootstrapPlan {
    pub bootstrap: Bootstrap,
    pub resolved: ResolvedConfig,
    pub node_count: usize,
    pub node_infos: Vec<NodeInfo>,
    pub node_failures: Vec<NodeFailure>,
    pub core_plan: Option<CorePlan>,
    pub hy2_port_forward: HysteriaPortForwardStatus,
    pub subscription_proxy_only: bool,
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

        Self::from_resolved(&resolved)
    }

    pub fn from_resolved(resolved: &ResolvedConfig) -> Self {
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

pub async fn bootstrap_from_config(
    config: &AppConfig,
) -> Result<RuntimeBootstrapPlan, String> {
    let (resolved, manager) = build_node_manager_from_config(config).await?;
    build_runtime_bootstrap_plan(
        resolved,
        manager.node_infos(),
        manager.failures().to_vec(),
    )
}

pub async fn bootstrap_from_config_with_users(
    config: &AppConfig,
) -> Result<RuntimeBootstrapPlan, String> {
    let (resolved, manager) = build_node_manager_from_config(config).await?;
    let users = manager.load_user_sets_from_panel().await?;
    let users_by_tag = users_by_node_tag(&users);
    build_runtime_bootstrap_plan_with_users(
        resolved,
        manager.node_infos(),
        manager.failures().to_vec(),
        &users_by_tag,
    )
}

async fn build_node_manager_from_config(
    config: &AppConfig,
) -> Result<(ResolvedConfig, NodeManager), String> {
    let resolved = resolve_runtime_with_machine_profiles(config).await?;
    let options = NodeManagerOptions {
        continue_on_error: resolved.machine.continue_on_error,
    };
    let manager = NodeManager::build_from_panel(&resolved.nodes, resolved.realtime.clone(), options)
        .await?;
    Ok((resolved, manager))
}

pub async fn resolve_runtime_with_machine_profiles(
    config: &AppConfig,
) -> Result<ResolvedConfig, String> {
    let mut resolved = config.resolve_runtime()?;
    if resolved.machine.profiles.is_empty() {
        return Ok(resolved);
    }

    let summary = resolve_machine_profiles_from_panel(
        &resolved.machine.profiles,
        resolved.machine.continue_on_error,
    )
    .await?;
    apply_machine_summary(&mut resolved, summary);
    Ok(resolved)
}

pub fn build_runtime_bootstrap_plan(
    resolved: ResolvedConfig,
    node_infos: Vec<NodeInfo>,
    node_failures: Vec<NodeFailure>,
) -> Result<RuntimeBootstrapPlan, String> {
    build_runtime_bootstrap_plan_with_users(
        resolved,
        node_infos,
        node_failures,
        &BTreeMap::new(),
    )
}

pub fn build_runtime_bootstrap_plan_with_users(
    resolved: ResolvedConfig,
    node_infos: Vec<NodeInfo>,
    node_failures: Vec<NodeFailure>,
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
) -> Result<RuntimeBootstrapPlan, String> {
    let subscription_proxy_only =
        node_infos.is_empty() && resolved.agent.subscription_proxy.enabled;
    let core_plan = if node_infos.is_empty() {
        None
    } else {
        Some(
            CorePlan::from_nodes_with_users(
                CoreKind::Xray,
                core_config_path(&resolved),
                &node_infos,
                users_by_node_tag,
            )
                .map_err(|err| err.message)?,
        )
    };
    let (hy2_rules, hy2_errors) = build_hysteria_port_forward_rules(&node_infos);
    let bootstrap = Bootstrap::from_resolved(&resolved);

    Ok(RuntimeBootstrapPlan {
        bootstrap,
        resolved,
        node_count: node_infos.len(),
        node_infos,
        node_failures,
        core_plan,
        hy2_port_forward: new_hysteria_port_forward_status(&hy2_rules, &hy2_errors, false),
        subscription_proxy_only,
    })
}

pub fn core_config_path(resolved: &ResolvedConfig) -> PathBuf {
    PathBuf::from(&resolved.kernel.config_dir).join("config.json")
}

pub fn apply_machine_summary(
    resolved: &mut ResolvedConfig,
    summary: MachineResolveSummary,
) {
    resolved.nodes.extend(summary.nodes);
    merge_agent_config(&mut resolved.agent, summary.agent);
}

fn merge_agent_config(target: &mut AgentConfig, source: AgentConfig) {
    merge_subscription_proxy(&mut target.subscription_proxy, source.subscription_proxy);
}

fn merge_subscription_proxy(
    target: &mut SubscriptionProxyConfig,
    source: SubscriptionProxyConfig,
) {
    if !source.enabled {
        return;
    }
    if !target.enabled {
        *target = source;
        return;
    }

    fill_if_empty(&mut target.https_listen, &source.https_listen);
    fill_if_empty(&mut target.http_listen, &source.http_listen);
    fill_if_empty(&mut target.cert_file, &source.cert_file);
    fill_if_empty(&mut target.key_file, &source.key_file);
    fill_if_empty(&mut target.certificate_domain, &source.certificate_domain);
    fill_if_empty(&mut target.challenge_dir, &source.challenge_dir);
    fill_if_empty(&mut target.site_id, &source.site_id);
    fill_if_empty(&mut target.upstream_base_url, &source.upstream_base_url);
    fill_if_empty(&mut target.subscribe_path, &source.subscribe_path);
    if target.max_response_bytes == 0 {
        target.max_response_bytes = source.max_response_bytes;
    }
    if !target.allow_http_fallback {
        target.allow_http_fallback = source.allow_http_fallback;
    }

    for profile in source.profiles {
        if target
            .profiles
            .iter()
            .any(|existing| existing.site_id.eq_ignore_ascii_case(&profile.site_id))
        {
            continue;
        }
        target.profiles.push(profile);
    }
}

fn fill_if_empty(target: &mut String, value: &str) {
    if target.trim().is_empty() {
        *target = value.trim().to_string();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use crate::config::{
        AgentConfig, AppConfig, MachineProfileConfig, NodeConfig, ResolvedConfig,
        ResolvedMachineConfig, SubscriptionProxyConfig, SubscriptionProxyProfile,
    };
    use crate::machine::MachineResolveSummary;
    use crate::panel::types::{CommonNode, NodeInfo, UserInfo};

    use super::{
        apply_machine_summary, build_runtime_bootstrap_plan,
        build_runtime_bootstrap_plan_with_users, core_config_path, Bootstrap, RuntimeMode,
    };

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

    #[test]
    fn applies_machine_summary_to_resolved_runtime() {
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig {
                subscription_proxy: SubscriptionProxyConfig {
                    enabled: true,
                    https_listen: "0.0.0.0:443".to_string(),
                    profiles: vec![SubscriptionProxyProfile {
                        site_id: "existing".to_string(),
                        upstream_base_url: "https://existing.example.test".to_string(),
                        subscribe_path: "s".to_string(),
                    }],
                    ..SubscriptionProxyConfig::default()
                },
            },
            nodes: vec![NodeConfig {
                url: "https://panel-a.example.test".to_string(),
                node_id: 1,
                ..NodeConfig::default()
            }],
        };
        let summary = MachineResolveSummary {
            nodes: vec![NodeConfig {
                url: "https://panel-b.example.test".to_string(),
                node_id: 2,
                ..NodeConfig::default()
            }],
            agent: AgentConfig {
                subscription_proxy: SubscriptionProxyConfig {
                    enabled: true,
                    https_listen: "0.0.0.0:8443".to_string(),
                    http_listen: "0.0.0.0:80".to_string(),
                    profiles: vec![SubscriptionProxyProfile {
                        site_id: "machine".to_string(),
                        upstream_base_url: "https://machine.example.test".to_string(),
                        subscribe_path: "s".to_string(),
                    }],
                    ..SubscriptionProxyConfig::default()
                },
            },
            ..MachineResolveSummary::default()
        };

        apply_machine_summary(&mut resolved, summary);

        assert_eq!(resolved.nodes.len(), 2);
        assert_eq!(resolved.agent.subscription_proxy.https_listen, "0.0.0.0:443");
        assert_eq!(resolved.agent.subscription_proxy.http_listen, "0.0.0.0:80");
        assert_eq!(resolved.agent.subscription_proxy.profiles.len(), 2);
    }

    #[test]
    fn builds_runtime_bootstrap_plan_with_core_and_hy2_status() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: false,
                continue_on_error: false,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                node_id: 7,
                ..NodeConfig::default()
            }],
        };
        let node = test_node("hysteria2", 7, 443, "30000-30002");

        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();

        assert_eq!(plan.bootstrap.mode, RuntimeMode::DirectNode);
        assert_eq!(plan.node_count, 1);
        assert_eq!(plan.core_plan.as_ref().unwrap().inbounds.len(), 1);
        assert_eq!(plan.hy2_port_forward.expected_rules.len(), 1);
        assert!(!plan.subscription_proxy_only);
    }

    #[test]
    fn builds_subscription_proxy_only_bootstrap_plan() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig {
                subscription_proxy: SubscriptionProxyConfig {
                    enabled: true,
                    site_id: "site".to_string(),
                    upstream_base_url: "https://site.example.test".to_string(),
                    ..SubscriptionProxyConfig::default()
                },
            },
            nodes: Vec::new(),
        };

        let plan = build_runtime_bootstrap_plan(resolved, Vec::new(), Vec::new()).unwrap();

        assert_eq!(plan.bootstrap.mode, RuntimeMode::MachineBinding);
        assert_eq!(plan.node_count, 0);
        assert!(plan.core_plan.is_none());
        assert!(plan.subscription_proxy_only);
    }

    #[test]
    fn core_config_path_uses_kernel_config_dir() {
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: false,
                continue_on_error: false,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: Vec::new(),
        };
        resolved.kernel.config_dir = "/srv/v2node".to_string();

        assert_eq!(
            core_config_path(&resolved),
            std::path::PathBuf::from("/srv/v2node").join("config.json")
        );
    }

    #[test]
    fn builds_core_plan_with_user_clients() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: false,
                continue_on_error: false,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                node_id: 7,
                ..NodeConfig::default()
            }],
        };
        let node = test_node("vless", 7, 443, "");
        let tag = node.tag.clone();
        let mut users = BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 1,
                uuid: "uuid-a".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );

        let plan =
            build_runtime_bootstrap_plan_with_users(resolved, vec![node], Vec::new(), &users)
                .unwrap();

        assert_eq!(
            plan.core_plan.as_ref().unwrap().inbounds[0].users[0].uuid,
            "uuid-a"
        );
    }

    fn test_node(protocol: &str, node_id: u32, server_port: u16, port: &str) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": protocol,
            "server_port": server_port,
            "port": port
        }))
        .unwrap();

        NodeInfo::from_common("https://panel.example.test", node_id, common).unwrap()
    }
}
