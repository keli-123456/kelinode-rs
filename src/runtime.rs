use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::config::{AgentConfig, AppConfig, NodeConfig, ResolvedConfig, SubscriptionProxyConfig};
use crate::core::{
    core_kind_from_name, split_core_plans_for_nodes_with_kind, CorePlan, CorePlanBundle,
    InboundPlan,
};
use crate::logging;
use crate::machine::{resolve_machine_profiles_from_panel, MachineResolveSummary};
use crate::node::{users_by_node_tag, NodeFailure, NodeManager, NodeManagerOptions};
use crate::panel::types::{NodeInfo, UserInfo};
use crate::port_forward::{
    build_hysteria_port_forward_rules, new_hysteria_port_forward_status, HysteriaPortForwardStatus,
};
use crate::realtime::{resolve_realtime_options, RealtimeOptions};

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
    pub realtime_options: Vec<RealtimeOptions>,
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

pub async fn bootstrap_from_config(config: &AppConfig) -> Result<RuntimeBootstrapPlan, String> {
    let (resolved, manager) = build_node_manager_from_config(config).await?;
    build_runtime_bootstrap_plan(resolved, manager.node_infos(), manager.failures().to_vec())
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
    let manager =
        NodeManager::build_from_panel(&resolved.nodes, resolved.realtime.clone(), options).await?;
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
    build_runtime_bootstrap_plan_with_users(resolved, node_infos, node_failures, &BTreeMap::new())
}

pub fn build_runtime_bootstrap_plan_with_users(
    resolved: ResolvedConfig,
    node_infos: Vec<NodeInfo>,
    node_failures: Vec<NodeFailure>,
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
) -> Result<RuntimeBootstrapPlan, String> {
    let subscription_proxy_only =
        node_infos.is_empty() && resolved.agent.subscription_proxy.enabled;
    let mut core_bundle = if node_infos.is_empty() {
        CorePlanBundle::default()
    } else {
        split_core_plans_for_nodes_with_kind(
            core_kind_from_name(&resolved.kernel.r#type).map_err(|err| err.message)?,
            core_config_path(&resolved),
            &node_infos,
            users_by_node_tag,
        )
        .map_err(|err| err.message)?
    };
    apply_kernel_dns_options(&resolved, &mut core_bundle);
    let (node_infos, node_failures) = filter_conflicting_runtime_listeners(
        &resolved,
        node_infos,
        node_failures,
        &mut core_bundle,
    )?;
    let (hy2_rules, hy2_errors) = build_hysteria_port_forward_rules(&node_infos);
    let realtime_options = resolve_realtime_options_for_nodes(&resolved, &node_infos);
    let bootstrap = Bootstrap::from_resolved(&resolved);

    Ok(RuntimeBootstrapPlan {
        bootstrap,
        resolved,
        node_count: node_infos.len(),
        node_infos,
        node_failures,
        core_plan: core_bundle.core,
        realtime_options,
        hy2_port_forward: new_hysteria_port_forward_status(&hy2_rules, &hy2_errors, false),
        subscription_proxy_only,
    })
}

fn apply_kernel_dns_options(resolved: &ResolvedConfig, bundle: &mut CorePlanBundle) {
    if let Some(plan) = bundle.core.as_mut() {
        plan.apply_kernel_dns_options(&resolved.kernel);
    }
}

pub fn rebuild_runtime_plan_with_users(
    plan: &RuntimeBootstrapPlan,
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
) -> Result<RuntimeBootstrapPlan, String> {
    build_runtime_bootstrap_plan_with_users(
        plan.resolved.clone(),
        plan.node_infos.clone(),
        plan.node_failures.clone(),
        users_by_node_tag,
    )
}

pub fn core_config_path(resolved: &ResolvedConfig) -> PathBuf {
    PathBuf::from(&resolved.kernel.config_dir).join("config.json")
}

pub fn node_config_for_info<'a>(
    resolved: &'a ResolvedConfig,
    node_id: u32,
    tag: &str,
) -> Option<&'a NodeConfig> {
    let exact = resolved.nodes.iter().find(|config| {
        config.node_id == node_id
            && tag.starts_with(&format!("[{}]", config.url.trim_end_matches('/')))
    });
    if exact.is_some() {
        return exact;
    }

    let mut candidates = resolved
        .nodes
        .iter()
        .filter(|config| config.node_id == node_id);
    let first = candidates.next()?;
    if candidates.next().is_none() {
        Some(first)
    } else {
        None
    }
}

fn filter_conflicting_runtime_listeners(
    resolved: &ResolvedConfig,
    node_infos: Vec<NodeInfo>,
    node_failures: Vec<NodeFailure>,
    core_bundle: &mut CorePlanBundle,
) -> Result<(Vec<NodeInfo>, Vec<NodeFailure>), String> {
    let Some(core_plan) = core_bundle.core.as_mut() else {
        return Ok((node_infos, node_failures));
    };

    let mut seen = Vec::<RuntimeListenerSpec>::new();
    let mut skipped_tags = BTreeSet::new();
    let mut failures = node_failures;
    for inbound in &core_plan.inbounds {
        let mut inbound_conflict = None;
        for spec in runtime_listener_specs(inbound) {
            if let Some(existing) = seen
                .iter()
                .find(|existing| runtime_listener_specs_conflict(existing, &spec))
            {
                inbound_conflict = Some(format!(
                    "duplicate {} listen {}:{} for inbound {} ({}) conflicts with {} ({}); change one node server port or listen address",
                    spec.network,
                    spec.listen,
                    spec.port,
                    spec.tag,
                    spec.protocol,
                    existing.tag,
                    existing.protocol
                ));
                break;
            }
            seen.push(spec);
        }

        let Some(error) = inbound_conflict else {
            continue;
        };
        if !resolved.machine.continue_on_error {
            return Err(error);
        }
        logging::warn(
            "core",
            format!(
                "skipping node due to listener conflict tag={} error={}",
                inbound.tag, error
            ),
        );
        skipped_tags.insert(inbound.tag.clone());
        if let Some(node) = node_infos.iter().find(|node| node.tag == inbound.tag) {
            failures.push(NodeFailure {
                config: node_config_for_info(resolved, node.id, &node.tag)
                    .cloned()
                    .unwrap_or_else(|| NodeConfig {
                        node_id: node.id,
                        ..NodeConfig::default()
                    }),
                error,
            });
        }
    }

    if skipped_tags.is_empty() {
        return Ok((node_infos, failures));
    }

    core_plan
        .inbounds
        .retain(|inbound| !skipped_tags.contains(&inbound.tag));
    core_plan
        .listen_tags
        .retain(|tag| !skipped_tags.contains(tag));
    if core_plan.inbounds.is_empty() {
        core_bundle.core = None;
    }
    let node_infos = node_infos
        .into_iter()
        .filter(|node| !skipped_tags.contains(&node.tag))
        .collect();
    Ok((node_infos, failures))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeListenerSpec {
    tag: String,
    protocol: String,
    network: &'static str,
    listen: String,
    port: u16,
}

fn runtime_listener_specs(inbound: &InboundPlan) -> Vec<RuntimeListenerSpec> {
    let listen = normalize_runtime_listen(&inbound.listen);
    let mut specs = Vec::with_capacity(2);
    if inbound_binds_tcp(inbound) {
        specs.push(RuntimeListenerSpec {
            tag: inbound.tag.clone(),
            protocol: inbound.protocol.clone(),
            network: "tcp",
            listen: listen.clone(),
            port: inbound.port,
        });
    }
    if inbound_binds_udp(inbound) {
        specs.push(RuntimeListenerSpec {
            tag: inbound.tag.clone(),
            protocol: inbound.protocol.clone(),
            network: "udp",
            listen,
            port: inbound.port,
        });
    }
    specs
}

fn inbound_binds_tcp(inbound: &InboundPlan) -> bool {
    matches!(
        inbound.protocol.as_str(),
        "socks"
            | "http"
            | "vless"
            | "vmess"
            | "trojan"
            | "shadowsocks"
            | "anytls"
            | "mieru"
            | "naive"
    )
}

fn inbound_binds_udp(inbound: &InboundPlan) -> bool {
    matches!(inbound.protocol.as_str(), "hysteria" | "hysteria2" | "tuic")
        || (inbound.protocol == "shadowsocks" && inbound.network.contains("udp"))
}

fn runtime_listener_specs_conflict(
    existing: &RuntimeListenerSpec,
    next: &RuntimeListenerSpec,
) -> bool {
    existing.network == next.network
        && existing.port == next.port
        && runtime_listens_conflict(&existing.listen, &next.listen)
}

fn runtime_listens_conflict(left: &str, right: &str) -> bool {
    left == right || is_wildcard_listen(left) || is_wildcard_listen(right)
}

fn is_wildcard_listen(value: &str) -> bool {
    matches!(
        normalize_runtime_listen(value).as_str(),
        "" | "0.0.0.0" | "::"
    )
}

fn normalize_runtime_listen(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

pub fn apply_machine_summary(resolved: &mut ResolvedConfig, summary: MachineResolveSummary) {
    resolved.nodes.extend(summary.nodes);
    merge_agent_config(&mut resolved.agent, summary.agent);
}

fn merge_agent_config(target: &mut AgentConfig, source: AgentConfig) {
    merge_subscription_proxy(&mut target.subscription_proxy, source.subscription_proxy);
}

fn merge_subscription_proxy(target: &mut SubscriptionProxyConfig, source: SubscriptionProxyConfig) {
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
    merge_subscription_proxy_zerossl(&mut target.zerossl, &source.zerossl);
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

fn merge_subscription_proxy_zerossl(
    target: &mut crate::config::SubscriptionProxyZeroSslConfig,
    source: &crate::config::SubscriptionProxyZeroSslConfig,
) {
    fill_if_empty(&mut target.status, &source.status);
    fill_if_empty(&mut target.certificate_id, &source.certificate_id);
    fill_if_empty(&mut target.validation_path, &source.validation_path);
    fill_if_empty(&mut target.validation_content, &source.validation_content);
    fill_if_empty(&mut target.certificate_pem, &source.certificate_pem);
    fill_if_empty(&mut target.ca_bundle_pem, &source.ca_bundle_pem);
    fill_if_empty(&mut target.expires_at, &source.expires_at);
}

fn fill_if_empty(target: &mut String, value: &str) {
    if target.trim().is_empty() {
        *target = value.trim().to_string();
    }
}

fn resolve_realtime_options_for_nodes(
    resolved: &ResolvedConfig,
    node_infos: &[NodeInfo],
) -> Vec<RealtimeOptions> {
    node_infos
        .iter()
        .filter_map(|node| {
            node_config_for_info(resolved, node.id, &node.tag)
                .and_then(|config| resolve_realtime_options(&resolved.realtime, config, node))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use crate::config::{
        AgentConfig, AppConfig, MachineProfileConfig, NodeConfig, RealtimeConfig, ResolvedConfig,
        ResolvedMachineConfig, SubscriptionProxyConfig, SubscriptionProxyProfile,
        SubscriptionProxyZeroSslConfig,
    };
    use crate::core::CoreKind;
    use crate::machine::MachineResolveSummary;
    use crate::panel::types::{CertInfo, CommonNode, NodeInfo, Security, UserInfo};

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
                    zerossl: SubscriptionProxyZeroSslConfig {
                        certificate_id: "cert-1".to_string(),
                        ..SubscriptionProxyZeroSslConfig::default()
                    },
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
        assert_eq!(
            resolved.agent.subscription_proxy.https_listen,
            "0.0.0.0:443"
        );
        assert_eq!(resolved.agent.subscription_proxy.http_listen, "0.0.0.0:80");
        assert_eq!(
            resolved.agent.subscription_proxy.zerossl.certificate_id,
            "cert-1"
        );
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
        let mut node = test_node("hysteria2", 7, 443, "30000-30002");
        node.security = Security::Tls;
        node.common.tls = 1;
        node.common.cert_info = Some(CertInfo {
            cert_mode: "file".to_string(),
            cert_file: "/tmp/hy2.crt".to_string(),
            key_file: "/tmp/hy2.key".to_string(),
            cert_domain: "hy2.example.test".to_string(),
            dns_env: Default::default(),
            provider: String::new(),
            reject_unknown_sni: false,
        });

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

    #[test]
    fn kernel_type_selects_keli_core_rs_plan() {
        let mut resolved = ResolvedConfig {
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
        resolved.kernel.r#type = "keli-core-rs".to_string();
        let node = test_node("socks", 7, 1080, "");

        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();

        assert_eq!(plan.core_plan.as_ref().unwrap().kind, CoreKind::KeliCoreRs);
        assert_eq!(
            plan.core_plan.as_ref().unwrap().inbounds[0].protocol,
            "socks"
        );
    }

    #[test]
    fn kernel_dns_security_options_reach_keli_core_rs_plan() {
        let mut resolved = ResolvedConfig {
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
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.dns_servers = vec!["9.9.9.9".to_string()];
        resolved.kernel.dns_block_private_ips = true;
        resolved.kernel.dns_private_ip_allowlist = vec!["domain:internal.example".to_string()];
        let node = test_node("socks", 7, 1080, "");

        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let core_plan = plan.core_plan.as_ref().unwrap();

        assert_eq!(core_plan.kind, CoreKind::KeliCoreRs);
        assert_eq!(core_plan.dns.servers, vec!["9.9.9.9".to_string()]);
        assert!(core_plan.dns.block_private_ips);
        assert_eq!(
            core_plan.dns.private_ip_allowlist,
            vec!["domain:internal.example".to_string()]
        );
    }

    #[test]
    fn keli_core_rs_skips_duplicate_listener_nodes_when_machine_continues_on_error() {
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![
                NodeConfig {
                    url: "https://panel-a.example.test".to_string(),
                    token: "token-a".to_string(),
                    node_id: 7,
                    machine_id: 1,
                    ..NodeConfig::default()
                },
                NodeConfig {
                    url: "https://panel-b.example.test".to_string(),
                    token: "token-b".to_string(),
                    node_id: 8,
                    machine_id: 2,
                    ..NodeConfig::default()
                },
            ],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        let nodes = vec![
            test_node_for_url("https://panel-a.example.test", "vless", 7, 57702, ""),
            test_node_for_url("https://panel-b.example.test", "vless", 8, 57702, ""),
        ];

        let plan = build_runtime_bootstrap_plan(resolved, nodes, Vec::new()).unwrap();

        assert_eq!(plan.node_infos.len(), 1);
        assert_eq!(plan.core_plan.as_ref().unwrap().inbounds.len(), 1);
        assert_eq!(plan.node_failures.len(), 1);
        assert!(
            plan.node_failures[0].error.contains("duplicate tcp listen"),
            "{}",
            plan.node_failures[0].error
        );
        assert_eq!(plan.node_failures[0].config.node_id, 8);
    }

    #[test]
    fn builds_runtime_plan_with_native_protocols() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![
                NodeConfig {
                    url: "https://panel.example.test".to_string(),
                    node_id: 7,
                    ..NodeConfig::default()
                },
                NodeConfig {
                    url: "https://panel.example.test".to_string(),
                    node_id: 8,
                    ..NodeConfig::default()
                },
            ],
        };
        let nodes = vec![
            test_node("vless", 7, 443, ""),
            test_node("mieru", 8, 8443, ""),
        ];
        let mut users = BTreeMap::new();
        users.insert(
            nodes[1].tag.clone(),
            vec![UserInfo {
                id: 8,
                uuid: "mieru-secret".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );

        let plan =
            build_runtime_bootstrap_plan_with_users(resolved, nodes, Vec::new(), &users).unwrap();

        let core = plan.core_plan.as_ref().unwrap();
        assert_eq!(core.kind, CoreKind::KeliCoreRs);
        assert_eq!(core.inbounds.len(), 2);
        assert_eq!(core.inbounds[0].protocol, "vless");
        assert_eq!(core.inbounds[1].protocol, "mieru");
    }

    #[test]
    fn native_only_runtime_plan_uses_keli_core_rs() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                node_id: 9,
                ..NodeConfig::default()
            }],
        };
        let mut naive = test_node("naive", 9, 9443, "");
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
        let mut users = BTreeMap::new();
        users.insert(
            naive.tag.clone(),
            vec![UserInfo {
                id: 9,
                uuid: "naive-password".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );

        let plan =
            build_runtime_bootstrap_plan_with_users(resolved, vec![naive], Vec::new(), &users)
                .unwrap();

        let core = plan.core_plan.as_ref().unwrap();
        assert_eq!(core.kind, CoreKind::KeliCoreRs);
        assert_eq!(core.inbounds.len(), 1);
        assert_eq!(core.inbounds[0].protocol, "naive");
    }

    #[test]
    fn builds_realtime_options_for_matching_active_node_configs() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: RealtimeConfig {
                enabled: true,
                ..RealtimeConfig::default()
            },
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![
                NodeConfig {
                    url: "https://panel-a.example.test".to_string(),
                    token: "token-a".to_string(),
                    node_id: 7,
                    machine_id: 1,
                    ..NodeConfig::default()
                },
                NodeConfig {
                    url: "https://panel-b.example.test".to_string(),
                    token: "token-b".to_string(),
                    node_id: 7,
                    machine_id: 2,
                    ..NodeConfig::default()
                },
            ],
        };
        let nodes = vec![
            test_node_for_url("https://panel-a.example.test", "vless", 7, 443, ""),
            test_node_for_url("https://panel-b.example.test", "vless", 7, 444, ""),
        ];

        let plan = build_runtime_bootstrap_plan(resolved, nodes, Vec::new()).unwrap();

        assert_eq!(plan.realtime_options.len(), 2);
        assert_eq!(
            plan.realtime_options[0].url,
            "wss://panel-a.example.test/ws/node"
        );
        assert_eq!(plan.realtime_options[0].token, "token-a");
        assert_eq!(
            plan.realtime_options[1].url,
            "wss://panel-b.example.test/ws/node"
        );
        assert_eq!(plan.realtime_options[1].token, "token-b");
    }

    fn test_node(protocol: &str, node_id: u32, server_port: u16, port: &str) -> NodeInfo {
        test_node_for_url(
            "https://panel.example.test",
            protocol,
            node_id,
            server_port,
            port,
        )
    }

    fn test_node_for_url(
        api_host: &str,
        protocol: &str,
        node_id: u32,
        server_port: u16,
        port: &str,
    ) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": protocol,
            "server_port": server_port,
            "port": port
        }))
        .unwrap();

        NodeInfo::from_common(api_host, node_id, common).unwrap()
    }
}
