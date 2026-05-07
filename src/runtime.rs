use crate::config::{AgentConfig, AppConfig, ResolvedConfig, SubscriptionProxyConfig};
use crate::machine::{resolve_machine_profiles_from_panel, MachineResolveSummary};

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
    use crate::config::{
        AgentConfig, AppConfig, MachineProfileConfig, NodeConfig, ResolvedConfig,
        ResolvedMachineConfig, SubscriptionProxyConfig, SubscriptionProxyProfile,
    };
    use crate::machine::MachineResolveSummary;

    use super::{apply_machine_summary, Bootstrap, RuntimeMode};

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
}
