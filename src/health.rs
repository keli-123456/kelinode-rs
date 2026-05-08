use serde_json::{json, Value};

use crate::config::AgentConfig;
use crate::machine::{MachineStatusPayload, NodeFailurePayload};
use crate::node::NodeFailure;
use crate::port_forward::{HysteriaPortForwardStatus, HysteriaPortForwardToolStatus};
use crate::process::{ProcessState, ProcessStatus};
use crate::runtime::{RuntimeBootstrapPlan, RuntimeMode};
use crate::subscription_proxy::SubscriptionProxyStatus;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsageSnapshot {
    pub total: u64,
    pub used: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResourceSnapshot {
    pub cpu: f64,
    pub mem: UsageSnapshot,
    pub swap: UsageSnapshot,
    pub disk: UsageSnapshot,
    pub net: Option<Value>,
    pub ip: Option<Value>,
    pub system: Option<Value>,
    pub uptime: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HealthReportInput {
    pub version: String,
    pub resources: ResourceSnapshot,
    pub core: Option<ProcessStatus>,
    pub subscription_proxy: Option<SubscriptionProxyStatus>,
    pub upgrade: Option<Value>,
}

pub fn build_machine_status_payload(
    machine_id: u32,
    plan: &RuntimeBootstrapPlan,
    input: HealthReportInput,
) -> MachineStatusPayload {
    let mut payload = MachineStatusPayload::new(machine_id);
    let subscription_proxy = input.subscription_proxy.as_ref();
    let resources = input.resources;

    payload.insert_status("cpu", json!(resources.cpu));
    payload.insert_status("mem", usage_value(resources.mem));
    payload.insert_status("swap", usage_value(resources.swap));
    payload.insert_status("disk", usage_value(resources.disk));
    payload.insert_status("net", resources.net.unwrap_or(Value::Null));
    payload.insert_status("ip", resources.ip.unwrap_or_else(|| json!({})));
    payload.insert_status("system", resources.system.unwrap_or(Value::Null));
    payload.insert_status(
        "uptime",
        resources.uptime.map(|uptime| json!(uptime)).unwrap_or(Value::Null),
    );
    payload.insert_status("version", version_value(input.version));
    payload.insert_status("runtime", runtime_value(plan));
    payload.insert_status("core", core_value(plan, input.core.as_ref()));
    payload.insert_status(
        "hy2_port_forward",
        hy2_port_forward_value(&plan.hy2_port_forward),
    );
    payload.insert_status(
        "node_failures",
        json!(node_failure_payloads(&plan.node_failures, machine_id)),
    );

    let agent = agent_value(&plan.resolved.agent, subscription_proxy);
    if !agent.is_null() {
        payload.insert_status("agent", agent);
    }
    if let Some(upgrade) = input.upgrade {
        payload.insert_status("upgrade", upgrade);
    }

    payload
}

pub fn node_failure_payloads(
    failures: &[NodeFailure],
    fallback_machine_id: u32,
) -> Vec<NodeFailurePayload> {
    failures
        .iter()
        .map(|failure| {
            let machine_id = if failure.config.machine_id == 0 {
                fallback_machine_id
            } else {
                failure.config.machine_id
            };
            NodeFailurePayload::v2node(
                failure.config.url.trim_end_matches('/'),
                failure.config.node_id,
                machine_id,
                &failure.error,
            )
        })
        .collect()
}

fn usage_value(usage: UsageSnapshot) -> Value {
    json!({
        "total": usage.total,
        "used": usage.used
    })
}

fn version_value(version: String) -> Value {
    let version = version.trim();
    if version.is_empty() {
        Value::String(format!("v{}", env!("CARGO_PKG_VERSION")))
    } else {
        Value::String(version.to_string())
    }
}

fn runtime_value(plan: &RuntimeBootstrapPlan) -> Value {
    json!({
        "mode": runtime_mode_label(&plan.bootstrap.mode),
        "nodes": plan.node_count,
        "configured_nodes": plan.resolved.nodes.len(),
        "machine_profiles": plan.bootstrap.machine_profile_count,
        "sidecars": plan.sidecar_core_plans.len(),
        "subscription_proxy_only": plan.subscription_proxy_only
    })
}

fn core_value(plan: &RuntimeBootstrapPlan, status: Option<&ProcessStatus>) -> Value {
    let config_path = plan
        .core_plan
        .as_ref()
        .map(|core| core.config_path.display().to_string());
    let inbounds = plan
        .core_plan
        .as_ref()
        .map(|core| core.inbounds.len())
        .unwrap_or(0);
    let sidecar_inbounds = plan
        .sidecar_core_plans
        .iter()
        .map(|core| core.inbounds.len())
        .sum::<usize>();
    let status = status.map(process_status_value);

    json!({
        "configured": plan.core_plan.is_some(),
        "config_path": config_path,
        "inbounds": inbounds,
        "sidecars": plan.sidecar_core_plans.len(),
        "sidecar_inbounds": sidecar_inbounds,
        "status": status
    })
}

fn process_status_value(status: &ProcessStatus) -> Value {
    json!({
        "name": &status.name,
        "pid": status.pid,
        "state": process_state_label(&status.state),
        "message": &status.message
    })
}

fn hy2_port_forward_value(status: &HysteriaPortForwardStatus) -> Value {
    let expected_rules = status
        .expected_rules
        .iter()
        .map(|rule| {
            json!({
                "protocol": &rule.protocol,
                "match_rule": &rule.match_rule,
                "target_port": rule.target_port,
                "spec": &rule.spec
            })
        })
        .collect::<Vec<_>>();
    let tools = status.tools.iter().map(hy2_tool_value).collect::<Vec<_>>();

    json!({
        "enabled": status.enabled,
        "running_as_root": status.running_as_root,
        "expected_rules": expected_rules,
        "tools": tools,
        "errors": &status.errors
    })
}

fn hy2_tool_value(status: &HysteriaPortForwardToolStatus) -> Value {
    json!({
        "tool": &status.tool,
        "available": status.available,
        "current": &status.current,
        "expected": &status.expected,
        "missing": &status.missing,
        "extra": &status.extra,
        "stale_chain": status.stale_chain,
        "error": &status.error
    })
}

fn agent_value(
    agent: &AgentConfig,
    subscription_proxy: Option<&SubscriptionProxyStatus>,
) -> Value {
    if let Some(status) = subscription_proxy {
        return json!({
            "subscription_proxy": subscription_proxy_status_value(status)
        });
    }

    let proxy = &agent.subscription_proxy;
    if !proxy.enabled {
        return Value::Null;
    }
    let profiles = proxy
        .profiles
        .iter()
        .map(|profile| {
            json!({
                "site_id": &profile.site_id,
                "upstream_base_url": &profile.upstream_base_url,
                "subscribe_path": &profile.subscribe_path
            })
        })
        .collect::<Vec<_>>();

    json!({
        "subscription_proxy": {
            "enabled": proxy.enabled,
            "https_listen": &proxy.https_listen,
            "http_listen": &proxy.http_listen,
            "certificate_domain": &proxy.certificate_domain,
            "site_id": &proxy.site_id,
            "upstream_base_url": &proxy.upstream_base_url,
            "subscribe_path": &proxy.subscribe_path,
            "profiles": profiles
        }
    })
}

fn subscription_proxy_status_value(status: &SubscriptionProxyStatus) -> Value {
    json!({
        "status": &status.status,
        "enabled": status.enabled,
        "running": status.running,
        "mode": &status.mode,
        "https_listen": &status.https_listen,
        "profiles": status.profiles,
        "certificate_domain": &status.certificate_domain,
        "certificate_owner_site_id": &status.certificate_owner_site_id,
        "certificate_id": &status.certificate_id,
        "need_certificate": status.need_certificate,
        "csr_pem": &status.csr_pem,
        "validation_ready": status.validation_ready,
        "cert_not_after": &status.cert_not_after,
        "last_error": &status.last_error
    })
}

fn runtime_mode_label(mode: &RuntimeMode) -> &'static str {
    match mode {
        RuntimeMode::DirectNode => "direct_node",
        RuntimeMode::MachineBinding => "machine_binding",
        RuntimeMode::Invalid => "invalid",
    }
}

fn process_state_label(state: &ProcessState) -> &'static str {
    match state {
        ProcessState::Running => "running",
        ProcessState::Stopped => "stopped",
        ProcessState::Exited(_) => "exited",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{
        AgentConfig, NodeConfig, ResolvedConfig, ResolvedMachineConfig, SubscriptionProxyConfig,
        SubscriptionProxyProfile,
    };
    use crate::node::NodeFailure;
    use crate::panel::types::{CommonNode, NodeInfo};
    use crate::process::ProcessStatus;
    use crate::runtime::build_runtime_bootstrap_plan;
    use crate::subscription_proxy::SubscriptionProxyStatus;

    use super::{
        build_machine_status_payload, node_failure_payloads, HealthReportInput,
        ResourceSnapshot, UsageSnapshot,
    };

    #[test]
    fn machine_status_payload_matches_board_contract() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![node_config("https://panel.example.test", 7, 3)],
        };
        let node = test_node("vless", 7);
        let failure = NodeFailure {
            config: node_config("https://panel-b.example.test/", 8, 0),
            error: "panel unavailable".to_string(),
        };
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], vec![failure]).unwrap();

        let payload = build_machine_status_payload(
            3,
            &plan,
            HealthReportInput {
                version: "v0.4.0".to_string(),
                resources: ResourceSnapshot {
                    cpu: 12.5,
                    mem: UsageSnapshot {
                        total: 1024,
                        used: 512,
                    },
                    ..ResourceSnapshot::default()
                },
                core: Some(ProcessStatus::running("core:xray", 42)),
                subscription_proxy: None,
                upgrade: None,
            },
        );

        assert_eq!(payload.machine_id, 3);
        assert_eq!(payload.status["cpu"], json!(12.5));
        assert_eq!(payload.status["mem"]["total"], json!(1024));
        assert_eq!(payload.status["version"], json!("v0.4.0"));
        assert_eq!(payload.status["runtime"]["mode"], json!("machine_binding"));
        assert_eq!(payload.status["core"]["status"]["state"], json!("running"));
        assert_eq!(
            payload.status["node_failures"][0]["api_host"],
            json!("https://panel-b.example.test")
        );
        assert_eq!(payload.status["node_failures"][0]["machine_id"], json!(3));
    }

    #[test]
    fn subscription_proxy_agent_status_is_nested_for_panel_service() {
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
                    certificate_domain: "proxy.example.test".to_string(),
                    profiles: vec![SubscriptionProxyProfile {
                        site_id: "site-a".to_string(),
                        upstream_base_url: "https://panel.example.test".to_string(),
                        subscribe_path: "s".to_string(),
                    }],
                    ..SubscriptionProxyConfig::default()
                },
            },
            nodes: Vec::new(),
        };
        let plan = build_runtime_bootstrap_plan(resolved, Vec::new(), Vec::new()).unwrap();

        let payload = build_machine_status_payload(9, &plan, HealthReportInput::default());

        assert_eq!(
            payload.status["agent"]["subscription_proxy"]["certificate_domain"],
            json!("proxy.example.test")
        );
        assert_eq!(
            payload.status["agent"]["subscription_proxy"]["profiles"][0]["site_id"],
            json!("site-a")
        );
    }

    #[test]
    fn runtime_subscription_proxy_status_overrides_config_snapshot() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: Vec::new(),
        };
        let plan = build_runtime_bootstrap_plan(resolved, Vec::new(), Vec::new()).unwrap();

        let payload = build_machine_status_payload(
            9,
            &plan,
            HealthReportInput {
                subscription_proxy: Some(SubscriptionProxyStatus {
                    status: "running".to_string(),
                    enabled: true,
                    running: true,
                    mode: "https".to_string(),
                    https_listen: "0.0.0.0:443".to_string(),
                    profiles: 2,
                    certificate_domain: "proxy.example.test".to_string(),
                    certificate_owner_site_id: "site-a".to_string(),
                    certificate_id: "cert-1".to_string(),
                    need_certificate: true,
                    csr_pem: "csr".to_string(),
                    validation_ready: true,
                    cert_not_after: "2026-06-01T00:00:00Z".to_string(),
                    last_error: String::new(),
                }),
                ..HealthReportInput::default()
            },
        );

        let proxy = &payload.status["agent"]["subscription_proxy"];
        assert_eq!(proxy["status"], json!("running"));
        assert_eq!(proxy["mode"], json!("https"));
        assert_eq!(proxy["profiles"], json!(2));
        assert_eq!(proxy["certificate_owner_site_id"], json!("site-a"));
        assert_eq!(proxy["need_certificate"], json!(true));
        assert_eq!(proxy["validation_ready"], json!(true));
    }

    #[test]
    fn node_failure_payloads_use_config_machine_id_when_present() {
        let failures = vec![NodeFailure {
            config: node_config("https://panel.example.test", 10, 22),
            error: "boom".to_string(),
        }];

        let payloads = node_failure_payloads(&failures, 9);

        assert_eq!(payloads[0].machine_id, 22);
        assert_eq!(payloads[0].api_host, "https://panel.example.test");
    }

    fn node_config(url: &str, node_id: u32, machine_id: u32) -> NodeConfig {
        NodeConfig {
            url: url.to_string(),
            token: "token".to_string(),
            node_id,
            machine_id,
            ..NodeConfig::default()
        }
    }

    fn test_node(protocol: &str, node_id: u32) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": protocol,
            "server_port": 10000 + node_id
        }))
        .unwrap();

        NodeInfo::from_common("https://panel.example.test", node_id, common).unwrap()
    }
}
