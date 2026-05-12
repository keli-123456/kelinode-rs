use std::{fs, path::Path};

use serde_json::{json, Map, Value};

use crate::config::AgentConfig;
use crate::core::CoreKind;
use crate::machine::{MachineStatusPayload, NodeFailurePayload};
use crate::node::NodeFailure;
use crate::port_forward::{HysteriaPortForwardStatus, HysteriaPortForwardToolStatus};
use crate::process::{ProcessState, ProcessStatus};
use crate::runtime::{RuntimeBootstrapPlan, RuntimeMode};
use crate::subscription_proxy::SubscriptionProxyStatus;

const DEFAULT_INSTALL_DIR: &str = "/usr/local/v2node";
const INSTALLED_CORE_VERSION_FILES: &[(&str, &str)] = &[("keli-core-rs", ".keli-core-rs_version")];

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
    pub sidecars: Vec<ProcessStatus>,
    pub subscription_proxy: Option<SubscriptionProxyStatus>,
    pub upgrade: Option<Value>,
    pub metrics: Option<Value>,
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
        resources
            .uptime
            .map(|uptime| json!(uptime))
            .unwrap_or(Value::Null),
    );
    payload.insert_status("version", version_value(input.version));
    payload.insert_status("runtime", runtime_value(plan));
    payload.insert_status(
        "core",
        core_value(plan, input.core.as_ref(), &input.sidecars),
    );
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
    if let Some(metrics) = input.metrics {
        payload.insert_status("metrics", metrics_value(metrics));
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

fn metrics_value(mut metrics: Value) -> Value {
    let Value::Object(metrics_map) = &mut metrics else {
        return metrics;
    };
    let summary = native_core_gray_health_value(metrics_map);
    if !summary.is_null() {
        metrics_map.insert("native_core_gray_health".to_string(), summary);
    }
    metrics
}

fn native_core_gray_health_value(metrics: &Map<String, Value>) -> Value {
    let native_success = nested_metric_u64(
        metrics,
        "user_delta",
        "kelinode_user_delta_native_apply_success_total",
    );
    let native_failed = nested_metric_u64(
        metrics,
        "user_delta",
        "kelinode_user_delta_native_apply_failed_total",
    );
    let full_snapshot_fallback = nested_metric_u64(
        metrics,
        "user_delta",
        "kelinode_user_delta_full_snapshot_fallback_total",
    );
    let full_rebuild = nested_metric_u64(
        metrics,
        "user_delta",
        "kelinode_user_delta_full_rebuild_total",
    );
    let revision_mismatch = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_user_delta_revision_mismatch_total",
    );
    let current_revision_missing = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_user_delta_current_revision_missing_total",
    );
    let core_apply_errors = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_user_delta_apply_error_total",
    );
    let metrics_failure = metrics.get("keli_core_rs_error").is_some();

    if native_success == 0
        && native_failed == 0
        && full_snapshot_fallback == 0
        && full_rebuild == 0
        && revision_mismatch == 0
        && current_revision_missing == 0
        && core_apply_errors == 0
        && !metrics_failure
    {
        return Value::Null;
    }

    let mut reasons = Vec::new();
    if metrics_failure {
        reasons.push("metrics_unavailable");
    }
    if native_failed > 0 {
        reasons.push("native_apply_failed");
    }
    if core_apply_errors > 0 {
        reasons.push("core_apply_error");
    }
    if full_rebuild > 0 {
        reasons.push("full_rebuild");
    }
    if full_snapshot_fallback > 0 {
        reasons.push("full_snapshot_fallback");
    }
    if revision_mismatch > 0 {
        reasons.push("revision_mismatch");
    }
    if current_revision_missing > 0 {
        reasons.push("current_revision_missing");
    }

    let mode = if metrics_failure || native_failed > 0 || core_apply_errors > 0 {
        "degraded"
    } else if full_rebuild > 0 {
        "full_rebuild"
    } else if full_snapshot_fallback > 0 || revision_mismatch > 0 || current_revision_missing > 0 {
        "fallback_repaired"
    } else if native_success > 0 {
        "native_delta"
    } else {
        "unknown"
    };
    let warning = match mode {
        "degraded" => "native core metrics unavailable or apply errors observed",
        "full_rebuild" => "native user delta fell back to full plan rebuild",
        "fallback_repaired" => "full snapshot fallback observed; monitor for repetition",
        _ => "",
    };

    json!({
        "mode": mode,
        "warning": warning,
        "native_apply_success_total": native_success,
        "native_apply_failed_total": native_failed,
        "full_snapshot_fallback_total": full_snapshot_fallback,
        "full_rebuild_total": full_rebuild,
        "revision_mismatch_total": revision_mismatch,
        "current_revision_missing_total": current_revision_missing,
        "core_apply_error_total": core_apply_errors,
        "metrics_available": !metrics_failure,
        "reasons": reasons
    })
}

fn nested_metric_u64(metrics: &Map<String, Value>, section: &str, key: &str) -> u64 {
    metrics
        .get(section)
        .and_then(Value::as_object)
        .and_then(|section| section.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
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
        "agent": "kelinode-rs",
        "mode": runtime_mode_label(&plan.bootstrap.mode),
        "nodes": plan.node_count,
        "configured_nodes": plan.resolved.nodes.len(),
        "machine_profiles": plan.bootstrap.machine_profile_count,
        "sidecars": plan.sidecar_core_plans.len(),
        "subscription_proxy_only": plan.subscription_proxy_only
    })
}

fn core_value(
    plan: &RuntimeBootstrapPlan,
    status: Option<&ProcessStatus>,
    sidecars: &[ProcessStatus],
) -> Value {
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
    let sidecar_statuses = sidecars
        .iter()
        .map(process_status_value)
        .collect::<Vec<_>>();

    json!({
        "configured": plan.core_plan.is_some(),
        "config_path": config_path,
        "inbounds": inbounds,
        "sidecars": plan.sidecar_core_plans.len(),
        "sidecar_inbounds": sidecar_inbounds,
        "sidecar_statuses": sidecar_statuses,
        "versions": installed_core_versions_value(Path::new(DEFAULT_INSTALL_DIR)),
        "user_limits": user_limit_value(plan),
        "status": status
    })
}

fn installed_core_versions_value(install_dir: &Path) -> Value {
    let mut versions = Map::new();
    for (component, file_name) in INSTALLED_CORE_VERSION_FILES {
        if let Some(version) = read_installed_version_marker(install_dir, file_name) {
            versions.insert((*component).to_string(), Value::String(version));
        }
    }
    Value::Object(versions)
}

fn read_installed_version_marker(install_dir: &Path, file_name: &str) -> Option<String> {
    let version = fs::read_to_string(install_dir.join(file_name)).ok()?;
    let version = version.trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

fn user_limit_value(plan: &RuntimeBootstrapPlan) -> Value {
    let mut users = 0usize;
    let mut speed_limited_users = 0usize;
    let mut device_limited_users = 0usize;
    let mut enforced_limited_users = 0usize;
    let mut pending_limited_users = 0usize;

    for core in plan.core_plan.iter().chain(plan.sidecar_core_plans.iter()) {
        let limits_enforced = matches!(core.kind, CoreKind::KeliCoreRs);
        for inbound in &core.inbounds {
            for user in &inbound.users {
                users += 1;
                let speed_limited = user.speed_limit > 0;
                let device_limited = user.device_limit > 0;
                if speed_limited {
                    speed_limited_users += 1;
                }
                if device_limited {
                    device_limited_users += 1;
                }
                if speed_limited || device_limited {
                    if limits_enforced {
                        enforced_limited_users += 1;
                    } else {
                        pending_limited_users += 1;
                    }
                }
            }
        }
    }

    let active = speed_limited_users > 0 || device_limited_users > 0;
    let enforcement = if !active {
        "none_required"
    } else if pending_limited_users == 0 {
        "keli_core_rs"
    } else if enforced_limited_users > 0 {
        "partial"
    } else {
        "external_core_pending"
    };
    let warning = if pending_limited_users > 0 {
        "per-user speed and device limits are not enforced by this external-core runtime yet"
    } else {
        ""
    };
    json!({
        "users": users,
        "speed_limited_users": speed_limited_users,
        "device_limited_users": device_limited_users,
        "enforced_limited_users": enforced_limited_users,
        "pending_limited_users": pending_limited_users,
        "active": active,
        "enforcement": enforcement,
        "warning": warning
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

fn agent_value(agent: &AgentConfig, subscription_proxy: Option<&SubscriptionProxyStatus>) -> Value {
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
    use std::{
        collections::BTreeMap,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;

    use crate::config::{
        AgentConfig, NodeConfig, ResolvedConfig, ResolvedMachineConfig, SubscriptionProxyConfig,
        SubscriptionProxyProfile,
    };
    use crate::node::NodeFailure;
    use crate::panel::types::{CommonNode, NodeInfo, UserInfo};
    use crate::process::ProcessStatus;
    use crate::runtime::{build_runtime_bootstrap_plan, build_runtime_bootstrap_plan_with_users};
    use crate::subscription_proxy::SubscriptionProxyStatus;

    use super::{
        build_machine_status_payload, installed_core_versions_value, metrics_value,
        node_failure_payloads, HealthReportInput, ResourceSnapshot, UsageSnapshot,
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
                sidecars: Vec::new(),
                subscription_proxy: None,
                upgrade: None,
                metrics: None,
            },
        );

        assert_eq!(payload.machine_id, 3);
        assert_eq!(payload.status["cpu"], json!(12.5));
        assert_eq!(payload.status["mem"]["total"], json!(1024));
        assert_eq!(payload.status["version"], json!("v0.4.0"));
        assert_eq!(payload.status["runtime"]["agent"], json!("kelinode-rs"));
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
    fn machine_status_surfaces_external_core_user_limit_gap() {
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
        let tag = node.tag.clone();
        let mut users = BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 1,
                uuid: "11111111-1111-1111-1111-111111111111".to_string(),
                speed_limit: 20,
                device_limit: 2,
            }],
        );
        let plan =
            build_runtime_bootstrap_plan_with_users(resolved, vec![node], Vec::new(), &users)
                .unwrap();

        let payload = build_machine_status_payload(3, &plan, HealthReportInput::default());

        let limits = &payload.status["core"]["user_limits"];
        assert_eq!(limits["users"], json!(1));
        assert_eq!(limits["speed_limited_users"], json!(1));
        assert_eq!(limits["device_limited_users"], json!(1));
        assert_eq!(limits["active"], json!(true));
        assert_eq!(limits["enforcement"], json!("external_core_pending"));
        assert_eq!(limits["pending_limited_users"], json!(1));
        assert_eq!(limits["enforced_limited_users"], json!(0));
    }

    #[test]
    fn machine_status_marks_keli_core_rs_user_limits_as_enforced() {
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![node_config("https://panel.example.test", 8, 3)],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        let node = test_node("socks", 8);
        let tag = node.tag.clone();
        let mut users = BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 1,
                uuid: "11111111-1111-1111-1111-111111111111".to_string(),
                speed_limit: 20,
                device_limit: 2,
            }],
        );
        let plan =
            build_runtime_bootstrap_plan_with_users(resolved, vec![node], Vec::new(), &users)
                .unwrap();

        let payload = build_machine_status_payload(3, &plan, HealthReportInput::default());

        let limits = &payload.status["core"]["user_limits"];
        assert_eq!(limits["users"], json!(1));
        assert_eq!(limits["speed_limited_users"], json!(1));
        assert_eq!(limits["device_limited_users"], json!(1));
        assert_eq!(limits["active"], json!(true));
        assert_eq!(limits["enforcement"], json!("keli_core_rs"));
        assert_eq!(limits["pending_limited_users"], json!(0));
        assert_eq!(limits["enforced_limited_users"], json!(1));
        assert_eq!(limits["warning"], json!(""));
    }

    #[test]
    fn machine_status_includes_native_core_metrics_without_user_cardinality() {
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![node_config("https://panel.example.test", 8, 3)],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        let node = test_node("socks", 8);
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let metrics = json!({
            "user_delta": {
                "kelinode_user_delta_native_apply_success_total": 7,
                "kelinode_user_delta_full_snapshot_fallback_total": 1
            },
            "keli_core_rs": {
                "keli_core_user_delta_apply_total": 8,
                "keli_core_user_delta_active_users": {
                    "panel.example.test|socks|8": 260000
                }
            }
        });

        let payload = build_machine_status_payload(
            3,
            &plan,
            HealthReportInput {
                metrics: Some(metrics),
                ..HealthReportInput::default()
            },
        );

        assert_eq!(
            payload.status["metrics"]["user_delta"]
                ["kelinode_user_delta_native_apply_success_total"],
            json!(7)
        );
        assert_eq!(
            payload.status["metrics"]["keli_core_rs"]["keli_core_user_delta_apply_total"],
            json!(8)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["mode"],
            json!("fallback_repaired")
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["full_snapshot_fallback_total"],
            json!(1)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["warning"],
            json!("full snapshot fallback observed; monitor for repetition")
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["metrics_available"],
            json!(true)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["reasons"],
            json!(["full_snapshot_fallback"])
        );
        let status = serde_json::to_string(&payload.status["metrics"]).unwrap();
        assert!(!status.contains("11111111-1111-1111-1111-111111111111"));
        assert!(!status.contains("KELI_CORE_CONTROL_TOKEN"));
    }

    #[test]
    fn native_core_metrics_summary_marks_apply_errors_as_degraded() {
        let metrics = json!({
            "user_delta": {
                "kelinode_user_delta_native_apply_success_total": 10,
                "kelinode_user_delta_native_apply_failed_total": 2
            },
            "keli_core_rs": {
                "keli_core_user_delta_apply_error_total": 1
            }
        });

        let summary = metrics_value(metrics)["native_core_gray_health"].clone();

        assert_eq!(summary["mode"], json!("degraded"));
        assert_eq!(summary["native_apply_failed_total"], json!(2));
        assert_eq!(summary["core_apply_error_total"], json!(1));
        assert_eq!(
            summary["warning"],
            json!("native core metrics unavailable or apply errors observed")
        );
        assert_eq!(summary["metrics_available"], json!(true));
        assert_eq!(
            summary["reasons"],
            json!(["native_apply_failed", "core_apply_error"])
        );
        assert!(!summary.to_string().contains("KELI_CORE_CONTROL_TOKEN"));
    }

    #[test]
    fn native_core_metrics_summary_marks_metrics_failure_as_degraded() {
        let metrics = json!({
            "user_delta": {
                "kelinode_user_delta_native_apply_success_total": 10
            },
            "keli_core_rs_error": {
                "message": "fetch keli-core-rs metrics: connection refused"
            }
        });

        let summary = metrics_value(metrics)["native_core_gray_health"].clone();

        assert_eq!(summary["mode"], json!("degraded"));
        assert_eq!(summary["metrics_available"], json!(false));
        assert_eq!(summary["reasons"], json!(["metrics_unavailable"]));
        assert_eq!(
            summary["warning"],
            json!("native core metrics unavailable or apply errors observed")
        );
        assert!(!summary.to_string().contains("KELI_CORE_CONTROL_TOKEN"));
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
    fn installed_core_versions_read_upgrade_markers() {
        let dir = temp_test_dir("installed-core-versions");
        fs::write(dir.join(".keli-core-rs_version"), " v0.2.0\n").unwrap();

        let versions = installed_core_versions_value(&dir);

        assert_eq!(versions["keli-core-rs"], json!("v0.2.0"));
        fs::remove_dir_all(dir).ok();
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

    fn temp_test_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "kelinode-rs-health-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
