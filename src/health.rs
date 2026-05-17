use std::{fs, path::Path};

use serde_json::{json, Map, Value};

use crate::config::AgentConfig;
use crate::core::CoreKind;
use crate::machine::{MachineStatusPayload, NodeFailurePayload};
use crate::node::NodeFailure;
use crate::port_forward::{HysteriaPortForwardStatus, HysteriaPortForwardToolStatus};
use crate::process::{ProcessState, ProcessStatus};
use crate::runtime::{node_config_for_info, RuntimeBootstrapPlan, RuntimeMode};
use crate::subscription_proxy::SubscriptionProxyStatus;

const DEFAULT_INSTALL_DIR: &str = "/usr/local/kelinode";
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
    let core_apply_total =
        nested_metric_u64(metrics, "keli_core_rs", "keli_core_user_delta_apply_total");
    let core_incremental = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_user_delta_incremental_total",
    );
    let core_full_snapshot = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_user_delta_full_snapshot_total",
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
    let core_apply_duration_count = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_user_delta_apply_duration_ms",
        "count",
    );
    let core_apply_duration_last_ms = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_user_delta_apply_duration_ms",
        "last_ms",
    );
    let core_apply_duration_max_ms = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_user_delta_apply_duration_ms",
        "max_ms",
    );
    let quic_total_limit = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_quic_resource",
        "total_limit",
    );
    let quic_active_connections = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_quic_resource",
        "active_connections",
    );
    let quic_available_connections = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_quic_resource",
        "available_connections",
    );
    let quic_listener_count = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_quic_resource",
        "listener_count",
    );
    let quic_per_listener_soft_limit = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_quic_resource",
        "per_listener_soft_limit",
    );
    let tls_handshake_failure_total = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_tls_handshake_failure_total",
    );
    let tls_handshake_backoff_reject_total = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_tls_handshake_backoff_reject_total",
    );
    let tls_handshake_backoff_active_ips = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_tls_handshake_backoff_active_ips",
    );
    let tls_handshake_backoff_blocked_ips = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_tls_handshake_backoff_blocked_ips",
    );
    let tcp_auth_failure_total =
        nested_metric_u64(metrics, "keli_core_rs", "keli_core_tcp_auth_failure_total");
    let tcp_auth_backoff_reject_total = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_tcp_auth_backoff_reject_total",
    );
    let tcp_auth_backoff_active_ips = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_tcp_auth_backoff_active_ips",
    );
    let tcp_auth_backoff_blocked_ips = nested_metric_u64(
        metrics,
        "keli_core_rs",
        "keli_core_tcp_auth_backoff_blocked_ips",
    );
    let dns_resolve_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_dns",
        "keli_core_dns_resolve_total",
    );
    let dns_system_query_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_dns",
        "keli_core_dns_system_query_total",
    );
    let dns_configured_query_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_dns",
        "keli_core_dns_configured_query_total",
    );
    let dns_positive_cache_hit_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_dns",
        "keli_core_dns_positive_cache_hit_total",
    );
    let dns_negative_cache_hit_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_dns",
        "keli_core_dns_negative_cache_hit_total",
    );
    let dns_resolve_error_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_dns",
        "keli_core_dns_resolve_error_total",
    );
    let dns_private_ip_filter_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_dns",
        "keli_core_dns_private_ip_filter_total",
    );
    let dns_private_ip_block_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_dns",
        "keli_core_dns_private_ip_block_total",
    );
    let connection_error_total =
        nested_metric_object_sum_u64(metrics, "keli_core_rs", "keli_core_connection_error_total");
    let hy2_connection_timeout_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_connection_error_total",
        "hysteria2.connection.timeout",
    );
    let hy2_tcp_relay_timeout_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_connection_error_total",
        "hysteria2.tcp_relay.timeout",
    );
    let vless_tcp_auth_failed_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_connection_error_total",
        "vless.tcp.auth_failed",
    );
    let vless_tcp_upstream_timeout_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_connection_error_total",
        "vless.tcp.upstream_timeout",
    );
    let vless_tcp_upstream_connect_failed_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_connection_error_total",
        "vless.tcp.upstream_connect_failed",
    );
    let vless_tcp_dns_private_blocked_total = nested_metric_object_u64(
        metrics,
        "keli_core_rs",
        "keli_core_connection_error_total",
        "vless.tcp.dns_private_blocked",
    );
    let quic_utilization_pct = if quic_total_limit == 0 {
        0
    } else {
        quic_active_connections.saturating_mul(100) / quic_total_limit
    };
    let abuse_backoff_pressure = tls_handshake_backoff_reject_total > 0
        || tls_handshake_backoff_blocked_ips > 0
        || tcp_auth_backoff_reject_total > 0
        || tcp_auth_backoff_blocked_ips > 0;
    let dns_guard_pressure = dns_private_ip_block_total > 0 || dns_resolve_error_total > 0;
    let connection_error_pressure = hy2_connection_timeout_total > 0
        || hy2_tcp_relay_timeout_total > 0
        || vless_tcp_upstream_timeout_total > 0
        || vless_tcp_upstream_connect_failed_total > 0
        || vless_tcp_dns_private_blocked_total > 0;
    let metrics_failure = metrics.get("keli_core_rs_error").is_some();

    if native_success == 0
        && native_failed == 0
        && full_snapshot_fallback == 0
        && full_rebuild == 0
        && core_apply_total == 0
        && core_incremental == 0
        && core_full_snapshot == 0
        && revision_mismatch == 0
        && current_revision_missing == 0
        && core_apply_errors == 0
        && quic_total_limit == 0
        && tls_handshake_failure_total == 0
        && tls_handshake_backoff_reject_total == 0
        && tls_handshake_backoff_active_ips == 0
        && tls_handshake_backoff_blocked_ips == 0
        && tcp_auth_failure_total == 0
        && tcp_auth_backoff_reject_total == 0
        && tcp_auth_backoff_active_ips == 0
        && tcp_auth_backoff_blocked_ips == 0
        && dns_resolve_total == 0
        && dns_system_query_total == 0
        && dns_configured_query_total == 0
        && dns_positive_cache_hit_total == 0
        && dns_negative_cache_hit_total == 0
        && dns_resolve_error_total == 0
        && dns_private_ip_filter_total == 0
        && dns_private_ip_block_total == 0
        && connection_error_total == 0
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
    if quic_utilization_pct >= 90 {
        reasons.push("quic_resource_high");
    }
    if tls_handshake_backoff_reject_total > 0 || tls_handshake_backoff_blocked_ips > 0 {
        reasons.push("tls_handshake_backoff");
    }
    if tcp_auth_backoff_reject_total > 0 || tcp_auth_backoff_blocked_ips > 0 {
        reasons.push("tcp_auth_backoff");
    }
    if dns_resolve_error_total > 0 {
        reasons.push("dns_resolve_error");
    }
    if dns_private_ip_block_total > 0 {
        reasons.push("dns_private_ip_block");
    }
    if hy2_connection_timeout_total > 0 || hy2_tcp_relay_timeout_total > 0 {
        reasons.push("hy2_timeout");
    }
    if vless_tcp_upstream_timeout_total > 0 || vless_tcp_upstream_connect_failed_total > 0 {
        reasons.push("vless_upstream_error");
    }
    if vless_tcp_dns_private_blocked_total > 0 {
        reasons.push("vless_dns_private_block");
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
    let warning = if quic_utilization_pct >= 90 {
        "QUIC resource usage is high; hold gray rollout until capacity is adjusted"
    } else if abuse_backoff_pressure {
        "client abuse backoff observed; monitor CPU and auth failure rate before widening"
    } else if dns_guard_pressure {
        "DNS guard or resolve errors observed; verify route rules and upstream DNS before widening"
    } else if connection_error_pressure {
        "native core connection errors observed; inspect HY2/VLESS counters before widening"
    } else {
        match mode {
            "degraded" => "native core metrics unavailable or apply errors observed",
            "full_rebuild" => "native user delta fell back to full plan rebuild",
            "fallback_repaired" => "full snapshot fallback observed; monitor for repetition",
            _ => "",
        }
    };
    let mut gate = match mode {
        "native_delta" => "allow_widen",
        "fallback_repaired" => "hold_monitor",
        "full_rebuild" | "degraded" => "hold_rollback",
        _ => "hold",
    };
    if quic_utilization_pct >= 90 && gate == "allow_widen" {
        gate = "hold_monitor";
    }
    if abuse_backoff_pressure && gate == "allow_widen" {
        gate = "hold_monitor";
    }
    if dns_guard_pressure && gate == "allow_widen" {
        gate = "hold_monitor";
    }
    if connection_error_pressure && gate == "allow_widen" {
        gate = "hold_monitor";
    }

    let mut summary = Map::new();
    summary.insert("mode".to_string(), json!(mode));
    summary.insert("gate".to_string(), json!(gate));
    summary.insert("can_widen".to_string(), json!(gate == "allow_widen"));
    summary.insert(
        "rollback_recommended".to_string(),
        json!(gate == "hold_rollback"),
    );
    summary.insert("warning".to_string(), json!(warning));
    insert_u64(&mut summary, "native_apply_success_total", native_success);
    insert_u64(&mut summary, "native_apply_failed_total", native_failed);
    insert_u64(
        &mut summary,
        "full_snapshot_fallback_total",
        full_snapshot_fallback,
    );
    insert_u64(&mut summary, "full_rebuild_total", full_rebuild);
    insert_u64(&mut summary, "core_apply_total", core_apply_total);
    insert_u64(&mut summary, "core_incremental_total", core_incremental);
    insert_u64(&mut summary, "core_full_snapshot_total", core_full_snapshot);
    insert_u64(&mut summary, "revision_mismatch_total", revision_mismatch);
    insert_u64(
        &mut summary,
        "current_revision_missing_total",
        current_revision_missing,
    );
    insert_u64(&mut summary, "core_apply_error_total", core_apply_errors);
    insert_u64(
        &mut summary,
        "core_apply_duration_count",
        core_apply_duration_count,
    );
    insert_u64(
        &mut summary,
        "core_apply_duration_last_ms",
        core_apply_duration_last_ms,
    );
    insert_u64(
        &mut summary,
        "core_apply_duration_max_ms",
        core_apply_duration_max_ms,
    );
    insert_u64(&mut summary, "quic_total_limit", quic_total_limit);
    insert_u64(
        &mut summary,
        "quic_active_connections",
        quic_active_connections,
    );
    insert_u64(
        &mut summary,
        "quic_available_connections",
        quic_available_connections,
    );
    insert_u64(&mut summary, "quic_listener_count", quic_listener_count);
    insert_u64(
        &mut summary,
        "quic_per_listener_soft_limit",
        quic_per_listener_soft_limit,
    );
    insert_u64(&mut summary, "quic_utilization_pct", quic_utilization_pct);
    insert_u64(
        &mut summary,
        "tls_handshake_failure_total",
        tls_handshake_failure_total,
    );
    insert_u64(
        &mut summary,
        "tls_handshake_backoff_reject_total",
        tls_handshake_backoff_reject_total,
    );
    insert_u64(
        &mut summary,
        "tls_handshake_backoff_active_ips",
        tls_handshake_backoff_active_ips,
    );
    insert_u64(
        &mut summary,
        "tls_handshake_backoff_blocked_ips",
        tls_handshake_backoff_blocked_ips,
    );
    insert_u64(
        &mut summary,
        "tcp_auth_failure_total",
        tcp_auth_failure_total,
    );
    insert_u64(
        &mut summary,
        "tcp_auth_backoff_reject_total",
        tcp_auth_backoff_reject_total,
    );
    insert_u64(
        &mut summary,
        "tcp_auth_backoff_active_ips",
        tcp_auth_backoff_active_ips,
    );
    insert_u64(
        &mut summary,
        "tcp_auth_backoff_blocked_ips",
        tcp_auth_backoff_blocked_ips,
    );
    insert_u64(&mut summary, "dns_resolve_total", dns_resolve_total);
    insert_u64(
        &mut summary,
        "dns_system_query_total",
        dns_system_query_total,
    );
    insert_u64(
        &mut summary,
        "dns_configured_query_total",
        dns_configured_query_total,
    );
    insert_u64(
        &mut summary,
        "dns_positive_cache_hit_total",
        dns_positive_cache_hit_total,
    );
    insert_u64(
        &mut summary,
        "dns_negative_cache_hit_total",
        dns_negative_cache_hit_total,
    );
    insert_u64(
        &mut summary,
        "dns_resolve_error_total",
        dns_resolve_error_total,
    );
    insert_u64(
        &mut summary,
        "dns_private_ip_filter_total",
        dns_private_ip_filter_total,
    );
    insert_u64(
        &mut summary,
        "dns_private_ip_block_total",
        dns_private_ip_block_total,
    );
    insert_u64(
        &mut summary,
        "connection_error_total",
        connection_error_total,
    );
    insert_u64(
        &mut summary,
        "hy2_connection_timeout_total",
        hy2_connection_timeout_total,
    );
    insert_u64(
        &mut summary,
        "hy2_tcp_relay_timeout_total",
        hy2_tcp_relay_timeout_total,
    );
    insert_u64(
        &mut summary,
        "vless_tcp_auth_failed_total",
        vless_tcp_auth_failed_total,
    );
    insert_u64(
        &mut summary,
        "vless_tcp_upstream_timeout_total",
        vless_tcp_upstream_timeout_total,
    );
    insert_u64(
        &mut summary,
        "vless_tcp_upstream_connect_failed_total",
        vless_tcp_upstream_connect_failed_total,
    );
    insert_u64(
        &mut summary,
        "vless_tcp_dns_private_blocked_total",
        vless_tcp_dns_private_blocked_total,
    );
    summary.insert("metrics_available".to_string(), json!(!metrics_failure));
    summary.insert("reasons".to_string(), json!(reasons));
    Value::Object(summary)
}

fn insert_u64(summary: &mut Map<String, Value>, key: &str, value: u64) {
    summary.insert(key.to_string(), json!(value));
}

fn nested_metric_u64(metrics: &Map<String, Value>, section: &str, key: &str) -> u64 {
    metrics
        .get(section)
        .and_then(Value::as_object)
        .and_then(|section| section.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn nested_metric_object_u64(
    metrics: &Map<String, Value>,
    section: &str,
    object_key: &str,
    key: &str,
) -> u64 {
    metrics
        .get(section)
        .and_then(Value::as_object)
        .and_then(|section| section.get(object_key))
        .and_then(Value::as_object)
        .and_then(|object| object.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn nested_metric_object_sum_u64(
    metrics: &Map<String, Value>,
    section: &str,
    object_key: &str,
) -> u64 {
    metrics
        .get(section)
        .and_then(Value::as_object)
        .and_then(|section| section.get(object_key))
        .and_then(Value::as_object)
        .map(|object| object.values().filter_map(Value::as_u64).sum())
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
        "node_statuses": runtime_node_statuses_value(plan),
        "machine_profiles": plan.bootstrap.machine_profile_count,
        "sidecars": plan.sidecar_core_plans.len(),
        "subscription_proxy_only": plan.subscription_proxy_only
    })
}

fn runtime_node_statuses_value(plan: &RuntimeBootstrapPlan) -> Value {
    let rows = plan
        .node_infos
        .iter()
        .map(|node| {
            let config = node_config_for_info(&plan.resolved, node.id, &node.tag);
            json!({
                "api_host": config.map(|config| config.url.trim_end_matches('/')).unwrap_or_default(),
                "machine_id": config.map(|config| config.machine_id).unwrap_or_default(),
                "node_id": node.id,
                "node_type": "v2node",
                "protocol": node.protocol.as_str(),
                "tag": node.tag,
                "listen_ip": node.common.listen_ip,
                "server_port": node.common.server_port,
                "port": node.common.port.0,
                "status": "configured"
            })
        })
        .collect::<Vec<_>>();

    Value::Array(rows)
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
        assert_eq!(
            payload.status["runtime"]["node_statuses"][0]["node_id"],
            json!(7)
        );
        assert_eq!(
            payload.status["runtime"]["node_statuses"][0]["protocol"],
            json!("vless")
        );
        assert_eq!(
            payload.status["runtime"]["node_statuses"][0]["status"],
            json!("configured")
        );
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
                "keli_core_user_delta_incremental_total": 7,
                "keli_core_user_delta_full_snapshot_total": 1,
                "keli_core_user_delta_apply_duration_ms": {
                    "count": 8,
                    "last_ms": 3,
                    "max_ms": 41
                },
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
            payload.status["metrics"]["native_core_gray_health"]["gate"],
            json!("hold_monitor")
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["can_widen"],
            json!(false)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["rollback_recommended"],
            json!(false)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["full_snapshot_fallback_total"],
            json!(1)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["core_apply_total"],
            json!(8)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["core_incremental_total"],
            json!(7)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["core_full_snapshot_total"],
            json!(1)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["core_apply_duration_count"],
            json!(8)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["core_apply_duration_last_ms"],
            json!(3)
        );
        assert_eq!(
            payload.status["metrics"]["native_core_gray_health"]["core_apply_duration_max_ms"],
            json!(41)
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
        assert_eq!(summary["gate"], json!("hold_rollback"));
        assert_eq!(summary["can_widen"], json!(false));
        assert_eq!(summary["rollback_recommended"], json!(true));
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
        assert_eq!(summary["gate"], json!("hold_rollback"));
        assert_eq!(summary["can_widen"], json!(false));
        assert_eq!(summary["rollback_recommended"], json!(true));
        assert_eq!(summary["metrics_available"], json!(false));
        assert_eq!(summary["reasons"], json!(["metrics_unavailable"]));
        assert_eq!(
            summary["warning"],
            json!("native core metrics unavailable or apply errors observed")
        );
        assert!(!summary.to_string().contains("KELI_CORE_CONTROL_TOKEN"));
    }

    #[test]
    fn native_core_metrics_summary_allows_widen_only_on_clean_native_delta() {
        let metrics = json!({
            "user_delta": {
                "kelinode_user_delta_native_apply_success_total": 12
            },
            "keli_core_rs": {
                "keli_core_user_delta_incremental_total": 12
            }
        });

        let summary = metrics_value(metrics)["native_core_gray_health"].clone();

        assert_eq!(summary["mode"], json!("native_delta"));
        assert_eq!(summary["gate"], json!("allow_widen"));
        assert_eq!(summary["can_widen"], json!(true));
        assert_eq!(summary["rollback_recommended"], json!(false));
        assert_eq!(summary["warning"], json!(""));
    }

    #[test]
    fn native_core_metrics_summary_holds_widen_on_high_quic_usage() {
        let metrics = json!({
            "user_delta": {
                "kelinode_user_delta_native_apply_success_total": 12
            },
            "keli_core_rs": {
                "keli_core_user_delta_incremental_total": 12,
                "keli_core_quic_resource": {
                    "total_limit": 1000,
                    "active_connections": 930,
                    "available_connections": 70,
                    "listener_count": 4,
                    "per_listener_soft_limit": 250
                }
            }
        });

        let summary = metrics_value(metrics)["native_core_gray_health"].clone();

        assert_eq!(summary["mode"], json!("native_delta"));
        assert_eq!(summary["gate"], json!("hold_monitor"));
        assert_eq!(summary["can_widen"], json!(false));
        assert_eq!(summary["quic_utilization_pct"], json!(93));
        assert_eq!(summary["quic_total_limit"], json!(1000));
        assert_eq!(summary["quic_active_connections"], json!(930));
        assert_eq!(
            summary["warning"],
            json!("QUIC resource usage is high; hold gray rollout until capacity is adjusted")
        );
        assert_eq!(summary["reasons"], json!(["quic_resource_high"]));
    }

    #[test]
    fn native_core_metrics_summary_holds_widen_on_abuse_backoff_pressure() {
        let metrics = json!({
            "user_delta": {
                "kelinode_user_delta_native_apply_success_total": 12
            },
            "keli_core_rs": {
                "keli_core_user_delta_incremental_total": 12,
                "keli_core_tls_handshake_failure_total": 9,
                "keli_core_tls_handshake_backoff_reject_total": 2,
                "keli_core_tls_handshake_backoff_active_ips": 3,
                "keli_core_tls_handshake_backoff_blocked_ips": 1,
                "keli_core_tcp_auth_failure_total": 7,
                "keli_core_tcp_auth_backoff_reject_total": 1,
                "keli_core_tcp_auth_backoff_active_ips": 2,
                "keli_core_tcp_auth_backoff_blocked_ips": 1
            }
        });

        let summary = metrics_value(metrics)["native_core_gray_health"].clone();

        assert_eq!(summary["mode"], json!("native_delta"));
        assert_eq!(summary["gate"], json!("hold_monitor"));
        assert_eq!(summary["can_widen"], json!(false));
        assert_eq!(summary["rollback_recommended"], json!(false));
        assert_eq!(
            summary["warning"],
            json!(
                "client abuse backoff observed; monitor CPU and auth failure rate before widening"
            )
        );
        assert_eq!(summary["tls_handshake_failure_total"], json!(9));
        assert_eq!(summary["tls_handshake_backoff_reject_total"], json!(2));
        assert_eq!(summary["tls_handshake_backoff_active_ips"], json!(3));
        assert_eq!(summary["tls_handshake_backoff_blocked_ips"], json!(1));
        assert_eq!(summary["tcp_auth_failure_total"], json!(7));
        assert_eq!(summary["tcp_auth_backoff_reject_total"], json!(1));
        assert_eq!(summary["tcp_auth_backoff_active_ips"], json!(2));
        assert_eq!(summary["tcp_auth_backoff_blocked_ips"], json!(1));
        assert_eq!(
            summary["reasons"],
            json!(["tls_handshake_backoff", "tcp_auth_backoff"])
        );
        let serialized = summary.to_string();
        assert!(!serialized.contains("KELI_CORE_CONTROL_TOKEN"));
        assert!(!serialized.contains("203.0.113."));
    }

    #[test]
    fn native_core_metrics_summary_holds_widen_on_dns_guard_pressure() {
        let metrics = json!({
            "user_delta": {
                "kelinode_user_delta_native_apply_success_total": 12
            },
            "keli_core_rs": {
                "keli_core_user_delta_incremental_total": 12,
                "keli_core_dns": {
                    "keli_core_dns_resolve_total": 30,
                    "keli_core_dns_system_query_total": 4,
                    "keli_core_dns_configured_query_total": 20,
                    "keli_core_dns_positive_cache_hit_total": 5,
                    "keli_core_dns_negative_cache_hit_total": 1,
                    "keli_core_dns_resolve_error_total": 2,
                    "keli_core_dns_private_ip_filter_total": 3,
                    "keli_core_dns_private_ip_block_total": 1
                }
            }
        });

        let summary = metrics_value(metrics)["native_core_gray_health"].clone();

        assert_eq!(summary["mode"], json!("native_delta"));
        assert_eq!(summary["gate"], json!("hold_monitor"));
        assert_eq!(summary["can_widen"], json!(false));
        assert_eq!(summary["rollback_recommended"], json!(false));
        assert_eq!(
            summary["warning"],
            json!(
                "DNS guard or resolve errors observed; verify route rules and upstream DNS before widening"
            )
        );
        assert_eq!(summary["dns_resolve_total"], json!(30));
        assert_eq!(summary["dns_system_query_total"], json!(4));
        assert_eq!(summary["dns_configured_query_total"], json!(20));
        assert_eq!(summary["dns_positive_cache_hit_total"], json!(5));
        assert_eq!(summary["dns_negative_cache_hit_total"], json!(1));
        assert_eq!(summary["dns_resolve_error_total"], json!(2));
        assert_eq!(summary["dns_private_ip_filter_total"], json!(3));
        assert_eq!(summary["dns_private_ip_block_total"], json!(1));
        assert_eq!(
            summary["reasons"],
            json!(["dns_resolve_error", "dns_private_ip_block"])
        );
        let serialized = summary.to_string();
        assert!(!serialized.contains("KELI_CORE_CONTROL_TOKEN"));
        assert!(!serialized.contains("api.rebind.example"));
    }

    #[test]
    fn native_core_metrics_summary_holds_widen_on_connection_errors_without_dynamic_labels() {
        let metrics = json!({
            "user_delta": {
                "kelinode_user_delta_native_apply_success_total": 12
            },
            "keli_core_rs": {
                "keli_core_user_delta_incremental_total": 12,
                "keli_core_connection_error_total": {
                    "hysteria2.connection.timeout": 3,
                    "hysteria2.tcp_relay.timeout": 2,
                    "vless.tcp.upstream_timeout": 4,
                    "vless.tcp.auth_failed": 1
                }
            }
        });

        let summary = metrics_value(metrics)["native_core_gray_health"].clone();

        assert_eq!(summary["mode"], json!("native_delta"));
        assert_eq!(summary["gate"], json!("hold_monitor"));
        assert_eq!(summary["can_widen"], json!(false));
        assert_eq!(summary["rollback_recommended"], json!(false));
        assert_eq!(
            summary["warning"],
            json!("native core connection errors observed; inspect HY2/VLESS counters before widening")
        );
        assert_eq!(summary["connection_error_total"], json!(10));
        assert_eq!(summary["hy2_connection_timeout_total"], json!(3));
        assert_eq!(summary["hy2_tcp_relay_timeout_total"], json!(2));
        assert_eq!(summary["vless_tcp_upstream_timeout_total"], json!(4));
        assert_eq!(summary["vless_tcp_auth_failed_total"], json!(1));
        assert_eq!(
            summary["reasons"],
            json!(["hy2_timeout", "vless_upstream_error"])
        );
        let serialized = summary.to_string();
        assert!(!serialized.contains("KELI_CORE_CONTROL_TOKEN"));
        assert!(!serialized.contains("11111111-1111-1111-1111-111111111111"));
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
