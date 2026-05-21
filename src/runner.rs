use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::NodeConfig;
use crate::control::{
    report_runtime_apply_result_to_panels, run_runtime_tick, runtime_loop_signal,
    RuntimeControlOptions, RuntimeLoopSignal, RuntimeTickOptions,
};
use crate::core::{parse_keli_core_rs_port_range, CorePlan};
use crate::core_control::KELI_CORE_APPLY_CONTROL_TIMEOUT;
use crate::health::ResourceSnapshot;
use crate::logging;
use crate::panel::client::{PanelClient, PanelClientOptions};
use crate::panel::types::{UserDeltaBody, UserInfo};
use crate::port_forward::PortForwardExecutor;
use crate::process::{core_process_spec, keli_core_rs_control_client, ProcessSupervisor};
use crate::realtime::{
    build_realtime_receipt, realtime_runtime_task, RealtimeMessage, RealtimeOptions,
    RealtimeRuntimeTask,
};
use crate::realtime_client::{connect_realtime_transport, RealtimeTransport};
use crate::report::{report_keli_core_activity_to_panel_with_user_lookup, KeliCoreUserIdLookup};
use crate::runtime::{
    node_config_for_info as runtime_node_config_for_info, rebuild_runtime_plan_with_users,
    RuntimeBootstrapPlan,
};
use crate::subscription_proxy::SubscriptionProxyRuntimeManager;
use crate::system::{ResourceSampler, SystemPublicIpProbe};
use crate::user::{
    apply_full_user_list, apply_user_delta_body, load_user_sync_state, save_user_sync_state,
    user_delta_body_diff, user_sync_state_path, UserListDiff, UserSyncState,
};
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeLoopOptions {
    pub control: RuntimeControlOptions,
    pub max_ticks: Option<usize>,
    pub tick_interval: Duration,
    pub user_refresh_interval: usize,
    pub panel_report_interval: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeLoopExit {
    pub ticks: usize,
    pub reason: RuntimeLoopExitReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeLoopExitReason {
    MaxTicks,
    Shutdown,
    Signal(RuntimeLoopSignal),
}

#[derive(Debug)]
pub struct RuntimeLoopEvent {
    pub kind: RuntimeLoopEventKind,
    reply: Option<tokio::sync::oneshot::Sender<Result<RuntimeLoopEventReply, String>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeLoopEventReply {
    pub status: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeLoopEventKind {
    Reload,
    RefreshUsers,
}

impl RuntimeLoopEvent {
    pub fn reload() -> Self {
        Self {
            kind: RuntimeLoopEventKind::Reload,
            reply: None,
        }
    }

    pub fn refresh_users() -> Self {
        Self {
            kind: RuntimeLoopEventKind::RefreshUsers,
            reply: None,
        }
    }

    fn with_reply(
        kind: RuntimeLoopEventKind,
        reply: tokio::sync::oneshot::Sender<Result<RuntimeLoopEventReply, String>>,
    ) -> Self {
        Self {
            kind,
            reply: Some(reply),
        }
    }
}

pub struct RealtimeRuntimeWorkers {
    _sender: tokio::sync::mpsc::UnboundedSender<RuntimeLoopEvent>,
    events: tokio::sync::mpsc::UnboundedReceiver<RuntimeLoopEvent>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl RealtimeRuntimeWorkers {
    pub fn events(&mut self) -> &mut tokio::sync::mpsc::UnboundedReceiver<RuntimeLoopEvent> {
        &mut self.events
    }

    pub fn abort(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
        self.handles.clear();
    }

    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

impl RuntimeLoopEventReply {
    fn queued(message: impl Into<String>) -> Self {
        Self {
            status: "queued".to_string(),
            message: message.into(),
        }
    }

    fn applied(message: impl Into<String>) -> Self {
        Self {
            status: "applied".to_string(),
            message: message.into(),
        }
    }
}

impl Drop for RealtimeRuntimeWorkers {
    fn drop(&mut self) {
        self.abort();
    }
}

pub trait RuntimeLoopCallbacks {
    fn refresh_users(&mut self) -> Result<BTreeMap<String, Vec<UserInfo>>, String>;
    fn run_tick(&mut self, options: RuntimeTickOptions) -> Result<RuntimeLoopSignal, String>;

    fn sleep(&mut self, duration: Duration) -> Result<(), String> {
        std::thread::sleep(duration);
        Ok(())
    }
}

pub type RuntimeLoopFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub trait AsyncRuntimeLoopCallbacks {
    fn refresh_users<'a>(
        &'a mut self,
    ) -> RuntimeLoopFuture<'a, Result<BTreeMap<String, Vec<UserInfo>>, String>>;

    fn run_tick<'a>(
        &'a mut self,
        options: RuntimeTickOptions,
    ) -> RuntimeLoopFuture<'a, Result<RuntimeLoopSignal, String>>;

    fn sleep<'a>(&'a mut self, duration: Duration) -> RuntimeLoopFuture<'a, Result<(), String>> {
        Box::pin(async move {
            tokio::time::sleep(duration).await;
            Ok(())
        })
    }
}

pub struct PanelRuntimeLoop<'a, P, F> {
    pub plan: RuntimeBootstrapPlan,
    pub process_supervisor: &'a mut P,
    pub port_forward_executor: &'a mut F,
    pub panel_clients: Vec<PanelClient>,
    pub version: String,
    pub refresh_health: bool,
    pub public_ip_probe: bool,
    pub upgrade_status: Option<Value>,
    pub resource_sampler: ResourceSampler,
    pub subscription_proxy_manager: Option<SubscriptionProxyRuntimeManager>,
    user_id_lookup: KeliCoreUserIdLookup,
    user_sync: BTreeMap<String, RuntimeUserSyncEntry>,
    user_delta_metrics: RuntimeUserDeltaMetrics,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RuntimeUserSyncEntry {
    state: UserSyncState,
    delta_supported: bool,
    path: String,
    last_change: Option<RuntimeUserDeltaChange>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RuntimeUserDeltaChange {
    full: bool,
    base_revision: i64,
    revision: i64,
    diff: UserListDiff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeUserDeltaApplyOutcome {
    Applied,
    Rebuild,
    Deferred,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RuntimeUserDeltaMetrics {
    kelinode_user_delta_full_snapshot_fallback_total: u64,
    kelinode_user_delta_native_apply_success_total: u64,
    kelinode_user_delta_native_apply_failed_total: u64,
    kelinode_user_delta_skipped_port_range_total: u64,
    kelinode_user_delta_full_rebuild_total: u64,
}

impl RuntimeUserDeltaMetrics {
    fn record_success(&mut self) {
        self.kelinode_user_delta_native_apply_success_total = self
            .kelinode_user_delta_native_apply_success_total
            .saturating_add(1);
    }

    fn record_failed(&mut self) {
        self.kelinode_user_delta_native_apply_failed_total = self
            .kelinode_user_delta_native_apply_failed_total
            .saturating_add(1);
    }

    fn record_full_snapshot_fallback(&mut self) {
        self.kelinode_user_delta_full_snapshot_fallback_total = self
            .kelinode_user_delta_full_snapshot_fallback_total
            .saturating_add(1);
    }

    fn record_full_rebuild(&mut self) {
        self.kelinode_user_delta_full_rebuild_total = self
            .kelinode_user_delta_full_rebuild_total
            .saturating_add(1);
    }

    fn status_value(&self) -> Value {
        json!({
            "kelinode_user_delta_full_snapshot_fallback_total": self.kelinode_user_delta_full_snapshot_fallback_total,
            "kelinode_user_delta_native_apply_success_total": self.kelinode_user_delta_native_apply_success_total,
            "kelinode_user_delta_native_apply_failed_total": self.kelinode_user_delta_native_apply_failed_total,
            "kelinode_user_delta_skipped_port_range_total": self.kelinode_user_delta_skipped_port_range_total,
            "kelinode_user_delta_full_rebuild_total": self.kelinode_user_delta_full_rebuild_total
        })
    }
}

impl<'a, P, F> PanelRuntimeLoop<'a, P, F>
where
    P: ProcessSupervisor,
    F: PortForwardExecutor,
{
    pub fn new(
        plan: RuntimeBootstrapPlan,
        process_supervisor: &'a mut P,
        port_forward_executor: &'a mut F,
        panel_client: Option<PanelClient>,
    ) -> Self {
        let user_id_lookup = runtime_user_id_lookup_from_plan(&plan);
        Self {
            plan,
            process_supervisor,
            port_forward_executor,
            panel_clients: panel_client.into_iter().collect(),
            version: String::new(),
            refresh_health: false,
            public_ip_probe: false,
            upgrade_status: None,
            resource_sampler: ResourceSampler::default(),
            subscription_proxy_manager: None,
            user_id_lookup,
            user_sync: BTreeMap::new(),
            user_delta_metrics: RuntimeUserDeltaMetrics::default(),
        }
    }

    pub fn with_health_refresh(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self.refresh_health = true;
        self
    }

    pub fn with_public_ip_probe(mut self, enabled: bool) -> Self {
        self.public_ip_probe = enabled;
        self
    }

    pub fn with_upgrade_status(mut self, status: Option<Value>) -> Self {
        self.upgrade_status = status;
        self
    }

    pub fn with_panel_clients(mut self, clients: Vec<PanelClient>) -> Self {
        self.panel_clients = clients;
        self
    }

    pub fn with_subscription_proxy_manager(
        mut self,
        manager: SubscriptionProxyRuntimeManager,
    ) -> Self {
        self.subscription_proxy_manager = Some(manager);
        self
    }
}

impl<P, F> AsyncRuntimeLoopCallbacks for PanelRuntimeLoop<'_, P, F>
where
    P: ProcessSupervisor,
    F: PortForwardExecutor,
{
    fn refresh_users<'a>(
        &'a mut self,
    ) -> RuntimeLoopFuture<'a, Result<BTreeMap<String, Vec<UserInfo>>, String>> {
        Box::pin(async move {
            load_users_by_node_tag_from_panel_with_state(&self.plan, &mut self.user_sync).await
        })
    }

    fn run_tick<'a>(
        &'a mut self,
        mut options: RuntimeTickOptions,
    ) -> RuntimeLoopFuture<'a, Result<RuntimeLoopSignal, String>> {
        Box::pin(async move {
            let mut startup_full_snapshot_tags = Vec::new();
            if !options.users_by_node_tag.is_empty() {
                let user_change_tags = options
                    .users_by_node_tag
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>();
                let native_core_running = keli_core_rs_process_is_running(
                    &self.plan,
                    &mut *self.process_supervisor,
                    options.control.core_command.as_deref(),
                )?;
                let user_delta_outcome = if native_core_running.unwrap_or(true) {
                    try_apply_keli_core_rs_user_deltas(
                        &self.plan,
                        &self.user_sync,
                        &options.users_by_node_tag,
                        &mut self.user_delta_metrics,
                    )
                } else {
                    RuntimeUserDeltaApplyOutcome::Rebuild
                };
                match user_delta_outcome {
                    RuntimeUserDeltaApplyOutcome::Applied => {
                        logging::info(
                            "core",
                            format!(
                                "user delta applied natively tags={}",
                                user_change_tags.len()
                            ),
                        );
                        options.control.keli_core_rs_user_delta_applied = true;
                        sync_runtime_user_id_lookup_from_state(
                            &mut self.user_id_lookup,
                            &self.user_sync,
                            &user_change_tags,
                        );
                        for node_tag in &user_change_tags {
                            if let Some(entry) = self.user_sync.get_mut(node_tag) {
                                entry.last_change = None;
                            }
                        }
                        if !options.report_to_panel {
                            return Ok(RuntimeLoopSignal::Continue);
                        }
                    }
                    RuntimeUserDeltaApplyOutcome::Deferred => {
                        logging::warn(
                            "core",
                            format!(
                                "user delta deferred; keeping runtime unchanged tags={}",
                                user_change_tags.len()
                            ),
                        );
                        if !options.report_to_panel {
                            options.users_by_node_tag.clear();
                            return Ok(RuntimeLoopSignal::Continue);
                        }
                    }
                    RuntimeUserDeltaApplyOutcome::Rebuild => {
                        if native_core_running == Some(false) {
                            logging::info(
                                "core",
                                format!(
                                    "user delta uses full runtime rebuild because native core is not running tags={}",
                                    user_change_tags.len()
                                ),
                            );
                        } else {
                            logging::warn(
                                "core",
                                format!(
                                    "user delta fell back to full runtime rebuild tags={}",
                                    user_change_tags.len()
                                ),
                            );
                        }
                        startup_full_snapshot_tags = user_change_tags.clone();
                        self.user_delta_metrics.record_full_rebuild();
                        let users_for_rebuild = user_sync_users_for_tags(
                            &self.user_sync,
                            &user_change_tags,
                            &options.users_by_node_tag,
                        );
                        self.plan =
                            rebuild_runtime_plan_with_users(&self.plan, &users_for_rebuild)?;
                        self.user_id_lookup = runtime_user_id_lookup_from_plan(&self.plan);
                    }
                }
                options.users_by_node_tag.clear();
            }
            if self.refresh_health {
                let resources = if self.public_ip_probe {
                    tokio::task::block_in_place(|| {
                        let mut probe = SystemPublicIpProbe::default();
                        self.resource_sampler
                            .sample_with_public_ip_probe(&mut probe)
                    })
                } else {
                    self.resource_sampler.sample()
                };
                refresh_runtime_health(
                    &mut options,
                    &self.version,
                    self.upgrade_status.clone(),
                    resources,
                );
            }
            if let Some(manager) = &self.subscription_proxy_manager {
                refresh_subscription_proxy_health(&mut options, manager);
            }
            let mut metrics = json!({
                "user_delta": self.user_delta_metrics.status_value()
            });
            match keli_core_rs_metrics_snapshot(&self.plan) {
                Ok(Some(core_metrics)) => {
                    metrics["keli_core_rs"] = core_metrics;
                }
                Ok(None) => {}
                Err(error) => {
                    metrics["keli_core_rs_error"] = json!({
                        "message": error
                    });
                }
            }
            options.control.health.metrics = Some(metrics);
            if options.control.start_core
                && ensure_keli_core_rs_restart_uses_latest_users(
                    &mut self.plan,
                    &self.user_sync,
                    &mut *self.process_supervisor,
                    options.control.core_command.as_deref(),
                )?
            {
                self.user_id_lookup = runtime_user_id_lookup_from_plan(&self.plan);
            }
            let report_to_panel = options.report_to_panel;
            if report_to_panel && self.panel_clients.is_empty() {
                return Err("runtime tick requested panel report without panel client".to_string());
            }
            options.report_to_panel = false;
            let result = run_runtime_tick(
                &self.plan,
                &mut *self.process_supervisor,
                &mut *self.port_forward_executor,
                None,
                options,
            )
            .await?;
            if !startup_full_snapshot_tags.is_empty() {
                try_establish_keli_core_rs_revision_baseline(
                    &self.plan,
                    &self.user_sync,
                    &startup_full_snapshot_tags,
                );
            }
            if report_to_panel {
                let action = nonfatal_panel_status_report(
                    report_runtime_apply_result_to_panels(&self.panel_clients, &result.apply).await,
                );
                nonfatal_keli_core_activity_report(
                    report_keli_core_activity_to_panel_with_user_lookup(
                        &self.plan,
                        &self.user_id_lookup,
                    )
                    .await,
                );
                return Ok(runtime_loop_signal(&action));
            }
            Ok(result.signal)
        })
    }
}

fn nonfatal_panel_status_report(
    result: Result<crate::control::RuntimePanelAction, String>,
) -> crate::control::RuntimePanelAction {
    match result {
        Ok(action) => action,
        Err(error) => {
            logging::warn(
                "panel",
                format!("machine status report failed; keeping runtime alive error={error}"),
            );
            crate::control::RuntimePanelAction::default()
        }
    }
}

fn nonfatal_keli_core_activity_report(
    result: Result<crate::report::NodeActivityBatchReport, String>,
) {
    if let Err(error) = result {
        logging::warn(
            "panel",
            format!("traffic report failed; keeping runtime alive error={error}"),
        );
    }
}

fn try_apply_keli_core_rs_user_deltas(
    plan: &RuntimeBootstrapPlan,
    sync_state: &BTreeMap<String, RuntimeUserSyncEntry>,
    users_by_node_tag: &BTreeMap<String, Vec<UserInfo>>,
    metrics: &mut RuntimeUserDeltaMetrics,
) -> RuntimeUserDeltaApplyOutcome {
    let Some(core_plan) = plan.core_plan.as_ref() else {
        return RuntimeUserDeltaApplyOutcome::Rebuild;
    };
    if users_by_node_tag.keys().any(|node_tag| {
        sync_state
            .get(node_tag)
            .and_then(|entry| entry.last_change.as_ref())
            .map(|change| change.full)
            .unwrap_or(true)
    }) {
        return RuntimeUserDeltaApplyOutcome::Rebuild;
    }

    let client = match keli_core_rs_control_client(&core_plan.config_path) {
        Ok(client) => client.with_timeout(KELI_CORE_APPLY_CONTROL_TIMEOUT),
        Err(_) => return RuntimeUserDeltaApplyOutcome::Rebuild,
    };
    for node_tag in users_by_node_tag.keys() {
        let Some(entry) = sync_state.get(node_tag) else {
            return RuntimeUserDeltaApplyOutcome::Rebuild;
        };
        let Some(change) = entry.last_change.as_ref() else {
            return RuntimeUserDeltaApplyOutcome::Rebuild;
        };
        let target_tags = match keli_core_user_delta_target_tags(core_plan, node_tag) {
            Ok(target_tags) => target_tags,
            Err(error) => {
                logging::warn(
                    "core",
                    format!(
                        "user delta target resolution failed node_tag={node_tag} error={error}"
                    ),
                );
                return RuntimeUserDeltaApplyOutcome::Rebuild;
            }
        };
        if target_tags.is_empty() {
            if plan.resolved.machine.continue_on_error {
                logging::warn(
                    "core",
                    format!("user delta deferred for missing inbound node_tag={node_tag}"),
                );
                return RuntimeUserDeltaApplyOutcome::Deferred;
            }
            return RuntimeUserDeltaApplyOutcome::Rebuild;
        }
        let delta = keli_core_user_delta_payload(node_tag, change);
        for target_tag in target_tags {
            match client.apply_user_delta(target_tag.clone(), delta.clone()) {
                Ok(_) => metrics.record_success(),
                Err(error) => {
                    metrics.record_failed();
                    if plan.resolved.machine.continue_on_error
                        && keli_core_user_delta_missing_inbound(&error.message)
                    {
                        logging::warn(
                            "core",
                            format!(
                                "user delta deferred for missing inbound node_tag={node_tag} target_tag={target_tag} error={}",
                                error.message
                            ),
                        );
                        return RuntimeUserDeltaApplyOutcome::Deferred;
                    }
                    if !keli_core_user_delta_requires_full_snapshot(&error.message) {
                        logging::warn(
                            "core",
                            format!(
                                "user delta apply failed node_tag={node_tag} target_tag={target_tag} error={}",
                                error.message
                            ),
                        );
                        return RuntimeUserDeltaApplyOutcome::Rebuild;
                    }
                    metrics.record_full_snapshot_fallback();
                    logging::warn(
                        "core",
                        format!(
                            "user delta requires full snapshot node_tag={node_tag} target_tag={target_tag} error={}",
                            error.message
                        ),
                    );
                    let full_delta = keli_core_user_full_snapshot_payload(node_tag, entry);
                    match client.apply_user_delta(target_tag.clone(), full_delta) {
                        Ok(_) => metrics.record_success(),
                        Err(error) => {
                            metrics.record_failed();
                            if plan.resolved.machine.continue_on_error
                                && keli_core_user_delta_missing_inbound(&error.message)
                            {
                                logging::warn(
                                    "core",
                                    format!(
                                        "full snapshot user delta deferred for missing inbound node_tag={node_tag} target_tag={target_tag} error={}",
                                        error.message
                                    ),
                                );
                                return RuntimeUserDeltaApplyOutcome::Deferred;
                            }
                            logging::error(
                                "core",
                                format!(
                                    "full snapshot user delta failed node_tag={node_tag} target_tag={target_tag}"
                                ),
                            );
                            return RuntimeUserDeltaApplyOutcome::Rebuild;
                        }
                    }
                }
            }
        }
    }
    RuntimeUserDeltaApplyOutcome::Applied
}

fn keli_core_user_delta_target_tags(
    core_plan: &CorePlan,
    node_tag: &str,
) -> Result<Vec<String>, String> {
    let mut targets = Vec::new();
    let mut expanded_targets = Vec::new();
    let expanded_prefix = format!("{node_tag}|port:");
    for inbound in &core_plan.inbounds {
        if inbound.tag == node_tag {
            if inbound.protocol == "mieru" && !inbound.port_range.trim().is_empty() {
                for port in parse_keli_core_rs_port_range(&inbound.port_range)? {
                    targets.push(format!("{node_tag}|port:{port}"));
                }
            } else {
                targets.push(node_tag.to_string());
            }
        } else if inbound.tag.starts_with(&expanded_prefix) {
            expanded_targets.push(inbound.tag.clone());
        }
    }
    if targets.is_empty() {
        Ok(expanded_targets)
    } else {
        Ok(targets)
    }
}

fn try_establish_keli_core_rs_revision_baseline(
    plan: &RuntimeBootstrapPlan,
    sync_state: &BTreeMap<String, RuntimeUserSyncEntry>,
    node_tags: &[String],
) -> bool {
    let Some(core_plan) = plan.core_plan.as_ref() else {
        return false;
    };
    let client = match keli_core_rs_control_client(&core_plan.config_path) {
        Ok(client) => client.with_timeout(KELI_CORE_APPLY_CONTROL_TIMEOUT),
        Err(error) => {
            logging::warn(
                "core",
                format!("revision baseline skipped: {}", error.message),
            );
            return false;
        }
    };
    let mut applied = 0usize;
    for node_tag in node_tags {
        let Some(entry) = sync_state.get(node_tag) else {
            continue;
        };
        let target_tags = match keli_core_user_delta_target_tags(core_plan, node_tag) {
            Ok(target_tags) => target_tags,
            Err(error) => {
                logging::warn(
                    "core",
                    format!(
                        "revision baseline target resolution failed node_tag={node_tag} error={error}"
                    ),
                );
                return false;
            }
        };
        if target_tags.is_empty() {
            logging::warn(
                "core",
                format!("revision baseline skipped missing inbound node_tag={node_tag}"),
            );
            continue;
        }
        let delta = keli_core_user_full_snapshot_payload(node_tag, entry);
        for target_tag in target_tags {
            match client.apply_user_delta(target_tag.clone(), delta.clone()) {
                Ok(_) => applied += 1,
                Err(error) => {
                    logging::warn(
                        "core",
                        format!(
                            "revision baseline full snapshot failed node_tag={node_tag} target_tag={target_tag} error={}",
                            error.message
                        ),
                    );
                    return false;
                }
            }
        }
    }
    if applied > 0 {
        logging::info(
            "core",
            format!("revision baseline established full_snapshots={applied}"),
        );
    }
    applied > 0
}

fn keli_core_rs_process_is_running<P>(
    plan: &RuntimeBootstrapPlan,
    process_supervisor: &mut P,
    core_command: Option<&str>,
) -> Result<Option<bool>, String>
where
    P: ProcessSupervisor,
{
    let Some(core_plan) = plan.core_plan.as_ref() else {
        return Ok(None);
    };
    let spec = core_process_spec(core_plan, core_command).map_err(|err| err.message)?;
    Ok(Some(
        process_supervisor
            .status(&spec.name)
            .map_err(|err| err.message)?
            .is_running(),
    ))
}

fn keli_core_user_delta_requires_full_snapshot(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("revision mismatch") || error.contains("full snapshot required")
}

fn keli_core_user_delta_missing_inbound(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("unknown inbound") || error.contains("inbound not found")
}

fn keli_core_user_full_snapshot_payload(node_tag: &str, entry: &RuntimeUserSyncEntry) -> Value {
    json!({
        "full": entry
            .state
            .users
            .iter()
            .map(|user| keli_core_user_delta_user(node_tag, user))
            .collect::<Vec<_>>(),
        "revision": entry.state.revision.to_string()
    })
}

fn keli_core_user_delta_payload(node_tag: &str, change: &RuntimeUserDeltaChange) -> Value {
    json!({
        "added": change
            .diff
            .added
            .iter()
            .map(|user| keli_core_user_delta_user(node_tag, user))
            .collect::<Vec<_>>(),
        "updated": change
            .diff
            .updated
            .iter()
            .map(|user| keli_core_user_delta_user(node_tag, user))
            .collect::<Vec<_>>(),
        "deleted": change
            .diff
            .deleted
            .iter()
            .map(|user| user.uuid.clone())
            .collect::<Vec<_>>(),
        "base_revision": change.base_revision.to_string(),
        "revision": change.revision.to_string()
    })
}

fn keli_core_user_delta_user(_node_tag: &str, user: &UserInfo) -> Value {
    json!({
        "id": user.id,
        "uuid": user.uuid,
        "password": null,
        "email": null,
        "speed_limit": user.speed_limit,
        "device_limit": user.device_limit
    })
}

fn ensure_keli_core_rs_restart_uses_latest_users<P>(
    plan: &mut RuntimeBootstrapPlan,
    sync_state: &BTreeMap<String, RuntimeUserSyncEntry>,
    process_supervisor: &mut P,
    core_command: Option<&str>,
) -> Result<bool, String>
where
    P: ProcessSupervisor,
{
    let Some(core_plan) = plan.core_plan.as_ref() else {
        return Ok(false);
    };
    let spec = core_process_spec(core_plan, core_command).map_err(|err| err.message)?;
    if process_supervisor
        .status(&spec.name)
        .map_err(|err| err.message)?
        .is_running()
    {
        return Ok(false);
    }
    let users_by_node_tag = latest_users_by_node_tag_for_core_plan(plan, sync_state);
    if users_by_node_tag.is_empty() {
        return Ok(false);
    }
    *plan = rebuild_runtime_plan_with_users(plan, &users_by_node_tag)?;
    Ok(true)
}

fn latest_users_by_node_tag_for_core_plan(
    plan: &RuntimeBootstrapPlan,
    sync_state: &BTreeMap<String, RuntimeUserSyncEntry>,
) -> BTreeMap<String, Vec<UserInfo>> {
    let Some(core_plan) = plan.core_plan.as_ref() else {
        return BTreeMap::new();
    };
    core_plan
        .inbounds
        .iter()
        .filter_map(|inbound| {
            let users = sync_state
                .get(&inbound.tag)
                .filter(|entry| !entry.state.users.is_empty())
                .map(|entry| entry.state.users.clone())
                .unwrap_or_else(|| {
                    inbound
                        .users
                        .iter()
                        .map(|user| UserInfo {
                            id: user.id,
                            uuid: user.uuid.clone(),
                            speed_limit: user.speed_limit,
                            device_limit: user.device_limit,
                        })
                        .collect()
                });
            if users.is_empty() {
                None
            } else {
                Some((inbound.tag.clone(), users))
            }
        })
        .collect()
}

fn runtime_user_id_lookup_from_plan(plan: &RuntimeBootstrapPlan) -> KeliCoreUserIdLookup {
    plan.core_plan
        .iter()
        .flat_map(|core_plan| core_plan.inbounds.iter())
        .map(|inbound| {
            (
                inbound.tag.clone(),
                inbound
                    .users
                    .iter()
                    .map(|user| (user.uuid.clone(), user.id))
                    .collect(),
            )
        })
        .collect()
}

fn sync_runtime_user_id_lookup_from_state(
    lookup: &mut KeliCoreUserIdLookup,
    sync_state: &BTreeMap<String, RuntimeUserSyncEntry>,
    node_tags: &[String],
) {
    for node_tag in node_tags {
        let Some(entry) = sync_state.get(node_tag) else {
            continue;
        };
        lookup.insert(
            node_tag.clone(),
            entry
                .state
                .users
                .iter()
                .map(|user| (user.uuid.clone(), user.id))
                .collect(),
        );
    }
}

fn keli_core_rs_metrics_snapshot(plan: &RuntimeBootstrapPlan) -> Result<Option<Value>, String> {
    let Some(core_plan) = plan.core_plan.as_ref() else {
        return Ok(None);
    };
    let client = keli_core_rs_control_client(&core_plan.config_path)
        .map_err(|error| format!("create keli-core-rs metrics client: {}", error.message))?;
    client
        .metrics()
        .map(Some)
        .map_err(|error| format!("fetch keli-core-rs metrics: {}", error.message))
}

fn refresh_runtime_health(
    options: &mut RuntimeTickOptions,
    version: &str,
    upgrade_status: Option<Value>,
    resources: ResourceSnapshot,
) {
    options.control.health.version = version.to_string();
    options.control.health.resources = resources;
    options.control.health.upgrade = upgrade_status;
}

fn refresh_subscription_proxy_health(
    options: &mut RuntimeTickOptions,
    manager: &SubscriptionProxyRuntimeManager,
) {
    options.control.health.subscription_proxy = Some(manager.status());
}

impl Default for RuntimeLoopOptions {
    fn default() -> Self {
        Self {
            control: RuntimeControlOptions::default(),
            max_ticks: None,
            tick_interval: Duration::from_secs(60),
            user_refresh_interval: 1,
            panel_report_interval: 1,
        }
    }
}

pub fn start_realtime_runtime_workers(options: Vec<RealtimeOptions>) -> RealtimeRuntimeWorkers {
    let (sender, events) = tokio::sync::mpsc::unbounded_channel();
    let handles = options
        .into_iter()
        .map(|option| {
            let sender = sender.clone();
            tokio::spawn(async move {
                run_realtime_runtime_worker(option, sender).await;
            })
        })
        .collect();

    RealtimeRuntimeWorkers {
        _sender: sender,
        events,
        handles,
    }
}

async fn run_realtime_runtime_worker(
    options: RealtimeOptions,
    sender: tokio::sync::mpsc::UnboundedSender<RuntimeLoopEvent>,
) {
    loop {
        if let Ok(mut transport) = connect_realtime_transport(&options).await {
            let _ = serve_realtime_runtime_transport(&options, &mut transport, &sender).await;
        }
        tokio::time::sleep(options.reconnect_delay).await;
    }
}

async fn serve_realtime_runtime_transport<T>(
    options: &RealtimeOptions,
    transport: &mut T,
    sender: &tokio::sync::mpsc::UnboundedSender<RuntimeLoopEvent>,
) -> Result<(), String>
where
    T: RealtimeTransport,
{
    transport
        .send(RealtimeMessage::ping(options, unix_now(), None))
        .await?;

    while let Some(message) = transport.recv().await? {
        let task = realtime_runtime_task(&message, unix_now());
        match task {
            RealtimeRuntimeTask::Pong(pong) => transport.send(pong).await?,
            task => {
                let Some((kind, topic, queued_message)) = runtime_loop_event_for_task(&task) else {
                    continue;
                };
                send_realtime_runtime_event(
                    transport,
                    sender,
                    kind,
                    topic,
                    &message,
                    queued_message,
                )
                .await?;
            }
        }
    }

    Ok(())
}

async fn send_realtime_runtime_event<T>(
    transport: &mut T,
    sender: &tokio::sync::mpsc::UnboundedSender<RuntimeLoopEvent>,
    kind: RuntimeLoopEventKind,
    topic: &str,
    source: &RealtimeMessage,
    queued_message: &str,
) -> Result<(), String>
where
    T: RealtimeTransport,
{
    let now = unix_now();
    transport
        .send(build_realtime_receipt(
            topic,
            source,
            "received",
            queued_message,
            now,
        ))
        .await?;

    let (reply, result) = tokio::sync::oneshot::channel();
    if sender
        .send(RuntimeLoopEvent::with_reply(kind, reply))
        .is_err()
    {
        transport
            .send(build_realtime_receipt(
                topic,
                source,
                "failed",
                "runtime event receiver closed",
                unix_now(),
            ))
            .await?;
        return Ok(());
    }

    let (status, message) = match result.await {
        Ok(Ok(reply)) => (reply.status, reply.message),
        Ok(Err(error)) => ("failed".to_string(), error),
        Err(_) => (
            "failed".to_string(),
            "runtime event reply dropped".to_string(),
        ),
    };
    transport
        .send(build_realtime_receipt(
            topic,
            source,
            &status,
            &message,
            unix_now(),
        ))
        .await
}

fn runtime_loop_event_for_task(
    task: &RealtimeRuntimeTask,
) -> Option<(RuntimeLoopEventKind, &'static str, &'static str)> {
    match task {
        RealtimeRuntimeTask::ConfigCheck | RealtimeRuntimeTask::ForceReload => {
            Some((RuntimeLoopEventKind::Reload, "config", "reload queued"))
        }
        RealtimeRuntimeTask::UserSync => Some((
            RuntimeLoopEventKind::RefreshUsers,
            "users",
            "user refresh queued",
        )),
        RealtimeRuntimeTask::Ignore
        | RealtimeRuntimeTask::Pong(_)
        | RealtimeRuntimeTask::Error(_)
        | RealtimeRuntimeTask::HelloAck => None,
    }
}

pub fn run_runtime_loop<C>(
    callbacks: &mut C,
    options: RuntimeLoopOptions,
) -> Result<RuntimeLoopExit, String>
where
    C: RuntimeLoopCallbacks,
{
    let mut ticks = 0usize;
    loop {
        if let Some(max_ticks) = options.max_ticks {
            if ticks >= max_ticks {
                return Ok(RuntimeLoopExit {
                    ticks,
                    reason: RuntimeLoopExitReason::MaxTicks,
                });
            }
        }

        ticks += 1;
        let users_by_node_tag = if should_run(ticks, options.user_refresh_interval) {
            callbacks.refresh_users()?
        } else {
            BTreeMap::new()
        };
        let signal = callbacks.run_tick(RuntimeTickOptions {
            control: options.control.clone(),
            report_to_panel: should_run(ticks, options.panel_report_interval),
            users_by_node_tag,
        })?;
        if signal != RuntimeLoopSignal::Continue {
            return Ok(RuntimeLoopExit {
                ticks,
                reason: RuntimeLoopExitReason::Signal(signal),
            });
        }
        if let Some(max_ticks) = options.max_ticks {
            if ticks >= max_ticks {
                return Ok(RuntimeLoopExit {
                    ticks,
                    reason: RuntimeLoopExitReason::MaxTicks,
                });
            }
        }

        if options.tick_interval > Duration::from_secs(0) {
            callbacks.sleep(options.tick_interval)?;
        }
    }
}

pub async fn run_runtime_loop_async<C>(
    callbacks: &mut C,
    options: RuntimeLoopOptions,
) -> Result<RuntimeLoopExit, String>
where
    C: AsyncRuntimeLoopCallbacks,
{
    let mut ticks = 0usize;
    loop {
        if let Some(max_ticks) = options.max_ticks {
            if ticks >= max_ticks {
                return Ok(RuntimeLoopExit {
                    ticks,
                    reason: RuntimeLoopExitReason::MaxTicks,
                });
            }
        }

        ticks += 1;
        let users_by_node_tag = if should_run(ticks, options.user_refresh_interval) {
            callbacks.refresh_users().await?
        } else {
            BTreeMap::new()
        };
        let signal = callbacks
            .run_tick(RuntimeTickOptions {
                control: options.control.clone(),
                report_to_panel: should_run(ticks, options.panel_report_interval),
                users_by_node_tag,
            })
            .await?;
        if signal != RuntimeLoopSignal::Continue {
            return Ok(RuntimeLoopExit {
                ticks,
                reason: RuntimeLoopExitReason::Signal(signal),
            });
        }
        if let Some(max_ticks) = options.max_ticks {
            if ticks >= max_ticks {
                return Ok(RuntimeLoopExit {
                    ticks,
                    reason: RuntimeLoopExitReason::MaxTicks,
                });
            }
        }

        if options.tick_interval > Duration::from_secs(0) {
            callbacks.sleep(options.tick_interval).await?;
        }
    }
}

pub async fn run_runtime_loop_async_with_events<C>(
    callbacks: &mut C,
    options: RuntimeLoopOptions,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<RuntimeLoopEvent>,
) -> Result<RuntimeLoopExit, String>
where
    C: AsyncRuntimeLoopCallbacks,
{
    let mut ticks = 0usize;
    loop {
        if let Some(max_ticks) = options.max_ticks {
            if ticks >= max_ticks {
                return Ok(RuntimeLoopExit {
                    ticks,
                    reason: RuntimeLoopExitReason::MaxTicks,
                });
            }
        }

        ticks += 1;
        let users_by_node_tag = if should_run(ticks, options.user_refresh_interval) {
            callbacks.refresh_users().await?
        } else {
            BTreeMap::new()
        };
        let signal = callbacks
            .run_tick(RuntimeTickOptions {
                control: options.control.clone(),
                report_to_panel: should_run(ticks, options.panel_report_interval),
                users_by_node_tag,
            })
            .await?;
        if signal != RuntimeLoopSignal::Continue {
            return Ok(RuntimeLoopExit {
                ticks,
                reason: RuntimeLoopExitReason::Signal(signal),
            });
        }
        if let Some(max_ticks) = options.max_ticks {
            if ticks >= max_ticks {
                return Ok(RuntimeLoopExit {
                    ticks,
                    reason: RuntimeLoopExitReason::MaxTicks,
                });
            }
        }

        if options.tick_interval > Duration::from_secs(0) {
            tokio::select! {
                _ = tokio::time::sleep(options.tick_interval) => {}
                event = events.recv() => {
                    if let Some(event) = event {
                        let signal = handle_runtime_loop_event(callbacks, &options, event).await?;
                        if signal != RuntimeLoopSignal::Continue {
                            return Ok(RuntimeLoopExit {
                                ticks,
                                reason: RuntimeLoopExitReason::Signal(signal),
                            });
                        }
                    }
                }
            }
        }
    }
}

async fn handle_runtime_loop_event<C>(
    callbacks: &mut C,
    options: &RuntimeLoopOptions,
    event: RuntimeLoopEvent,
) -> Result<RuntimeLoopSignal, String>
where
    C: AsyncRuntimeLoopCallbacks,
{
    let reply = event.reply;
    let result = match event.kind {
        RuntimeLoopEventKind::Reload => Ok((
            RuntimeLoopSignal::Reload,
            RuntimeLoopEventReply::queued("reload queued"),
        )),
        RuntimeLoopEventKind::RefreshUsers => match callbacks.refresh_users().await {
            Ok(users_by_node_tag) if users_by_node_tag.is_empty() => Ok((
                RuntimeLoopSignal::Continue,
                RuntimeLoopEventReply::applied("user refresh no changes"),
            )),
            Ok(users_by_node_tag) => {
                match callbacks
                    .run_tick(RuntimeTickOptions {
                        control: options.control.clone(),
                        report_to_panel: false,
                        users_by_node_tag,
                    })
                    .await
                {
                    Ok(signal) => Ok((
                        signal,
                        RuntimeLoopEventReply::applied("user refresh applied"),
                    )),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        },
    };

    if let Some(reply) = reply {
        let _ = reply.send(
            result
                .as_ref()
                .map(|(_, reply)| reply.clone())
                .map_err(|error| error.clone()),
        );
    }
    result.map(|(signal, _)| signal)
}

pub async fn load_users_by_node_tag_from_panel(
    plan: &RuntimeBootstrapPlan,
) -> Result<BTreeMap<String, Vec<UserInfo>>, String> {
    let mut state = BTreeMap::new();
    load_users_by_node_tag_from_panel_with_state(plan, &mut state).await
}

async fn load_users_by_node_tag_from_panel_with_state(
    plan: &RuntimeBootstrapPlan,
    sync_state: &mut BTreeMap<String, RuntimeUserSyncEntry>,
) -> Result<BTreeMap<String, Vec<UserInfo>>, String> {
    let mut users_by_tag = BTreeMap::new();
    for node in &plan.node_infos {
        let Some(config) = node_config_for_info(plan, node.id, &node.tag) else {
            continue;
        };
        let options = PanelClientOptions::from(config);
        let mut client = PanelClient::new(options).map_err(|err| err.to_string())?;
        let entry = sync_state
            .entry(node.tag.clone())
            .or_insert_with(|| load_runtime_user_sync_entry(config));
        let users = match load_users_for_node(config, entry, &mut client).await {
            Ok(users) => users,
            Err(error) if plan.resolved.machine.continue_on_error => {
                logging::warn(
                    "users",
                    format!(
                        "user refresh skipped api_host={} node_id={} node_tag={} error={}",
                        config.url.trim_end_matches('/'),
                        config.node_id,
                        node.tag,
                        error
                    ),
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        if entry.last_change.is_some() {
            users_by_tag.insert(node.tag.clone(), users);
        } else if runtime_plan_needs_cached_users(plan, &node.tag, entry) {
            users_by_tag.insert(node.tag.clone(), entry.state.users.clone());
        }
    }
    Ok(users_by_tag)
}

fn runtime_plan_needs_cached_users(
    plan: &RuntimeBootstrapPlan,
    node_tag: &str,
    entry: &RuntimeUserSyncEntry,
) -> bool {
    if entry.state.users.is_empty() {
        return false;
    }
    let Some(core_plan) = plan.core_plan.as_ref() else {
        return plan.node_infos.iter().any(|node| node.tag == node_tag);
    };
    match core_plan
        .inbounds
        .iter()
        .find(|inbound| inbound.tag == node_tag)
    {
        Some(inbound) => inbound.users.is_empty(),
        None => plan.node_infos.iter().any(|node| node.tag == node_tag),
    }
}

async fn load_users_for_node(
    config: &NodeConfig,
    entry: &mut RuntimeUserSyncEntry,
    client: &mut PanelClient,
) -> Result<Vec<UserInfo>, String> {
    if entry.delta_supported {
        let base_revision = entry.state.revision;
        match client.get_user_delta(entry.state.revision).await {
            Ok(delta) => {
                if user_delta_body_is_revision_only(&delta) && !entry.state.users.is_empty() {
                    entry.state.revision = delta.revision;
                    entry.last_change = None;
                    return Ok(Vec::new());
                }
                let diff = user_delta_body_diff(&entry.state, &delta);
                let change =
                    runtime_user_delta_change(delta.full, base_revision, delta.revision, diff);
                if change.is_none() {
                    entry.state.revision = delta.revision;
                    entry.last_change = None;
                    return Ok(Vec::new());
                }
                let result = apply_user_delta_body(&entry.state, &delta);
                entry.state = result.state;
                entry.last_change = change;
                save_runtime_user_sync_entry(entry);
                return Ok(entry.state.users.clone());
            }
            Err(err) if user_delta_not_supported(&err.to_string()) => {
                entry.delta_supported = false;
            }
            Err(err) => {
                return Err(format!(
                    "get user delta [{}-{}] error: {}",
                    config.url.trim_end_matches('/'),
                    config.node_id,
                    err
                ));
            }
        }
    }

    let users = client
        .get_user_list()
        .await
        .map_err(|err| {
            format!(
                "get user list [{}-{}] error: {}",
                config.url.trim_end_matches('/'),
                config.node_id,
                err
            )
        })?
        .unwrap_or_else(|| entry.state.users.clone());
    let result = apply_full_user_list(&entry.state, &users);
    let change = runtime_user_delta_change(
        true,
        entry.state.revision,
        entry.state.revision,
        result.diff.clone(),
    );
    entry.state = result.state;
    entry.last_change = change;
    if entry.last_change.is_none() {
        return Ok(Vec::new());
    }
    save_runtime_user_sync_entry(entry);
    Ok(entry.state.users.clone())
}

fn runtime_user_delta_change(
    full: bool,
    base_revision: i64,
    revision: i64,
    diff: UserListDiff,
) -> Option<RuntimeUserDeltaChange> {
    if user_list_diff_is_empty(&diff) {
        return None;
    }
    Some(RuntimeUserDeltaChange {
        full,
        base_revision,
        revision,
        diff,
    })
}

fn user_list_diff_is_empty(diff: &UserListDiff) -> bool {
    diff.deleted.is_empty() && diff.added.is_empty() && diff.updated.is_empty()
}

fn user_delta_body_is_revision_only(delta: &UserDeltaBody) -> bool {
    !delta.full && delta.deleted.is_empty() && delta.upsert.is_empty()
}

fn user_sync_users_for_tags(
    sync_state: &BTreeMap<String, RuntimeUserSyncEntry>,
    tags: &[String],
    fallback: &BTreeMap<String, Vec<UserInfo>>,
) -> BTreeMap<String, Vec<UserInfo>> {
    tags.iter()
        .filter_map(|tag| {
            if let Some(entry) = sync_state.get(tag) {
                return Some((tag.clone(), entry.state.users.clone()));
            }
            fallback.get(tag).map(|users| (tag.clone(), users.clone()))
        })
        .collect()
}

fn load_runtime_user_sync_entry(config: &NodeConfig) -> RuntimeUserSyncEntry {
    let path = user_sync_state_path(&config.config_dir, &config.url, config.node_id);
    let state = load_user_sync_state(&path).unwrap_or_default();
    RuntimeUserSyncEntry {
        state,
        delta_supported: true,
        path,
        last_change: None,
    }
}

fn save_runtime_user_sync_entry(entry: &RuntimeUserSyncEntry) {
    if !entry.path.trim().is_empty() {
        let _ = save_user_sync_state(&entry.path, &entry.state);
    }
}

fn user_delta_not_supported(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("404")
        || error.contains("405")
        || error.contains("not found")
        || error.contains("method not allowed")
}

fn node_config_for_info<'a>(
    plan: &'a RuntimeBootstrapPlan,
    node_id: u32,
    tag: &str,
) -> Option<&'a NodeConfig> {
    runtime_node_config_for_info(&plan.resolved, node_id, tag)
}

pub fn should_run(tick: usize, interval: usize) -> bool {
    interval > 0 && tick % interval == 0
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        handle_runtime_loop_event, keli_core_rs_metrics_snapshot, keli_core_user_delta_payload,
        keli_core_user_delta_requires_full_snapshot, keli_core_user_full_snapshot_payload,
        load_users_by_node_tag_from_panel_with_state, node_config_for_info,
        nonfatal_keli_core_activity_report, nonfatal_panel_status_report, refresh_runtime_health,
        refresh_subscription_proxy_health, run_runtime_loop, run_runtime_loop_async,
        run_runtime_loop_async_with_events, runtime_loop_event_for_task,
        runtime_plan_needs_cached_users, runtime_user_delta_change, should_run,
        try_apply_keli_core_rs_user_deltas, try_establish_keli_core_rs_revision_baseline,
        user_delta_body_is_revision_only, user_delta_not_supported, AsyncRuntimeLoopCallbacks,
        PanelRuntimeLoop, RuntimeLoopCallbacks, RuntimeLoopEvent, RuntimeLoopEventKind,
        RuntimeLoopExit, RuntimeLoopExitReason, RuntimeLoopFuture, RuntimeLoopOptions,
        RuntimeUserDeltaApplyOutcome, RuntimeUserDeltaChange, RuntimeUserDeltaMetrics,
        RuntimeUserSyncEntry,
    };
    use crate::config::{NodeConfig, ResolvedConfig, ResolvedMachineConfig};
    use crate::control::RuntimeControlOptions;
    use crate::control::{RuntimeLoopSignal, RuntimePanelAction, RuntimeTickOptions};
    use crate::health::ResourceSnapshot;
    use crate::machine::MachineUpgradeCommand;
    use crate::panel::types::{CommonNode, NodeInfo, PortValue, UserInfo};
    use crate::port_forward::{PortForwardCommand, PortForwardExecutor};
    use crate::process::{
        keli_core_rs_control_addr, keli_core_rs_control_token, MemoryProcessSupervisor,
        ProcessSupervisor,
    };
    use crate::realtime::RealtimeRuntimeTask;
    use crate::runtime::{build_runtime_bootstrap_plan, build_runtime_bootstrap_plan_with_users};
    use crate::subscription_proxy::SubscriptionProxyRuntimeManager;
    use crate::user::{UserListDiff, UserSyncState};
    use serde_json::json;

    #[test]
    fn should_run_matches_tick_interval() {
        assert!(should_run(1, 1));
        assert!(!should_run(1, 2));
        assert!(should_run(2, 2));
        assert!(!should_run(2, 0));
    }

    #[test]
    fn health_refresh_adds_version_resources_and_upgrade_status() {
        let mut options = RuntimeTickOptions::default();

        refresh_runtime_health(
            &mut options,
            "v-test",
            Some(json!({"status": "running"})),
            ResourceSnapshot {
                system: Some(json!({"os": "test"})),
                ..ResourceSnapshot::default()
            },
        );

        assert_eq!(options.control.health.version, "v-test");
        assert!(options.control.health.resources.system.is_some());
        assert_eq!(
            options.control.health.upgrade,
            Some(json!({"status": "running"}))
        );
    }

    #[test]
    fn subscription_proxy_health_refresh_uses_manager_status() {
        let mut manager = SubscriptionProxyRuntimeManager::new();
        manager
            .apply(
                &crate::config::SubscriptionProxyConfig {
                    enabled: true,
                    allow_http_fallback: true,
                    site_id: "site-a".to_string(),
                    upstream_base_url: "https://panel.example.test".to_string(),
                    certificate_domain: "proxy.example.test".to_string(),
                    ..crate::config::SubscriptionProxyConfig::default()
                },
                |_| String::new(),
                |_, _| Ok("csr".to_string()),
                |_| false,
                |_| Ok(()),
            )
            .unwrap();
        let mut options = RuntimeTickOptions::default();

        refresh_subscription_proxy_health(&mut options, &manager);

        let status = options.control.health.subscription_proxy.unwrap();
        assert_eq!(status.status, "running");
        assert_eq!(status.mode, "http");
        assert_eq!(status.certificate_domain, "proxy.example.test");
        assert_eq!(status.csr_pem, "csr");
    }

    #[test]
    fn panel_status_report_failure_keeps_runtime_alive() {
        let action = nonfatal_panel_status_report(Err("panel timed out".to_string()));

        assert_eq!(action, RuntimePanelAction::default());
    }

    #[test]
    fn panel_status_report_success_preserves_runtime_action() {
        let action = RuntimePanelAction {
            reload: true,
            upgrade: None,
        };

        assert_eq!(nonfatal_panel_status_report(Ok(action.clone())), action);
    }

    #[test]
    fn traffic_report_failure_keeps_runtime_alive() {
        nonfatal_keli_core_activity_report(Err("panel report failed".to_string()));
    }

    #[test]
    fn user_delta_unsupported_matches_legacy_panel_errors() {
        assert!(user_delta_not_supported(
            "user delta request failed: 404 Not Found"
        ));
        assert!(user_delta_not_supported("405 Method Not Allowed"));
        assert!(!user_delta_not_supported("403 Forbidden"));
    }

    #[test]
    fn revision_only_user_delta_does_not_trigger_runtime_change() {
        assert!(runtime_user_delta_change(false, 42, 43, UserListDiff::default()).is_none());
        assert!(user_delta_body_is_revision_only(
            &crate::panel::types::UserDeltaBody {
                full: false,
                revision: 43,
                users: Vec::new(),
                deleted: Vec::new(),
                upsert: Vec::new(),
            }
        ));
    }

    #[test]
    fn keli_core_user_delta_payload_maps_panel_diff() {
        let change = RuntimeUserDeltaChange {
            full: false,
            base_revision: 41,
            revision: 42,
            diff: UserListDiff {
                deleted: vec![UserInfo {
                    id: 1,
                    uuid: "deleted-user".to_string(),
                    speed_limit: 0,
                    device_limit: 0,
                }],
                added: vec![UserInfo {
                    id: 2,
                    uuid: "added-user".to_string(),
                    speed_limit: 10,
                    device_limit: 2,
                }],
                updated: vec![UserInfo {
                    id: 3,
                    uuid: "updated-user".to_string(),
                    speed_limit: 20,
                    device_limit: 3,
                }],
            },
        };

        let payload = keli_core_user_delta_payload("panel|vless|1", &change);

        assert_eq!(
            payload,
            json!({
                "added": [{
                    "id": 2,
                    "uuid": "added-user",
                    "password": null,
                    "email": null,
                    "speed_limit": 10,
                    "device_limit": 2
                }],
                "updated": [{
                    "id": 3,
                    "uuid": "updated-user",
                    "password": null,
                    "email": null,
                    "speed_limit": 20,
                    "device_limit": 3
                }],
                "deleted": ["deleted-user"],
                "base_revision": "41",
                "revision": "42"
            })
        );
    }

    #[test]
    fn keli_core_user_delta_revision_errors_require_full_snapshot() {
        assert!(keli_core_user_delta_requires_full_snapshot(
            "revision mismatch for inbound node-a"
        ));
        assert!(keli_core_user_delta_requires_full_snapshot(
            "current <missing>, base 42; full snapshot required"
        ));
        assert!(!keli_core_user_delta_requires_full_snapshot(
            "connect keli-core-rs control 127.0.0.1:18080: connection refused"
        ));
    }

    #[test]
    fn keli_core_user_full_snapshot_payload_maps_revision_and_users() {
        let entry = RuntimeUserSyncEntry {
            state: UserSyncState {
                revision: 88,
                users: vec![UserInfo {
                    id: 7,
                    uuid: "11111111-1111-1111-1111-111111111111".to_string(),
                    speed_limit: 1024,
                    device_limit: 3,
                }],
                updated_at: None,
            },
            delta_supported: true,
            path: String::new(),
            last_change: None,
        };

        let payload = keli_core_user_full_snapshot_payload("panel|vless|1", &entry);

        assert_eq!(payload["revision"], "88");
        assert_eq!(
            payload["full"][0],
            json!({
                "id": 7,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "password": null,
                "email": null,
                "speed_limit": 1024,
                "device_limit": 3
            })
        );
    }

    #[test]
    fn keli_core_user_delta_revision_mismatch_falls_back_to_full_snapshot() {
        let dir = temp_test_dir("user-delta-full-snapshot-fallback");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 12,
                machine_id: 12,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 12);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let config_path = plan.core_plan.as_ref().unwrap().config_path.clone();
        let old_user = UserInfo {
            id: 12,
            uuid: "55555555-5555-5555-5555-555555555555".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let new_user = UserInfo {
            id: 13,
            uuid: "66666666-6666-6666-6666-666666666666".to_string(),
            speed_limit: 30,
            device_limit: 3,
        };
        let mut sync_state = BTreeMap::new();
        sync_state.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 43,
                    users: vec![old_user.clone(), new_user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: Some(RuntimeUserDeltaChange {
                    full: false,
                    base_revision: 42,
                    revision: 43,
                    diff: UserListDiff {
                        added: vec![new_user.clone()],
                        updated: Vec::new(),
                        deleted: Vec::new(),
                    },
                }),
            },
        );
        let mut users_by_tag = BTreeMap::new();
        users_by_tag.insert(tag.clone(), vec![old_user, new_user.clone()]);
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let tag_for_thread = tag.clone();
        let new_user_for_thread = new_user.clone();
        let control_thread = thread::spawn(move || {
            let mut commands = Vec::new();
            for index in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(2);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                panic!(
                                    "keli-core-rs user delta control command {index} was not received"
                                );
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept keli-core-rs control command: {error}"),
                    }
                };
                let mut command = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut command)
                    .unwrap();
                let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
                commands.push(command.clone());
                if index == 0 {
                    writeln!(
                        stream,
                        "{}",
                        json!({
                            "type": "error",
                            "message": "revision mismatch for inbound"
                        })
                    )
                    .unwrap();
                } else {
                    writeln!(
                        stream,
                        "{}",
                        json!({
                            "type": "user_delta_applied",
                            "node_tag": tag_for_thread,
                            "result": {
                                "added": 0,
                                "updated": 0,
                                "deleted": 0,
                                "missing_updated": 0,
                                "missing_deleted": 0,
                                "active_users": 2,
                                "full_applied": true
                            },
                            "status": "running",
                            "listeners": []
                        })
                    )
                    .unwrap();
                }
            }
            assert_eq!(commands[0]["delta"]["base_revision"], "42");
            assert_eq!(commands[1]["delta"]["revision"], "43");
            assert_eq!(
                commands[1]["delta"]["full"][1]["uuid"],
                new_user_for_thread.uuid
            );
        });

        let mut metrics = RuntimeUserDeltaMetrics::default();
        assert_eq!(
            try_apply_keli_core_rs_user_deltas(&plan, &sync_state, &users_by_tag, &mut metrics),
            RuntimeUserDeltaApplyOutcome::Applied
        );
        assert_eq!(metrics.kelinode_user_delta_native_apply_failed_total, 1);
        assert_eq!(metrics.kelinode_user_delta_full_snapshot_fallback_total, 1);
        assert_eq!(metrics.kelinode_user_delta_native_apply_success_total, 1);
        control_thread.join().unwrap();

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn keli_core_user_delta_fans_out_mieru_port_range_targets() {
        let dir = temp_test_dir("user-delta-mieru-port-range-fanout");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 12,
                machine_id: 12,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let mut node = test_node_with_host("https://panel.example.test", "mieru", 12);
        node.common.ports = PortValue("2100-2101".to_string());
        let tag = node.tag.clone();
        let new_user = UserInfo {
            id: 13,
            uuid: "mieru-new-secret".to_string(),
            speed_limit: 10,
            device_limit: 1,
        };
        let mut initial_users = BTreeMap::new();
        initial_users.insert(
            tag.clone(),
            vec![UserInfo {
                id: 12,
                uuid: "mieru-secret".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan = build_runtime_bootstrap_plan_with_users(
            resolved,
            vec![node],
            Vec::new(),
            &initial_users,
        )
        .unwrap();
        let mut users_by_tag = BTreeMap::new();
        users_by_tag.insert(tag.clone(), vec![new_user.clone()]);
        let mut sync_state = BTreeMap::new();
        sync_state.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 2,
                    users: vec![new_user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: Some(RuntimeUserDeltaChange {
                    full: false,
                    base_revision: 1,
                    revision: 2,
                    diff: UserListDiff {
                        added: vec![new_user.clone()],
                        updated: Vec::new(),
                        deleted: Vec::new(),
                    },
                }),
            },
        );
        let config_path = plan.core_plan.as_ref().unwrap().config_path.clone();
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let expected_tags = [format!("{tag}|port:2100"), format!("{tag}|port:2101")];
        let expected_tags_for_thread = expected_tags.clone();
        let new_uuid_for_thread = new_user.uuid.clone();
        let control_thread = thread::spawn(move || {
            let mut received = Vec::new();
            for index in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(2);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                panic!("mieru fanout control command {index} was not received");
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept keli-core-rs control command: {error}"),
                    }
                };
                let mut command = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut command)
                    .unwrap();
                let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
                assert_eq!(command["type"], "apply_user_delta");
                assert_eq!(command["node_tag"], expected_tags_for_thread[index]);
                assert_eq!(command["delta"]["base_revision"], "1");
                assert_eq!(command["delta"]["revision"], "2");
                assert_eq!(command["delta"]["added"][0]["uuid"], new_uuid_for_thread);
                received.push(command["node_tag"].as_str().unwrap().to_string());
                writeln!(
                    stream,
                    "{}",
                    json!({
                        "type": "user_delta_applied",
                        "node_tag": expected_tags_for_thread[index],
                        "result": {
                            "added": 1,
                            "updated": 0,
                            "deleted": 0,
                            "missing_updated": 0,
                            "missing_deleted": 0,
                            "active_users": 1,
                            "full_applied": false
                        },
                        "status": "running",
                        "listeners": []
                    })
                )
                .unwrap();
            }
            received
        });
        let mut metrics = RuntimeUserDeltaMetrics::default();

        assert_eq!(
            try_apply_keli_core_rs_user_deltas(&plan, &sync_state, &users_by_tag, &mut metrics),
            RuntimeUserDeltaApplyOutcome::Applied
        );
        assert_eq!(control_thread.join().unwrap(), expected_tags.to_vec());

        assert_eq!(metrics.kelinode_user_delta_skipped_port_range_total, 0);
        assert_eq!(metrics.kelinode_user_delta_full_rebuild_total, 0);
        assert_eq!(metrics.kelinode_user_delta_native_apply_success_total, 2);
        let status = metrics.status_value();
        assert_eq!(
            status["kelinode_user_delta_skipped_port_range_total"],
            json!(0)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn keli_core_user_delta_does_not_skip_hysteria2_port_range() {
        let dir = temp_test_dir("user-delta-hysteria2-port-range");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 12,
                machine_id: 12,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "hysteria2",
            "server_port": 10012,
            "tls": 1,
            "tls_settings": {
                "server_name": "hy2.example.test",
                "cert_file": "/tmp/hy2.cer",
                "key_file": "/tmp/hy2.key"
            }
        }))
        .unwrap();
        let node = NodeInfo::from_common("https://panel.example.test", 12, common).unwrap();
        let tag = node.tag.clone();
        let mut plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        plan.core_plan.as_mut().unwrap().inbounds[0].port_range = "32000-33000".to_string();
        let mut users_by_tag = BTreeMap::new();
        users_by_tag.insert(tag, Vec::new());
        let mut metrics = RuntimeUserDeltaMetrics::default();

        assert_eq!(
            try_apply_keli_core_rs_user_deltas(
                &plan,
                &BTreeMap::new(),
                &users_by_tag,
                &mut metrics
            ),
            RuntimeUserDeltaApplyOutcome::Rebuild
        );

        assert_eq!(metrics.kelinode_user_delta_skipped_port_range_total, 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn revision_baseline_fans_out_mieru_port_range_targets() {
        let dir = temp_test_dir("revision-baseline-mieru-port-range-fanout");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 14,
                machine_id: 14,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let mut node = test_node_with_host("https://panel.example.test", "mieru", 14);
        node.common.ports = PortValue("2200-2201".to_string());
        let tag = node.tag.clone();
        let user = UserInfo {
            id: 14,
            uuid: "mieru-baseline-secret".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let mut users_by_tag = BTreeMap::new();
        users_by_tag.insert(tag.clone(), vec![user.clone()]);
        let plan = build_runtime_bootstrap_plan_with_users(
            resolved,
            vec![node],
            Vec::new(),
            &users_by_tag,
        )
        .unwrap();
        let mut sync_state = BTreeMap::new();
        sync_state.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 9,
                    users: vec![user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: None,
            },
        );
        let config_path = plan.core_plan.as_ref().unwrap().config_path.clone();
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let expected_tags = [format!("{tag}|port:2200"), format!("{tag}|port:2201")];
        let expected_tags_for_thread = expected_tags.clone();
        let user_uuid_for_thread = user.uuid.clone();
        let control_thread = thread::spawn(move || {
            let mut received = Vec::new();
            for index in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(2);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                panic!("mieru baseline control command {index} was not received");
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept keli-core-rs control command: {error}"),
                    }
                };
                let mut command = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut command)
                    .unwrap();
                let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
                assert_eq!(command["type"], "apply_user_delta");
                assert_eq!(command["node_tag"], expected_tags_for_thread[index]);
                assert_eq!(command["delta"]["revision"], "9");
                assert_eq!(command["delta"]["full"][0]["uuid"], user_uuid_for_thread);
                received.push(command["node_tag"].as_str().unwrap().to_string());
                writeln!(
                    stream,
                    "{}",
                    json!({
                        "type": "user_delta_applied",
                        "node_tag": expected_tags_for_thread[index],
                        "result": {
                            "added": 0,
                            "updated": 0,
                            "deleted": 0,
                            "missing_updated": 0,
                            "missing_deleted": 0,
                            "active_users": 1,
                            "full_applied": true
                        },
                        "status": "running",
                        "listeners": []
                    })
                )
                .unwrap();
            }
            received
        });

        let established = try_establish_keli_core_rs_revision_baseline(&plan, &sync_state, &[tag]);
        assert!(established);
        assert_eq!(control_thread.join().unwrap(), expected_tags.to_vec());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn keli_core_metrics_snapshot_uses_generated_control_token() {
        let dir = temp_test_dir("core-metrics-token");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 14,
                machine_id: 14,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let plan = build_runtime_bootstrap_plan(
            resolved,
            vec![test_node_with_host(
                "https://panel.example.test",
                "vless",
                14,
            )],
            Vec::new(),
        )
        .unwrap();
        let config_path = plan.core_plan.as_ref().unwrap().config_path.clone();
        let token = keli_core_rs_control_token(&config_path).unwrap();
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        let control_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
            assert_eq!(command["type"], "metrics");
            assert_eq!(command["token"], token);
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "metrics",
                    "metrics": {
                        "keli_core_user_delta_apply_total": 3,
                        "keli_core_user_delta_incremental_total": 2,
                        "keli_core_user_delta_active_users": {
                            "panel.example.test|vless|14": 260000
                        }
                    }
                })
            )
            .unwrap();
        });

        let metrics = keli_core_rs_metrics_snapshot(&plan).unwrap().unwrap();

        assert_eq!(metrics["keli_core_user_delta_apply_total"], json!(3));
        assert_eq!(
            metrics["keli_core_user_delta_active_users"]["panel.example.test|vless|14"],
            json!(260000)
        );
        assert!(!metrics.to_string().contains("KELI_CORE_CONTROL_TOKEN"));
        assert!(!metrics
            .to_string()
            .contains(&config_path.display().to_string()));
        control_thread.join().unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn keli_core_metrics_snapshot_reports_fetch_errors_without_token() {
        let dir = temp_test_dir("core-metrics-error");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 16,
                machine_id: 16,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let plan = build_runtime_bootstrap_plan(
            resolved,
            vec![test_node_with_host(
                "https://panel.example.test",
                "vless",
                16,
            )],
            Vec::new(),
        )
        .unwrap();
        let config_path = plan.core_plan.as_ref().unwrap().config_path.clone();
        let token = keli_core_rs_control_token(&config_path).unwrap();

        let error = keli_core_rs_metrics_snapshot(&plan).expect_err("metrics should fail");

        assert!(error.contains("fetch keli-core-rs metrics"));
        assert!(!error.contains(&token));
        assert!(!error.contains("KELI_CORE_CONTROL_TOKEN"));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_ignores_native_core_metrics_failure() {
        let dir = temp_test_dir("core-metrics-failure");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 15,
                machine_id: 15,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let plan = build_runtime_bootstrap_plan(
            resolved,
            vec![test_node_with_host(
                "https://panel.example.test",
                "vless",
                15,
            )],
            Vec::new(),
        )
        .unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 15,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: BTreeMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn loop_stops_after_max_ticks() {
        let mut callbacks = FakeCallbacks::default();

        let exit = run_runtime_loop(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(3),
                tick_interval: Duration::from_secs(0),
                ..RuntimeLoopOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            exit,
            RuntimeLoopExit {
                ticks: 3,
                reason: RuntimeLoopExitReason::MaxTicks,
            }
        );
        assert_eq!(callbacks.ticks.len(), 3);
        assert_eq!(callbacks.refreshes, 3);
    }

    #[test]
    fn loop_passes_periodic_user_refresh_and_report_flags() {
        let mut callbacks = FakeCallbacks::default();

        let exit = run_runtime_loop(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(4),
                tick_interval: Duration::from_secs(0),
                user_refresh_interval: 2,
                panel_report_interval: 3,
                ..RuntimeLoopOptions::default()
            },
        )
        .unwrap();

        assert_eq!(exit.reason, RuntimeLoopExitReason::MaxTicks);
        assert_eq!(callbacks.refreshes, 2);
        assert!(callbacks.ticks[0].users_by_node_tag.is_empty());
        assert!(!callbacks.ticks[1].users_by_node_tag.is_empty());
        assert!(!callbacks.ticks[0].report_to_panel);
        assert!(callbacks.ticks[2].report_to_panel);
    }

    #[test]
    fn loop_exits_on_reload_or_upgrade_signal() {
        let mut callbacks = FakeCallbacks {
            signal_at: Some(2),
            signal: RuntimeLoopSignal::Reload,
            ..FakeCallbacks::default()
        };

        let exit = run_runtime_loop(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(5),
                tick_interval: Duration::from_secs(0),
                ..RuntimeLoopOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            exit.reason,
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Reload)
        );
        assert_eq!(exit.ticks, 2);

        let mut callbacks = FakeCallbacks {
            signal_at: Some(1),
            signal: RuntimeLoopSignal::Upgrade(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.0".to_string(),
                component: String::new(),
            }),
            ..FakeCallbacks::default()
        };

        let exit = run_runtime_loop(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(5),
                tick_interval: Duration::from_secs(0),
                ..RuntimeLoopOptions::default()
            },
        )
        .unwrap();

        assert_eq!(exit.ticks, 1);
        assert_eq!(
            exit.reason,
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Upgrade(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.0".to_string(),
                component: String::new(),
            }))
        );
    }

    #[tokio::test]
    async fn async_loop_uses_same_refresh_report_and_signal_rules() {
        let mut callbacks = AsyncFakeCallbacks {
            signal_at: Some(3),
            signal: RuntimeLoopSignal::Reload,
            ..AsyncFakeCallbacks::default()
        };

        let exit = run_runtime_loop_async(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(5),
                tick_interval: Duration::from_secs(0),
                user_refresh_interval: 2,
                panel_report_interval: 3,
                ..RuntimeLoopOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            exit.reason,
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Reload)
        );
        assert_eq!(exit.ticks, 3);
        assert_eq!(callbacks.refreshes, 1);
        assert!(callbacks.ticks[0].users_by_node_tag.is_empty());
        assert!(!callbacks.ticks[1].users_by_node_tag.is_empty());
        assert!(callbacks.ticks[2].report_to_panel);
    }

    #[tokio::test]
    async fn async_loop_exits_on_external_reload_event() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(RuntimeLoopEvent::reload()).unwrap();
        let mut callbacks = AsyncFakeCallbacks::default();

        let exit = run_runtime_loop_async_with_events(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(5),
                tick_interval: Duration::from_secs(60),
                user_refresh_interval: 0,
                panel_report_interval: 0,
                ..RuntimeLoopOptions::default()
            },
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(
            exit.reason,
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Reload)
        );
        assert_eq!(exit.ticks, 1);
        assert_eq!(callbacks.ticks.len(), 1);
    }

    #[tokio::test]
    async fn async_loop_refreshes_users_on_external_event() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(RuntimeLoopEvent::refresh_users()).unwrap();
        let mut callbacks = AsyncFakeCallbacks::default();

        let exit = run_runtime_loop_async_with_events(
            &mut callbacks,
            RuntimeLoopOptions {
                max_ticks: Some(2),
                tick_interval: Duration::from_millis(1),
                user_refresh_interval: 0,
                panel_report_interval: 0,
                ..RuntimeLoopOptions::default()
            },
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(exit.reason, RuntimeLoopExitReason::MaxTicks);
        assert_eq!(callbacks.refreshes, 1);
        assert!(!callbacks.ticks[1].users_by_node_tag.is_empty());
        assert!(!callbacks.ticks[1].report_to_panel);
    }

    #[tokio::test]
    async fn runtime_event_replies_after_user_refresh() {
        let (reply, result) = tokio::sync::oneshot::channel();
        let mut callbacks = AsyncFakeCallbacks::default();

        let signal = handle_runtime_loop_event(
            &mut callbacks,
            &RuntimeLoopOptions {
                user_refresh_interval: 0,
                panel_report_interval: 0,
                ..RuntimeLoopOptions::default()
            },
            RuntimeLoopEvent::with_reply(RuntimeLoopEventKind::RefreshUsers, reply),
        )
        .await
        .unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        let reply = result.await.unwrap().unwrap();
        assert_eq!(reply.status, "applied");
        assert_eq!(reply.message, "user refresh applied");
        assert_eq!(callbacks.refreshes, 1);
    }

    #[tokio::test]
    async fn runtime_event_skips_tick_when_user_refresh_has_no_changes() {
        let (reply, result) = tokio::sync::oneshot::channel();
        let mut callbacks = AsyncFakeCallbacks {
            empty_refresh_users: true,
            ..AsyncFakeCallbacks::default()
        };

        let signal = handle_runtime_loop_event(
            &mut callbacks,
            &RuntimeLoopOptions {
                user_refresh_interval: 0,
                panel_report_interval: 0,
                ..RuntimeLoopOptions::default()
            },
            RuntimeLoopEvent::with_reply(RuntimeLoopEventKind::RefreshUsers, reply),
        )
        .await
        .unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        let reply = result.await.unwrap().unwrap();
        assert_eq!(reply.status, "applied");
        assert_eq!(reply.message, "user refresh no changes");
        assert_eq!(callbacks.refreshes, 1);
        assert!(callbacks.ticks.is_empty());
    }

    #[tokio::test]
    async fn runtime_event_marks_reload_reply_as_queued() {
        let (reply, result) = tokio::sync::oneshot::channel();
        let mut callbacks = AsyncFakeCallbacks::default();

        let signal = handle_runtime_loop_event(
            &mut callbacks,
            &RuntimeLoopOptions::default(),
            RuntimeLoopEvent::with_reply(RuntimeLoopEventKind::Reload, reply),
        )
        .await
        .unwrap();

        let reply = result.await.unwrap().unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Reload);
        assert_eq!(reply.status, "queued");
        assert_eq!(reply.message, "reload queued");
        assert_eq!(callbacks.refreshes, 0);
    }

    #[test]
    fn realtime_runtime_task_maps_reload_event_metadata() {
        let (kind, topic, message) =
            runtime_loop_event_for_task(&RealtimeRuntimeTask::ConfigCheck).unwrap();

        assert_eq!(kind, RuntimeLoopEventKind::Reload);
        assert_eq!(topic, "config");
        assert_eq!(message, "reload queued");
    }

    #[test]
    fn realtime_runtime_task_maps_user_refresh_event_metadata() {
        let (kind, topic, message) =
            runtime_loop_event_for_task(&RealtimeRuntimeTask::UserSync).unwrap();

        assert_eq!(kind, RuntimeLoopEventKind::RefreshUsers);
        assert_eq!(topic, "users");
        assert_eq!(message, "user refresh queued");
    }

    #[test]
    fn node_config_matching_keeps_same_node_id_on_different_panels_distinct() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![
                NodeConfig {
                    url: "https://panel-a.example.test".to_string(),
                    token: "a".to_string(),
                    node_id: 7,
                    machine_id: 1,
                    ..NodeConfig::default()
                },
                NodeConfig {
                    url: "https://panel-b.example.test".to_string(),
                    token: "b".to_string(),
                    node_id: 7,
                    machine_id: 1,
                    ..NodeConfig::default()
                },
            ],
        };
        let node = test_node_with_host("https://panel-b.example.test", "vless", 7);
        let plan = build_runtime_bootstrap_plan(resolved, vec![node.clone()], Vec::new()).unwrap();

        let matched = node_config_for_info(&plan, node.id, &node.tag).unwrap();

        assert_eq!(matched.url, "https://panel-b.example.test");
        assert_eq!(matched.token, "b");
    }

    #[tokio::test]
    async fn user_refresh_skips_panel_request_failure_when_continue_on_error() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "http://127.0.0.1:9".to_string(),
                token: "token".to_string(),
                node_id: 41,
                machine_id: 41,
                timeout: 1,
                ..NodeConfig::default()
            }],
        };
        let node = test_node_with_host("http://127.0.0.1:9", "vless", 41);
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut sync_state = BTreeMap::new();

        let users = load_users_by_node_tag_from_panel_with_state(&plan, &mut sync_state)
            .await
            .unwrap();

        assert!(users.is_empty());
    }

    #[test]
    fn skipped_user_required_native_inbound_requests_cached_users() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 42,
                machine_id: 42,
                ..NodeConfig::default()
            }],
        };
        let node = test_node_with_host("https://panel.example.test", "mieru", 42);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let entry = RuntimeUserSyncEntry {
            state: UserSyncState {
                revision: 7,
                users: vec![UserInfo {
                    id: 42,
                    uuid: "mieru-secret".to_string(),
                    speed_limit: 0,
                    device_limit: 0,
                }],
                updated_at: None,
            },
            delta_supported: true,
            path: String::new(),
            last_change: None,
        };

        assert!(plan.core_plan.is_none());
        assert!(runtime_plan_needs_cached_users(&plan, &tag, &entry));
    }

    #[tokio::test]
    async fn panel_runtime_loop_rebuilds_plan_with_refreshed_users_before_tick() {
        let dir = temp_test_dir("panel-runtime-loop");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 9,
                machine_id: 9,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 9);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let mut users_by_node_tag = BTreeMap::new();
        users_by_node_tag.insert(
            tag,
            vec![UserInfo {
                id: 9,
                uuid: "44444444-4444-4444-4444-444444444444".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 9,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag,
            },
        )
        .await
        .unwrap();
        let saved = fs::read_to_string(dir.join("v2node").join("config.json")).unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        assert!(saved.contains("44444444-4444-4444-4444-444444444444"));

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_does_not_try_native_delta_before_core_is_running() {
        let dir = temp_test_dir("panel-runtime-loop-native-delta-startup");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 10,
                machine_id: 10,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 10);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let mut users_by_node_tag = BTreeMap::new();
        users_by_node_tag.insert(
            tag,
            vec![UserInfo {
                id: 10,
                uuid: "55555555-5555-5555-5555-555555555555".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 10,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag,
            },
        )
        .await
        .unwrap();
        let saved = fs::read_to_string(dir.join("v2node").join("config.json")).unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        assert!(saved.contains("55555555-5555-5555-5555-555555555555"));
        assert_eq!(runner.process_supervisor.starts.len(), 1);
        assert_eq!(
            runner
                .user_delta_metrics
                .kelinode_user_delta_native_apply_failed_total,
            0
        );
        assert_eq!(
            runner
                .user_delta_metrics
                .kelinode_user_delta_full_rebuild_total,
            1
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_establishes_revision_baseline_after_startup_rebuild() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = temp_test_dir(&format!("panel-runtime-loop-native-baseline-{nanos}"));
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 10,
                machine_id: 10,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 10);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let config_path = plan.core_plan.as_ref().unwrap().config_path.clone();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let user = UserInfo {
            id: 10,
            uuid: "66666666-6666-6666-6666-666666666666".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        runner.user_sync.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 77,
                    users: vec![user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: Some(RuntimeUserDeltaChange {
                    full: true,
                    base_revision: 77,
                    revision: 77,
                    diff: UserListDiff {
                        added: vec![user.clone()],
                        updated: Vec::new(),
                        deleted: Vec::new(),
                    },
                }),
            },
        );
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let tag_for_thread = tag.clone();
        let user_uuid_for_thread = user.uuid.clone();
        let control_thread = thread::spawn(move || {
            for index in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(2);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                panic!(
                                    "revision baseline control command {index} was not received"
                                );
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept keli-core-rs control command: {error}"),
                    }
                };
                let mut command = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut command)
                    .unwrap();
                let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
                if index == 0 {
                    assert_eq!(command["type"], "metrics");
                    writeln!(
                        stream,
                        "{}",
                        json!({
                            "type": "metrics",
                            "metrics": {
                                "keli_core_user_delta_apply_total": 0,
                                "keli_core_user_delta_apply_error_total": 0,
                                "keli_core_user_delta_incremental_total": 0,
                                "keli_core_user_delta_full_snapshot_total": 0,
                                "keli_core_user_delta_revision_mismatch_total": 0,
                                "keli_core_user_delta_current_revision_missing_total": 0,
                                "keli_core_user_delta_apply_duration_ms": {
                                    "count": 0,
                                    "total_ms": 0,
                                    "last_ms": 0,
                                    "max_ms": 0,
                                    "buckets": {}
                                },
                                "keli_core_user_delta_active_users": {}
                            }
                        })
                    )
                    .unwrap();
                    continue;
                }
                assert_eq!(command["type"], "apply_user_delta");
                assert_eq!(command["node_tag"], tag_for_thread);
                assert_eq!(command["delta"]["revision"], "77");
                assert_eq!(command["delta"]["full"][0]["uuid"], user_uuid_for_thread);
                writeln!(
                    stream,
                    "{}",
                    json!({
                        "type": "user_delta_applied",
                        "node_tag": tag_for_thread,
                        "result": {
                            "added": 0,
                            "updated": 0,
                            "deleted": 0,
                            "missing_updated": 0,
                            "missing_deleted": 0,
                            "active_users": 1,
                            "full_applied": true
                        },
                        "status": "running",
                        "listeners": []
                    })
                )
                .unwrap();
            }
        });

        let mut users_by_node_tag = BTreeMap::new();
        users_by_node_tag.insert(tag, vec![user]);
        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 10,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag,
            },
        )
        .await
        .unwrap();
        control_thread.join().unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        assert_eq!(
            runner
                .user_delta_metrics
                .kelinode_user_delta_native_apply_failed_total,
            0
        );
        assert_eq!(
            runner
                .user_delta_metrics
                .kelinode_user_delta_full_rebuild_total,
            1
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_skips_full_plan_rebuild_after_user_delta_apply() {
        let dir = temp_test_dir("panel-runtime-loop-user-delta");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 10,
                machine_id: 10,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 10);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let old_user = UserInfo {
            id: 10,
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let new_user = UserInfo {
            id: 11,
            uuid: "22222222-2222-2222-2222-222222222222".to_string(),
            speed_limit: 20,
            device_limit: 2,
        };
        let mut initial_users_by_tag = BTreeMap::new();
        initial_users_by_tag.insert(tag.clone(), vec![old_user.clone()]);

        AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 10,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: initial_users_by_tag,
            },
        )
        .await
        .unwrap();
        let config_path = runner.plan.core_plan.as_ref().unwrap().config_path.clone();
        let saved_before = fs::read_to_string(&config_path).unwrap();
        assert!(saved_before.contains(&old_user.uuid));
        assert!(!saved_before.contains(&new_user.uuid));
        let stops_before = runner.process_supervisor.stops.len();
        let starts_before = runner.process_supervisor.starts.len();

        runner.user_sync.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 43,
                    users: vec![old_user.clone(), new_user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: Some(RuntimeUserDeltaChange {
                    full: false,
                    base_revision: 42,
                    revision: 43,
                    diff: UserListDiff {
                        added: vec![new_user.clone()],
                        updated: Vec::new(),
                        deleted: Vec::new(),
                    },
                }),
            },
        );
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let tag_for_thread = tag.clone();
        let new_uuid_for_thread = new_user.uuid.clone();
        let control_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            panic!("keli-core-rs user delta control command was not received");
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept keli-core-rs control command: {error}"),
                }
            };
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
            assert_eq!(command["type"], "apply_user_delta");
            assert_eq!(command["node_tag"], tag_for_thread);
            assert_eq!(command["delta"]["added"][0]["uuid"], new_uuid_for_thread);
            assert_eq!(command["delta"]["base_revision"], "42");
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "user_delta_applied",
                    "node_tag": tag_for_thread,
                    "result": {
                        "added": 1,
                        "updated": 0,
                        "deleted": 0,
                        "missing_updated": 0,
                        "missing_deleted": 0,
                        "active_users": 2,
                        "full_applied": false
                    },
                    "status": "running",
                    "listeners": []
                })
            )
            .unwrap();
        });
        let mut current_users_by_tag = BTreeMap::new();
        current_users_by_tag.insert(tag.clone(), vec![old_user.clone(), new_user.clone()]);

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 10,
                    start_core: true,
                    hot_apply_keli_core_rs: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: current_users_by_tag,
            },
        )
        .await
        .unwrap();
        control_thread.join().unwrap();
        let saved_after = fs::read_to_string(&config_path).unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        assert_eq!(saved_after, saved_before);
        assert_eq!(runner.process_supervisor.stops.len(), stops_before);
        assert_eq!(runner.process_supervisor.starts.len(), starts_before);
        assert!(runner
            .user_sync
            .get(&tag)
            .and_then(|entry| entry.last_change.as_ref())
            .is_none());
        assert!(runner
            .plan
            .core_plan
            .as_ref()
            .unwrap()
            .inbounds
            .iter()
            .flat_map(|inbound| inbound.users.iter())
            .all(|user| user.uuid != new_user.uuid));

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_restores_latest_users_when_native_core_restarts() {
        let dir = temp_test_dir("panel-runtime-loop-user-delta-restart");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 10,
                machine_id: 10,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 10);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let old_user = UserInfo {
            id: 10,
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let new_user = UserInfo {
            id: 11,
            uuid: "22222222-2222-2222-2222-222222222222".to_string(),
            speed_limit: 20,
            device_limit: 2,
        };
        let mut initial_users_by_tag = BTreeMap::new();
        initial_users_by_tag.insert(tag.clone(), vec![old_user.clone()]);

        AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 10,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: initial_users_by_tag,
            },
        )
        .await
        .unwrap();
        let config_path = runner.plan.core_plan.as_ref().unwrap().config_path.clone();
        let saved_before = fs::read_to_string(&config_path).unwrap();
        assert!(saved_before.contains(&old_user.uuid));
        assert!(!saved_before.contains(&new_user.uuid));

        runner.user_sync.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 43,
                    users: vec![old_user, new_user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: None,
            },
        );
        runner
            .process_supervisor
            .stop("core:keli-core-rs")
            .expect("stop native core");
        let starts_before = runner.process_supervisor.starts.len();

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 10,
                    start_core: true,
                    hot_apply_keli_core_rs: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: BTreeMap::new(),
            },
        )
        .await
        .unwrap();
        let saved_after = fs::read_to_string(&config_path).unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        assert!(saved_after.contains(&new_user.uuid));
        assert_eq!(runner.process_supervisor.starts.len(), starts_before + 1);
        assert_eq!(runner.user_id_lookup[&tag][&new_user.uuid], new_user.id);

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_sends_empty_user_delta_to_advance_core_revision() {
        let dir = temp_test_dir("panel-runtime-loop-empty-user-delta");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 12,
                machine_id: 12,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 12);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let user = UserInfo {
            id: 12,
            uuid: "55555555-5555-5555-5555-555555555555".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let mut initial_users_by_tag = BTreeMap::new();
        initial_users_by_tag.insert(tag.clone(), vec![user.clone()]);

        AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 12,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: initial_users_by_tag,
            },
        )
        .await
        .unwrap();
        let config_path = runner.plan.core_plan.as_ref().unwrap().config_path.clone();
        let saved_before = fs::read_to_string(&config_path).unwrap();
        let stops_before = runner.process_supervisor.stops.len();

        runner.user_sync.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 43,
                    users: vec![user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: Some(RuntimeUserDeltaChange {
                    full: false,
                    base_revision: 42,
                    revision: 43,
                    diff: UserListDiff {
                        added: Vec::new(),
                        updated: Vec::new(),
                        deleted: Vec::new(),
                    },
                }),
            },
        );
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let tag_for_thread = tag.clone();
        let control_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            panic!(
                                "empty keli-core-rs user delta control command was not received"
                            );
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept keli-core-rs control command: {error}"),
                }
            };
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
            assert_eq!(command["type"], "apply_user_delta");
            assert_eq!(command["node_tag"], tag_for_thread);
            assert_eq!(command["delta"]["added"].as_array().unwrap().len(), 0);
            assert_eq!(command["delta"]["updated"].as_array().unwrap().len(), 0);
            assert_eq!(command["delta"]["deleted"].as_array().unwrap().len(), 0);
            assert_eq!(command["delta"]["base_revision"], "42");
            assert_eq!(command["delta"]["revision"], "43");
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "user_delta_applied",
                    "node_tag": tag_for_thread,
                    "result": {
                        "added": 0,
                        "updated": 0,
                        "deleted": 0,
                        "missing_updated": 0,
                        "missing_deleted": 0,
                        "active_users": 1,
                        "full_applied": false
                    },
                    "status": "running",
                    "listeners": []
                })
            )
            .unwrap();
        });
        let mut current_users_by_tag = BTreeMap::new();
        current_users_by_tag.insert(tag, vec![user]);

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 12,
                    start_core: true,
                    hot_apply_keli_core_rs: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: current_users_by_tag,
            },
        )
        .await
        .unwrap();
        control_thread.join().unwrap();
        let saved_after = fs::read_to_string(&config_path).unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        assert_eq!(saved_after, saved_before);
        assert_eq!(runner.process_supervisor.stops.len(), stops_before);

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_reestablishes_revision_baseline_after_hot_rebuild() {
        let dir = temp_test_dir("panel-runtime-loop-hot-rebuild-baseline");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 13,
                machine_id: 13,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 13);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let old_user = UserInfo {
            id: 13,
            uuid: "13131313-1313-1313-1313-131313131313".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let new_user = UserInfo {
            id: 14,
            uuid: "14141414-1414-1414-1414-141414141414".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let mut initial_users_by_tag = BTreeMap::new();
        initial_users_by_tag.insert(tag.clone(), vec![old_user.clone()]);

        AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 13,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: initial_users_by_tag,
            },
        )
        .await
        .unwrap();
        let config_path = runner.plan.core_plan.as_ref().unwrap().config_path.clone();

        runner.user_sync.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 44,
                    users: vec![old_user.clone(), new_user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: Some(RuntimeUserDeltaChange {
                    full: true,
                    base_revision: 43,
                    revision: 44,
                    diff: UserListDiff {
                        added: vec![new_user.clone()],
                        updated: Vec::new(),
                        deleted: Vec::new(),
                    },
                }),
            },
        );
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let tag_for_thread = tag.clone();
        let new_uuid_for_thread = new_user.uuid.clone();
        let control_thread = thread::spawn(move || {
            for index in 0..3 {
                let deadline = Instant::now() + Duration::from_secs(2);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                panic!("hot rebuild control command {index} was not received");
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept keli-core-rs control command: {error}"),
                    }
                };
                let mut command = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut command)
                    .unwrap();
                let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
                match index {
                    0 => {
                        assert_eq!(command["type"], "metrics");
                        writeln!(
                            stream,
                            "{}",
                            json!({
                                "type": "metrics",
                                "metrics": {
                                    "keli_core_user_delta_apply_total": 0
                                }
                            })
                        )
                        .unwrap();
                    }
                    1 => {
                        assert_eq!(command["type"], "apply_config");
                        assert!(command["config"].to_string().contains(&new_uuid_for_thread));
                        writeln!(
                            stream,
                            "{}",
                            json!({
                                "type": "applied",
                                "decision": "updated",
                                "status": "running",
                                "listeners": []
                            })
                        )
                        .unwrap();
                    }
                    _ => {
                        assert_eq!(command["type"], "apply_user_delta");
                        assert_eq!(command["node_tag"], tag_for_thread);
                        assert_eq!(command["delta"]["revision"], "44");
                        assert_eq!(command["delta"]["full"][1]["uuid"], new_uuid_for_thread);
                        writeln!(
                            stream,
                            "{}",
                            json!({
                                "type": "user_delta_applied",
                                "node_tag": tag_for_thread,
                                "result": {
                                    "added": 0,
                                    "updated": 0,
                                    "deleted": 0,
                                    "missing_updated": 0,
                                    "missing_deleted": 0,
                                    "active_users": 2,
                                    "full_applied": true
                                },
                                "status": "running",
                                "listeners": []
                            })
                        )
                        .unwrap();
                    }
                }
            }
        });
        let mut current_users_by_tag = BTreeMap::new();
        current_users_by_tag.insert(tag, vec![old_user, new_user]);

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 13,
                    start_core: true,
                    hot_apply_keli_core_rs: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: current_users_by_tag,
            },
        )
        .await
        .unwrap();
        control_thread.join().unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_falls_back_to_full_plan_on_user_delta_error() {
        let dir = temp_test_dir("panel-runtime-loop-user-delta-fallback");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 11,
                machine_id: 11,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 11);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let old_user = UserInfo {
            id: 11,
            uuid: "33333333-3333-3333-3333-333333333333".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let new_user = UserInfo {
            id: 12,
            uuid: "44444444-4444-4444-4444-444444444444".to_string(),
            speed_limit: 30,
            device_limit: 3,
        };
        let mut initial_users_by_tag = BTreeMap::new();
        initial_users_by_tag.insert(tag.clone(), vec![old_user.clone()]);

        AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 11,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: initial_users_by_tag,
            },
        )
        .await
        .unwrap();
        let config_path = runner.plan.core_plan.as_ref().unwrap().config_path.clone();
        let saved_before = fs::read_to_string(&config_path).unwrap();
        assert!(saved_before.contains(&old_user.uuid));
        assert!(!saved_before.contains(&new_user.uuid));
        let stops_before = runner.process_supervisor.stops.len();

        runner.user_sync.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 43,
                    users: vec![old_user.clone(), new_user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: Some(RuntimeUserDeltaChange {
                    full: false,
                    base_revision: 42,
                    revision: 43,
                    diff: UserListDiff {
                        added: vec![new_user.clone()],
                        updated: Vec::new(),
                        deleted: Vec::new(),
                    },
                }),
            },
        );
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let tag_for_thread = tag.clone();
        let control_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            panic!("keli-core-rs user delta control command was not received");
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept keli-core-rs control command: {error}"),
                }
            };
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
            assert_eq!(command["type"], "apply_user_delta");
            assert_eq!(command["node_tag"], tag_for_thread);
            assert_eq!(command["delta"]["base_revision"], "42");
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "error",
                    "message": "permission denied"
                })
            )
            .unwrap();
        });
        let mut current_users_by_tag = BTreeMap::new();
        current_users_by_tag.insert(tag.clone(), vec![old_user, new_user.clone()]);

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 11,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: current_users_by_tag,
            },
        )
        .await
        .unwrap();
        control_thread.join().unwrap();
        let saved_after = fs::read_to_string(&config_path).unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        assert!(saved_after.contains(&new_user.uuid));
        assert!(runner
            .plan
            .core_plan
            .as_ref()
            .unwrap()
            .inbounds
            .iter()
            .flat_map(|inbound| inbound.users.iter())
            .any(|user| user.uuid == new_user.uuid));
        assert!(runner.process_supervisor.stops.len() > stops_before);

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn panel_runtime_loop_keeps_runtime_when_delta_reports_unknown_inbound() {
        let dir = temp_test_dir("panel-runtime-loop-user-delta-unknown-inbound");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 13,
                machine_id: 13,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node_with_host("https://panel.example.test", "vless", 13);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut runner = PanelRuntimeLoop::new(plan, &mut process, &mut port_forward, None);
        let old_user = UserInfo {
            id: 13,
            uuid: "33333333-3333-3333-3333-333333333333".to_string(),
            speed_limit: 0,
            device_limit: 0,
        };
        let new_user = UserInfo {
            id: 14,
            uuid: "44444444-4444-4444-4444-444444444444".to_string(),
            speed_limit: 30,
            device_limit: 3,
        };
        let mut initial_users_by_tag = BTreeMap::new();
        initial_users_by_tag.insert(tag.clone(), vec![old_user.clone()]);

        AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 13,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: initial_users_by_tag,
            },
        )
        .await
        .unwrap();
        let config_path = runner.plan.core_plan.as_ref().unwrap().config_path.clone();
        let saved_before = fs::read_to_string(&config_path).unwrap();
        let stops_before = runner.process_supervisor.stops.len();
        let full_rebuilds_before = runner
            .user_delta_metrics
            .kelinode_user_delta_full_rebuild_total;

        runner.user_sync.insert(
            tag.clone(),
            RuntimeUserSyncEntry {
                state: UserSyncState {
                    revision: 43,
                    users: vec![old_user.clone(), new_user.clone()],
                    updated_at: None,
                },
                delta_supported: true,
                path: String::new(),
                last_change: Some(RuntimeUserDeltaChange {
                    full: false,
                    base_revision: 42,
                    revision: 43,
                    diff: UserListDiff {
                        added: vec![new_user.clone()],
                        updated: Vec::new(),
                        deleted: Vec::new(),
                    },
                }),
            },
        );
        let control_addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&control_addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        let tag_for_thread = tag.clone();
        let control_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            panic!("keli-core-rs user delta control command was not received");
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept keli-core-rs control command: {error}"),
                }
            };
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            let command = serde_json::from_str::<serde_json::Value>(command.trim()).unwrap();
            assert_eq!(command["type"], "apply_user_delta");
            assert_eq!(command["node_tag"], tag_for_thread);
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "error",
                    "message": format!("unknown inbound node_tag {tag_for_thread}")
                })
            )
            .unwrap();
        });
        let mut current_users_by_tag = BTreeMap::new();
        current_users_by_tag.insert(tag.clone(), vec![old_user, new_user.clone()]);

        let signal = AsyncRuntimeLoopCallbacks::run_tick(
            &mut runner,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 13,
                    start_core: true,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag: current_users_by_tag,
            },
        )
        .await
        .unwrap();
        control_thread.join().unwrap();
        let saved_after = fs::read_to_string(&config_path).unwrap();

        assert_eq!(signal, RuntimeLoopSignal::Continue);
        assert_eq!(saved_after, saved_before);
        assert_eq!(runner.process_supervisor.stops.len(), stops_before);
        assert!(runner.user_sync.get(&tag).unwrap().last_change.is_some());
        assert_eq!(
            runner
                .user_delta_metrics
                .kelinode_user_delta_native_apply_failed_total,
            1
        );
        assert_eq!(
            runner
                .user_delta_metrics
                .kelinode_user_delta_full_rebuild_total,
            full_rebuilds_before
        );

        let _ = fs::remove_dir_all(dir);
    }

    struct FakeCallbacks {
        ticks: Vec<RuntimeTickOptions>,
        refreshes: usize,
        signal_at: Option<usize>,
        signal: RuntimeLoopSignal,
    }

    impl Default for FakeCallbacks {
        fn default() -> Self {
            Self {
                ticks: Vec::new(),
                refreshes: 0,
                signal_at: None,
                signal: RuntimeLoopSignal::Continue,
            }
        }
    }

    impl RuntimeLoopCallbacks for FakeCallbacks {
        fn refresh_users(&mut self) -> Result<BTreeMap<String, Vec<UserInfo>>, String> {
            self.refreshes += 1;
            let mut users = BTreeMap::new();
            users.insert(
                "node-a".to_string(),
                vec![UserInfo {
                    id: self.refreshes as u32,
                    uuid: format!("user-{}", self.refreshes),
                    speed_limit: 0,
                    device_limit: 0,
                }],
            );
            Ok(users)
        }

        fn run_tick(&mut self, options: RuntimeTickOptions) -> Result<RuntimeLoopSignal, String> {
            self.ticks.push(options);
            if self.signal_at == Some(self.ticks.len()) {
                return Ok(self.signal.clone());
            }
            Ok(RuntimeLoopSignal::Continue)
        }

        fn sleep(&mut self, _duration: Duration) -> Result<(), String> {
            Ok(())
        }
    }

    struct AsyncFakeCallbacks {
        ticks: Vec<RuntimeTickOptions>,
        refreshes: usize,
        signal_at: Option<usize>,
        signal: RuntimeLoopSignal,
        empty_refresh_users: bool,
    }

    impl Default for AsyncFakeCallbacks {
        fn default() -> Self {
            Self {
                ticks: Vec::new(),
                refreshes: 0,
                signal_at: None,
                signal: RuntimeLoopSignal::Continue,
                empty_refresh_users: false,
            }
        }
    }

    impl AsyncRuntimeLoopCallbacks for AsyncFakeCallbacks {
        fn refresh_users<'a>(
            &'a mut self,
        ) -> RuntimeLoopFuture<'a, Result<BTreeMap<String, Vec<UserInfo>>, String>> {
            Box::pin(async move {
                self.refreshes += 1;
                if self.empty_refresh_users {
                    return Ok(BTreeMap::new());
                }
                let mut users = BTreeMap::new();
                users.insert(
                    "node-a".to_string(),
                    vec![UserInfo {
                        id: self.refreshes as u32,
                        uuid: format!("async-user-{}", self.refreshes),
                        speed_limit: 0,
                        device_limit: 0,
                    }],
                );
                Ok(users)
            })
        }

        fn run_tick<'a>(
            &'a mut self,
            options: RuntimeTickOptions,
        ) -> RuntimeLoopFuture<'a, Result<RuntimeLoopSignal, String>> {
            Box::pin(async move {
                self.ticks.push(options);
                if self.signal_at == Some(self.ticks.len()) {
                    return Ok(self.signal.clone());
                }
                Ok(RuntimeLoopSignal::Continue)
            })
        }

        fn sleep<'a>(
            &'a mut self,
            _duration: Duration,
        ) -> RuntimeLoopFuture<'a, Result<(), String>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Default)]
    struct FakePortForwardExecutor {
        available: BTreeSet<String>,
    }

    impl PortForwardExecutor for FakePortForwardExecutor {
        fn is_tool_available(&mut self, tool: &str) -> bool {
            self.available.contains(tool)
        }

        fn command_output(&mut self, command: &PortForwardCommand) -> Result<String, String> {
            Err(format!("{} unavailable", command.tool))
        }

        fn run_command(&mut self, command: &PortForwardCommand) -> Result<(), String> {
            Err(format!("{} unavailable", command.tool))
        }

        fn running_as_root(&self) -> bool {
            false
        }
    }

    fn test_node_with_host(api_host: &str, protocol: &str, node_id: u32) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": protocol,
            "server_port": 10000 + node_id
        }))
        .unwrap();

        NodeInfo::from_common(api_host, node_id, common).unwrap()
    }

    fn temp_test_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("kelinode-rs-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
