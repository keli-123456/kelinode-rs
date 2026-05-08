use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::NodeConfig;
use crate::control::{
    report_runtime_apply_result_to_panels, run_runtime_tick, runtime_loop_signal,
    RuntimeControlOptions, RuntimeLoopSignal, RuntimeTickOptions,
};
use crate::health::ResourceSnapshot;
use crate::panel::client::{PanelClient, PanelClientOptions};
use crate::panel::types::UserInfo;
use crate::port_forward::PortForwardExecutor;
use crate::process::ProcessSupervisor;
use crate::realtime::{
    build_realtime_receipt, realtime_runtime_task, RealtimeMessage, RealtimeOptions,
    RealtimeRuntimeTask,
};
use crate::realtime_client::{connect_realtime_transport, RealtimeTransport};
use crate::report::report_keli_core_activity_to_panel;
use crate::runtime::{
    node_config_for_info as runtime_node_config_for_info, rebuild_runtime_plan_with_users,
    RuntimeBootstrapPlan,
};
use crate::subscription_proxy::SubscriptionProxyRuntimeManager;
use crate::system::{ResourceSampler, SystemPublicIpProbe};
use crate::user::{
    apply_full_user_list, apply_user_delta_body, load_user_sync_state, save_user_sync_state,
    user_sync_state_path, UserSyncState,
};
use serde_json::Value;

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
    user_sync: BTreeMap<String, RuntimeUserSyncEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RuntimeUserSyncEntry {
    state: UserSyncState,
    delta_supported: bool,
    path: String,
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
            user_sync: BTreeMap::new(),
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
            if !options.users_by_node_tag.is_empty() {
                self.plan =
                    rebuild_runtime_plan_with_users(&self.plan, &options.users_by_node_tag)?;
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
            if report_to_panel {
                let action =
                    report_runtime_apply_result_to_panels(&self.panel_clients, &result.apply)
                        .await?;
                report_keli_core_activity_to_panel(&self.plan).await?;
                return Ok(runtime_loop_signal(&action));
            }
            Ok(result.signal)
        })
    }
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
            Ok(users_by_node_tag) => match callbacks
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
            },
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
        let users = load_users_for_node(config, entry, &mut client).await?;
        users_by_tag.insert(node.tag.clone(), users);
    }
    Ok(users_by_tag)
}

async fn load_users_for_node(
    config: &NodeConfig,
    entry: &mut RuntimeUserSyncEntry,
    client: &mut PanelClient,
) -> Result<Vec<UserInfo>, String> {
    if entry.delta_supported {
        match client.get_user_delta(entry.state.revision).await {
            Ok(delta) => {
                let result = apply_user_delta_body(&entry.state, &delta);
                entry.state = result.state;
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
    entry.state = result.state;
    save_runtime_user_sync_entry(entry);
    Ok(entry.state.users.clone())
}

fn load_runtime_user_sync_entry(config: &NodeConfig) -> RuntimeUserSyncEntry {
    let path = user_sync_state_path(&config.config_dir, &config.url, config.node_id);
    let state = load_user_sync_state(&path).unwrap_or_default();
    RuntimeUserSyncEntry {
        state,
        delta_supported: true,
        path,
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
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        handle_runtime_loop_event, node_config_for_info, refresh_runtime_health,
        refresh_subscription_proxy_health, run_runtime_loop, run_runtime_loop_async,
        run_runtime_loop_async_with_events, runtime_loop_event_for_task, should_run,
        user_delta_not_supported, AsyncRuntimeLoopCallbacks, PanelRuntimeLoop,
        RuntimeLoopCallbacks, RuntimeLoopEvent, RuntimeLoopEventKind, RuntimeLoopExit,
        RuntimeLoopExitReason, RuntimeLoopFuture, RuntimeLoopOptions,
    };
    use crate::config::{NodeConfig, ResolvedConfig, ResolvedMachineConfig};
    use crate::control::RuntimeControlOptions;
    use crate::control::{RuntimeLoopSignal, RuntimeTickOptions};
    use crate::health::ResourceSnapshot;
    use crate::machine::MachineUpgradeCommand;
    use crate::panel::types::{CommonNode, NodeInfo, UserInfo};
    use crate::port_forward::{PortForwardCommand, PortForwardExecutor};
    use crate::process::MemoryProcessSupervisor;
    use crate::realtime::RealtimeRuntimeTask;
    use crate::runtime::build_runtime_bootstrap_plan;
    use crate::subscription_proxy::SubscriptionProxyRuntimeManager;
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
    fn user_delta_unsupported_matches_legacy_panel_errors() {
        assert!(user_delta_not_supported(
            "user delta request failed: 404 Not Found"
        ));
        assert!(user_delta_not_supported("405 Method Not Allowed"));
        assert!(!user_delta_not_supported("403 Forbidden"));
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
    }

    impl Default for AsyncFakeCallbacks {
        fn default() -> Self {
            Self {
                ticks: Vec::new(),
                refreshes: 0,
                signal_at: None,
                signal: RuntimeLoopSignal::Continue,
            }
        }
    }

    impl AsyncRuntimeLoopCallbacks for AsyncFakeCallbacks {
        fn refresh_users<'a>(
            &'a mut self,
        ) -> RuntimeLoopFuture<'a, Result<BTreeMap<String, Vec<UserInfo>>, String>> {
            Box::pin(async move {
                self.refreshes += 1;
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
