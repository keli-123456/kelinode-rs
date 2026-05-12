use std::collections::BTreeMap;

use crate::config::SidecarProcessConfig;
use crate::core::{
    render_core_config, write_core_config, CoreConfigWriteResult, CoreKind, CorePlan,
};
use crate::core_control::{KeliCoreControlClient, KeliCoreResponse};
use crate::health::{build_machine_status_payload, HealthReportInput};
use crate::machine::{MachineStatusPayload, MachineStatusResponse, MachineUpgradeCommand};
use crate::panel::types::UserInfo;
use crate::panel::PanelClient;
use crate::port_forward::{
    inspect_hysteria_port_forward, repair_hysteria_port_forward, HysteriaPortForwardStatus,
    PortForwardExecutor,
};
use crate::process::{
    core_process_spec, keli_core_rs_control_addr, sidecar_process_spec, ProcessSpec, ProcessStatus,
    ProcessSupervisor,
};
use crate::runtime::{rebuild_runtime_plan_with_users, RuntimeBootstrapPlan};
use crate::upgrade::{UpgradeExecutor, UpgradeManager, UpgradeStatus};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuntimeControlOptions {
    pub machine_id: u32,
    pub core_command: Option<String>,
    pub sidecar_processes: BTreeMap<String, SidecarProcessConfig>,
    pub start_core: bool,
    pub hot_apply_keli_core_rs: bool,
    pub keli_core_rs_user_delta_applied: bool,
    pub repair_port_forward: bool,
    pub health: HealthReportInput,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeApplyResult {
    pub core_config: Option<CoreConfigWriteResult>,
    pub sidecar_configs: Vec<CoreConfigWriteResult>,
    pub core_process: Option<ProcessStatus>,
    pub sidecar_processes: Vec<ProcessStatus>,
    pub hy2_port_forward: HysteriaPortForwardStatus,
    pub machine_status: MachineStatusPayload,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimePanelAction {
    pub reload: bool,
    pub upgrade: Option<MachineUpgradeCommand>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuntimeTickOptions {
    pub control: RuntimeControlOptions,
    pub report_to_panel: bool,
    pub users_by_node_tag: BTreeMap<String, Vec<UserInfo>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeTickResult {
    pub apply: RuntimeApplyResult,
    pub panel_action: RuntimePanelAction,
    pub signal: RuntimeLoopSignal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HotApplyError {
    message: String,
    fallback_reload: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeLoopSignal {
    Continue,
    Reload,
    Upgrade(MachineUpgradeCommand),
}

pub fn apply_runtime_plan<P, F>(
    plan: &RuntimeBootstrapPlan,
    process_supervisor: &mut P,
    port_forward_executor: &mut F,
    options: RuntimeControlOptions,
) -> Result<RuntimeApplyResult, String>
where
    P: ProcessSupervisor,
    F: PortForwardExecutor,
{
    let mut core_config = None;
    let mut sidecar_configs = Vec::new();
    let mut core_process = None;
    let mut sidecar_processes = Vec::new();

    if let Some(core_plan) = &plan.core_plan {
        let write_result = write_core_config(core_plan).map_err(|err| err.message)?;
        if options.start_core {
            let status =
                apply_core_process(core_plan, &write_result, process_supervisor, &options)?;
            core_process = Some(status);
        }
        core_config = Some(write_result);
    }

    for sidecar_plan in &plan.sidecar_core_plans {
        let write_result = write_core_config(sidecar_plan).map_err(|err| err.message)?;
        if options.start_core {
            if let Some(config) = configured_sidecar_process(sidecar_plan, &options) {
                let spec =
                    sidecar_process_spec(sidecar_plan, &config.command, &config.args, &config.env)
                        .map_err(|err| err.message)?;
                let status = if write_result.changed {
                    process_supervisor.reload(&spec)
                } else {
                    process_supervisor.start(&spec)
                }
                .map_err(|err| err.message)?;
                sidecar_processes.push(status);
            }
        }
        sidecar_configs.push(write_result);
    }

    let hy2_port_forward = if options.repair_port_forward {
        repair_hysteria_port_forward(&plan.node_infos, port_forward_executor)
    } else {
        inspect_hysteria_port_forward(&plan.node_infos, port_forward_executor)
    };

    let mut report_plan = plan.clone();
    report_plan.hy2_port_forward = hy2_port_forward.clone();
    let mut health = options.health;
    if health.core.is_none() {
        health.core = core_process.clone();
    }
    if health.sidecars.is_empty() {
        health.sidecars = sidecar_processes.clone();
    }
    let machine_status = build_machine_status_payload(options.machine_id, &report_plan, health);

    Ok(RuntimeApplyResult {
        core_config,
        sidecar_configs,
        core_process,
        sidecar_processes,
        hy2_port_forward,
        machine_status,
    })
}

fn apply_core_process<P>(
    core_plan: &CorePlan,
    write_result: &CoreConfigWriteResult,
    process_supervisor: &mut P,
    options: &RuntimeControlOptions,
) -> Result<ProcessStatus, String>
where
    P: ProcessSupervisor,
{
    let spec =
        core_process_spec(core_plan, options.core_command.as_deref()).map_err(|err| err.message)?;
    if write_result.changed {
        if options.keli_core_rs_user_delta_applied && core_plan.kind == CoreKind::KeliCoreRs {
            if let Ok(mut status) = process_supervisor.status(&spec.name) {
                if status.is_running() {
                    status.message = "kept running after keli-core-rs user delta apply".to_string();
                    return Ok(status);
                }
            }
        }
        if options.hot_apply_keli_core_rs {
            match try_hot_apply_keli_core_rs_config(core_plan, process_supervisor, &spec) {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(error) if error.fallback_reload => {
                    let mut status = process_supervisor
                        .reload(&spec)
                        .map_err(|err| err.message)?;
                    status.message = format!(
                        "reloaded after keli-core-rs hot apply failed: {}",
                        error.message
                    );
                    return Ok(status);
                }
                Err(error) => return Err(error.message),
            }
        }
        return process_supervisor.reload(&spec).map_err(|err| err.message);
    }

    process_supervisor.start(&spec).map_err(|err| err.message)
}

fn try_hot_apply_keli_core_rs_config<P>(
    core_plan: &CorePlan,
    process_supervisor: &mut P,
    spec: &ProcessSpec,
) -> Result<Option<ProcessStatus>, HotApplyError>
where
    P: ProcessSupervisor,
{
    if core_plan.kind != CoreKind::KeliCoreRs {
        return Ok(None);
    }

    let current = process_supervisor
        .status(&spec.name)
        .map_err(|err| HotApplyError::fallback(err.message))?;
    if !current.is_running() {
        return Ok(None);
    }

    let config = render_core_config(core_plan).map_err(|err| HotApplyError::fatal(err.message))?;
    let client = KeliCoreControlClient::new(keli_core_rs_control_addr(&core_plan.config_path));
    match client.apply_config_response(config) {
        Ok(KeliCoreResponse::Applied { decision, .. }) => {
            let mut status = current;
            status.message = format!("hot applied keli-core-rs config ({decision})");
            Ok(Some(status))
        }
        Ok(KeliCoreResponse::Error { message }) => Err(HotApplyError::fatal(format!(
            "keli-core-rs rejected hot config: {message}"
        ))),
        Ok(response) => Err(HotApplyError::fallback(format!(
            "unexpected keli-core-rs apply response: {response:?}"
        ))),
        Err(error) => Err(HotApplyError::fallback(error.message)),
    }
}

impl HotApplyError {
    fn fallback(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fallback_reload: true,
        }
    }

    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fallback_reload: false,
        }
    }
}

fn configured_sidecar_process<'a>(
    plan: &CorePlan,
    options: &'a RuntimeControlOptions,
) -> Option<&'a SidecarProcessConfig> {
    let CoreKind::Sidecar(name) = &plan.kind else {
        return None;
    };

    options.sidecar_processes.get(name)
}

pub async fn report_runtime_apply_result(
    client: &PanelClient,
    result: &RuntimeApplyResult,
) -> Result<RuntimePanelAction, String> {
    report_machine_status_payload(client, result.machine_status.clone()).await
}

pub async fn report_runtime_apply_result_to_panels(
    clients: &[PanelClient],
    result: &RuntimeApplyResult,
) -> Result<RuntimePanelAction, String> {
    let mut reported = 0usize;
    let mut errors = Vec::new();
    let mut action = RuntimePanelAction::default();

    for client in clients {
        let payload = machine_status_payload_for_client(&result.machine_status, client);
        match report_machine_status_payload(client, payload).await {
            Ok(next) => {
                reported += 1;
                action = merge_runtime_panel_action(action, next);
            }
            Err(error) => errors.push(format!(
                "{}#{}: {}",
                client.options().api_host.trim_end_matches('/'),
                client.options().machine_id,
                error
            )),
        }
    }

    if reported == 0 && !errors.is_empty() {
        return Err(format!(
            "all machine status reports failed: {}",
            errors.join("; ")
        ));
    }

    Ok(action)
}

fn machine_status_payload_for_client(
    payload: &MachineStatusPayload,
    client: &PanelClient,
) -> MachineStatusPayload {
    let mut payload = payload.clone();
    if client.options().machine_id > 0 {
        payload.machine_id = client.options().machine_id;
    }

    let api_host = client.options().api_host.trim_end_matches('/');
    let machine_id = client.options().machine_id as u64;
    if let Some(Value::Array(failures)) = payload.status.get_mut("node_failures") {
        failures.retain(|failure| {
            let failure_host = failure
                .get("api_host")
                .and_then(Value::as_str)
                .map(|host| host.trim_end_matches('/'))
                .unwrap_or_default();
            let failure_machine_id = failure
                .get("machine_id")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            failure_host == api_host && failure_machine_id == machine_id
        });
    }

    payload
}

pub async fn report_machine_status_payload(
    client: &PanelClient,
    payload: MachineStatusPayload,
) -> Result<RuntimePanelAction, String> {
    let response = client
        .report_machine_status(payload)
        .await
        .map_err(|err| err.to_string())?;
    Ok(runtime_panel_action(&response))
}

pub fn runtime_panel_action(response: &MachineStatusResponse) -> RuntimePanelAction {
    RuntimePanelAction {
        reload: response.reload,
        upgrade: response.upgrade.clone(),
    }
}

pub fn merge_runtime_panel_action(
    mut target: RuntimePanelAction,
    next: RuntimePanelAction,
) -> RuntimePanelAction {
    target.reload |= next.reload;
    if target.upgrade.is_none() {
        target.upgrade = next.upgrade;
    }
    target
}

pub async fn run_runtime_tick<P, F>(
    plan: &RuntimeBootstrapPlan,
    process_supervisor: &mut P,
    port_forward_executor: &mut F,
    panel_client: Option<&PanelClient>,
    options: RuntimeTickOptions,
) -> Result<RuntimeTickResult, String>
where
    P: ProcessSupervisor,
    F: PortForwardExecutor,
{
    let RuntimeTickOptions {
        control,
        report_to_panel,
        users_by_node_tag,
    } = options;
    let refreshed_plan = if users_by_node_tag.is_empty() {
        None
    } else {
        Some(rebuild_runtime_plan_with_users(plan, &users_by_node_tag)?)
    };
    let active_plan = refreshed_plan.as_ref().unwrap_or(plan);
    let apply = apply_runtime_plan(
        active_plan,
        process_supervisor,
        port_forward_executor,
        control,
    )?;
    let panel_action = if report_to_panel {
        let client = panel_client.ok_or_else(|| {
            "runtime tick requested panel report without panel client".to_string()
        })?;
        report_runtime_apply_result(client, &apply).await?
    } else {
        RuntimePanelAction::default()
    };
    let signal = runtime_loop_signal(&panel_action);

    Ok(RuntimeTickResult {
        apply,
        panel_action,
        signal,
    })
}

pub fn runtime_loop_signal(action: &RuntimePanelAction) -> RuntimeLoopSignal {
    if let Some(upgrade) = &action.upgrade {
        return RuntimeLoopSignal::Upgrade(upgrade.clone());
    }
    if action.reload {
        RuntimeLoopSignal::Reload
    } else {
        RuntimeLoopSignal::Continue
    }
}

pub fn handle_runtime_signal<E: UpgradeExecutor>(
    signal: &RuntimeLoopSignal,
    upgrade_manager: &mut UpgradeManager,
    current_version: &str,
    now: i64,
    upgrade_executor: &mut E,
) -> Result<Option<UpgradeStatus>, String> {
    match signal {
        RuntimeLoopSignal::Upgrade(command) => {
            upgrade_manager.request(command.clone(), current_version, now, upgrade_executor)
        }
        RuntimeLoopSignal::Continue | RuntimeLoopSignal::Reload => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use crate::config::{NodeConfig, ResolvedConfig, ResolvedMachineConfig, SidecarProcessConfig};
    use crate::panel::client::{PanelClient, PanelClientOptions};
    use crate::panel::types::{CommonNode, NodeInfo, UserInfo};
    use crate::port_forward::{PortForwardCommand, PortForwardExecutor};
    use crate::process::{keli_core_rs_control_addr, MemoryProcessSupervisor};
    use crate::runtime::{
        build_runtime_bootstrap_plan, build_runtime_bootstrap_plan_with_users, RuntimeBootstrapPlan,
    };

    use crate::machine::{MachineStatusPayload, MachineStatusResponse, MachineUpgradeCommand};
    use crate::upgrade::{MemoryUpgradeExecutor, UpgradeManager};

    use super::{
        apply_runtime_plan, handle_runtime_signal, machine_status_payload_for_client,
        merge_runtime_panel_action, run_runtime_tick, runtime_loop_signal, runtime_panel_action,
        RuntimeControlOptions, RuntimeLoopSignal, RuntimePanelAction, RuntimeTickOptions,
    };

    #[test]
    fn applies_plan_by_writing_config_starting_core_and_building_status() {
        let dir = temp_test_dir("runtime-control");
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
                node_id: 7,
                machine_id: 3,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let plan = build_runtime_bootstrap_plan(resolved, vec![test_node("vless", 7)], Vec::new())
            .unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();

        let result = apply_runtime_plan(
            &plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                repair_port_forward: true,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();

        assert!(result.core_config.as_ref().unwrap().changed);
        assert_eq!(process.starts.len(), 1);
        assert_eq!(process.stops.len(), 1);
        assert_eq!(
            result.machine_status.status["core"]["status"]["state"],
            json!("running")
        );
        assert_eq!(result.machine_status.status["runtime"]["nodes"], json!(1));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn hot_applies_running_keli_core_rs_config_without_process_reload() {
        let (dir, initial_plan, listener) =
            bindable_keli_core_rs_plan("11111111-1111-1111-1111-111111111111");
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();

        apply_runtime_plan(
            &initial_plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                hot_apply_keli_core_rs: true,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();

        let updated_plan =
            keli_core_rs_plan_with_user(&dir, "22222222-2222-2222-2222-222222222222");
        let (seen_tx, seen_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut command = String::new();
                        BufReader::new(stream.try_clone().unwrap())
                            .read_line(&mut command)
                            .unwrap();
                        let command: serde_json::Value =
                            serde_json::from_str(command.trim()).unwrap();
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
                        seen_tx.send(command).unwrap();
                        return;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            seen_tx
                                .send(json!({ "error": "no hot apply connection" }))
                                .unwrap();
                            return;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept keli-core-rs control connection: {err}"),
                }
            }
        });

        let result = apply_runtime_plan(
            &updated_plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                hot_apply_keli_core_rs: true,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();
        let command = seen_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        assert_eq!(command["type"], json!("apply_config"));
        assert!(command["config"]
            .to_string()
            .contains("22222222-2222-2222-2222-222222222222"));
        assert_eq!(process.starts.len(), 1);
        assert_eq!(process.stops.len(), 1);
        assert!(result
            .core_process
            .as_ref()
            .unwrap()
            .message
            .contains("updated"));
        join.join().unwrap();

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn user_delta_applied_keli_core_rs_config_write_does_not_full_apply_again() {
        let dir = temp_test_dir("keli-core-user-delta-applied");
        let initial_plan =
            keli_core_rs_plan_with_user(&dir, "11111111-1111-1111-1111-111111111111");
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();

        apply_runtime_plan(
            &initial_plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();

        let updated_plan =
            keli_core_rs_plan_with_user(&dir, "22222222-2222-2222-2222-222222222222");
        let result = apply_runtime_plan(
            &updated_plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                hot_apply_keli_core_rs: true,
                keli_core_rs_user_delta_applied: true,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();

        assert_eq!(process.starts.len(), 1);
        assert_eq!(process.stops.len(), 1);
        assert_eq!(
            result.core_process.as_ref().unwrap().message,
            "kept running after keli-core-rs user delta apply"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejected_keli_core_rs_hot_config_does_not_reload_running_process() {
        let (dir, initial_plan, listener) =
            bindable_keli_core_rs_plan("33333333-3333-3333-3333-333333333333");
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();

        apply_runtime_plan(
            &initial_plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                hot_apply_keli_core_rs: true,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();

        let updated_plan =
            keli_core_rs_plan_with_user(&dir, "44444444-4444-4444-4444-444444444444");
        let (seen_tx, seen_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut command = String::new();
                        BufReader::new(stream.try_clone().unwrap())
                            .read_line(&mut command)
                            .unwrap();
                        writeln!(
                            stream,
                            "{}",
                            json!({
                                "type": "error",
                                "message": "invalid hot config"
                            })
                        )
                        .unwrap();
                        seen_tx.send(command).unwrap();
                        return;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            seen_tx.send("no hot apply connection".to_string()).unwrap();
                            return;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept keli-core-rs control connection: {err}"),
                }
            }
        });

        let error = apply_runtime_plan(
            &updated_plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                hot_apply_keli_core_rs: true,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap_err();
        let command = seen_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        assert!(command.contains("\"apply_config\""));
        assert!(error.contains("rejected hot config"));
        assert!(error.contains("invalid hot config"));
        assert_eq!(process.starts.len(), 1);
        assert_eq!(process.stops.len(), 1);
        join.join().unwrap();

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn inspect_mode_does_not_start_core_when_disabled() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: Vec::new(),
        };
        let plan = build_runtime_bootstrap_plan(resolved, Vec::new(), Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();

        let result = apply_runtime_plan(
            &plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 9,
                start_core: false,
                repair_port_forward: false,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();

        assert!(result.core_config.is_none());
        assert!(result.core_process.is_none());
        assert!(process.starts.is_empty());
        assert_eq!(result.machine_status.machine_id, 9);
    }

    #[test]
    fn applies_sidecar_configs_without_starting_xray_core() {
        let dir = temp_test_dir("runtime-sidecar-config");
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
                node_id: 22,
                machine_id: 3,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node("mieru", 22);
        let tag = node.tag.clone();
        let mut users = BTreeMap::new();
        users.insert(
            tag,
            vec![UserInfo {
                id: 22,
                uuid: "mieru-secret".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let plan =
            build_runtime_bootstrap_plan_with_users(resolved, vec![node], Vec::new(), &users)
                .unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();

        let result = apply_runtime_plan(
            &plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();
        let saved = fs::read_to_string(dir.join("v2node").join("sidecar-mieru-22.json")).unwrap();

        assert!(result.core_config.is_none());
        assert_eq!(result.sidecar_configs.len(), 1);
        assert!(result.sidecar_configs[0].changed);
        assert!(result.sidecar_processes.is_empty());
        assert!(process.starts.is_empty());
        assert!(saved.contains("mieru-secret"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn applies_configured_sidecar_processes() {
        let dir = temp_test_dir("runtime-sidecar-process");
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
                node_id: 23,
                machine_id: 3,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node("mieru", 23);
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();
        let mut sidecar_processes = BTreeMap::new();
        sidecar_processes.insert(
            "mieru".to_string(),
            SidecarProcessConfig {
                command: "/usr/local/bin/mita".to_string(),
                args: vec![
                    "run".to_string(),
                    "--config".to_string(),
                    "{config}".to_string(),
                ],
                env: BTreeMap::from([(
                    "MITA_CONFIG_JSON_FILE".to_string(),
                    "{config}".to_string(),
                )]),
            },
        );

        let result = apply_runtime_plan(
            &plan,
            &mut process,
            &mut port_forward,
            RuntimeControlOptions {
                machine_id: 3,
                start_core: true,
                sidecar_processes,
                ..RuntimeControlOptions::default()
            },
        )
        .unwrap();

        assert_eq!(result.sidecar_processes.len(), 1);
        assert_eq!(
            result.machine_status.status["core"]["sidecar_statuses"][0]["state"],
            json!("running")
        );
        assert_eq!(
            result.machine_status.status["core"]["sidecar_statuses"][0]["name"],
            json!("core:sidecar-mieru")
        );
        assert_eq!(process.starts.len(), 1);
        assert_eq!(process.starts[0].name, "core:sidecar-mieru");
        assert_eq!(
            process.starts[0].args,
            vec![
                "run".to_string(),
                "--config".to_string(),
                dir.join("v2node")
                    .join("sidecar-mieru-23.json")
                    .display()
                    .to_string()
            ]
        );
        assert_eq!(
            process.starts[0].env["MITA_CONFIG_JSON_FILE"],
            dir.join("v2node")
                .join("sidecar-mieru-23.json")
                .display()
                .to_string()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn panel_action_preserves_reload_and_upgrade_command() {
        let response = MachineStatusResponse {
            reload: true,
            upgrade: Some(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.1".to_string(),
                component: String::new(),
            }),
        };

        let action = runtime_panel_action(&response);

        assert!(action.reload);
        assert_eq!(action.upgrade.unwrap().target_version, "v0.4.1");
    }

    #[test]
    fn loop_signal_prefers_upgrade_over_reload() {
        let action = RuntimePanelAction {
            reload: true,
            upgrade: Some(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.1".to_string(),
                component: String::new(),
            }),
        };

        assert_eq!(
            runtime_loop_signal(&action),
            RuntimeLoopSignal::Upgrade(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.1".to_string(),
                component: String::new(),
            })
        );
    }

    #[test]
    fn merged_panel_action_preserves_reload_and_first_upgrade() {
        let merged = merge_runtime_panel_action(
            RuntimePanelAction {
                reload: true,
                upgrade: None,
            },
            RuntimePanelAction {
                reload: false,
                upgrade: Some(MachineUpgradeCommand {
                    id: "upgrade-1".to_string(),
                    target_version: "v0.4.1".to_string(),
                    component: String::new(),
                }),
            },
        );
        let merged = merge_runtime_panel_action(
            merged,
            RuntimePanelAction {
                reload: false,
                upgrade: Some(MachineUpgradeCommand {
                    id: "upgrade-2".to_string(),
                    target_version: "v0.4.2".to_string(),
                    component: String::new(),
                }),
            },
        );

        assert!(merged.reload);
        assert_eq!(merged.upgrade.unwrap().id, "upgrade-1");
    }

    #[test]
    fn machine_status_payload_for_client_filters_node_failures_by_profile() {
        let mut payload = MachineStatusPayload::new(1);
        payload.insert_status(
            "node_failures",
            json!([
                {
                    "api_host": "https://panel-a.example.test",
                    "machine_id": 1,
                    "node_id": 7
                },
                {
                    "api_host": "https://panel-b.example.test/",
                    "machine_id": 2,
                    "node_id": 8
                }
            ]),
        );
        let client = PanelClient::new(PanelClientOptions {
            api_host: "https://panel-b.example.test".to_string(),
            token: "token-b".to_string(),
            node_id: 0,
            machine_id: 2,
            timeout: Duration::from_secs(1),
            config_dir: String::new(),
        })
        .unwrap();

        let filtered = machine_status_payload_for_client(&payload, &client);

        assert_eq!(filtered.machine_id, 2);
        assert_eq!(
            filtered.status["node_failures"].as_array().unwrap().len(),
            1
        );
        assert_eq!(filtered.status["node_failures"][0]["node_id"], json!(8));
    }

    #[tokio::test]
    async fn tick_can_run_without_panel_reporting() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: Vec::new(),
        };
        let plan = build_runtime_bootstrap_plan(resolved, Vec::new(), Vec::new()).unwrap();
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();

        let result = run_runtime_tick(
            &plan,
            &mut process,
            &mut port_forward,
            None,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 9,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                ..RuntimeTickOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(result.signal, RuntimeLoopSignal::Continue);
        assert_eq!(result.apply.machine_status.machine_id, 9);
    }

    #[tokio::test]
    async fn tick_can_rebuild_core_plan_with_refreshed_users() {
        let dir = temp_test_dir("runtime-users");
        let mut resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: Vec::new(),
        };
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node("vless", 21);
        let tag = node.tag.clone();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node], Vec::new()).unwrap();
        let mut users_by_node_tag = BTreeMap::new();
        users_by_node_tag.insert(
            tag,
            vec![UserInfo {
                id: 21,
                uuid: "33333333-3333-3333-3333-333333333333".to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        let mut process = MemoryProcessSupervisor::default();
        let mut port_forward = FakePortForwardExecutor::default();

        let result = run_runtime_tick(
            &plan,
            &mut process,
            &mut port_forward,
            None,
            RuntimeTickOptions {
                control: RuntimeControlOptions {
                    machine_id: 21,
                    ..RuntimeControlOptions::default()
                },
                report_to_panel: false,
                users_by_node_tag,
            },
        )
        .await
        .unwrap();
        let saved = fs::read_to_string(dir.join("v2node").join("config.json")).unwrap();

        assert!(result.apply.core_config.unwrap().changed);
        assert!(saved.contains("33333333-3333-3333-3333-333333333333"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn upgrade_signal_enters_upgrade_manager() {
        let mut manager = UpgradeManager::default();
        let mut executor = MemoryUpgradeExecutor::default();
        let signal = RuntimeLoopSignal::Upgrade(MachineUpgradeCommand {
            id: "upgrade-1".to_string(),
            target_version: "v0.4.1".to_string(),
            component: String::new(),
        });

        let status = handle_runtime_signal(&signal, &mut manager, "v0.4.0", 300, &mut executor)
            .unwrap()
            .unwrap();

        assert_eq!(status.status, "running");
        assert_eq!(status.target_version, "v0.4.1");
        assert_eq!(executor.launches.len(), 1);
    }

    #[derive(Default)]
    struct FakePortForwardExecutor {
        available: BTreeSet<String>,
        root: bool,
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
            self.root
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

    fn bindable_keli_core_rs_plan(
        user_uuid: &str,
    ) -> (std::path::PathBuf, RuntimeBootstrapPlan, TcpListener) {
        for attempt in 0..100 {
            let dir = temp_test_dir(&format!("runtime-keli-core-hot-apply-{attempt}"));
            let plan = keli_core_rs_plan_with_user(&dir, user_uuid);
            let addr = keli_core_rs_control_addr(&plan.core_plan.as_ref().unwrap().config_path);
            match TcpListener::bind(addr) {
                Ok(listener) => return (dir, plan, listener),
                Err(_) => {
                    let _ = fs::remove_dir_all(dir);
                }
            }
        }

        panic!("could not bind a keli-core-rs control test port")
    }

    fn keli_core_rs_plan_with_user(dir: &std::path::Path, user_uuid: &str) -> RuntimeBootstrapPlan {
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
                node_id: 17,
                machine_id: 3,
                ..NodeConfig::default()
            }],
        };
        resolved.kernel.r#type = "keli-core-rs".to_string();
        resolved.kernel.config_dir = dir.join("v2node").display().to_string();
        let node = test_node("vless", 17);
        let mut users = BTreeMap::new();
        users.insert(
            node.tag.clone(),
            vec![UserInfo {
                id: 17,
                uuid: user_uuid.to_string(),
                speed_limit: 0,
                device_limit: 0,
            }],
        );
        build_runtime_bootstrap_plan_with_users(resolved, vec![node], Vec::new(), &users).unwrap()
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
