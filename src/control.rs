use std::collections::BTreeMap;

use crate::core::{write_core_config, CoreConfigWriteResult};
use crate::health::{build_machine_status_payload, HealthReportInput};
use crate::machine::{MachineStatusPayload, MachineStatusResponse, MachineUpgradeCommand};
use crate::panel::PanelClient;
use crate::panel::types::UserInfo;
use crate::port_forward::{
    inspect_hysteria_port_forward, repair_hysteria_port_forward, HysteriaPortForwardStatus,
    PortForwardExecutor,
};
use crate::process::{core_process_spec, ProcessStatus, ProcessSupervisor};
use crate::runtime::{build_runtime_bootstrap_plan_with_users, RuntimeBootstrapPlan};
use crate::upgrade::{UpgradeExecutor, UpgradeManager, UpgradeStatus};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuntimeControlOptions {
    pub machine_id: u32,
    pub core_command: Option<String>,
    pub start_core: bool,
    pub repair_port_forward: bool,
    pub health: HealthReportInput,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeApplyResult {
    pub core_config: Option<CoreConfigWriteResult>,
    pub core_process: Option<ProcessStatus>,
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
    let mut core_process = None;

    if let Some(core_plan) = &plan.core_plan {
        let write_result = write_core_config(core_plan).map_err(|err| err.message)?;
        if options.start_core {
            let spec = core_process_spec(core_plan, options.core_command.as_deref())
                .map_err(|err| err.message)?;
            let status = if write_result.changed {
                process_supervisor.reload(&spec)
            } else {
                process_supervisor.start(&spec)
            }
            .map_err(|err| err.message)?;
            core_process = Some(status);
        }
        core_config = Some(write_result);
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
    let machine_status =
        build_machine_status_payload(options.machine_id, &report_plan, health);

    Ok(RuntimeApplyResult {
        core_config,
        core_process,
        hy2_port_forward,
        machine_status,
    })
}

pub async fn report_runtime_apply_result(
    client: &PanelClient,
    result: &RuntimeApplyResult,
) -> Result<RuntimePanelAction, String> {
    report_machine_status_payload(client, result.machine_status.clone()).await
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
        Some(build_runtime_bootstrap_plan_with_users(
            plan.resolved.clone(),
            plan.node_infos.clone(),
            plan.node_failures.clone(),
            &users_by_node_tag,
        )?)
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
        RuntimeLoopSignal::Upgrade(command) => upgrade_manager.request(
            command.clone(),
            current_version,
            now,
            upgrade_executor,
        ),
        RuntimeLoopSignal::Continue | RuntimeLoopSignal::Reload => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use crate::config::{NodeConfig, ResolvedConfig, ResolvedMachineConfig};
    use crate::panel::types::{CommonNode, NodeInfo, UserInfo};
    use crate::port_forward::{PortForwardCommand, PortForwardExecutor};
    use crate::process::MemoryProcessSupervisor;
    use crate::runtime::build_runtime_bootstrap_plan;

    use crate::machine::{MachineStatusResponse, MachineUpgradeCommand};
    use crate::upgrade::{MemoryUpgradeExecutor, UpgradeManager};

    use super::{
        apply_runtime_plan, handle_runtime_signal, run_runtime_tick, runtime_loop_signal,
        runtime_panel_action, RuntimeControlOptions, RuntimeLoopSignal, RuntimePanelAction,
        RuntimeTickOptions,
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
        let plan =
            build_runtime_bootstrap_plan(resolved, vec![test_node("vless", 7)], Vec::new())
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
        assert_eq!(
            result.machine_status.status["runtime"]["nodes"],
            json!(1)
        );

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
    fn panel_action_preserves_reload_and_upgrade_command() {
        let response = MachineStatusResponse {
            reload: true,
            upgrade: Some(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.1".to_string(),
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
            }),
        };

        assert_eq!(
            runtime_loop_signal(&action),
            RuntimeLoopSignal::Upgrade(MachineUpgradeCommand {
                id: "upgrade-1".to_string(),
                target_version: "v0.4.1".to_string(),
            })
        );
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
        });

        let status =
            handle_runtime_signal(&signal, &mut manager, "v0.4.0", 300, &mut executor)
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
