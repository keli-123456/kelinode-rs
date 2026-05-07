#![forbid(unsafe_code)]

use kelinode_rs::config::AppConfig;
use kelinode_rs::control::{handle_runtime_signal, RuntimeControlOptions, RuntimeLoopSignal};
use kelinode_rs::panel::client::{PanelClient, PanelClientOptions};
use kelinode_rs::panel::contract::NODE_API_CONTRACT_VERSION;
use kelinode_rs::port_forward::SystemPortForwardExecutor;
use kelinode_rs::process::{core_process_spec, ProcessSupervisor, SystemProcessSupervisor};
use kelinode_rs::runner::{
    run_runtime_loop_async, PanelRuntimeLoop, RuntimeLoopExit, RuntimeLoopExitReason,
    RuntimeLoopOptions,
};
use kelinode_rs::runtime::{bootstrap_from_config, Bootstrap, RuntimeBootstrapPlan};
use kelinode_rs::upgrade::{SystemUpgradeExecutor, UpgradeManager};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "version".to_string());
    match command.as_str() {
        "version" => {
            println!(
                "kelinode-rs {} contract={}",
                env!("CARGO_PKG_VERSION"),
                NODE_API_CONTRACT_VERSION
            );
        }
        "check-config" => {
            let path = args
                .next()
                .unwrap_or_else(|| "/etc/v2node/config.yml".to_string());
            let config = AppConfig::load_from_path(path)?;
            let resolved = config.resolve_runtime()?;
            let bootstrap = Bootstrap::from_config(&config);
            println!(
                "mode={:?} nodes={} machine_profiles={} subscription_proxy={}",
                bootstrap.mode,
                resolved.nodes.len(),
                resolved.machine.profiles.len(),
                resolved.agent.subscription_proxy.enabled
            );
        }
        "run" => {
            let path = args
                .next()
                .unwrap_or_else(|| "/etc/v2node/config.yml".to_string());
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|err| format!("start tokio runtime: {err}"))?;
            runtime.block_on(run_agent(&path))?;
        }
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            return Err("invalid command".to_string());
        }
    }
    Ok(())
}

async fn run_agent(path: &str) -> Result<(), String> {
    let mut process_supervisor = SystemProcessSupervisor::default();
    let mut port_forward_executor = SystemPortForwardExecutor::default();
    let mut upgrade_manager = UpgradeManager::default();
    let mut upgrade_executor = SystemUpgradeExecutor::default();

    loop {
        let exit = run_agent_once(
            path,
            &mut process_supervisor,
            &mut port_forward_executor,
            upgrade_manager.current_status_value(),
        )
        .await?;
        println!(
            "runtime loop exited after {} ticks: {:?}",
            exit.ticks, exit.reason
        );

        match exit.reason {
            RuntimeLoopExitReason::MaxTicks => return Ok(()),
            RuntimeLoopExitReason::Shutdown => return Ok(()),
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Continue) => {}
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Reload) => {
                println!("runtime reload requested; rebuilding bootstrap plan");
            }
            RuntimeLoopExitReason::Signal(signal @ RuntimeLoopSignal::Upgrade(_)) => {
                let current_version = agent_version();
                if let Err(err) = handle_runtime_signal(
                    &signal,
                    &mut upgrade_manager,
                    &current_version,
                    unix_now(),
                    &mut upgrade_executor,
                ) {
                    eprintln!("runtime upgrade command ignored: {err}");
                }
            }
        }
    }
}

async fn run_agent_once(
    path: &str,
    process_supervisor: &mut SystemProcessSupervisor,
    port_forward_executor: &mut SystemPortForwardExecutor,
    upgrade_status: Option<Value>,
) -> Result<RuntimeLoopExit, String> {
    let config = AppConfig::load_from_path(path)?;
    let plan = bootstrap_from_config(&config).await?;
    let panel_clients = machine_panel_clients(&plan)?;
    let options = runtime_loop_options(&plan, !panel_clients.is_empty());
    let mut runner = PanelRuntimeLoop::new(
        plan,
        process_supervisor,
        port_forward_executor,
        None,
    )
    .with_panel_clients(panel_clients)
    .with_health_refresh(agent_version())
    .with_upgrade_status(upgrade_status);
    let mut shutdown = false;
    let result = tokio::select! {
        result = run_runtime_loop_async(&mut runner, options) => result,
        signal = wait_shutdown_signal() => {
            signal?;
            shutdown = true;
            Ok(RuntimeLoopExit {
                ticks: 0,
                reason: RuntimeLoopExitReason::Shutdown,
            })
        }
    };
    if shutdown {
        stop_core_for_plan(&mut runner)?;
    }
    result
}

fn stop_core_for_plan<P, F>(runner: &mut PanelRuntimeLoop<'_, P, F>) -> Result<(), String>
where
    P: ProcessSupervisor,
    F: kelinode_rs::port_forward::PortForwardExecutor,
{
    let Some(core_plan) = runner.plan.core_plan.as_ref() else {
        return Ok(());
    };
    let spec = core_process_spec(core_plan, None).map_err(|err| err.message)?;
    runner
        .process_supervisor
        .stop(&spec.name)
        .map_err(|err| err.message)?;
    Ok(())
}

async fn wait_shutdown_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|err| format!("register SIGTERM handler: {err}"))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|err| format!("listen for Ctrl-C: {err}"))
            }
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|err| format!("listen for Ctrl-C: {err}"))
    }
}

fn machine_panel_clients(plan: &RuntimeBootstrapPlan) -> Result<Vec<PanelClient>, String> {
    let mut seen = BTreeSet::new();
    let mut clients = Vec::new();

    for config in plan.resolved.nodes.iter().filter(|config| config.machine_id > 0) {
        let key = format!(
            "{}#{}#{}",
            config.url.trim_end_matches('/'),
            config.machine_id,
            config.token
        );
        if !seen.insert(key) {
            continue;
        }
        clients.push(
            PanelClient::new(PanelClientOptions::from(config))
                .map_err(|err| err.to_string())?,
        );
    }

    Ok(clients)
}

fn runtime_loop_options(
    plan: &RuntimeBootstrapPlan,
    report_to_panel: bool,
) -> RuntimeLoopOptions {
    let mut options = RuntimeLoopOptions {
        control: RuntimeControlOptions {
            machine_id: plan
                .resolved
                .nodes
                .iter()
                .find_map(|config| {
                    if config.machine_id > 0 {
                        Some(config.machine_id)
                    } else {
                        None
                    }
                })
                .unwrap_or_default(),
            start_core: true,
            repair_port_forward: true,
            ..RuntimeControlOptions::default()
        },
        tick_interval: runtime_tick_interval(plan),
        user_refresh_interval: 1,
        panel_report_interval: if report_to_panel { 1 } else { 0 },
        ..RuntimeLoopOptions::default()
    };
    if options.tick_interval == Duration::from_secs(0) {
        options.tick_interval = Duration::from_secs(60);
    }
    options
}

fn runtime_tick_interval(plan: &RuntimeBootstrapPlan) -> Duration {
    let seconds = plan
        .node_infos
        .iter()
        .filter_map(|node| {
            let push = node.push_interval.as_secs();
            let pull = node.pull_interval.as_secs();
            let value = match (push, pull) {
                (0, 0) => 0,
                (0, value) | (value, 0) => value,
                (left, right) => left.min(right),
            };
            if value > 0 {
                Some(value)
            } else {
                None
            }
        })
        .min()
        .unwrap_or(60);
    Duration::from_secs(seconds)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn agent_version() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

fn print_help() {
    println!("kelinode-rs commands:");
    println!("  version    print version and API contract");
    println!("  check-config [path]    load config and print resolved runtime shape");
    println!("  run [path]    start the node runtime loop");
}

#[cfg(test)]
mod tests {
    use super::{machine_panel_clients, runtime_loop_options, runtime_tick_interval};
    use kelinode_rs::config::{NodeConfig, ResolvedConfig, ResolvedMachineConfig};
    use kelinode_rs::panel::types::{CommonNode, NodeInfo};
    use kelinode_rs::runtime::{build_runtime_bootstrap_plan, RuntimeBootstrapPlan};
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn runtime_loop_options_keep_binary_machine_reporting_enabled() {
        let plan = test_plan(
            vec![test_node_with_intervals(7, 30, 45)],
            vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 7,
                machine_id: 33,
                ..NodeConfig::default()
            }],
        );

        let options = runtime_loop_options(&plan, true);

        assert_eq!(options.control.machine_id, 33);
        assert!(options.control.start_core);
        assert!(options.control.repair_port_forward);
        assert_eq!(options.panel_report_interval, 1);
        assert_eq!(options.tick_interval, Duration::from_secs(30));
    }

    #[test]
    fn runtime_loop_options_keep_direct_node_panel_reports_disabled() {
        let plan = test_plan(Vec::new(), Vec::new());

        let options = runtime_loop_options(&plan, false);

        assert_eq!(options.control.machine_id, 0);
        assert_eq!(options.panel_report_interval, 0);
        assert_eq!(runtime_tick_interval(&plan), Duration::from_secs(60));
    }

    #[test]
    fn machine_panel_clients_deduplicate_machine_profiles() {
        let plan = test_plan(
            Vec::new(),
            vec![
                NodeConfig {
                    url: "https://panel-a.example.test/".to_string(),
                    token: "token-a".to_string(),
                    node_id: 7,
                    machine_id: 1,
                    ..NodeConfig::default()
                },
                NodeConfig {
                    url: "https://panel-a.example.test".to_string(),
                    token: "token-a".to_string(),
                    node_id: 8,
                    machine_id: 1,
                    ..NodeConfig::default()
                },
                NodeConfig {
                    url: "https://panel-b.example.test".to_string(),
                    token: "token-b".to_string(),
                    node_id: 9,
                    machine_id: 2,
                    ..NodeConfig::default()
                },
            ],
        );

        let clients = machine_panel_clients(&plan).unwrap();

        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].options().machine_id, 1);
        assert_eq!(clients[1].options().machine_id, 2);
    }

    fn test_plan(nodes: Vec<NodeInfo>, configs: Vec<NodeConfig>) -> RuntimeBootstrapPlan {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles: Vec::new(),
            },
            agent: Default::default(),
            nodes: configs,
        };

        build_runtime_bootstrap_plan(resolved, nodes, Vec::new()).unwrap()
    }

    fn test_node_with_intervals(node_id: u32, push: u64, pull: u64) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "vless",
            "server_port": 10000 + node_id,
            "base_config": {
                "push_interval": push,
                "pull_interval": pull
            }
        }))
        .unwrap();

        NodeInfo::from_common("https://panel.example.test", node_id, common).unwrap()
    }
}
