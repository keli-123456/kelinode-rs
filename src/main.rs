#![forbid(unsafe_code)]

use kelinode_rs::config::{AppConfig, MachineProfileConfig, DEFAULT_TIMEOUT_SECS};
use kelinode_rs::control::{handle_runtime_signal, RuntimeControlOptions, RuntimeLoopSignal};
use kelinode_rs::core::{build_inbound_plan, keli_core_rs_inbound_capability};
use kelinode_rs::logging;
use kelinode_rs::native_capability::{
    entry_allowed_by_explicit_native_canary_env, RenderDecision, NATIVE_CANARY_ALLOW_ENV,
};
use kelinode_rs::panel::client::{PanelClient, PanelClientOptions};
use kelinode_rs::panel::contract::NODE_API_CONTRACT_VERSION;
use kelinode_rs::port_forward::{
    cleanup_hysteria_port_forward, inspect_hysteria_port_forward, repair_hysteria_port_forward,
    HysteriaPortForwardStatus, SystemPortForwardExecutor,
};
use kelinode_rs::process::{core_process_spec, ProcessSupervisor, SystemProcessSupervisor};
use kelinode_rs::runner::{
    run_runtime_loop_async_with_events, start_realtime_runtime_workers, PanelRuntimeLoop,
    RuntimeLoopExit, RuntimeLoopExitReason, RuntimeLoopOptions,
};
use kelinode_rs::runtime::{bootstrap_from_config, Bootstrap, RuntimeBootstrapPlan};
use kelinode_rs::subscription_proxy::{
    ensure_subscription_proxy_csr_with_openssl, SubscriptionProxyRuntimeManager,
};
use kelinode_rs::upgrade::{SystemUpgradeExecutor, UpgradeManager};
use serde_json::Value;
use std::collections::BTreeSet;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_CONFIG_FILE: &str = "/etc/kelinode/config.yml";
const DEFAULT_SERVICE_NAME: &str = "kelinode";

fn main() {
    apply_embedded_core_process_defaults();
    if let Err(err) = run() {
        logging::error("agent", err);
        std::process::exit(1);
    }
}

#[cfg(feature = "embedded-core")]
fn apply_embedded_core_process_defaults() {
    keli_core_rs::apply_process_memory_defaults();
}

#[cfg(not(feature = "embedded-core"))]
fn apply_embedded_core_process_defaults() {}

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
            let path = config_path_from_args(args, DEFAULT_CONFIG_FILE)?;
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
        "gray-preflight" => {
            let path = config_path_from_args(args, DEFAULT_CONFIG_FILE)?;
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|err| format!("start tokio runtime: {err}"))?;
            let report = runtime.block_on(run_native_gray_preflight(&path))?;
            print_native_gray_preflight_report(&report);
            if !report.errors.is_empty() {
                return Err("native gray preflight failed".to_string());
            }
        }
        "rules" => {
            let args = args.collect::<Vec<_>>();
            let (action, config_args) = parse_rules_args(&args)?;
            let path = config_path_from_args(config_args, DEFAULT_CONFIG_FILE)?;
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|err| format!("start tokio runtime: {err}"))?;
            let status = runtime.block_on(run_rules_command(&path, action))?;
            print_hy2_rules_status(&status)?;
            if !status.errors.is_empty() {
                return Err("HY2 port forwarding has errors".to_string());
            }
        }
        "log" | "logs" => {
            let args = args.collect::<Vec<_>>();
            if args
                .iter()
                .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
            {
                print_log_help();
                return Ok(());
            }
            let options = parse_log_args(args)?;
            run_log_command(options)?;
        }
        "run" | "server" => {
            let path = config_path_from_args(args, DEFAULT_CONFIG_FILE)?;
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

fn config_path_from_args(
    args: impl IntoIterator<Item = String>,
    default_path: &str,
) -> Result<String, String> {
    let mut path: Option<String> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a config path"))?;
                path = Some(value);
            }
            value if value.starts_with("--config=") => {
                path = Some(value.trim_start_matches("--config=").to_string());
            }
            value if value.starts_with("-c=") => {
                path = Some(value.trim_start_matches("-c=").to_string());
            }
            "--" => {
                if let Some(value) = iter.next() {
                    path = Some(value);
                }
                break;
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown config option {value}"));
            }
            value => {
                path = Some(value.to_string());
            }
        }
    }

    Ok(path.unwrap_or_else(|| default_path.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RulesAction {
    Status,
    Repair,
    Cleanup,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogOptions {
    tail: usize,
    follow: bool,
    raw: bool,
}

fn parse_rules_args(args: &[String]) -> Result<(RulesAction, Vec<String>), String> {
    let Some(first) = args.first() else {
        return Ok((RulesAction::Status, Vec::new()));
    };
    if first.starts_with('-') {
        return Ok((RulesAction::Status, args.to_vec()));
    }

    let action = match first.as_str() {
        "status" => RulesAction::Status,
        "repair" => RulesAction::Repair,
        "cleanup" | "clean" => RulesAction::Cleanup,
        other => return Err(format!("unknown rules action: {other}")),
    };
    Ok((action, args[1..].to_vec()))
}

fn parse_log_args(args: impl IntoIterator<Item = String>) -> Result<LogOptions, String> {
    let mut options = LogOptions {
        tail: 200,
        follow: true,
        raw: false,
    };
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--tail" | "-n" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a line count"))?;
                options.tail = value
                    .parse::<usize>()
                    .map_err(|_| format!("{arg} requires a positive integer"))?;
                if options.tail == 0 {
                    return Err(format!("{arg} requires a positive integer"));
                }
            }
            value if value.starts_with("--tail=") => {
                let value = value.trim_start_matches("--tail=");
                options.tail = value
                    .parse::<usize>()
                    .map_err(|_| "--tail requires a positive integer".to_string())?;
                if options.tail == 0 {
                    return Err("--tail requires a positive integer".to_string());
                }
            }
            "--no-follow" => options.follow = false,
            "--follow" | "-f" => options.follow = true,
            "--raw" => options.raw = true,
            other => return Err(format!("unknown log option {other}")),
        }
    }
    Ok(options)
}

fn run_log_command(options: LogOptions) -> Result<(), String> {
    let mut command = Command::new("journalctl");
    command
        .arg("-u")
        .arg(DEFAULT_SERVICE_NAME)
        .arg("-n")
        .arg(options.tail.to_string())
        .arg("--no-pager")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if !options.raw {
        command.arg("--output").arg("cat");
    }
    if options.follow {
        command.arg("-f");
    }

    match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!(
            "journalctl exited with status {status}; try: journalctl -u {DEFAULT_SERVICE_NAME} -n {} --no-pager{}{}",
            options.tail,
            if options.raw { "" } else { " --output cat" },
            if options.follow { " -f" } else { "" }
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(
            format!("journalctl is not available on this system; use your service manager logs, or run kelinode server --config {DEFAULT_CONFIG_FILE} in the foreground")
                .to_string(),
        ),
        Err(err) => Err(format!("run journalctl: {err}")),
    }
}

async fn run_rules_command(
    path: &str,
    action: RulesAction,
) -> Result<HysteriaPortForwardStatus, String> {
    let mut executor = SystemPortForwardExecutor::default();
    if action == RulesAction::Cleanup {
        return Ok(cleanup_hysteria_port_forward(&mut executor));
    }

    let config = AppConfig::load_from_path(path)?;
    let plan = bootstrap_from_config(&config).await?;
    Ok(match action {
        RulesAction::Status => inspect_hysteria_port_forward(&plan.node_infos, &mut executor),
        RulesAction::Repair => repair_hysteria_port_forward(&plan.node_infos, &mut executor),
        RulesAction::Cleanup => unreachable!("cleanup returned before config load"),
    })
}

fn print_hy2_rules_status(status: &HysteriaPortForwardStatus) -> Result<(), String> {
    let output = serde_json::to_string_pretty(status)
        .map_err(|err| format!("serialize HY2 rules status: {err}"))?;
    println!("{output}");
    Ok(())
}

async fn run_native_gray_preflight(path: &str) -> Result<NativeGrayPreflightReport, String> {
    let config = AppConfig::load_from_path(path)?;
    match bootstrap_from_config(&config).await {
        Ok(plan) => Ok(native_gray_preflight_report(&plan)),
        Err(error) => {
            let mut report = NativeGrayPreflightReport::default();
            report.errors.push(format!("runtime plan failed: {error}"));
            Ok(report)
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeGrayPreflightReport {
    details: Vec<String>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

fn native_gray_preflight_report(plan: &RuntimeBootstrapPlan) -> NativeGrayPreflightReport {
    let mut report = NativeGrayPreflightReport::default();
    report
        .details
        .push(format!("mode={:?}", plan.bootstrap.mode));
    report
        .details
        .push(format!("resolved_nodes={}", plan.node_infos.len()));
    report.details.push(format!(
        "machine_profiles={}",
        plan.resolved.machine.profiles.len()
    ));

    for failure in &plan.node_failures {
        report.errors.push(format!(
            "node resolve failed: api_host={} node_id={} machine_id={} error={}",
            failure.config.url, failure.config.node_id, failure.config.machine_id, failure.error
        ));
    }

    push_native_capability_preflight_findings(plan, &mut report);

    let Some(core_plan) = plan.core_plan.as_ref() else {
        report
            .errors
            .push("no primary core plan was built for this config".to_string());
        return report;
    };

    report
        .details
        .push(format!("native_inbounds={}", core_plan.inbounds.len()));
    if core_plan.inbounds.is_empty() {
        report
            .errors
            .push("native core plan has no inbounds".to_string());
    }

    if core_plan
        .inbounds
        .iter()
        .all(|inbound| inbound.users.is_empty())
    {
        report.warnings.push(
            "preflight checks node config without panel user list; verify user sync and ApplyUserDelta during the smoke window"
                .to_string(),
        );
    }

    for inbound in &core_plan.inbounds {
        if !is_wildcard_listen(&inbound.listen) {
            report.warnings.push(format!(
                "inbound {} listens on explicit address {}; automatic dual-stack wildcard does not apply",
                inbound.tag, inbound.listen
            ));
        }
        if inbound.port == 0 {
            report
                .errors
                .push(format!("inbound {} has empty server port", inbound.tag));
        }
    }

    report
}

fn push_native_capability_preflight_findings(
    plan: &RuntimeBootstrapPlan,
    report: &mut NativeGrayPreflightReport,
) {
    for node in &plan.node_infos {
        let entry = match build_inbound_plan(node).and_then(|inbound| {
            keli_core_rs_inbound_capability(&inbound).map_err(|err| {
                kelinode_rs::core::CoreError::new(format!(
                    "native capability classify failed for inbound {}: {}",
                    inbound.tag, err.message
                ))
            })
        }) {
            Ok(entry) => entry,
            Err(error) => {
                report.errors.push(error.message);
                continue;
            }
        };

        match &entry.decision {
            RenderDecision::RenderNative => {}
            RenderDecision::RenderNativeWithWarning => report.warnings.push(format!(
                "native capability warning: {}",
                entry.gate_message()
            )),
            RenderDecision::Reject { .. }
                if entry_allowed_by_explicit_native_canary_env(&entry) =>
            {
                report.warnings.push(format!(
                    "native capability canary override env={}: {}",
                    NATIVE_CANARY_ALLOW_ENV,
                    entry.gate_message()
                ))
            }
            RenderDecision::FallbackGo | RenderDecision::Reject { .. } => report.errors.push(
                format!("native capability blocker: {}", entry.gate_message()),
            ),
        }
    }
}

fn is_wildcard_listen(value: &str) -> bool {
    matches!(value.trim(), "" | "0.0.0.0" | "::" | "[::]")
}

fn print_native_gray_preflight_report(report: &NativeGrayPreflightReport) {
    if report.errors.is_empty() {
        println!("native gray preflight: ok");
    } else {
        println!("native gray preflight: failed");
    }
    for detail in &report.details {
        println!("  {detail}");
    }
    for warning in &report.warnings {
        println!("  warning: {warning}");
    }
    for error in &report.errors {
        println!("  error: {error}");
    }
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
        logging::info(
            "agent",
            format!(
                "runtime loop exited ticks={} reason={:?}",
                exit.ticks, exit.reason
            ),
        );

        match exit.reason {
            RuntimeLoopExitReason::MaxTicks => return Ok(()),
            RuntimeLoopExitReason::Shutdown => return Ok(()),
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Continue) => {}
            RuntimeLoopExitReason::Signal(RuntimeLoopSignal::Reload) => {
                logging::info(
                    "agent",
                    "runtime reload requested; rebuilding bootstrap plan",
                );
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
                    logging::warn("upgrade", format!("runtime upgrade command ignored: {err}"));
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
    logging::info("agent", format!("loading config path={path}"));
    let config = AppConfig::load_from_path(path)?;
    logging::info("agent", "building runtime bootstrap");
    let plan = bootstrap_from_config(&config).await?;
    logging::info(
        "agent",
        format!(
            "bootstrap ready mode={:?} resolved_nodes={} active_nodes={} machine_profiles={} realtime_workers={}",
        plan.bootstrap.mode,
        plan.resolved.nodes.len(),
        plan.node_count,
        plan.resolved.machine.profiles.len(),
        plan.realtime_options.len()
        ),
    );
    for failure in &plan.node_failures {
        logging::warn(
            "node",
            format!(
                "skipped api_host={} node_id={} machine_id={} error={}",
                failure.config.url,
                failure.config.node_id,
                failure.config.machine_id,
                failure.error
            ),
        );
    }
    let panel_clients = machine_panel_clients(&plan)?;
    logging::info("panel", format!("clients={}", panel_clients.len()));
    let options = runtime_loop_options(&plan, !panel_clients.is_empty());
    let realtime_options = plan.realtime_options.clone();
    let subscription_proxy_manager = start_subscription_proxy_manager(&plan);
    let mut runner = PanelRuntimeLoop::new(plan, process_supervisor, port_forward_executor, None)
        .with_panel_clients(panel_clients)
        .with_health_refresh(agent_version())
        .with_public_ip_probe(true)
        .with_upgrade_status(upgrade_status);
    if let Some(manager) = subscription_proxy_manager {
        runner = runner.with_subscription_proxy_manager(manager);
    }
    let mut realtime_workers = start_realtime_runtime_workers(realtime_options);
    logging::info("agent", "runtime loop started");
    let mut shutdown = false;
    let result = tokio::select! {
        result = run_runtime_loop_async_with_events(
            &mut runner,
            options,
            realtime_workers.events(),
        ) => result,
        signal = wait_shutdown_signal() => {
            signal?;
            shutdown = true;
            Ok(RuntimeLoopExit {
                ticks: 0,
                reason: RuntimeLoopExitReason::Shutdown,
            })
        }
    };
    tokio::task::yield_now().await;
    realtime_workers.abort();
    if shutdown {
        stop_core_for_plan(&mut runner)?;
        cleanup_hy2_port_forward_on_shutdown(&mut runner);
    }
    result
}

fn start_subscription_proxy_manager(
    plan: &RuntimeBootstrapPlan,
) -> Option<SubscriptionProxyRuntimeManager> {
    let config = &plan.resolved.agent.subscription_proxy;
    if !config.enabled {
        return None;
    }
    let mut manager = SubscriptionProxyRuntimeManager::new();
    if let Err(err) =
        manager.apply_and_start_with_file_system(config, ensure_subscription_proxy_csr_with_openssl)
    {
        logging::warn("subproxy", format!("start failed error={err}"));
    }
    Some(manager)
}

fn stop_core_for_plan<P, F>(runner: &mut PanelRuntimeLoop<'_, P, F>) -> Result<(), String>
where
    P: ProcessSupervisor,
    F: kelinode_rs::port_forward::PortForwardExecutor,
{
    if let Some(core_plan) = runner.plan.core_plan.as_ref() {
        let spec = core_process_spec(
            core_plan,
            non_empty_command_override(&runner.plan.resolved.kernel.core_command),
        )
        .map_err(|err| err.message)?;
        runner
            .process_supervisor
            .stop(&spec.name)
            .map_err(|err| err.message)?;
    }

    Ok(())
}

fn cleanup_hy2_port_forward_on_shutdown<P, F>(runner: &mut PanelRuntimeLoop<'_, P, F>)
where
    P: ProcessSupervisor,
    F: kelinode_rs::port_forward::PortForwardExecutor,
{
    let status = cleanup_hysteria_port_forward(&mut *runner.port_forward_executor);
    if !status.errors.is_empty() {
        logging::warn(
            "hy2",
            format!("port forwarding cleanup: {}", status.errors.join("; ")),
        );
    }
    for tool in status.tools.iter().filter(|tool| !tool.error.is_empty()) {
        logging::warn(
            "hy2",
            format!(
                "port forwarding cleanup tool={} error={}",
                tool.tool, tool.error
            ),
        );
    }
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

    for config in plan
        .resolved
        .nodes
        .iter()
        .filter(|config| config.machine_id > 0)
    {
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
            PanelClient::new(PanelClientOptions::from(config)).map_err(|err| err.to_string())?,
        );
    }
    for profile in plan
        .resolved
        .machine
        .profiles
        .iter()
        .filter(|profile| profile.machine_id > 0)
    {
        let key = format!(
            "{}#{}#{}",
            profile.url.trim_end_matches('/'),
            profile.machine_id,
            profile.token
        );
        if !seen.insert(key) {
            continue;
        }
        clients.push(
            PanelClient::new(panel_options_from_machine_profile(profile))
                .map_err(|err| err.to_string())?,
        );
    }

    Ok(clients)
}

fn panel_options_from_machine_profile(profile: &MachineProfileConfig) -> PanelClientOptions {
    let timeout = if profile.timeout == 0 {
        DEFAULT_TIMEOUT_SECS
    } else {
        profile.timeout
    };
    PanelClientOptions {
        api_host: profile.url.clone(),
        token: profile.token.clone(),
        node_id: 0,
        machine_id: profile.machine_id,
        timeout: Duration::from_secs(timeout),
        config_dir: profile.config_dir.clone(),
    }
}

fn runtime_loop_options(plan: &RuntimeBootstrapPlan, report_to_panel: bool) -> RuntimeLoopOptions {
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
                .or_else(|| {
                    plan.resolved.machine.profiles.iter().find_map(|profile| {
                        if profile.machine_id > 0 {
                            Some(profile.machine_id)
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_default(),
            core_command: non_empty_command_override(&plan.resolved.kernel.core_command)
                .map(str::to_string),
            start_core: true,
            hot_apply_keli_core_rs: true,
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

fn non_empty_command_override(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
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
    println!("kelinode commands:");
    println!("  version    print version and API contract");
    println!("  check-config [path|--config path]    load config and print resolved runtime shape");
    println!(
        "  gray-preflight [path|--config path]    check whether config is ready for native core gray release"
    );
    println!(
        "  rules [status|repair|cleanup] [path|--config path]    inspect or reconcile HY2 iptables rules"
    );
    println!("  log [--tail N] [--no-follow] [--raw]    show kelinode service logs");
    println!("  run|server [path|--config path]    start the node runtime loop");
}

fn print_log_help() {
    println!("kelinode log command:");
    println!("  kelinode log                 show and follow the last 200 service log lines");
    println!("  kelinode log --tail 500      show and follow the last 500 service log lines");
    println!("  kelinode log --no-follow     print recent logs and exit");
    println!("  kelinode log --raw           show raw journalctl metadata");
}

#[cfg(test)]
mod tests {
    use super::{
        apply_embedded_core_process_defaults, config_path_from_args, machine_panel_clients,
        native_gray_preflight_report, parse_log_args, parse_rules_args, runtime_loop_options,
        runtime_tick_interval, start_subscription_proxy_manager, LogOptions, RulesAction,
        DEFAULT_CONFIG_FILE,
    };
    use kelinode_rs::config::{
        AgentConfig, MachineProfileConfig, NodeConfig, ResolvedConfig, ResolvedMachineConfig,
        SubscriptionProxyConfig,
    };
    use kelinode_rs::core::CoreKind;
    use kelinode_rs::panel::types::{CommonNode, NodeInfo};
    use kelinode_rs::runtime::{build_runtime_bootstrap_plan, RuntimeBootstrapPlan};
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn embedded_core_process_defaults_are_safe_to_apply() {
        apply_embedded_core_process_defaults();
    }

    #[test]
    fn config_path_parser_accepts_legacy_config_flags() {
        assert_eq!(
            config_path_from_args(Vec::<String>::new(), DEFAULT_CONFIG_FILE).unwrap(),
            DEFAULT_CONFIG_FILE
        );
        assert_eq!(
            config_path_from_args(
                vec!["--config".to_string(), "/tmp/a.yml".to_string()],
                DEFAULT_CONFIG_FILE,
            )
            .unwrap(),
            "/tmp/a.yml"
        );
        assert_eq!(
            config_path_from_args(vec!["-c=/tmp/b.yml".to_string()], DEFAULT_CONFIG_FILE,).unwrap(),
            "/tmp/b.yml"
        );
        assert_eq!(
            config_path_from_args(vec!["/tmp/c.yml".to_string()], DEFAULT_CONFIG_FILE,).unwrap(),
            "/tmp/c.yml"
        );
    }

    #[test]
    fn rules_args_default_to_status_and_parse_action() {
        assert_eq!(
            parse_rules_args(&[]).unwrap(),
            (RulesAction::Status, Vec::<String>::new())
        );
        assert_eq!(
            parse_rules_args(&["--config".to_string(), "node.yml".to_string()]).unwrap(),
            (
                RulesAction::Status,
                vec!["--config".to_string(), "node.yml".to_string()]
            )
        );
        assert_eq!(
            parse_rules_args(&[
                "repair".to_string(),
                "--config".to_string(),
                "node.yml".to_string()
            ])
            .unwrap(),
            (
                RulesAction::Repair,
                vec!["--config".to_string(), "node.yml".to_string()]
            )
        );
        assert_eq!(
            parse_rules_args(&["cleanup".to_string()]).unwrap(),
            (RulesAction::Cleanup, Vec::<String>::new())
        );
    }

    #[test]
    fn log_args_parse_tail_and_follow_options() {
        assert_eq!(
            parse_log_args(Vec::<String>::new()).unwrap(),
            LogOptions {
                tail: 200,
                follow: true,
                raw: false,
            }
        );
        assert_eq!(
            parse_log_args(vec!["--tail".to_string(), "500".to_string()]).unwrap(),
            LogOptions {
                tail: 500,
                follow: true,
                raw: false,
            }
        );
        assert_eq!(
            parse_log_args(vec!["--tail=50".to_string(), "--no-follow".to_string()]).unwrap(),
            LogOptions {
                tail: 50,
                follow: false,
                raw: false,
            }
        );
        assert_eq!(
            parse_log_args(vec![
                "--raw".to_string(),
                "-n".to_string(),
                "20".to_string()
            ])
            .unwrap(),
            LogOptions {
                tail: 20,
                follow: true,
                raw: true,
            }
        );
        assert!(parse_log_args(vec!["--tail".to_string(), "0".to_string()]).is_err());
        assert!(parse_log_args(vec!["--bad".to_string()]).is_err());
    }

    #[test]
    fn runtime_loop_options_keep_binary_machine_reporting_enabled() {
        let mut plan = test_plan(
            vec![test_node_with_intervals(7, 30, 45)],
            vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 7,
                machine_id: 33,
                ..NodeConfig::default()
            }],
        );
        plan.resolved.kernel.core_command = "/opt/keli/bin/keli-core-rs".to_string();

        let options = runtime_loop_options(&plan, true);

        assert_eq!(options.control.machine_id, 33);
        assert_eq!(
            options.control.core_command.as_deref(),
            Some("/opt/keli/bin/keli-core-rs")
        );
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

    #[test]
    fn machine_panel_clients_include_subscription_proxy_only_profiles() {
        let plan = test_plan_with_machine_profiles(
            Vec::new(),
            Vec::new(),
            vec![MachineProfileConfig {
                url: "https://panel.example.test".to_string(),
                token: "machine-token".to_string(),
                machine_id: 6,
                timeout: 12,
                ..MachineProfileConfig::default()
            }],
        );

        let clients = machine_panel_clients(&plan).unwrap();
        let options = runtime_loop_options(&plan, true);

        assert!(plan.subscription_proxy_only);
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].options().api_host, "https://panel.example.test");
        assert_eq!(clients[0].options().machine_id, 6);
        assert_eq!(clients[0].options().node_id, 0);
        assert_eq!(clients[0].options().timeout, Duration::from_secs(12));
        assert_eq!(options.control.machine_id, 6);
    }

    #[test]
    fn subscription_proxy_manager_is_not_started_when_disabled() {
        let plan = test_plan(Vec::new(), Vec::new());

        assert!(start_subscription_proxy_manager(&plan).is_none());
    }

    #[test]
    fn native_gray_preflight_accepts_native_core_plan() {
        let mut plan = test_plan(vec![test_node_with_intervals(7, 30, 45)], Vec::new());
        plan.resolved.kernel.r#type = "keli-core-rs".to_string();
        plan.core_plan.as_mut().unwrap().kind = CoreKind::KeliCoreRs;

        let report = native_gray_preflight_report(&plan);

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report
            .details
            .iter()
            .any(|detail| detail == "native_inbounds=1"));
    }

    #[test]
    fn native_gray_preflight_rejects_missing_core_plan() {
        let mut plan = test_plan(Vec::new(), Vec::new());
        plan.core_plan = None;

        let report = native_gray_preflight_report(&plan);

        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("no primary core plan")));
    }

    #[test]
    fn native_gray_preflight_warns_for_explicit_single_stack_listen() {
        let mut plan = test_plan(vec![test_node_with_intervals(7, 30, 45)], Vec::new());
        plan.resolved.kernel.r#type = "keli-core-rs".to_string();
        let core_plan = plan.core_plan.as_mut().unwrap();
        core_plan.kind = CoreKind::KeliCoreRs;
        core_plan.inbounds[0].listen = "127.0.0.1".to_string();

        let report = native_gray_preflight_report(&plan);

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("explicit address 127.0.0.1")
                && warning.contains("dual-stack wildcard")
        }));
    }

    #[test]
    fn native_gray_preflight_warns_for_non_stable_capabilities() {
        let mut plan = test_plan(vec![test_node_with_intervals(7, 30, 45)], Vec::new());
        plan.resolved.kernel.r#type = "keli-core-rs".to_string();
        plan.core_plan.as_mut().unwrap().kind = CoreKind::KeliCoreRs;

        let report = native_gray_preflight_report(&plan);

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("protocol=vless")
                && warning.contains("status=usable_needs_soak")
                && warning.contains("decision=render_native_with_warning")
                && warning.contains("baseline_source=GoLegacyBaseline")
        }));
    }

    #[test]
    fn native_gray_preflight_reports_rejected_capability_blocker() {
        let mut node = test_node_with_protocol(8, "trojan");
        node.common.network = "ws".to_string();
        node.common.network_settings = json!({
            "path": "/trojan",
            "headers": {
                "Host": "trojan.example.test"
            }
        });
        let mut plan = test_plan(vec![test_node_with_intervals(7, 30, 45)], Vec::new());
        plan.resolved.kernel.r#type = "keli-core-rs".to_string();
        plan.node_infos = vec![node];
        plan.core_plan = None;

        let report = native_gray_preflight_report(&plan);

        assert!(report.errors.iter().any(|error| {
            error.contains("protocol=trojan")
                && error.contains("transport=ws")
                && error.contains("status=canary_only")
                && error.contains("decision=reject")
                && error.contains("baseline_source=GoLegacyBaseline")
                && error.contains("evidence_level=ThirdPartyClientInterop")
        }));
    }

    fn test_plan(nodes: Vec<NodeInfo>, configs: Vec<NodeConfig>) -> RuntimeBootstrapPlan {
        test_plan_with_machine_profiles(nodes, configs, Vec::new())
    }

    fn test_plan_with_machine_profiles(
        nodes: Vec<NodeInfo>,
        configs: Vec<NodeConfig>,
        profiles: Vec<MachineProfileConfig>,
    ) -> RuntimeBootstrapPlan {
        let subscription_proxy_enabled = !profiles.is_empty() && nodes.is_empty();
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: true,
                continue_on_error: true,
                profiles,
            },
            agent: AgentConfig {
                subscription_proxy: SubscriptionProxyConfig {
                    enabled: subscription_proxy_enabled,
                    ..SubscriptionProxyConfig::default()
                },
            },
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

    fn test_node_with_protocol(node_id: u32, protocol: &str) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": protocol,
            "server_port": 10000 + node_id
        }))
        .unwrap();

        NodeInfo::from_common("https://panel.example.test", node_id, common).unwrap()
    }
}
