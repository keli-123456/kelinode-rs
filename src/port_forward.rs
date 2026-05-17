use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::panel::types::{NodeInfo, Protocol};
use serde::Serialize;

pub const HYSTERIA_PORT_FORWARD_COMMENT: &str = "V2NODE-HY2";
pub const HYSTERIA_PORT_FORWARD_CHAIN: &str = "V2NODE-HY2";
pub const HYSTERIA_PORT_FORWARD_TOOLS: [&str; 2] = ["iptables", "ip6tables"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortForwardMatcher {
    pub args: Vec<String>,
    pub single_port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortForwardRule {
    pub matcher: PortForwardMatcher,
    pub target_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HysteriaPortForwardRuleSpec {
    pub protocol: String,
    pub match_rule: String,
    pub target_port: u16,
    pub spec: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HysteriaPortForwardToolStatus {
    pub tool: String,
    pub available: bool,
    pub current: Vec<String>,
    pub expected: Vec<String>,
    pub missing: Vec<String>,
    pub extra: Vec<String>,
    pub stale_chain: bool,
    pub error: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HysteriaPortForwardStatus {
    pub enabled: bool,
    pub running_as_root: bool,
    pub expected_rules: Vec<HysteriaPortForwardRuleSpec>,
    pub tools: Vec<HysteriaPortForwardToolStatus>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortForwardCommand {
    pub tool: String,
    pub args: Vec<String>,
}

pub trait PortForwardExecutor {
    fn is_tool_available(&mut self, tool: &str) -> bool;
    fn command_output(&mut self, command: &PortForwardCommand) -> Result<String, String>;
    fn run_command(&mut self, command: &PortForwardCommand) -> Result<(), String>;
    fn running_as_root(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemPortForwardExecutor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortForwardRange {
    start: u16,
    end: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AllocatedPortForwardRange {
    node_id: u32,
    target_port: u16,
    range: PortForwardRange,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct HysteriaPortForwardPlan {
    nat_rules: Vec<PortForwardRule>,
    allow_ports: Vec<u16>,
    errors: Vec<String>,
}

fn build_hysteria_port_forward_plan(infos: &[NodeInfo]) -> HysteriaPortForwardPlan {
    let (nat_rules, errors) = build_hysteria_port_forward_rules(infos);
    let allow_ports = collect_hysteria_target_ports(infos)
        .keys()
        .copied()
        .collect::<Vec<_>>();
    HysteriaPortForwardPlan {
        nat_rules,
        allow_ports,
        errors,
    }
}

pub fn build_hysteria_port_forward_rules(
    infos: &[NodeInfo],
) -> (Vec<PortForwardRule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    let mut allocated = Vec::new();
    let target_ports = collect_hysteria_target_ports(infos);

    for info in infos {
        if !matches!(info.protocol, Protocol::Hysteria2) {
            continue;
        }
        let target_port = info.common.server_port;
        if target_port == 0 {
            errors.push(format!(
                "node {} has invalid server_port {}",
                info.id, target_port
            ));
            continue;
        }

        let external_port = first_non_empty(info.common.port.0.trim(), info.common.ports.0.trim());
        if external_port.is_empty() {
            continue;
        }

        let (_, ranges) =
            match parse_port_forward_matchers_and_ranges_except(&external_port, target_port) {
                Ok(result) => result,
                Err(error) => {
                    errors.push(format!(
                        "node {} has invalid port {:?}: {}",
                        info.id, external_port, error
                    ));
                    continue;
                }
            };
        if ranges.is_empty() {
            continue;
        }
        let ranges = trim_target_port_conflicts(ranges, target_port, &target_ports);
        let ranges = trim_allocated_range_conflicts(ranges, target_port, &allocated);
        if ranges.is_empty() {
            errors.push(format!(
                "node {} port {:?} is fully covered by other HY2 port-forward ranges",
                info.id, external_port
            ));
            continue;
        }
        let matchers = port_forward_matchers_from_ranges(&ranges);

        for range in ranges {
            allocated.push(AllocatedPortForwardRange {
                node_id: info.id,
                target_port,
                range,
            });
        }
        for matcher in matchers {
            let key = format!("{}|{}", target_port, matcher.args.join("\0"));
            if !seen.insert(key) {
                continue;
            }
            rules.push(PortForwardRule {
                matcher,
                target_port,
            });
        }
    }

    (rules, errors)
}

pub fn new_hysteria_port_forward_status(
    rules: &[PortForwardRule],
    errors: &[String],
    running_as_root: bool,
) -> HysteriaPortForwardStatus {
    HysteriaPortForwardStatus {
        enabled: true,
        running_as_root,
        expected_rules: describe_port_forward_rules(rules),
        tools: Vec::new(),
        errors: errors.to_vec(),
    }
}

fn new_hysteria_port_forward_status_from_plan(
    plan: &HysteriaPortForwardPlan,
    running_as_root: bool,
) -> HysteriaPortForwardStatus {
    HysteriaPortForwardStatus {
        enabled: true,
        running_as_root,
        expected_rules: describe_hysteria_managed_rules(&plan.nat_rules, &plan.allow_ports),
        tools: Vec::new(),
        errors: plan.errors.clone(),
    }
}

pub fn set_hysteria_port_forward_disabled(running_as_root: bool) -> HysteriaPortForwardStatus {
    HysteriaPortForwardStatus {
        enabled: false,
        running_as_root,
        expected_rules: Vec::new(),
        tools: Vec::new(),
        errors: Vec::new(),
    }
}

pub fn inspect_hysteria_port_forward<E: PortForwardExecutor>(
    infos: &[NodeInfo],
    executor: &mut E,
) -> HysteriaPortForwardStatus {
    let plan = build_hysteria_port_forward_plan(infos);
    let mut status = new_hysteria_port_forward_status_from_plan(&plan, executor.running_as_root());

    for tool in HYSTERIA_PORT_FORWARD_TOOLS {
        status
            .tools
            .push(inspect_port_forward_tool_with_allow_ports(
                executor,
                tool,
                &plan.nat_rules,
                &plan.allow_ports,
            ));
    }

    status
}

pub fn repair_hysteria_port_forward<E: PortForwardExecutor>(
    infos: &[NodeInfo],
    executor: &mut E,
) -> HysteriaPortForwardStatus {
    let plan = build_hysteria_port_forward_plan(infos);
    let mut status = new_hysteria_port_forward_status_from_plan(&plan, executor.running_as_root());

    if !status.running_as_root {
        for tool in HYSTERIA_PORT_FORWARD_TOOLS {
            status
                .tools
                .push(inspect_port_forward_tool_with_allow_ports(
                    executor,
                    tool,
                    &plan.nat_rules,
                    &plan.allow_ports,
                ));
        }
        if !plan.nat_rules.is_empty()
            || !plan.allow_ports.is_empty()
            || hysteria_port_forward_needs_repair(&status)
        {
            status
                .errors
                .push("HY2 port forwarding repair requires root".to_string());
        }
        return status;
    }

    for tool in HYSTERIA_PORT_FORWARD_TOOLS {
        let mut tool_status = inspect_port_forward_tool_with_allow_ports(
            executor,
            tool,
            &plan.nat_rules,
            &plan.allow_ports,
        );
        if tool_status.available {
            let needs_repair = tool_status.error.is_empty()
                && (!tool_status.missing.is_empty()
                    || !tool_status.extra.is_empty()
                    || tool_status.stale_chain);
            if needs_repair {
                match execute_reconcile_port_forward_tool(
                    executor,
                    tool,
                    &plan.nat_rules,
                    &plan.allow_ports,
                ) {
                    Ok(()) => {
                        tool_status = inspect_port_forward_tool_with_allow_ports(
                            executor,
                            tool,
                            &plan.nat_rules,
                            &plan.allow_ports,
                        );
                    }
                    Err(error) => {
                        tool_status.error = error.clone();
                        status.errors.push(format!("{tool}: {error}"));
                    }
                }
            }
        }
        status.tools.push(tool_status);
    }

    status
}

pub fn cleanup_hysteria_port_forward<E: PortForwardExecutor>(
    executor: &mut E,
) -> HysteriaPortForwardStatus {
    let mut status = set_hysteria_port_forward_disabled(executor.running_as_root());

    if !status.running_as_root {
        status
            .errors
            .push("HY2 port forwarding cleanup requires root".to_string());
        for tool in HYSTERIA_PORT_FORWARD_TOOLS {
            status
                .tools
                .push(inspect_port_forward_tool(executor, tool, &[]));
        }
        return status;
    }

    for tool in HYSTERIA_PORT_FORWARD_TOOLS {
        let mut tool_status = inspect_port_forward_tool_with_allow_ports(executor, tool, &[], &[]);
        if tool_status.available {
            match execute_cleanup_port_forward_tool(executor, tool) {
                Ok(()) => {
                    tool_status =
                        inspect_port_forward_tool_with_allow_ports(executor, tool, &[], &[]);
                }
                Err(error) => {
                    tool_status.error = error.clone();
                    status.errors.push(format!("{tool}: {error}"));
                }
            }
        }
        status.tools.push(tool_status);
    }

    status
}

pub fn describe_port_forward_rules(rules: &[PortForwardRule]) -> Vec<HysteriaPortForwardRuleSpec> {
    rules
        .iter()
        .map(|rule| HysteriaPortForwardRuleSpec {
            protocol: "udp".to_string(),
            match_rule: rule.matcher.args.join(" "),
            target_port: rule.target_port,
            spec: expected_port_forward_spec_fields(rule).join(" "),
        })
        .collect()
}

fn describe_hysteria_managed_rules(
    nat_rules: &[PortForwardRule],
    allow_ports: &[u16],
) -> Vec<HysteriaPortForwardRuleSpec> {
    let mut specs = describe_port_forward_rules(nat_rules);
    specs.extend(allow_ports.iter().map(|port| HysteriaPortForwardRuleSpec {
        protocol: "udp".to_string(),
        match_rule: format!("INPUT --dport {port}"),
        target_port: *port,
        spec: expected_firewall_allow_spec_fields(*port).join(" "),
    }));
    specs
}

pub fn inspect_port_forward_tool<E: PortForwardExecutor>(
    executor: &mut E,
    tool: &str,
    rules: &[PortForwardRule],
) -> HysteriaPortForwardToolStatus {
    inspect_port_forward_tool_with_allow_ports(executor, tool, rules, &[])
}

fn inspect_port_forward_tool_with_allow_ports<E: PortForwardExecutor>(
    executor: &mut E,
    tool: &str,
    rules: &[PortForwardRule],
    allow_ports: &[u16],
) -> HysteriaPortForwardToolStatus {
    let mut status = HysteriaPortForwardToolStatus {
        tool: tool.to_string(),
        expected: expected_hysteria_managed_specs(rules, allow_ports),
        current: Vec::new(),
        missing: Vec::new(),
        extra: Vec::new(),
        ..HysteriaPortForwardToolStatus::default()
    };
    if !executor.is_tool_available(tool) {
        return status;
    }
    status.available = true;

    let prerouting_command = command(tool, vec!["-t", "nat", "-S", "PREROUTING"]);
    let prerouting_output = match executor.command_output(&prerouting_command) {
        Ok(output) => output,
        Err(error) => {
            status.error = error;
            return status;
        }
    };
    let input_command = command(tool, vec!["-S", "INPUT"]);
    let input_output = match executor.command_output(&input_command) {
        Ok(output) => output,
        Err(error) => {
            status.error = error;
            return status;
        }
    };
    let chain_command = command(tool, vec!["-t", "nat", "-S", HYSTERIA_PORT_FORWARD_CHAIN]);
    status = inspect_hysteria_managed_specs(
        tool,
        rules,
        allow_ports,
        &prerouting_output,
        &input_output,
        executor.command_output(&chain_command).is_ok(),
    );
    status.available = true;
    status
}

pub fn inspect_port_forward_specs(
    tool: &str,
    rules: &[PortForwardRule],
    prerouting_output: &str,
    stale_chain: bool,
) -> HysteriaPortForwardToolStatus {
    inspect_hysteria_managed_specs(tool, rules, &[], prerouting_output, "", stale_chain)
}

fn inspect_hysteria_managed_specs(
    tool: &str,
    rules: &[PortForwardRule],
    allow_ports: &[u16],
    prerouting_output: &str,
    input_output: &str,
    stale_chain: bool,
) -> HysteriaPortForwardToolStatus {
    let mut current = list_port_forward_specs_from_output(prerouting_output);
    current.extend(list_firewall_allow_specs_from_output(input_output));
    let expected = expected_hysteria_managed_specs(rules, allow_ports);

    let expected_keys = expected
        .iter()
        .map(|spec| {
            let fields = parse_iptables_spec(spec);
            (port_forward_fields_key(&fields), spec.clone())
        })
        .collect::<BTreeMap<_, _>>();
    let current_keys = current
        .iter()
        .map(|spec| {
            let fields = parse_iptables_spec(spec);
            (port_forward_fields_key(&fields), spec.clone())
        })
        .collect::<BTreeMap<_, _>>();

    let missing = expected_keys
        .iter()
        .filter(|(key, _)| !current_keys.contains_key(*key))
        .map(|(_, spec)| spec.clone())
        .collect::<Vec<_>>();
    let extra = current_keys
        .iter()
        .filter(|(key, _)| !expected_keys.contains_key(*key))
        .map(|(_, spec)| spec.clone())
        .collect::<Vec<_>>();

    HysteriaPortForwardToolStatus {
        tool: tool.to_string(),
        available: true,
        current,
        expected,
        missing,
        extra,
        stale_chain,
        error: String::new(),
    }
}

pub fn hysteria_port_forward_needs_repair(status: &HysteriaPortForwardStatus) -> bool {
    status.tools.iter().any(|tool| {
        tool.available
            && tool.error.is_empty()
            && (!tool.missing.is_empty() || !tool.extra.is_empty() || tool.stale_chain)
    })
}

pub fn reconcile_port_forward_commands(
    tool: &str,
    rules: &[PortForwardRule],
    prerouting_output: &str,
    chain_exists: bool,
) -> Vec<PortForwardCommand> {
    reconcile_port_forward_commands_with_allow_ports(
        tool,
        rules,
        &[],
        prerouting_output,
        "",
        chain_exists,
    )
}

fn reconcile_port_forward_commands_with_allow_ports(
    tool: &str,
    rules: &[PortForwardRule],
    allow_ports: &[u16],
    prerouting_output: &str,
    input_output: &str,
    chain_exists: bool,
) -> Vec<PortForwardCommand> {
    let mut commands = delete_port_forward_commands(tool, prerouting_output);
    commands.extend(delete_firewall_allow_commands(tool, input_output));
    if chain_exists {
        commands.push(command(
            tool,
            vec!["-t", "nat", "-F", HYSTERIA_PORT_FORWARD_CHAIN],
        ));
        commands.push(command(
            tool,
            vec!["-t", "nat", "-X", HYSTERIA_PORT_FORWARD_CHAIN],
        ));
    }

    for rule in rules {
        let mut args = vec!["-t", "nat", "-A", "PREROUTING", "-p", "udp"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        args.extend(rule.matcher.args.clone());
        args.extend(
            [
                "-m",
                "comment",
                "--comment",
                HYSTERIA_PORT_FORWARD_COMMENT,
                "-j",
                "REDIRECT",
                "--to-ports",
            ]
            .into_iter()
            .map(str::to_string),
        );
        args.push(rule.target_port.to_string());
        commands.push(PortForwardCommand {
            tool: tool.to_string(),
            args,
        });
    }

    for port in allow_ports {
        commands.push(PortForwardCommand {
            tool: tool.to_string(),
            args: vec![
                "-I".to_string(),
                "INPUT".to_string(),
                "-p".to_string(),
                "udp".to_string(),
                "--dport".to_string(),
                port.to_string(),
                "-m".to_string(),
                "comment".to_string(),
                "--comment".to_string(),
                HYSTERIA_PORT_FORWARD_COMMENT.to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ],
        });
    }

    commands
}

pub fn cleanup_port_forward_commands(
    tool: &str,
    prerouting_output: &str,
    chain_exists: bool,
) -> Vec<PortForwardCommand> {
    cleanup_port_forward_commands_with_filter(tool, prerouting_output, "", chain_exists)
}

fn cleanup_port_forward_commands_with_filter(
    tool: &str,
    prerouting_output: &str,
    input_output: &str,
    chain_exists: bool,
) -> Vec<PortForwardCommand> {
    let mut commands = delete_port_forward_commands(tool, prerouting_output);
    commands.extend(delete_firewall_allow_commands(tool, input_output));
    if chain_exists {
        commands.push(command(
            tool,
            vec!["-t", "nat", "-F", HYSTERIA_PORT_FORWARD_CHAIN],
        ));
        commands.push(command(
            tool,
            vec!["-t", "nat", "-X", HYSTERIA_PORT_FORWARD_CHAIN],
        ));
    }
    commands
}

pub fn execute_reconcile_port_forward_tool<E: PortForwardExecutor>(
    executor: &mut E,
    tool: &str,
    rules: &[PortForwardRule],
    allow_ports: &[u16],
) -> Result<(), String> {
    let prerouting_output = executor
        .command_output(&command(tool, vec!["-t", "nat", "-S", "PREROUTING"]))
        .unwrap_or_default();
    let input_output = executor
        .command_output(&command(tool, vec!["-S", "INPUT"]))
        .unwrap_or_default();
    let chain_exists = executor
        .command_output(&command(
            tool,
            vec!["-t", "nat", "-S", HYSTERIA_PORT_FORWARD_CHAIN],
        ))
        .is_ok();
    execute_port_forward_commands(
        executor,
        &reconcile_port_forward_commands_with_allow_ports(
            tool,
            rules,
            allow_ports,
            &prerouting_output,
            &input_output,
            chain_exists,
        ),
    )
}

pub fn execute_cleanup_port_forward_tool<E: PortForwardExecutor>(
    executor: &mut E,
    tool: &str,
) -> Result<(), String> {
    let prerouting_output = executor
        .command_output(&command(tool, vec!["-t", "nat", "-S", "PREROUTING"]))
        .unwrap_or_default();
    let input_output = executor
        .command_output(&command(tool, vec!["-S", "INPUT"]))
        .unwrap_or_default();
    let chain_exists = executor
        .command_output(&command(
            tool,
            vec!["-t", "nat", "-S", HYSTERIA_PORT_FORWARD_CHAIN],
        ))
        .is_ok();
    execute_port_forward_commands(
        executor,
        &cleanup_port_forward_commands_with_filter(
            tool,
            &prerouting_output,
            &input_output,
            chain_exists,
        ),
    )
}

pub fn execute_port_forward_commands<E: PortForwardExecutor>(
    executor: &mut E,
    commands: &[PortForwardCommand],
) -> Result<(), String> {
    for command in commands {
        executor.run_command(command)?;
    }
    Ok(())
}

pub fn delete_port_forward_commands(
    tool: &str,
    prerouting_output: &str,
) -> Vec<PortForwardCommand> {
    prerouting_output
        .lines()
        .filter_map(|line| {
            let mut fields = parse_iptables_spec(line.trim());
            if !is_port_forward_rule_spec(&fields) {
                return None;
            }
            fields[0] = "-D".to_string();
            let mut args = vec!["-t".to_string(), "nat".to_string()];
            args.extend(fields);
            Some(PortForwardCommand {
                tool: tool.to_string(),
                args,
            })
        })
        .collect()
}

fn delete_firewall_allow_commands(tool: &str, input_output: &str) -> Vec<PortForwardCommand> {
    input_output
        .lines()
        .filter_map(|line| {
            let mut fields = parse_iptables_spec(line.trim());
            if !is_firewall_allow_rule_spec(&fields) {
                return None;
            }
            fields[0] = "-D".to_string();
            Some(PortForwardCommand {
                tool: tool.to_string(),
                args: fields,
            })
        })
        .collect()
}

pub fn expected_port_forward_specs(rules: &[PortForwardRule]) -> Vec<String> {
    rules
        .iter()
        .map(|rule| expected_port_forward_spec_fields(rule).join(" "))
        .collect()
}

fn expected_hysteria_managed_specs(
    nat_rules: &[PortForwardRule],
    allow_ports: &[u16],
) -> Vec<String> {
    let mut specs = expected_port_forward_specs(nat_rules);
    specs.extend(
        allow_ports
            .iter()
            .map(|port| expected_firewall_allow_spec_fields(*port).join(" ")),
    );
    specs
}

pub fn expected_port_forward_spec_fields(rule: &PortForwardRule) -> Vec<String> {
    let mut fields = vec![
        "-A".to_string(),
        "PREROUTING".to_string(),
        "-p".to_string(),
        "udp".to_string(),
    ];
    fields.extend(rule.matcher.args.clone());
    fields.extend([
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        HYSTERIA_PORT_FORWARD_COMMENT.to_string(),
        "-j".to_string(),
        "REDIRECT".to_string(),
        "--to-ports".to_string(),
        rule.target_port.to_string(),
    ]);
    normalize_port_forward_spec_fields(&fields)
}

fn expected_firewall_allow_spec_fields(port: u16) -> Vec<String> {
    normalize_port_forward_spec_fields(&[
        "-A".to_string(),
        "INPUT".to_string(),
        "-p".to_string(),
        "udp".to_string(),
        "--dport".to_string(),
        port.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        HYSTERIA_PORT_FORWARD_COMMENT.to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ])
}

pub fn list_port_forward_specs_from_output(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let fields = parse_iptables_spec(line.trim());
            if is_port_forward_rule_spec(&fields) {
                Some(normalize_port_forward_spec_fields(&fields).join(" "))
            } else {
                None
            }
        })
        .collect()
}

fn list_firewall_allow_specs_from_output(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let fields = parse_iptables_spec(line.trim());
            if is_firewall_allow_rule_spec(&fields) {
                Some(normalize_port_forward_spec_fields(&fields).join(" "))
            } else {
                None
            }
        })
        .collect()
}

pub fn is_port_forward_rule_spec(fields: &[String]) -> bool {
    if fields.len() < 4 || fields[0] != "-A" || fields[1] != "PREROUTING" {
        return false;
    }
    for index in 2..fields.len().saturating_sub(1) {
        if fields[index] == "-j" && fields[index + 1] == HYSTERIA_PORT_FORWARD_CHAIN {
            return true;
        }
        if fields[index] == "--comment"
            && fields[index + 1].trim_matches(|value| value == '"' || value == '\'')
                == HYSTERIA_PORT_FORWARD_COMMENT
        {
            return true;
        }
    }
    false
}

fn is_firewall_allow_rule_spec(fields: &[String]) -> bool {
    if fields.len() < 4 || fields[0] != "-A" || fields[1] != "INPUT" {
        return false;
    }
    let mut has_comment = false;
    let mut accepts = false;
    for index in 2..fields.len().saturating_sub(1) {
        if fields[index] == "--comment"
            && fields[index + 1].trim_matches(|value| value == '"' || value == '\'')
                == HYSTERIA_PORT_FORWARD_COMMENT
        {
            has_comment = true;
        }
        if fields[index] == "-j" && fields[index + 1] == "ACCEPT" {
            accepts = true;
        }
    }
    has_comment && accepts
}

pub fn parse_iptables_spec(line: &str) -> Vec<String> {
    if line.is_empty() {
        return Vec::new();
    }

    let mut fields = Vec::new();
    let mut builder = String::new();
    let mut quote = None;

    for character in line.chars() {
        match quote {
            Some(active_quote) => {
                if character == active_quote {
                    quote = None;
                } else {
                    builder.push(character);
                }
            }
            None if character == '"' || character == '\'' => {
                quote = Some(character);
            }
            None if character == ' ' || character == '\t' => {
                if !builder.is_empty() {
                    fields.push(std::mem::take(&mut builder));
                }
            }
            None => builder.push(character),
        }
    }
    if !builder.is_empty() {
        fields.push(builder);
    }
    fields
}

pub fn normalize_port_forward_spec_fields(fields: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(fields.len());
    let mut index = 0usize;
    while index < fields.len() {
        if fields[index] == "-m" && fields.get(index + 1).is_some_and(|value| value == "udp") {
            index += 2;
            continue;
        }
        let mut value = fields[index].clone();
        if index > 0 && fields[index - 1] == "--comment" {
            value = value
                .trim_matches(|value| value == '"' || value == '\'')
                .to_string();
        }
        out.push(value);
        index += 1;
    }
    out
}

pub fn port_forward_fields_key(fields: &[String]) -> String {
    normalize_port_forward_spec_fields(fields).join("\0")
}

fn command(tool: &str, args: Vec<&str>) -> PortForwardCommand {
    PortForwardCommand {
        tool: tool.to_string(),
        args: args.into_iter().map(str::to_string).collect(),
    }
}

impl PortForwardExecutor for SystemPortForwardExecutor {
    fn is_tool_available(&mut self, tool: &str) -> bool {
        tool_exists(tool)
    }

    fn command_output(&mut self, command: &PortForwardCommand) -> Result<String, String> {
        let output = Command::new(&command.tool)
            .args(&command.args)
            .output()
            .map_err(|err| format!("run {} failed: {err}", command.tool))?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = first_non_empty(&stderr, &stdout);
        if detail.is_empty() {
            Err(format!("{} exited with {}", command.tool, output.status))
        } else {
            Err(format!(
                "{} exited with {}: {}",
                command.tool, output.status, detail
            ))
        }
    }

    fn run_command(&mut self, command: &PortForwardCommand) -> Result<(), String> {
        let output = Command::new(&command.tool)
            .args(&command.args)
            .output()
            .map_err(|err| format!("run {} failed: {err}", command.tool))?;
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = first_non_empty(&stderr, &stdout);
        if detail.is_empty() {
            Err(format!("{} exited with {}", command.tool, output.status))
        } else {
            Err(format!(
                "{} exited with {}: {}",
                command.tool, output.status, detail
            ))
        }
    }

    fn running_as_root(&self) -> bool {
        running_as_root()
    }
}

fn tool_exists(tool: &str) -> bool {
    let path = Path::new(tool);
    if path.components().count() > 1 {
        return fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
    }

    let Some(paths) = env::var_os("PATH") else {
        return false;
    };
    candidate_tool_names(tool).into_iter().any(|name| {
        env::split_paths(&paths).any(|path| {
            fs::metadata(path.join(&name))
                .map(|metadata| metadata.is_file())
                .unwrap_or(false)
        })
    })
}

fn candidate_tool_names(tool: &str) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let path = Path::new(tool);
        if path.extension().is_some() {
            return vec![PathBuf::from(tool)];
        }
        let extensions = env::var_os("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|extension| !extension.trim().is_empty())
                    .map(|extension| format!("{tool}{extension}"))
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![PathBuf::from(format!("{tool}.exe"))]);
        let mut names = vec![PathBuf::from(tool)];
        names.extend(extensions);
        names
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from(tool)]
    }
}

fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    Some(String::from_utf8_lossy(&output.stdout).trim() == "0")
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn parse_port_forward_matchers(raw: &str) -> Result<Vec<PortForwardMatcher>, String> {
    parse_port_forward_matchers_except(raw, 0)
}

pub fn parse_port_forward_matchers_except(
    raw: &str,
    excluded_port: u16,
) -> Result<Vec<PortForwardMatcher>, String> {
    let (matchers, _) = parse_port_forward_matchers_and_ranges_except(raw, excluded_port)?;
    Ok(matchers)
}

fn parse_port_forward_matchers_and_ranges_except(
    raw: &str,
    excluded_port: u16,
) -> Result<(Vec<PortForwardMatcher>, Vec<PortForwardRange>), String> {
    let cleaned = raw.trim().replace(' ', "");
    if cleaned.is_empty() {
        return Err("empty port".to_string());
    }

    let mut matchers = Vec::new();
    let mut ranges = Vec::new();
    let mut singles = Vec::new();

    for token in cleaned.split(',') {
        if token.is_empty() {
            return Err("empty token".to_string());
        }
        if token.contains('-') || token.contains(':') {
            let (start, end) = parse_port_range(token)?;
            if start == end {
                add_single(start, excluded_port, &mut singles, &mut ranges);
                continue;
            }
            flush_singles(&mut singles, &mut matchers);
            add_range(start, end, excluded_port, &mut matchers, &mut ranges);
            continue;
        }
        let port = parse_port_number(token)?;
        add_single(port, excluded_port, &mut singles, &mut ranges);
    }
    flush_singles(&mut singles, &mut matchers);

    Ok((matchers, ranges))
}

fn add_single(
    port: u16,
    excluded_port: u16,
    singles: &mut Vec<u16>,
    ranges: &mut Vec<PortForwardRange>,
) {
    if port == excluded_port {
        return;
    }
    singles.push(port);
    ranges.push(PortForwardRange {
        start: port,
        end: port,
    });
}

fn flush_singles(singles: &mut Vec<u16>, matchers: &mut Vec<PortForwardMatcher>) {
    while !singles.is_empty() {
        let chunk_size = singles.len().min(15);
        let chunk = singles.drain(..chunk_size).collect::<Vec<_>>();
        if chunk.len() == 1 {
            matchers.push(PortForwardMatcher {
                args: vec!["--dport".to_string(), chunk[0].to_string()],
                single_port: Some(chunk[0]),
            });
        } else {
            let joined = chunk
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            matchers.push(PortForwardMatcher {
                args: vec![
                    "-m".to_string(),
                    "multiport".to_string(),
                    "--dports".to_string(),
                    joined,
                ],
                single_port: None,
            });
        }
    }
}

fn add_range(
    start: u16,
    end: u16,
    excluded_port: u16,
    matchers: &mut Vec<PortForwardMatcher>,
    ranges: &mut Vec<PortForwardRange>,
) {
    let mut append_range = |start: u16, end: u16| {
        ranges.push(PortForwardRange { start, end });
        matchers.push(PortForwardMatcher {
            args: vec!["--dport".to_string(), format!("{start}:{end}")],
            single_port: None,
        });
    };

    if excluded_port > 0 && start <= excluded_port && excluded_port <= end {
        if start < excluded_port {
            append_range(start, excluded_port - 1);
        }
        if excluded_port < end {
            append_range(excluded_port + 1, end);
        }
        return;
    }

    append_range(start, end);
}

fn parse_port_range(token: &str) -> Result<(u16, u16), String> {
    let separator = if token.contains('-') { '-' } else { ':' };
    let parts = token.split(separator).collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err(format!("invalid range {token:?}"));
    }
    let start = parse_port_number(parts[0])?;
    let end = parse_port_number(parts[1])?;
    if start > end {
        return Err(format!("invalid reversed range {token:?}"));
    }
    Ok((start, end))
}

fn parse_port_number(token: &str) -> Result<u16, String> {
    if token.is_empty() {
        return Err("empty port".to_string());
    }
    let port = token
        .parse::<u32>()
        .map_err(|_| format!("invalid port {token:?}"))?;
    if port == 0 || port > u16::MAX as u32 {
        return Err(format!("port out of range {token:?}"));
    }
    Ok(port as u16)
}

fn collect_hysteria_target_ports(infos: &[NodeInfo]) -> BTreeMap<u16, u32> {
    infos
        .iter()
        .filter(|info| matches!(info.protocol, Protocol::Hysteria2))
        .filter(|info| info.common.server_port > 0)
        .map(|info| (info.common.server_port, info.id))
        .collect()
}

fn trim_target_port_conflicts(
    mut ranges: Vec<PortForwardRange>,
    target_port: u16,
    target_ports: &BTreeMap<u16, u32>,
) -> Vec<PortForwardRange> {
    for port in target_ports.keys() {
        if *port == target_port {
            continue;
        }
        ranges = subtract_single_port(ranges, *port);
    }
    ranges
}

fn trim_allocated_range_conflicts(
    mut ranges: Vec<PortForwardRange>,
    target_port: u16,
    allocated: &[AllocatedPortForwardRange],
) -> Vec<PortForwardRange> {
    for existing in allocated {
        if existing.target_port == target_port {
            continue;
        }
        ranges = subtract_range(ranges, existing.range);
    }
    ranges
}

fn subtract_single_port(ranges: Vec<PortForwardRange>, port: u16) -> Vec<PortForwardRange> {
    subtract_range(
        ranges,
        PortForwardRange {
            start: port,
            end: port,
        },
    )
}

fn subtract_range(
    ranges: Vec<PortForwardRange>,
    blocked: PortForwardRange,
) -> Vec<PortForwardRange> {
    let mut output = Vec::new();
    for range in ranges {
        if !range.overlaps(blocked) {
            output.push(range);
            continue;
        }
        if range.start < blocked.start {
            output.push(PortForwardRange {
                start: range.start,
                end: blocked.start.saturating_sub(1),
            });
        }
        if blocked.end < range.end {
            output.push(PortForwardRange {
                start: blocked.end.saturating_add(1),
                end: range.end,
            });
        }
    }
    output
}

fn port_forward_matchers_from_ranges(ranges: &[PortForwardRange]) -> Vec<PortForwardMatcher> {
    let mut matchers = Vec::new();
    let mut singles = Vec::new();
    for range in ranges {
        if range.start == range.end {
            singles.push(range.start);
            continue;
        }
        flush_singles(&mut singles, &mut matchers);
        matchers.push(PortForwardMatcher {
            args: vec![
                "--dport".to_string(),
                format!("{}:{}", range.start, range.end),
            ],
            single_port: None,
        });
    }
    flush_singles(&mut singles, &mut matchers);
    matchers
}

fn first_non_empty(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

impl PortForwardRange {
    fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::json;

    use super::{
        build_hysteria_port_forward_rules, cleanup_hysteria_port_forward,
        expected_port_forward_specs, hysteria_port_forward_needs_repair,
        inspect_hysteria_port_forward, inspect_port_forward_specs,
        list_port_forward_specs_from_output, new_hysteria_port_forward_status, parse_iptables_spec,
        parse_port_forward_matchers, reconcile_port_forward_commands, repair_hysteria_port_forward,
        PortForwardCommand, PortForwardExecutor,
    };
    use crate::panel::types::{CommonNode, NodeInfo};

    #[test]
    fn builds_hysteria_port_forward_rules() {
        let infos = vec![
            node(1, 443, "30000-30002", ""),
            node(2, 8443, "20000,20001,20002", ""),
            node(3, 9443, "", "21000:21010"),
            node(4, 443, "443", ""),
            node(5, 443, "440-445", ""),
            node(6, 443, "443,444,445", ""),
        ];

        let (rules, errors) = build_hysteria_port_forward_rules(&infos);

        assert!(errors.is_empty(), "{errors:?}");
        let got = rules
            .iter()
            .map(|rule| {
                let mut args = rule.matcher.args.clone();
                args.push(format!("to={}", rule.target_port));
                args
            })
            .collect::<Vec<_>>();
        let want = string_rows(vec![
            vec!["--dport", "30000:30002", "to=443"],
            vec![
                "-m",
                "multiport",
                "--dports",
                "20000,20001,20002",
                "to=8443",
            ],
            vec!["--dport", "21000:21010", "to=9443"],
            vec!["--dport", "440:442", "to=443"],
            vec!["--dport", "444:445", "to=443"],
            vec!["-m", "multiport", "--dports", "444,445", "to=443"],
        ]);

        assert_eq!(got, want);
    }

    #[test]
    fn splits_large_multiport_matchers() {
        let matchers =
            parse_port_forward_matchers("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16").unwrap();

        assert_eq!(matchers.len(), 2);
        assert_eq!(
            matchers[0].args,
            strings(vec![
                "-m",
                "multiport",
                "--dports",
                "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
            ])
        );
        assert_eq!(matchers[1].args, strings(vec!["--dport", "16"]));
    }

    #[test]
    fn rejects_invalid_ports() {
        for input in ["", "0", "65536", "300-200", "abc", "200,,201"] {
            assert!(parse_port_forward_matchers(input).is_err(), "{input}");
        }
    }

    #[test]
    fn trims_overlapping_external_ports_without_skipping_node() {
        let infos = vec![
            node(1, 443, "30000-30002", ""),
            node(2, 8443, "30002-30004", ""),
        ];

        let (rules, errors) = build_hysteria_port_forward_rules(&infos);

        assert!(errors.is_empty(), "{errors:?}");
        let got = rules
            .iter()
            .map(|rule| {
                let mut args = rule.matcher.args.clone();
                args.push(format!("to={}", rule.target_port));
                args
            })
            .collect::<Vec<_>>();
        assert_eq!(
            got,
            string_rows(vec![
                vec!["--dport", "30000:30002", "to=443"],
                vec!["--dport", "30003:30004", "to=8443"],
            ])
        );
    }

    #[test]
    fn trims_boundary_overlap_between_adjacent_hysteria_port_ranges() {
        let infos = vec![
            node(11, 10003, "39000-40000", ""),
            node(8, 10002, "38000-39000", ""),
        ];

        let (rules, errors) = build_hysteria_port_forward_rules(&infos);

        assert!(errors.is_empty(), "{errors:?}");
        let got = rules
            .iter()
            .map(|rule| {
                let mut args = rule.matcher.args.clone();
                args.push(format!("to={}", rule.target_port));
                args
            })
            .collect::<Vec<_>>();
        assert_eq!(
            got,
            string_rows(vec![
                vec!["--dport", "39000:40000", "to=10003"],
                vec!["--dport", "38000:38999", "to=10002"],
            ])
        );
    }

    #[test]
    fn trims_external_port_over_another_server_port() {
        let infos = vec![node(1, 443, "", ""), node(2, 8443, "440-445", "")];

        let (rules, errors) = build_hysteria_port_forward_rules(&infos);

        assert!(errors.is_empty(), "{errors:?}");
        let got = rules
            .iter()
            .map(|rule| {
                let mut args = rule.matcher.args.clone();
                args.push(format!("to={}", rule.target_port));
                args
            })
            .collect::<Vec<_>>();
        assert_eq!(
            got,
            string_rows(vec![
                vec!["--dport", "440:442", "to=8443"],
                vec!["--dport", "444:445", "to=8443"],
            ])
        );
    }

    #[test]
    fn describes_expected_port_forward_specs() {
        let infos = vec![node(1, 443, "30000-30002", "")];
        let (rules, errors) = build_hysteria_port_forward_rules(&infos);

        assert!(errors.is_empty());
        assert_eq!(
            expected_port_forward_specs(&rules),
            strings(vec![
                "-A PREROUTING -p udp --dport 30000:30002 -m comment --comment V2NODE-HY2 -j REDIRECT --to-ports 443"
            ])
        );

        let status = new_hysteria_port_forward_status(&rules, &errors, true);
        assert_eq!(status.expected_rules.len(), 1);
        assert_eq!(status.expected_rules[0].protocol, "udp");
        assert_eq!(status.expected_rules[0].target_port, 443);
    }

    #[test]
    fn parses_quoted_iptables_specs() {
        let fields = parse_iptables_spec(
            "-A PREROUTING -p udp --dport 30000:30002 -m comment --comment \"V2NODE-HY2\" -j REDIRECT --to-ports 443",
        );

        assert_eq!(
            fields,
            strings(vec![
                "-A",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                "30000:30002",
                "-m",
                "comment",
                "--comment",
                "V2NODE-HY2",
                "-j",
                "REDIRECT",
                "--to-ports",
                "443",
            ])
        );
    }

    #[test]
    fn lists_only_hysteria_port_forward_specs() {
        let output = [
            "-A PREROUTING -p udp -m udp --dport 10000:10002 -j V2NODE-HY2",
            "-A PREROUTING -p udp -m udp --dport 30000:30002 -m comment --comment \"V2NODE-HY2\" -j REDIRECT --to-ports 443",
            "-A PREROUTING -p tcp -j OTHER",
        ]
        .join("\n");

        let specs = list_port_forward_specs_from_output(&output);

        assert_eq!(specs.len(), 2);
        assert_eq!(
            specs[0],
            "-A PREROUTING -p udp --dport 10000:10002 -j V2NODE-HY2"
        );
        assert_eq!(
            specs[1],
            "-A PREROUTING -p udp --dport 30000:30002 -m comment --comment V2NODE-HY2 -j REDIRECT --to-ports 443"
        );
    }

    #[test]
    fn inspect_port_forward_specs_detects_drift() {
        let infos = vec![
            node(1, 443, "30000-30002", ""),
            node(2, 8443, "20000-20002", ""),
        ];
        let (rules, errors) = build_hysteria_port_forward_rules(&infos);
        assert!(errors.is_empty());
        let output = [
            "-A PREROUTING -p udp -m udp --dport 30000:30002 -m comment --comment \"V2NODE-HY2\" -j REDIRECT --to-ports 443",
            "-A PREROUTING -p udp -m udp --dport 10000:10002 -j V2NODE-HY2",
        ]
        .join("\n");

        let tool = inspect_port_forward_specs("iptables", &rules, &output, true);
        let mut status = new_hysteria_port_forward_status(&rules, &errors, true);
        status.tools.push(tool.clone());

        assert_eq!(tool.missing.len(), 1);
        assert!(tool.missing[0].contains("20000:20002"));
        assert_eq!(tool.extra.len(), 1);
        assert!(tool.extra[0].contains("V2NODE-HY2"));
        assert!(tool.stale_chain);
        assert!(hysteria_port_forward_needs_repair(&status));
    }

    #[test]
    fn reconcile_commands_delete_old_specs_and_append_expected_rules() {
        let infos = vec![
            node(1, 443, "30000-30002", ""),
            node(2, 8443, "20000,20001", ""),
        ];
        let (rules, errors) = build_hysteria_port_forward_rules(&infos);
        assert!(errors.is_empty());
        let output = [
            "-A PREROUTING -p udp -j V2NODE-HY2",
            "-A PREROUTING -p udp --dport 10000:10002 -j V2NODE-HY2",
            "-A PREROUTING -p udp --dport 30000:30002 -m comment --comment \"V2NODE-HY2\" -j REDIRECT --to-ports 443",
            "-A PREROUTING -p tcp -j OTHER",
        ]
        .join("\n");

        let commands = reconcile_port_forward_commands("iptables", &rules, &output, true);
        let got = commands
            .iter()
            .map(|command| {
                let mut row = vec![command.tool.clone()];
                row.extend(command.args.clone());
                row
            })
            .collect::<Vec<_>>();
        let want = string_rows(vec![
            vec![
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                "udp",
                "-j",
                "V2NODE-HY2",
            ],
            vec![
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                "10000:10002",
                "-j",
                "V2NODE-HY2",
            ],
            vec![
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                "30000:30002",
                "-m",
                "comment",
                "--comment",
                "V2NODE-HY2",
                "-j",
                "REDIRECT",
                "--to-ports",
                "443",
            ],
            vec!["iptables", "-t", "nat", "-F", "V2NODE-HY2"],
            vec!["iptables", "-t", "nat", "-X", "V2NODE-HY2"],
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                "30000:30002",
                "-m",
                "comment",
                "--comment",
                "V2NODE-HY2",
                "-j",
                "REDIRECT",
                "--to-ports",
                "443",
            ],
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "udp",
                "-m",
                "multiport",
                "--dports",
                "20000,20001",
                "-m",
                "comment",
                "--comment",
                "V2NODE-HY2",
                "-j",
                "REDIRECT",
                "--to-ports",
                "8443",
            ],
        ]);

        assert_eq!(got, want);
    }

    #[test]
    fn reconcile_commands_skip_missing_stale_chain_cleanup() {
        let infos = vec![node(1, 443, "30000-30002", "")];
        let (rules, errors) = build_hysteria_port_forward_rules(&infos);
        assert!(errors.is_empty());

        let commands = reconcile_port_forward_commands("iptables", &rules, "", false);
        let got = commands
            .iter()
            .map(|command| {
                let mut row = vec![command.tool.clone()];
                row.extend(command.args.clone());
                row
            })
            .collect::<Vec<_>>();
        let want = string_rows(vec![vec![
            "iptables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            "udp",
            "--dport",
            "30000:30002",
            "-m",
            "comment",
            "--comment",
            "V2NODE-HY2",
            "-j",
            "REDIRECT",
            "--to-ports",
            "443",
        ]]);

        assert_eq!(got, want);
    }

    #[test]
    fn inspect_hysteria_port_forward_uses_executor_outputs() {
        let infos = vec![node(1, 443, "30000-30002", "")];
        let mut executor = FakePortForwardExecutor::root();
        executor.available.insert("iptables".to_string());
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "PREROUTING"],
            Ok("-A PREROUTING -p udp -j V2NODE-HY2\n".to_string()),
        );
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "V2NODE-HY2"],
            Ok("-N V2NODE-HY2\n".to_string()),
        );

        let status = inspect_hysteria_port_forward(&infos, &mut executor);

        assert!(status.running_as_root);
        assert_eq!(status.tools.len(), 2);
        assert!(status.tools[0].available);
        assert_eq!(status.tools[0].missing.len(), 2);
        assert!(status.tools[0]
            .missing
            .iter()
            .any(|spec| spec.contains("-A INPUT") && spec.contains("--dport 443")));
        assert!(status.tools[0].stale_chain);
        assert!(!status.tools[1].available);
    }

    #[test]
    fn repair_hysteria_port_forward_allows_target_server_port() {
        let infos = vec![node(1, 10088, "32000-33000", "")];
        let mut executor = FakePortForwardExecutor::root();
        executor.available.insert("iptables".to_string());
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "PREROUTING"],
            Ok(String::new()),
        );
        executor.output("iptables", &["-S", "INPUT"], Ok(String::new()));
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "V2NODE-HY2"],
            Err("missing chain".to_string()),
        );

        let status = repair_hysteria_port_forward(&infos, &mut executor);

        assert!(status.errors.is_empty(), "{:?}", status.errors);
        assert!(executor.ran.iter().any(|command| {
            command.args
                == strings(vec![
                    "-I",
                    "INPUT",
                    "-p",
                    "udp",
                    "--dport",
                    "10088",
                    "-m",
                    "comment",
                    "--comment",
                    "V2NODE-HY2",
                    "-j",
                    "ACCEPT",
                ])
        }));
        assert!(status.tools[0]
            .expected
            .iter()
            .any(|spec| spec.contains("-A INPUT") && spec.contains("--dport 10088")));
    }

    #[test]
    fn inspect_hysteria_port_forward_counts_existing_target_port_allow() {
        let infos = vec![node(1, 10088, "32000-33000", "")];
        let mut executor = FakePortForwardExecutor::root();
        executor.available.insert("iptables".to_string());
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "PREROUTING"],
            Ok("-A PREROUTING -p udp --dport 32000:33000 -m comment --comment V2NODE-HY2 -j REDIRECT --to-ports 10088\n".to_string()),
        );
        executor.output(
            "iptables",
            &["-S", "INPUT"],
            Ok("-A INPUT -p udp -m udp --dport 10088 -m comment --comment \"V2NODE-HY2\" -j ACCEPT\n".to_string()),
        );

        let status = inspect_hysteria_port_forward(&infos, &mut executor);

        assert!(
            status.tools[0].missing.is_empty(),
            "{:?}",
            status.tools[0].missing
        );
        assert!(
            status.tools[0].extra.is_empty(),
            "{:?}",
            status.tools[0].extra
        );
    }

    #[test]
    fn repair_hysteria_port_forward_noops_when_rules_are_current() {
        let infos = vec![node(1, 10088, "32000-33000", "")];
        let mut executor = FakePortForwardExecutor::root();
        executor.available.insert("iptables".to_string());
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "PREROUTING"],
            Ok("-A PREROUTING -p udp --dport 32000:33000 -m comment --comment V2NODE-HY2 -j REDIRECT --to-ports 10088\n".to_string()),
        );
        executor.output(
            "iptables",
            &["-S", "INPUT"],
            Ok(
                "-A INPUT -p udp -m udp --dport 10088 -m comment --comment V2NODE-HY2 -j ACCEPT\n"
                    .to_string(),
            ),
        );
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "V2NODE-HY2"],
            Err("missing chain".to_string()),
        );

        let status = repair_hysteria_port_forward(&infos, &mut executor);

        assert!(status.errors.is_empty(), "{:?}", status.errors);
        assert!(status.tools[0].missing.is_empty());
        assert!(status.tools[0].extra.is_empty());
        assert!(executor.ran.is_empty(), "{:?}", executor.ran);
    }

    #[test]
    fn cleanup_hysteria_port_forward_removes_target_port_allow() {
        let mut executor = FakePortForwardExecutor::root();
        executor.available.insert("iptables".to_string());
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "PREROUTING"],
            Ok(String::new()),
        );
        executor.output(
            "iptables",
            &["-S", "INPUT"],
            Ok(
                "-A INPUT -p udp -m udp --dport 10088 -m comment --comment V2NODE-HY2 -j ACCEPT\n"
                    .to_string(),
            ),
        );
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "V2NODE-HY2"],
            Err("missing chain".to_string()),
        );

        let status = cleanup_hysteria_port_forward(&mut executor);

        assert!(status.errors.is_empty(), "{:?}", status.errors);
        assert!(executor.ran.iter().any(|command| {
            command.args
                == strings(vec![
                    "-D",
                    "INPUT",
                    "-p",
                    "udp",
                    "-m",
                    "udp",
                    "--dport",
                    "10088",
                    "-m",
                    "comment",
                    "--comment",
                    "V2NODE-HY2",
                    "-j",
                    "ACCEPT",
                ])
        }));
    }

    #[test]
    fn repair_hysteria_port_forward_requires_root() {
        let infos = vec![node(1, 443, "30000-30002", "")];
        let mut executor = FakePortForwardExecutor::non_root();
        executor.available.insert("iptables".to_string());
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "PREROUTING"],
            Ok(String::new()),
        );

        let status = repair_hysteria_port_forward(&infos, &mut executor);

        assert!(!status.running_as_root);
        assert!(status
            .errors
            .iter()
            .any(|error| error.contains("requires root")));
        assert!(executor.ran.is_empty());
    }

    #[test]
    fn repair_hysteria_port_forward_runs_planned_commands() {
        let infos = vec![node(1, 443, "30000-30002", "")];
        let mut executor = FakePortForwardExecutor::root();
        executor.available.insert("iptables".to_string());
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "PREROUTING"],
            Ok("-A PREROUTING -p udp -j V2NODE-HY2\n".to_string()),
        );
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "V2NODE-HY2"],
            Err("missing chain".to_string()),
        );

        let status = repair_hysteria_port_forward(&infos, &mut executor);

        assert!(status.running_as_root);
        assert!(status.errors.is_empty());
        assert!(executor
            .ran
            .iter()
            .any(|command| command.args.contains(&"-A".to_string())));
        assert!(executor
            .ran
            .iter()
            .any(|command| command.args.contains(&"-D".to_string())));
    }

    #[test]
    fn cleanup_hysteria_port_forward_runs_cleanup_commands() {
        let mut executor = FakePortForwardExecutor::root();
        executor.available.insert("iptables".to_string());
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "PREROUTING"],
            Ok("-A PREROUTING -p udp -j V2NODE-HY2\n".to_string()),
        );
        executor.output(
            "iptables",
            &["-t", "nat", "-S", "V2NODE-HY2"],
            Ok("-N V2NODE-HY2\n".to_string()),
        );

        let status = cleanup_hysteria_port_forward(&mut executor);

        assert!(!status.enabled);
        assert!(status.errors.is_empty());
        assert!(executor
            .ran
            .iter()
            .any(|command| command.args == strings(vec!["-t", "nat", "-F", "V2NODE-HY2"])));
    }

    fn node(id: u32, server_port: u16, port: &str, ports: &str) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(json!({
            "protocol": "hysteria2",
            "server_port": server_port,
            "port": port,
            "ports": ports
        }))
        .unwrap();
        NodeInfo::from_common("https://panel.example.test", id, common).unwrap()
    }

    fn string_rows(rows: Vec<Vec<&str>>) -> Vec<Vec<String>> {
        rows.into_iter().map(strings).collect()
    }

    fn strings(values: Vec<&str>) -> Vec<String> {
        values.into_iter().map(str::to_string).collect()
    }

    #[derive(Default)]
    struct FakePortForwardExecutor {
        available: BTreeSet<String>,
        outputs: BTreeMap<String, Result<String, String>>,
        ran: Vec<PortForwardCommand>,
        root: bool,
    }

    impl FakePortForwardExecutor {
        fn root() -> Self {
            Self {
                root: true,
                ..Self::default()
            }
        }

        fn non_root() -> Self {
            Self::default()
        }

        fn output(&mut self, tool: &str, args: &[&str], result: Result<String, String>) {
            let command = PortForwardCommand {
                tool: tool.to_string(),
                args: args.iter().map(|value| value.to_string()).collect(),
            };
            self.outputs.insert(command_key(&command), result);
        }
    }

    impl PortForwardExecutor for FakePortForwardExecutor {
        fn is_tool_available(&mut self, tool: &str) -> bool {
            self.available.contains(tool)
        }

        fn command_output(&mut self, command: &PortForwardCommand) -> Result<String, String> {
            self.outputs
                .get(&command_key(command))
                .cloned()
                .unwrap_or_else(|| Ok(String::new()))
        }

        fn run_command(&mut self, command: &PortForwardCommand) -> Result<(), String> {
            self.ran.push(command.clone());
            Ok(())
        }

        fn running_as_root(&self) -> bool {
            self.root
        }
    }

    fn command_key(command: &PortForwardCommand) -> String {
        format!("{} {}", command.tool, command.args.join(" "))
    }
}
