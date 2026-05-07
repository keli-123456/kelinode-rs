use std::collections::{BTreeMap, BTreeSet};

use crate::panel::types::{NodeInfo, Protocol};

pub const HYSTERIA_PORT_FORWARD_COMMENT: &str = "V2NODE-HY2";

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

        let (matchers, ranges) =
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
        if let Some(conflict_port) =
            find_target_port_conflict(&ranges, target_port, &target_ports)
        {
            errors.push(format!(
                "node {} port {:?} overlaps server_port {} from another HY2 node",
                info.id, external_port, conflict_port
            ));
            continue;
        }
        if let Some(conflict) = find_range_conflict(&ranges, target_port, &allocated) {
            errors.push(format!(
                "node {} port {:?} overlaps node {} port {}-{} with different target server_port",
                info.id, external_port, conflict.node_id, conflict.range.start, conflict.range.end
            ));
            continue;
        }

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

fn find_target_port_conflict(
    ranges: &[PortForwardRange],
    target_port: u16,
    target_ports: &BTreeMap<u16, u32>,
) -> Option<u16> {
    for port in target_ports.keys() {
        if *port == target_port {
            continue;
        }
        if ranges.iter().any(|range| range.contains(*port)) {
            return Some(*port);
        }
    }
    None
}

fn find_range_conflict(
    ranges: &[PortForwardRange],
    target_port: u16,
    allocated: &[AllocatedPortForwardRange],
) -> Option<AllocatedPortForwardRange> {
    for range in ranges {
        for existing in allocated {
            if existing.target_port == target_port {
                continue;
            }
            if range.overlaps(existing.range) {
                return Some(existing.clone());
            }
        }
    }
    None
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

    fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{build_hysteria_port_forward_rules, parse_port_forward_matchers};
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
            vec!["-m", "multiport", "--dports", "20000,20001,20002", "to=8443"],
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
            parse_port_forward_matchers("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16")
                .unwrap();

        assert_eq!(matchers.len(), 2);
        assert_eq!(
            matchers[0].args,
            strings(vec!["-m", "multiport", "--dports", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"])
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
    fn rejects_overlapping_external_ports() {
        let infos = vec![
            node(1, 443, "30000-30002", ""),
            node(2, 8443, "30002-30004", ""),
        ];

        let (rules, errors) = build_hysteria_port_forward_rules(&infos);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("overlaps node 1"));
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn rejects_external_port_over_another_server_port() {
        let infos = vec![node(1, 443, "", ""), node(2, 8443, "440-445", "")];

        let (rules, errors) = build_hysteria_port_forward_rules(&infos);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("server_port"));
        assert!(rules.is_empty());
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
}
