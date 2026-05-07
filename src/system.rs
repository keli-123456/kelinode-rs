use std::env;
use std::fs;

use serde_json::{json, Value};

use crate::health::{ResourceSnapshot, UsageSnapshot};

pub fn collect_resource_snapshot() -> ResourceSnapshot {
    let (mem, swap) = read_linux_memory_snapshot().unwrap_or_default();

    ResourceSnapshot {
        mem,
        swap,
        system: Some(system_info_value()),
        uptime: read_linux_uptime_seconds(),
        ..ResourceSnapshot::default()
    }
}

pub fn system_info_value() -> Value {
    json!({
        "hostname": hostname(),
        "os": env::consts::OS,
        "family": env::consts::FAMILY,
        "arch": env::consts::ARCH
    })
}

pub fn parse_linux_meminfo(input: &str) -> (UsageSnapshot, UsageSnapshot) {
    let mem_total = meminfo_kib(input, "MemTotal").unwrap_or(0) * 1024;
    let mem_available = meminfo_kib(input, "MemAvailable")
        .or_else(|| meminfo_kib(input, "MemFree"))
        .unwrap_or(0)
        * 1024;
    let swap_total = meminfo_kib(input, "SwapTotal").unwrap_or(0) * 1024;
    let swap_free = meminfo_kib(input, "SwapFree").unwrap_or(0) * 1024;

    (
        UsageSnapshot {
            total: mem_total,
            used: mem_total.saturating_sub(mem_available),
        },
        UsageSnapshot {
            total: swap_total,
            used: swap_total.saturating_sub(swap_free),
        },
    )
}

pub fn parse_linux_uptime_seconds(input: &str) -> Option<u64> {
    input
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .map(|value| value.max(0.0) as u64)
}

fn read_linux_memory_snapshot() -> Option<(UsageSnapshot, UsageSnapshot)> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    Some(parse_linux_meminfo(&content))
}

fn read_linux_uptime_seconds() -> Option<u64> {
    let content = fs::read_to_string("/proc/uptime").ok()?;
    parse_linux_uptime_seconds(&content)
}

fn meminfo_kib(input: &str, key: &str) -> Option<u64> {
    input.lines().find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        if name.trim() != key {
            return None;
        }
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

fn hostname() -> String {
    env::var("HOSTNAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{parse_linux_meminfo, parse_linux_uptime_seconds, system_info_value};

    #[test]
    fn parses_linux_meminfo_into_used_totals() {
        let (mem, swap) = parse_linux_meminfo(
            r#"
MemTotal:        1000 kB
MemAvailable:    250 kB
SwapTotal:       800 kB
SwapFree:        500 kB
"#,
        );

        assert_eq!(mem.total, 1000 * 1024);
        assert_eq!(mem.used, 750 * 1024);
        assert_eq!(swap.total, 800 * 1024);
        assert_eq!(swap.used, 300 * 1024);
    }

    #[test]
    fn parses_linux_uptime_integer_seconds() {
        assert_eq!(parse_linux_uptime_seconds("123.45 678.90"), Some(123));
        assert_eq!(parse_linux_uptime_seconds(""), None);
    }

    #[test]
    fn system_info_contains_platform_shape() {
        let value = system_info_value();

        assert_ne!(value["os"], json!(""));
        assert_ne!(value["arch"], json!(""));
    }
}
