use std::env;
use std::fs;
use std::process::Command;

use serde_json::{json, Value};

use crate::health::{ResourceSnapshot, UsageSnapshot};

pub fn collect_resource_snapshot() -> ResourceSnapshot {
    let (mem, swap) = read_linux_memory_snapshot().unwrap_or_default();

    ResourceSnapshot {
        cpu: read_linux_loadavg_cpu_percent().unwrap_or_default(),
        mem,
        swap,
        disk: read_linux_disk_snapshot().unwrap_or_default(),
        net: read_linux_net_snapshot(),
        ip: read_local_ip_snapshot(),
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

pub fn parse_linux_loadavg_cpu_percent(input: &str, cpu_count: usize) -> Option<f64> {
    if cpu_count == 0 {
        return None;
    }
    let one_minute = input
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())?;
    if !one_minute.is_finite() || one_minute < 0.0 {
        return None;
    }
    Some(((one_minute / cpu_count as f64) * 100.0).max(0.0))
}

pub fn parse_df_portable_bytes(input: &str) -> Option<UsageSnapshot> {
    let line = input.lines().find(|line| {
        let trimmed = line.trim_start();
        !trimmed.is_empty() && !trimmed.starts_with("Filesystem")
    })?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 3 {
        return None;
    }
    let total = fields.get(1)?.parse::<u64>().ok()?;
    let used = fields.get(2)?.parse::<u64>().ok()?;
    Some(UsageSnapshot { total, used })
}

pub fn parse_linux_net_dev(input: &str) -> Option<Value> {
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut interfaces = Vec::new();

    for line in input.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name == "lo" {
            continue;
        }
        let fields = rest.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 16 {
            continue;
        }
        let rx = fields[0].parse::<u64>().unwrap_or(0);
        let tx = fields[8].parse::<u64>().unwrap_or(0);
        rx_bytes = rx_bytes.saturating_add(rx);
        tx_bytes = tx_bytes.saturating_add(tx);
        interfaces.push(json!({
            "name": name,
            "rx_bytes": rx,
            "tx_bytes": tx
        }));
    }

    if interfaces.is_empty() {
        None
    } else {
        Some(json!({
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "interfaces": interfaces
        }))
    }
}

pub fn parse_hostname_i_addresses(input: &str) -> Option<Value> {
    let mut local = Vec::new();
    let mut local_ipv4 = Vec::new();
    let mut local_ipv6 = Vec::new();

    for value in input.split_whitespace().map(str::trim) {
        if value.is_empty() {
            continue;
        }
        local.push(value.to_string());
        if value.contains(':') {
            local_ipv6.push(value.to_string());
        } else {
            local_ipv4.push(value.to_string());
        }
    }

    if local.is_empty() {
        None
    } else {
        Some(json!({
            "local": local,
            "local_ipv4": local_ipv4,
            "local_ipv6": local_ipv6
        }))
    }
}

fn read_linux_memory_snapshot() -> Option<(UsageSnapshot, UsageSnapshot)> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    Some(parse_linux_meminfo(&content))
}

fn read_linux_disk_snapshot() -> Option<UsageSnapshot> {
    let output = Command::new("df")
        .args(["-P", "-B1", "/"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let content = String::from_utf8(output.stdout).ok()?;
    parse_df_portable_bytes(&content)
}

fn read_linux_loadavg_cpu_percent() -> Option<f64> {
    let content = fs::read_to_string("/proc/loadavg").ok()?;
    let cpu_count = std::thread::available_parallelism().ok()?.get();
    parse_linux_loadavg_cpu_percent(&content, cpu_count)
}

fn read_local_ip_snapshot() -> Option<Value> {
    let output = Command::new("hostname").arg("-I").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let content = String::from_utf8(output.stdout).ok()?;
    parse_hostname_i_addresses(&content)
}

fn read_linux_net_snapshot() -> Option<Value> {
    let content = fs::read_to_string("/proc/net/dev").ok()?;
    parse_linux_net_dev(&content)
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

    use super::{
        parse_df_portable_bytes, parse_hostname_i_addresses, parse_linux_loadavg_cpu_percent,
        parse_linux_meminfo, parse_linux_net_dev, parse_linux_uptime_seconds,
        system_info_value,
    };

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
    fn parses_loadavg_as_cpu_percent() {
        assert_eq!(
            parse_linux_loadavg_cpu_percent("2.00 1.00 0.50 1/100 1", 4),
            Some(50.0)
        );
        assert_eq!(parse_linux_loadavg_cpu_percent("2.00", 0), None);
        assert_eq!(parse_linux_loadavg_cpu_percent("", 4), None);
    }

    #[test]
    fn parses_df_portable_bytes_output() {
        let snapshot = parse_df_portable_bytes(
            r#"
Filesystem     1B-blocks    Used Available Use% Mounted on
/dev/root       4096        1024      3072  25% /
"#,
        )
        .unwrap();

        assert_eq!(snapshot.total, 4096);
        assert_eq!(snapshot.used, 1024);
    }

    #[test]
    fn parses_linux_net_dev_totals_without_loopback() {
        let value = parse_linux_net_dev(
            r#"
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0
  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0
  eth1: 3000 0 0 0 0 0 0 0 4000 0 0 0 0 0 0 0
"#,
        )
        .unwrap();

        assert_eq!(value["rx_bytes"], json!(4000));
        assert_eq!(value["tx_bytes"], json!(6000));
        assert_eq!(value["interfaces"][0]["name"], json!("eth0"));
    }

    #[test]
    fn parses_hostname_i_addresses_by_family() {
        let value = parse_hostname_i_addresses("192.0.2.10 2001:db8::10 ").unwrap();

        assert_eq!(value["local"][0], json!("192.0.2.10"));
        assert_eq!(value["local_ipv4"][0], json!("192.0.2.10"));
        assert_eq!(value["local_ipv6"][0], json!("2001:db8::10"));
    }

    #[test]
    fn system_info_contains_platform_shape() {
        let value = system_info_value();

        assert_ne!(value["os"], json!(""));
        assert_ne!(value["arch"], json!(""));
    }
}
