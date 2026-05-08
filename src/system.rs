use std::env;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::health::{ResourceSnapshot, UsageSnapshot};

const PUBLIC_IPV4_ENDPOINT: &str = "https://api4.ipify.org";
const PUBLIC_IPV6_ENDPOINT: &str = "https://api6.ipify.org";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResourceSampler {
    cpu: Option<CpuCounters>,
    network: Option<TimedNetworkSnapshot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicIpFamily {
    Ipv4,
    Ipv6,
}

pub trait PublicIpProbe {
    fn probe_public_ip(&mut self, family: PublicIpFamily) -> Option<String>;
}

#[derive(Clone, Debug)]
pub struct SystemPublicIpProbe {
    client: reqwest::blocking::Client,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuCounters {
    pub total: u64,
    pub idle: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetworkSnapshot {
    pub counters: NetworkCounters,
    pub interfaces: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq)]
struct TimedNetworkSnapshot {
    at_seconds: f64,
    counters: NetworkCounters,
}

pub fn collect_resource_snapshot() -> ResourceSnapshot {
    ResourceSampler::default().sample()
}

impl ResourceSampler {
    pub fn sample(&mut self) -> ResourceSnapshot {
        self.sample_at(unix_now_seconds())
    }

    pub fn sample_with_public_ip_probe<P: PublicIpProbe>(
        &mut self,
        probe: &mut P,
    ) -> ResourceSnapshot {
        let mut snapshot = self.sample();
        snapshot.ip = enrich_public_ip_snapshot(snapshot.ip, probe);
        snapshot
    }

    fn sample_at(&mut self, now_seconds: f64) -> ResourceSnapshot {
        let (mem, swap) = read_linux_memory_snapshot().unwrap_or_default();

        ResourceSnapshot {
            cpu: self.sample_cpu_percent(),
            mem,
            swap,
            disk: read_linux_disk_snapshot().unwrap_or_default(),
            net: read_linux_net_snapshot()
                .map(|snapshot| self.sample_network_value(now_seconds, snapshot)),
            ip: read_local_ip_snapshot(),
            system: Some(system_info_value()),
            uptime: read_linux_uptime_seconds(),
            ..ResourceSnapshot::default()
        }
    }

    fn sample_cpu_percent(&mut self) -> f64 {
        let Some(current) = read_linux_cpu_counters() else {
            return read_linux_loadavg_cpu_percent().unwrap_or_default();
        };
        self.sample_cpu_percent_from_counters(current)
    }

    fn sample_cpu_percent_from_counters(&mut self, current: CpuCounters) -> f64 {
        let mut percent = 0.0;
        if let Some(previous) = self.cpu {
            let total_delta = current.total.saturating_sub(previous.total);
            let idle_delta = current.idle.saturating_sub(previous.idle);
            if total_delta > 0 && idle_delta <= total_delta {
                percent = ((total_delta - idle_delta) as f64 * 100.0) / total_delta as f64;
            }
        }
        self.cpu = Some(current);
        percent
    }

    fn sample_network_value(&mut self, now_seconds: f64, snapshot: NetworkSnapshot) -> Value {
        let mut rx_rate = 0.0;
        let mut tx_rate = 0.0;

        if let Some(previous) = &self.network {
            let elapsed = now_seconds - previous.at_seconds;
            if elapsed > 0.0 {
                if snapshot.counters.rx_bytes >= previous.counters.rx_bytes {
                    rx_rate =
                        (snapshot.counters.rx_bytes - previous.counters.rx_bytes) as f64 / elapsed;
                }
                if snapshot.counters.tx_bytes >= previous.counters.tx_bytes {
                    tx_rate =
                        (snapshot.counters.tx_bytes - previous.counters.tx_bytes) as f64 / elapsed;
                }
            }
        }

        self.network = Some(TimedNetworkSnapshot {
            at_seconds: now_seconds,
            counters: snapshot.counters,
        });
        network_status_value(snapshot, rx_rate, tx_rate)
    }
}

impl Default for SystemPublicIpProbe {
    fn default() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Self { client }
    }
}

impl PublicIpProbe for SystemPublicIpProbe {
    fn probe_public_ip(&mut self, family: PublicIpFamily) -> Option<String> {
        let endpoint = match family {
            PublicIpFamily::Ipv4 => PUBLIC_IPV4_ENDPOINT,
            PublicIpFamily::Ipv6 => PUBLIC_IPV6_ENDPOINT,
        };
        let value = self
            .client
            .get(endpoint)
            .send()
            .ok()?
            .error_for_status()
            .ok()?
            .text()
            .ok()?;
        let value = value.trim();
        match family {
            PublicIpFamily::Ipv4 if is_public_ipv4(value) => Some(value.to_string()),
            PublicIpFamily::Ipv6 if is_public_ipv6(value) => Some(value.to_string()),
            _ => None,
        }
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

pub fn parse_linux_proc_stat_cpu(input: &str) -> Option<CpuCounters> {
    let line = input
        .lines()
        .find(|line| line.trim_start().starts_with("cpu "))?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 5 || fields[0] != "cpu" {
        return None;
    }
    let values = fields[1..]
        .iter()
        .map(|value| value.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    let total = values
        .iter()
        .fold(0u64, |total, value| total.saturating_add(*value));
    let idle = values
        .get(3)
        .copied()
        .unwrap_or_default()
        .saturating_add(values.get(4).copied().unwrap_or_default());
    Some(CpuCounters { total, idle })
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
    parse_linux_net_dev_snapshot(input).map(|snapshot| network_status_value(snapshot, 0.0, 0.0))
}

pub fn parse_linux_net_dev_snapshot(input: &str) -> Option<NetworkSnapshot> {
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
        Some(NetworkSnapshot {
            counters: NetworkCounters { rx_bytes, tx_bytes },
            interfaces,
        })
    }
}

fn network_status_value(snapshot: NetworkSnapshot, rx_rate: f64, tx_rate: f64) -> Value {
    json!({
        "rx_bytes": snapshot.counters.rx_bytes,
        "tx_bytes": snapshot.counters.tx_bytes,
        "rx_rate": rx_rate,
        "tx_rate": tx_rate,
        "rx_bps": rx_rate,
        "tx_bps": tx_rate,
        "interfaces": snapshot.interfaces
    })
}

pub fn parse_hostname_i_addresses(input: &str) -> Option<Value> {
    let mut local = Vec::new();
    let mut local_ipv4 = Vec::new();
    let mut local_ipv6 = Vec::new();
    let mut public_ipv4 = String::new();
    let mut public_ipv6 = String::new();

    for value in input.split_whitespace().map(str::trim) {
        if value.is_empty() {
            continue;
        }
        local.push(value.to_string());
        if value.contains(':') {
            local_ipv6.push(value.to_string());
            if public_ipv6.is_empty() && is_public_ipv6(value) {
                public_ipv6 = value.to_string();
            }
        } else {
            local_ipv4.push(value.to_string());
            if public_ipv4.is_empty() && is_public_ipv4(value) {
                public_ipv4 = value.to_string();
            }
        }
    }

    if local.is_empty() {
        None
    } else {
        Some(json!({
            "local": local,
            "local_ipv4": local_ipv4,
            "local_ipv6": local_ipv6,
            "public_ipv4": public_ipv4,
            "public_ipv6": public_ipv6
        }))
    }
}

pub fn enrich_public_ip_snapshot<P: PublicIpProbe>(
    snapshot: Option<Value>,
    probe: &mut P,
) -> Option<Value> {
    let mut value = snapshot.unwrap_or_else(|| {
        json!({
            "local": [],
            "local_ipv4": [],
            "local_ipv6": [],
            "public_ipv4": "",
            "public_ipv6": ""
        })
    });

    if value
        .get("public_ipv4")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        if let Some(public_ipv4) = probe
            .probe_public_ip(PublicIpFamily::Ipv4)
            .filter(|value| is_public_ipv4(value))
        {
            value["public_ipv4"] = json!(public_ipv4);
        }
    }

    if value
        .get("public_ipv6")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        if let Some(public_ipv6) = probe
            .probe_public_ip(PublicIpFamily::Ipv6)
            .filter(|value| is_public_ipv6(value))
        {
            value["public_ipv6"] = json!(public_ipv6);
        }
    }

    Some(value)
}

fn is_public_ipv4(value: &str) -> bool {
    let Ok(addr) = Ipv4Addr::from_str(value) else {
        return false;
    };
    let octets = addr.octets();
    if octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || octets[0] >= 224
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return false;
    }
    true
}

fn is_public_ipv6(value: &str) -> bool {
    let Ok(addr) = Ipv6Addr::from_str(value) else {
        return false;
    };
    let segments = addr.segments();
    let first = segments[0];
    if addr.is_loopback()
        || addr.is_unspecified()
        || (first & 0xffc0) == 0xfe80
        || (first & 0xfe00) == 0xfc00
        || (first & 0xff00) == 0xff00
    {
        return false;
    }
    (first & 0xe000) == 0x2000
}

fn read_linux_memory_snapshot() -> Option<(UsageSnapshot, UsageSnapshot)> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    Some(parse_linux_meminfo(&content))
}

fn read_linux_disk_snapshot() -> Option<UsageSnapshot> {
    let output = Command::new("df").args(["-P", "-B1", "/"]).output().ok()?;
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

fn read_linux_cpu_counters() -> Option<CpuCounters> {
    let content = fs::read_to_string("/proc/stat").ok()?;
    parse_linux_proc_stat_cpu(&content)
}

fn read_local_ip_snapshot() -> Option<Value> {
    let output = Command::new("hostname").arg("-I").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let content = String::from_utf8(output.stdout).ok()?;
    parse_hostname_i_addresses(&content)
}

fn read_linux_net_snapshot() -> Option<NetworkSnapshot> {
    let content = fs::read_to_string("/proc/net/dev").ok()?;
    parse_linux_net_dev_snapshot(&content)
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

fn unix_now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        enrich_public_ip_snapshot, parse_df_portable_bytes, parse_hostname_i_addresses,
        parse_linux_loadavg_cpu_percent, parse_linux_meminfo, parse_linux_net_dev,
        parse_linux_proc_stat_cpu, parse_linux_uptime_seconds, system_info_value, CpuCounters,
        NetworkCounters, NetworkSnapshot, PublicIpFamily, PublicIpProbe, ResourceSampler,
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
    fn parses_proc_stat_cpu_counters() {
        let counters = parse_linux_proc_stat_cpu(
            r#"
cpu  100 0 50 800 100 0 0 0 0 0
cpu0 50 0 25 400 50 0 0 0 0 0
"#,
        )
        .unwrap();

        assert_eq!(counters.total, 1050);
        assert_eq!(counters.idle, 900);
    }

    #[test]
    fn resource_sampler_calculates_cpu_percent_between_samples() {
        let mut sampler = ResourceSampler::default();

        let first = sampler.sample_cpu_percent_from_counters(CpuCounters {
            total: 1000,
            idle: 800,
        });
        let second = sampler.sample_cpu_percent_from_counters(CpuCounters {
            total: 1100,
            idle: 850,
        });

        assert_eq!(first, 0.0);
        assert_eq!(second, 50.0);
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
        assert_eq!(value["rx_rate"], json!(0.0));
        assert_eq!(value["tx_rate"], json!(0.0));
        assert_eq!(value["interfaces"][0]["name"], json!("eth0"));
    }

    #[test]
    fn resource_sampler_calculates_network_rates_between_samples() {
        let mut sampler = ResourceSampler::default();

        let first = sampler.sample_network_value(
            10.0,
            NetworkSnapshot {
                counters: NetworkCounters {
                    rx_bytes: 1000,
                    tx_bytes: 2000,
                },
                interfaces: Vec::new(),
            },
        );
        let second = sampler.sample_network_value(
            12.0,
            NetworkSnapshot {
                counters: NetworkCounters {
                    rx_bytes: 1400,
                    tx_bytes: 2600,
                },
                interfaces: Vec::new(),
            },
        );

        assert_eq!(first["rx_rate"], json!(0.0));
        assert_eq!(second["rx_rate"], json!(200.0));
        assert_eq!(second["tx_rate"], json!(300.0));
        assert_eq!(second["rx_bps"], json!(200.0));
        assert_eq!(second["tx_bps"], json!(300.0));
    }

    #[test]
    fn parses_hostname_i_addresses_by_family() {
        let value = parse_hostname_i_addresses("192.168.1.10 2.56.116.39 fe80::1 2001:4860::8888 ")
            .unwrap();

        assert_eq!(value["local"][0], json!("192.168.1.10"));
        assert_eq!(value["local_ipv4"][0], json!("192.168.1.10"));
        assert_eq!(value["local_ipv6"][0], json!("fe80::1"));
        assert_eq!(value["public_ipv4"], json!("2.56.116.39"));
        assert_eq!(value["public_ipv6"], json!("2001:4860::8888"));
    }

    #[test]
    fn enriches_missing_public_ips_from_probe() {
        let snapshot = parse_hostname_i_addresses("192.168.1.10 fe80::1 ").unwrap();
        let mut probe = FakePublicIpProbe {
            ipv4: Some("2.56.116.39".to_string()),
            ipv6: Some("2001:4860::8888".to_string()),
            ..FakePublicIpProbe::default()
        };

        let value = enrich_public_ip_snapshot(Some(snapshot), &mut probe).unwrap();

        assert_eq!(value["public_ipv4"], json!("2.56.116.39"));
        assert_eq!(value["public_ipv6"], json!("2001:4860::8888"));
        assert_eq!(probe.ipv4_calls, 1);
        assert_eq!(probe.ipv6_calls, 1);
    }

    #[test]
    fn keeps_existing_public_ip_candidates_without_reprobing() {
        let snapshot = parse_hostname_i_addresses("2.56.116.39 2001:4860::8888 ").unwrap();
        let mut probe = FakePublicIpProbe::default();

        let value = enrich_public_ip_snapshot(Some(snapshot), &mut probe).unwrap();

        assert_eq!(value["public_ipv4"], json!("2.56.116.39"));
        assert_eq!(value["public_ipv6"], json!("2001:4860::8888"));
        assert_eq!(probe.ipv4_calls, 0);
        assert_eq!(probe.ipv6_calls, 0);
    }

    #[test]
    fn system_info_contains_platform_shape() {
        let value = system_info_value();

        assert_ne!(value["os"], json!(""));
        assert_ne!(value["arch"], json!(""));
    }

    #[derive(Default)]
    struct FakePublicIpProbe {
        ipv4: Option<String>,
        ipv6: Option<String>,
        ipv4_calls: usize,
        ipv6_calls: usize,
    }

    impl PublicIpProbe for FakePublicIpProbe {
        fn probe_public_ip(&mut self, family: PublicIpFamily) -> Option<String> {
            match family {
                PublicIpFamily::Ipv4 => {
                    self.ipv4_calls += 1;
                    self.ipv4.clone()
                }
                PublicIpFamily::Ipv6 => {
                    self.ipv6_calls += 1;
                    self.ipv6.clone()
                }
            }
        }
    }
}
