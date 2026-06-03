# Native Core Gray Release Runbook

This runbook is for widening the `kelinode-rs -> keli-core-rs` production path.
The native core is the default for new Rust-node installs. Keep a rollback path available until
the real-client matrix and soak results are complete on each site.

## Scope

Widen native traffic only when all of these are true:

- The node is selected for gray release.
- The protocol is covered by the current native renderer and core data path.
- The panel config does not contain native-rejected fields.
- The node has active monitoring for machine status, traffic report failures, and user delta fallback.
- Operators have a rollback plan that does not require changing user subscriptions.

Do not gray release unsupported panel features by silently dropping them. `kelinode-rs` must reject
unsupported native core options with a clear error.

## Enablement

New installs already default to native core. Keep the config explicit on production nodes:

```yaml
kernel:
  type: keli-core-rs
  config_dir: "/etc/kelinode"
```

Before starting the runtime, run the preflight gate:

```bash
kelinode gray-preflight /etc/kelinode/config.yml
```

The preflight output includes capability matrix warnings and blockers. A blocker means the native
renderer would reject or fallback that exact protocol/transport/security/UDP combination. A warning
means the config can render, but the combination still needs canary/soak evidence before widening.
Do not widen traffic while any warning is unexplained or any blocker is present.

Treat any `error:` line as a blocker. Warnings are not automatic blockers, but they must be
understood before widening traffic. In particular, explicit listen addresses such as `127.0.0.1`
or a single public IPv4/IPv6 address bypass the native core wildcard dual-stack listener behavior.

For binary gray releases, prefer the embedded native package instead of installing the agent and
core separately. The package contains one native agent binary with the Rust core linked in:

```text
bin/kelinode
```

Install it with:

```bash
sudo ./install.sh
sudo kelinode server --config /etc/kelinode/config.yml
```

The native package installs the `kelinode` binary under `/usr/local/kelinode/kelinode` and creates
`/usr/local/bin/kelinode`. It does not create a `v2node` command alias, so it will not overwrite an
existing Go `v2node` command on mixed or rollback machines.

For Docker gray releases, build the image from the `kelinode-rs` repository:

```bash
docker build --build-arg KELI_CORE_RS_REF=main -t keli-native-node:latest .
docker run --rm --network host -v /etc/kelinode:/etc/kelinode keli-native-node:latest
```

The Docker image starts `kelinode server` by default. The native core runs in-process, so there is no
separate core binary to install in the container.

Certificates remain external files. Mount the host certificate directory into the same path rendered
by the panel, or in direct-node Docker mode provide `V2NODE_TLS_CERT_URL` and
`V2NODE_TLS_KEY_URL` so the entrypoint can download them before startup. In machine or multi-node
mode, prefer mounting the certificate directory, or set `V2NODE_TLS_CERT_FILE` and
`V2NODE_TLS_KEY_FILE` explicitly when using URL download. If certificate files are missing, empty, or
clearly malformed, the agent generates a self-signed fallback certificate using the panel-rendered
domain before writing the core config. Treat that as a startup safety net only; widening gray traffic
should still require trusted certificates to be mounted or downloaded successfully.

Native `geoip:` and `geosite:` rules read text files from `geoip/<rule>.txt` and
`geosite/<rule>.txt` below `kernel.config_dir`. The one-click installer downloads common rule
groups by default, including `geosite:apple` and `geoip:cn`; use `--skip-geo-rules` or the
`KELI_GEOSITE_RULES` / `KELI_GEOIP_RULES` environment variables to customize that bootstrap. The
native core follows v2fly-style `include:` lines and strips attributes such as `@cn` from geosite
text files. Built-in private rules and a small common-domain fallback work without files. Binary
`.dat` geodata files are not parsed by the native Rust core.

Native DNS uses `kernel.dns_servers` when present and falls back to `1.1.1.1` / `8.8.8.8` when it
is empty. DNS private-address blocking is opt-in so existing internal deployments keep working by
default:

```yaml
kernel:
  type: keli-core-rs
  dns_servers:
    - "1.1.1.1"
    - "8.8.8.8"
  dns_block_private_ips: true
  dns_private_ip_allowlist:
    - "domain:internal.example"
    - "ip:10.0.0.0/8"
```

Enable `dns_block_private_ips` for public proxy nodes when DNS rebinding or accidental private IP
egress is a concern. Keep explicit allowlist entries for local upstreams that are intentionally
private, such as internal DNS names or private service subnets.

Recommended rollout:

1. Internal test node with no customer traffic.
2. One protocol on one low-risk node.
3. One region with a small number of real users.
4. 1% traffic or a single production node.
5. 5% traffic after a stable soak window.
6. More nodes only after user delta, traffic, and interop signals stay healthy.

## Control Safety

`kelinode-rs` generates a local per-config control token for `keli-core-rs`, injects it through
`KELI_CORE_CONTROL_TOKEN`, and uses the same token for control commands. The token is stored beside
the generated config as a local secret. On Unix systems the token file is kept at `0600` when it is
created or reused. It must not be copied into:

- core config JSON
- machine status payloads
- logs
- panel-visible health details

The core also rejects non-loopback control listeners without a token. Loopback without token is only
for explicit development mode.

## User Delta Signals

Use machine status metrics to verify that small user changes stay on the native delta path:

- `metrics.user_delta.kelinode_user_delta_native_apply_success_total`
- `metrics.user_delta.kelinode_user_delta_native_apply_failed_total`
- `metrics.user_delta.kelinode_user_delta_full_snapshot_fallback_total`
- `metrics.user_delta.kelinode_user_delta_full_rebuild_total`
- `metrics.keli_core_rs.keli_core_user_delta_incremental_total`
- `metrics.keli_core_rs.keli_core_user_delta_full_snapshot_total`
- `metrics.keli_core_rs.keli_core_user_delta_revision_mismatch_total`
- `metrics.keli_core_rs.keli_core_user_delta_current_revision_missing_total`
- `metrics.keli_core_rs.keli_core_user_delta_active_users`
- `metrics.native_core_gray_health.mode`
- `metrics.native_core_gray_health.gate`
- `metrics.native_core_gray_health.can_widen`
- `metrics.native_core_gray_health.rollback_recommended`
- `metrics.native_core_gray_health.warning`
- `metrics.native_core_gray_health.reasons`
- `metrics.native_core_gray_health.metrics_available`
- `metrics.native_core_gray_health.core_apply_total`
- `metrics.native_core_gray_health.core_incremental_total`
- `metrics.native_core_gray_health.core_full_snapshot_total`
- `metrics.native_core_gray_health.core_apply_duration_last_ms`
- `metrics.native_core_gray_health.core_apply_duration_max_ms`
- `metrics.native_core_gray_health.core_process_rss_bytes`
- `metrics.native_core_gray_health.core_process_peak_rss_bytes`
- `metrics.native_core_gray_health.core_process_anonymous_rss_bytes`
- `metrics.native_core_gray_health.core_process_file_rss_bytes`
- `metrics.native_core_gray_health.core_process_data_bytes`
- `metrics.native_core_gray_health.core_process_threads`
- `metrics.native_core_gray_health.core_process_cpu_percent_x100`
- `metrics.native_core_gray_health.core_process_open_fds`
- `metrics.native_core_gray_health.core_connection_active_total`

Healthy gray behavior:

- Incremental applies increase during normal user changes.
- Full snapshot fallback is rare and explains revision recovery.
- Full rebuild does not increase during normal small user changes.
- Current-revision-missing does not repeat after fallback snapshot repair.
- Active user counts match the expected node user set.
- `native_core_gray_health.mode` stays `native_delta` or briefly `fallback_repaired`; `degraded` and
  `full_rebuild` are rollback investigation signals.
- `native_core_gray_health.gate` is `allow_widen` only for a clean `native_delta` path. Treat
  `hold_monitor` as a pause before widening and `hold_rollback` as a rollback investigation signal.
- `native_core_gray_health.reasons` explains the gate, for example `metrics_unavailable`,
  `native_apply_failed`, `core_apply_error`, `full_rebuild`, `revision_mismatch`, or
  `current_revision_missing`.

Resource sampling notes:

- `core_process_rss_bytes` and `core_process_peak_rss_bytes` come from the native core process and
  should be tracked as a trend, not as a single absolute pass/fail number.
- `core_process_anonymous_rss_bytes` helps distinguish heap/private memory from mapped file cache.
- `core_process_cpu_percent_x100` is CPU percentage multiplied by 100. For example `6075` means
  about `60.75%` of one CPU core between samples.
- `core_process_open_fds`, `core_connection_active_total`, and relay-active counters are still the
  first place to look when RSS grows with connection pressure.

Linux side-check commands for a gray node:

```bash
pid=$(pgrep -f 'kelinode server --config|keli-core-rs' | head -n1)
grep -E 'VmRSS|VmHWM|RssAnon|RssFile|VmData|Threads' /proc/$pid/status
ls /proc/$pid/fd | wc -l
ps -p "$pid" -o pid,pcpu,pmem,rss,vsz,nlwp,comm
ss -tanp 2>/dev/null | grep "pid=$pid," | awk '{count[$1]++} END {for (s in count) print s,count[s]}'
```

Do not expose `user_uuid` or token values as metric dimensions.

## Traffic Reliability Signals

Traffic report failure must not lose data. Before increasing traffic, verify:

- pending traffic files survive report failures
- retry success clears only successful records
- failed-node records remain pending
- exact duplicate records from pending plus fresh drain are reported once
- `user_id` is preferred over lookup fallback for deleted-user tail traffic
- expanded port tags such as `node-a|port:2100` fold back to `node-a`
- minimum report thresholds are honored

If panel traffic reporting fails, keep the native core running only if pending traffic continues to
persist and retry. Otherwise stop widening and roll the node back to the last known-good release.

## Rollback

Rollback should be a release-level decision: pin the previous known-good `kelinode` release or
temporarily reinstall the old Go node package if a site-specific blocker requires it.

Expected rollback behavior:

- The native service is stopped cleanly before the rollback package starts.
- Existing pending traffic remains recoverable.
- User sync state remains available for the next native widening attempt.

Rollback triggers:

- repeated `ApplyUserDelta` failures that do not recover through full snapshot fallback
- repeated full rebuilds for small user changes
- traffic report failures with pending spool write failures
- native core process restart loops
- protocol-specific client failures above the agreed gray threshold
- p95/p99 latency or error rate regression versus the last known-good native release

## Interop And Soak Gate

Before widening a gray release, record at least:

- HY2 TCP relay result
- HY2 UDP relay result
- one main TCP protocol result, preferably VLESS or Trojan for the target site
- delete-user behavior result
- speed-limit behavior result
- device-limit behavior result
- traffic drain/requeue result
- one restart recovery result

The native core remains a gray candidate until the real-client matrix and soak window are complete.
