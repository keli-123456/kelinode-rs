# Native Core Gray Release Runbook

This runbook is for small production gray releases of the `kelinode-rs -> keli-core-rs` path.
It does not mark the native core as the default production path. The stable rollback path remains
the existing Go/Xray deployment until the real-client matrix and soak results are complete.

## Scope

Use the native core only when all of these are true:

- The node is selected for gray release.
- The protocol is covered by the current native renderer and core data path.
- The panel config does not contain native-rejected fields.
- The node has active monitoring for machine status, traffic report failures, and user delta fallback.
- Operators can switch the node back to the stable core path without changing user subscriptions.

Do not gray release unsupported panel features by silently dropping them. `kelinode-rs` must reject
unsupported native core options so the stable Xray path can remain the fallback.

## Enablement

Start with an opt-in node or machine profile:

```yaml
kernel:
  type: keli-core-rs
  core_command: "/usr/local/bin/keli-core-rs"
  config_dir: "/etc/v2node"
```

Keep `kernel.type: xray` for nodes that are not part of the gray release.

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
the generated config as a local secret. It must not be copied into:

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
- `metrics.native_core_gray_health.warning`

Healthy gray behavior:

- Incremental applies increase during normal user changes.
- Full snapshot fallback is rare and explains revision recovery.
- Full rebuild does not increase during normal small user changes.
- Current-revision-missing does not repeat after fallback snapshot repair.
- Active user counts match the expected node user set.
- `native_core_gray_health.mode` stays `native_delta` or briefly `fallback_repaired`; `degraded` and
  `full_rebuild` are rollback investigation signals.

Do not expose `user_uuid` or token values as metric dimensions.

## Traffic Reliability Signals

Traffic report failure must not lose data. Before increasing traffic, verify:

- pending traffic files survive report failures
- retry success clears only successful records
- failed-node records remain pending
- `user_id` is preferred over lookup fallback for deleted-user tail traffic
- expanded port tags such as `node-a|port:2100` fold back to `node-a`
- minimum report thresholds are honored

If panel traffic reporting fails, keep the native core running only if pending traffic continues to
persist and retry. Otherwise stop the gray release and switch the node back to the stable core path.

## Rollback

Rollback should be a config-level decision:

```yaml
kernel:
  type: xray
```

Expected rollback behavior:

- `kelinode-rs` writes the stable core config.
- The native core process is stopped or replaced by the stable core process.
- Existing pending traffic remains recoverable.
- User sync state remains available for the next native gray attempt.

Rollback triggers:

- repeated `ApplyUserDelta` failures that do not recover through full snapshot fallback
- repeated full rebuilds for small user changes
- traffic report failures with pending spool write failures
- native core process restart loops
- protocol-specific client failures above the agreed gray threshold
- p95/p99 latency or error rate regression versus the stable path

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
