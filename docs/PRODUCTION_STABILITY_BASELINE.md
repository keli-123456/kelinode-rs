# Production Stability Baseline

Date: 2026-06-13

Baseline versions:

- `kelinode-rs v0.1.310`
- `keli-core-rs v0.1.203`
- Production host: `2.56.116.39`

This document records the current production-stability gate. It is intentionally stricter than a
single benchmark run: speed, resource trend, protocol behavior, user lifecycle behavior, and
release CI all need evidence before this baseline can be treated as long-running stable.

## Automated Gates

| Gate | Location | Purpose | Required result |
| --- | --- | --- | --- |
| Unit and integration tests | GitHub Actions `CI` | Prevent renderer, user-delta, traffic, proxy, and upgrade regressions | success |
| Resource gate smoke | `.github/workflows/ci.yml` | Keeps the resource TSV verifier from silently rotting | success |
| Watcher pattern self-test | `scripts/ops/native_resource_watch.sh --self-test-patterns` | Prevents benign domains like `panic.com` from being counted as process panics | success |
| Resource trend gate | `scripts/ops/native_resource_gate.sh` | Fails production samples on stopped service, panic lines, native relay backlog, external-core start failures, or excessive RSS | success |
| Bench comparison gate | `keli-core-rs bench compare --max-throughput-drop-percent --max-p99-increase-percent --fail-on-errors --require-all-baseline-commands` | Makes same-host protocol benchmark regressions fail instead of only producing a report | success when enabled for release comparison |
| Release workflow | `.github/workflows/release.yml` | Builds signed release artifacts and manifests | success before release |

## Production Watch

The active 24-hour watcher runs on `2.56.116.39` and writes:

```text
/tmp/keli-native-resource-v0.1.310-24h/samples.tsv
```

Start command shape:

```bash
/tmp/native_resource_watch.sh \
  --samples 1440 \
  --interval 60 \
  --out /tmp/keli-native-resource-v0.1.310-24h \
  --since "2026-06-12 18:50:00"
```

Current acceptance command:

```bash
/tmp/native_resource_gate.sh \
  --samples /tmp/keli-native-resource-v0.1.310-24h/samples.tsv \
  --min-samples 1440 \
  --max-native-pending 0 \
  --max-panic-lines 0 \
  --max-external-core-errors 0 \
  --max-rss-kb 2500000
```

Current partial evidence, before the 24-hour window is complete:

- sample time: `2026-06-12T20:01:01-04:00`
- `rows=69`
- `max_rss_kb=824168`
- `rss_growth_kb=-39140`
- `max_cpu_percent=112.77`
- `max_native_pending=0`
- `max_panic_lines=0`
- `max_external_core_errors=0`
- `max_native_user_deltas=39`

The final 24-hour verdict must not be recorded until the watcher has produced the full sample set
or the operator explicitly accepts a shorter soak window.

## Functional Acceptance Matrix

| Area | Evidence | What it proves | Remaining production check |
| --- | --- | --- | --- |
| User deletion and expiry path | Core tests named `deleting_*_user_*`, `*_delete_closes_connection`, and `*_revoked_*`; node tests `apply_user_delta_*`, `panel_runtime_loop_*user_delta*` | A removed user is deleted from the native auth table, existing relays are revoked where supported, and incremental deltas do not force unnecessary full rebuilds | Observe production user-delta counters during real panel expiry/delete events |
| Device limit | Core `limits::*device*` tests, protocol-level `allows_same_ip*` tests, production `device limit reached` logs | Device slots are enforced and released; over-limit connections are rejected without stopping the runtime | Confirm device-limit events do not correlate with native relay backlog |
| Traffic accounting | Core protocol relay tests and node `report::*` tests | Upload/download records survive user deletion tail traffic, failed reports are requeued, duplicates are folded | Confirm production traffic report failures do not grow pending spool |
| Hot user delta | Core `apply_user_delta_*without_rebinding_listener` tests and node `panel_runtime_loop_*delta*` tests | Normal user changes are applied through native delta instead of listener rebuilds | Production samples must keep `native_user_deltas` increasing and severe apply errors at zero |
| Subscription proxy | Node `subscription_proxy::*` tests and CI | Subscription route, certificate planning, health, response limits, and HTTPS server boundary behavior are covered | Run live health/proxy request when a production profile is enabled |
| Website proxy | Node `handles_website_proxy_request_with_response_rewrite`, `plans_direct_website_proxy_request_with_post_body`, `plans_path_prefixed_website_proxy_request`, and `subscription_route_takes_precedence_over_root_website_proxy` | Site proxy path matching, POST forwarding, redirect/header rewriting, and subscription route precedence are covered | Run live HTTPS request when a production website profile is enabled |
| Restart/reload recovery | Node `runtime_loop_*`, `memory_supervisor_start_reload_stop_status`, and production `Signal(Reload)` logs | Reloads rebuild runtime state without changing binary version or losing native core control | 24-hour watch should show no crash-loop restart and no severe restart logs |

Panel expiry is treated as a user-delta delete/update in the native runtime. Do not claim live
expiry acceptance from unit tests alone; the production proof is the combination of panel delta
logs, active user count changes, and rejected post-expiry authentication.

Current targeted functional verification:

```powershell
# keli-core-rs
cargo test apply_user_delta_changes -- --test-threads=1
# 7 passed: AnyTLS, Hysteria2, Shadowsocks, Trojan, TUIC, VLESS, VMess auth updates/deletes.

cargo test deleting_ -- --test-threads=1
# 13 passed: existing deleted-user relays close/stop forwarding and report tail traffic across
# AnyTLS, HTTP, Hysteria2, Mieru, Naive, Shadowsocks, SOCKS, Trojan, TUIC, VLESS, and VMess paths.

# kelinode-rs
cargo test user_delta -- --test-threads=1
# 22 passed: panel user-delta decode, Go parity, control socket ApplyUserDelta, fallback, revision,
# runtime loop, payload mapping, and no unnecessary full rebuild after successful delta apply.
```

## Protocol Regression Matrix

Local release benchmark baseline generated as:

```powershell
cargo run --release -- bench suite `
  --commands direct-tcp-stream,vless-tcp-stream,trojan-tcp-stream,hy2-tcp-stream,hy2-udp,tuic-tcp-stream,tuic-udp `
  --streams 8 `
  --requests 512 `
  --payload 1024 `
  --repeats 3 `
  --label production-gate-v0.1.203 `
  --out ..\.codex-tmp\production-gate-v0.1.203.json
```

Summary:

| Command | Errors | Retries | Avg req/s | Avg Mbps | Avg p95 us | Avg p99 us |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `direct-tcp-stream` | 0 | 0 | 114914.13 | 1882.75 | 57.33 | 149.33 |
| `vless-tcp-stream` | 0 | 0 | 34306.53 | 562.08 | 359.67 | 598.33 |
| `trojan-tcp-stream` | 0 | 0 | 28801.19 | 471.88 | 405.33 | 793.67 |
| `hy2-tcp-stream` | 0 | 0 | 32643.03 | 534.82 | 416.00 | 570.67 |
| `hy2-udp` | 0 | 0 | 17812.80 | 291.84 | 416.00 | 580.67 |
| `tuic-tcp-stream` | 0 | 0 | 30650.86 | 502.18 | 437.00 | 722.00 |
| `tuic-udp` | 0 | 0 | 17442.30 | 285.77 | 439.00 | 592.33 |

For protocol coverage beyond local loopback, use the existing remote interop helpers documented in
`docs/NATIVE_CORE_SELF_ACCEPTANCE.md`:

```bash
scripts/interop/native_matrix_remote.sh --rounds 30 --interval-ms 1000 --base-port 19500
scripts/interop/trojan_ws_remote.sh --rounds 120 --interval-ms 1000 --base-port 19420
scripts/interop/mieru_official_remote.sh --rounds 120 --interval-ms 1000
scripts/interop/naive_official_remote.sh --case naive-h2-tls --rounds 120 --interval-ms 1000
```

## Final 24-Hour Pass Criteria

The baseline is production-stable only when all of these are true:

- `kelinode` still reports `v0.1.310`.
- `ActiveState=active` and `SubState=running`.
- No unexplained service stop/start after the soak window begins.
- `native_resource_gate.sh` passes the full watcher TSV.
- The full watcher TSV has at least `1440` data rows for a 24-hour run.
- `panic_lines=0`.
- `external_core_errors=0`.
- `native_pending=0` for every sample, or any nonzero row is investigated and explained as a
  bounded transient before acceptance.
- RSS/PSS do not show monotonic growth under comparable connection load.
- User-delta apply logs continue without repeated full rebuild or revision-mismatch failure.
- GitHub CI for the gate commit is green.
