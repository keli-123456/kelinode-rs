# Kelinode RS

`kelinode-rs` is the Rust native node agent for Keli.

The goal is a drop-in node agent that speaks the same `keliboard` API contract while using `keli-core-rs` as the primary data plane.

## Scope

First cut:

- Mirror the existing Keli node API contract.
- Model single-node and machine-bound deployment configuration.
- Pull node config, user list, user delta, alive list, and report traffic through the same endpoints.
- Pull machine-bound nodes and report machine status through the same machine endpoints.
- Keep Docker direct node mode and binary machine binding as explicit compatibility targets.
- Use the native `keli-core-rs` data plane as the default runtime boundary.
- Plan and inspect HY2 port-forward rules, with repair/cleanup executor boundaries.
- Build runtime bootstrap plans that combine resolved config, node bootstrap, core config planning, and HY2 status.
- Render a native `keli-core-rs` config and write it through a stable file layout.
- Provide process supervisor and health payload aggregation layers for runtime integration.
- Apply a runtime plan by writing core config, reconciling HY2 forwarding state, starting/reloading core, and building the machine status payload.
- Report machine status to `keliboard` and normalize returned reload/upgrade commands for the runtime loop.
- Run a single runtime tick that applies local state, optionally reports to the panel, and returns a continue/reload/upgrade signal.
- Track machine self-upgrade status and launch verified GitHub Release upgrades through a systemd-run or detached-shell boundary.
- Feed upgrade signals into the self-upgrade state machine so the next status report can include running/failed/succeeded state.
- Collect basic host resource snapshots for system metadata, Linux memory/swap, and uptime.
- Render panel users into native core user entries for UUID/password based protocols.
- Preserve user IDs in native traffic records so deleted-user tail traffic can still be billed.
- Load panel users per active node and pass them into runtime bootstrap planning by node tag to keep multi-site nodes distinct.
- Build a runtime plan from config with both node configs and panel user lists loaded.
- Pass native stream transport settings through for websocket, grpc, httpupgrade, xhttp, tcp, and related networks.
- Render PROXY protocol socket options from panel network settings.
- Render Go-compatible default inbound sniffing for HTTP and TLS targets.
- Render TLS `rejectUnknownSni` from panel certificate metadata.
- Render REALITY `dest`, `xver`, and `mldsa65Seed` from panel TLS settings.
- Render VLESS flow and Shadowsocks cipher/method options from panel node fields.
- Render supported VLESS encryption decryption strings instead of silently forcing `none`.
- Render Shadowsocks HTTP obfs transport headers and TCP-only network mode.
- Render native DNS, block, protocol, and custom outbound route rules from panel node routes.
- Render Go-compatible default outbound and DNS fallback settings.
- Render native stats and user traffic policy defaults needed for traffic reporting.
- Let runtime ticks rebuild the core plan from refreshed panel user sets before applying config.
- Render SOCKS/HTTP account settings and AnyTLS client/padding settings from panel users.
- Render HY2 bandwidth/obfs stream settings and native TUIC congestion settings.
- Render Shadowsocks 2022 server keys and Go-compatible per-user keys.
- Parse Naive and Mieru node protocols and render supported variants directly into `keli-core-rs`.
- Report node traffic/online snapshots through the unified panel endpoint with legacy fallback.
- Batch report per-node activity snapshots by runtime tag for multi-node machines.
- Advance cached user sync state from delta or full-list responses with Go-compatible empty-list semantics.
- Use cached user sync state in the runtime loop, preferring `user_delta` and falling back to full user lists for old panels.
- Add realtime message, receipt, URL, and invalidate-action models compatible with the Go agent worker behavior.
- Resolve realtime runtime options from local config, panel node base config, and node identity.
- Map realtime inbound messages into runtime tasks for pong, config checks, forced reloads, and user sync.
- Add a transport-neutral realtime session worker for initial ping, pong replies, and task dispatch.
- Add a `tokio-tungstenite` realtime connector with rustls webpki roots.
- Let the async runtime loop react to external realtime reload and user-refresh events.
- Start realtime workers from the `run` command and queue reload/user-refresh runtime events.
- Tie realtime receipts to runtime event replies so user refresh can report applied or failed.
- Mark realtime reload receipts as queued instead of applied because the runtime exits for rebuild.
- Wrap node/core self-upgrade execution with install-dir backup, GitHub Release manifest download, sha256 verification, post-install version verification, and rollback.
- Probe external IPv4/IPv6 addresses for machine status when local interface candidates are missing.
- Collect Linux root disk usage and network byte counters for machine status payloads.
- Compute Linux CPU usage from `/proc/stat` samples, with `/proc/loadavg` as a fallback.
- Collect local and public IPv4/IPv6 candidates for machine status payloads without external network calls.
- Compute network byte rates across runtime loop samples for machine status payloads.
- Surface native per-user speed/device limit enforcement in machine status.
- Add a runtime loop scheduler for periodic user refresh, panel reports, and reload/upgrade signal exits.
- Add an async runtime loop variant for panel-backed user refresh and report ticks.
- Add a panel-backed runtime loop adapter that reloads users by node tag before applying ticks.
- Add a `run` command that keeps the runtime loop alive across reloads and carries upgrade status into machine reports.
- Report machine status to each configured machine-bound panel profile instead of only the first resolved node.
- Stop the active core process when the `run` command receives Ctrl-C or SIGTERM.
- Start the subscription proxy runtime manager from the `run` command and report startup failures through machine status.
- Normalize subscription proxy profiles and build upstream subscription URLs compatible with the Go agent.
- Plan subscription proxy `/health` and `/sub/{site}/{token}` requests with Go-compatible header forwarding.
- Fetch subscription proxy upstream responses through a bounded reqwest execution boundary.
- Handle subscription proxy main and HTTP challenge requests through injectable execution boundaries.
- Parse and render minimal HTTP/1.1 requests and responses for the subscription proxy server boundary.
- Add blocking TCP server boundaries for subscription proxy HTTP challenge and HTTP fallback modes.
- Wire subscription proxy runtime manager to start/stop HTTP fallback servers while refusing fake HTTPS serving.
- Plan subscription proxy response forwarding with size limits, header filtering, and HEAD handling.
- Resolve IPv6 subscription proxy certificate domains through an injectable public IPv4 detector.
- Plan subscription proxy certificate status, owner site selection, and HTTP fallback mode.
- Preserve subscription proxy ZeroSSL certificate, validation, and expiry fields from panel configs.
- Plan ZeroSSL validation-file and fullchain certificate writes without touching the filesystem.
- Prepare subscription proxy certificate status through an injectable file-write executor.
- Report ZeroSSL expiry as certificate not-after when local certificate parsing is unavailable.
- Plan subscription proxy CSR generation and provide an OpenSSL-backed execution boundary.
- Write planned subscription proxy files with parent directory creation and Unix mode handling.
- Map runtime subscription proxy status into the machine health payload.
- Generate stable subscription proxy fingerprints for reload decisions.
- Plan subscription proxy HTTP health and ZeroSSL challenge-file routes.
- Plan subscription proxy apply decisions for disabled, unchanged, start, and error states.
- Add a subscription proxy runtime manager that tracks fingerprint and reportable status.
- Wire the subscription proxy runtime manager to filesystem writes and readable-file checks.
- Feed subscription proxy manager status into runtime health refresh.
- Plan the optional subscription proxy HTTP challenge server from `http_listen`.
- Plan the main subscription proxy server from `https_listen` for HTTPS and HTTP fallback modes.
- Keep machine-profile panel reporting alive for subscription-proxy-only deployments.

Not implemented yet:

- Complete advanced protocol-specific limit edge cases and credentials beyond the native core's current per-user speed/device enforcement.
- Native rendering covers SOCKS/HTTP, Shadowsocks, VMess, VLESS, Trojan, AnyTLS, Hysteria2, TUIC, Mieru TCP with expanded port ranges and stream multiplexing, Naive H2/TLS, common TCP/WS/HTTPUpgrade/gRPC transports, VLESS REALITY config, direct outbound, per-user credentials, and common block/route rules.
- `kernel.type` defaults to `keli-core-rs`; the Rust-native core is the primary runtime path for new installs.
- Set `kernel.core_command` when the native core binary is installed outside `PATH`, such as from a `keli-core-rs` release tarball.
- When `keli-core-rs` is already running, `kelinode-rs` hot-applies changed native configs through the local `ApplyConfig` control socket and falls back to a process reload if that control path is unavailable.
- For native core control, `kelinode-rs` generates a per-config local token, injects it into the `keli-core-rs` process as `KELI_CORE_CONTROL_TOKEN`, and uses the same token for `ApplyConfig`, `ApplyUserDelta`, metrics, traffic drain, and requeue commands. The token is stored beside the generated config as a local control secret and is not written into the core config or machine status payload.
- Native core DNS uses `kernel.dns_servers` when configured, and supports opt-in DNS private-address blocking through `kernel.dns_block_private_ips` plus `kernel.dns_private_ip_allowlist` for intentional internal domains or CIDRs.
- Run `kelinode gray-preflight /etc/kelinode/config.yml` before widening a node. It resolves the runtime plan and fails early when nodes fail to resolve or no native inbounds are available; warnings call out missing user-sync validation and explicit single-stack listen addresses.
- Real-client interop and production soak testing are still required before removing the rollback path entirely.
- Subscription reverse proxy.

The native renderer parity gate is tracked in `docs/NATIVE_CORE_PARITY.md`.
The native production gray release runbook is tracked in `docs/NATIVE_CORE_GRAY_RELEASE.md`.

## Native Core Binary Example

When built without `embedded-core`, `kelinode-rs` starts `keli-core-rs run-config <generated-config> --control <local-addr>`. Install the `keli-core-rs` release binary on the same machine and either keep it in `PATH` or point the runtime at the absolute binary path:

```yaml
kernel:
  type: keli-core-rs
  core_command: "/usr/local/bin/keli-core-rs"
  config_dir: "/etc/v2node"
```

Leave `core_command` empty when the binary name `keli-core-rs` resolves from `PATH`.

The native bundle builds with the `embedded-core` feature, so the Rust data-plane runs inside the
agent process. The package ships a single native node binary:

```text
bin/kelinode
```

Linux release packages are built as static `x86_64-unknown-linux-musl` binaries under the
`linux-x86_64` asset name. They do not depend on the host glibc version, which keeps binary installs
compatible with older distributions.

After extracting the release package on Linux:

```bash
sudo ./install.sh
sudo v2node server --config /etc/v2node/config.yml
```

The `server` command is an alias for `run`, and both commands accept the old config flag style:

```bash
v2node server --config /etc/v2node/config.yml
v2node server -c /etc/v2node/config.yml
/usr/local/v2node/v2node run /etc/v2node/config.yml
```

Installed systemd services can be inspected with the compatibility log command:

```bash
v2node log
v2node log --tail 500 --no-follow
v2node log --raw
journalctl -u v2node -n 200 --no-pager -f
```

`v2node log` uses concise output by default and the runtime prefixes important events with
`agent`, `core`, `node`, `panel`, `hy2`, `subproxy`, or `upgrade`. Use `--raw` when you need full
`journalctl` metadata. Set `V2NODE_LOG_LEVEL=debug` only while diagnosing detailed runtime behavior.

Running the one-click installer again with a different `--machine-url` or `--machine-id` appends a
new machine profile to `/etc/v2node/config.yml` instead of replacing the previous site. The installer
keeps a timestamped backup beside the config before editing it. If the same URL and machine ID are
already present, it leaves the existing profile in place to avoid duplicate reports.

For machine-bound native testing, keep the config explicit:

```yaml
kernel:
  type: keli-core-rs
  config_dir: "/etc/v2node"

machine:
  enabled: true
  continue_on_error: true
  profiles:
    - name: "test"
      url: "https://panel.example.com"
      token: "replace-me"
      machine_id: 3
```

Docker builds produce the same single native agent binary:

```bash
docker build \
  --build-arg KELI_CORE_RS_REF=main \
  -t keli-native-node:latest \
  .

docker run --rm --network host \
  -v /etc/v2node:/etc/v2node \
  keli-native-node:latest
```

Or generate a direct-node config from environment variables:

```bash
docker run --rm --network host \
  -e V2NODE_API_HOST="https://panel.example.com" \
  -e V2NODE_API_KEY="replace-me" \
  -e V2NODE_NODE_ID="1" \
  keli-native-node:latest
```

For machine-bound mode, use `V2NODE_MACHINE_ID` instead of `V2NODE_NODE_ID`.

Certificates are not embedded in the binary. TLS, HY2, TUIC, AnyTLS, and similar listeners use the
`cert_file` and `key_file` paths rendered from the panel config, so Docker deployments should mount
the certificate directory from the host into the same path visible to the container. This matches the
old operational model and avoids baking private keys into release artifacts.

If the rendered certificate files are missing, empty, or clearly malformed, `kelinode-rs` now creates
a local self-signed fallback certificate at the rendered paths before writing the core config. The
fallback certificate uses the domain from the panel certificate metadata when available, with
`localhost` used only as a last-resort startup fallback. Existing usable certificate files are not
overwritten. This keeps a node from failing hard when certificate delivery is temporarily broken, but
public production traffic should still use a trusted certificate from the panel or mounted host path.

For direct-node Docker compatibility, the entrypoint also accepts certificate download URLs:

```bash
-e V2NODE_TLS_CERT_URL="https://example.com/fullchain.pem"
-e V2NODE_TLS_KEY_URL="https://example.com/privkey.pem"
```

When `V2NODE_NODE_ID` is present, the entrypoint asks the panel for the configured certificate paths
and downloads the files there. In machine or multi-node mode, pass explicit
`V2NODE_TLS_CERT_FILE` and `V2NODE_TLS_KEY_FILE`, or mount the certificate directory directly.

For native `geoip:` and `geosite:` route rules, the one-click installer downloads common text
rule files into the generated core config directory by default. Use `--skip-geo-rules` if the
server cannot access GitHub raw content, or set `KELI_GEOSITE_RULES`, `KELI_GEOIP_RULES`,
`KELI_GEOSITE_SOURCE_BASE`, and `KELI_GEOIP_SOURCE_BASE` before running the installer to use a
custom mirror/list.

Rule files live next to the generated core config:

```text
/etc/kelinode/geoip/<rule>.txt
/etc/kelinode/geosite/<rule>.txt
```

For example, `geosite:apple` reads `/etc/kelinode/geosite/apple.txt` and recursively follows
`include:` lines when those included rule files are present. Multi-node deployments that use
per-node config directories keep their rule files under each node's generated config directory.
Built-in `geoip:private`, `geosite:private`, and a small set of common domains such as
`geosite:apple` work without files. Binary `.dat` geodata files are not parsed by the native
Rust core; use one text file per rule group.
For Docker, mount those folders together with `/etc/kelinode` or a custom `kernel.config_dir`.

## Compatibility Targets

- Existing `keliboard` node API version: `2026-04-26`.
- Docker direct node mode.
- Binary deployment with server machine binding.
- Multi-site, multi-node runtime.
- Old panel fields must be optional and non-fatal where the Go implementation already tolerates them.

## Development

```bash
cargo test
cargo run -- version
cargo run -- run /etc/v2node/config.yml
```

This Windows workspace has Rust installed through rustup for local validation.
