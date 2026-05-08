# Kelinode RS

`kelinode-rs` is the Rust rewrite track for `kelinode`.

The goal is a future drop-in node agent that can speak the same `keliboard` API contract as the Go implementation while gradually replacing runtime pieces with safer Rust modules.

## Scope

First cut:

- Mirror the existing Keli node API contract.
- Model single-node and machine-bound deployment configuration.
- Pull node config, user list, user delta, alive list, and report traffic through the same endpoints.
- Pull machine-bound nodes and report machine status through the same machine endpoints.
- Keep Docker direct node mode and binary machine binding as explicit compatibility targets.
- Define a core adapter boundary before choosing whether each protocol is external-core, sidecar, or Rust-native.
- Plan and inspect HY2 port-forward rules, with repair/cleanup executor boundaries.
- Build runtime bootstrap plans that combine resolved config, node bootstrap, core config planning, and HY2 status.
- Render an Xray-compatible core config skeleton and write it through a stable file layout.
- Provide process supervisor and health payload aggregation layers for runtime integration.
- Apply a runtime plan by writing core config, reconciling HY2 forwarding state, starting/reloading core, and building the machine status payload.
- Report machine status to `keliboard` and normalize returned reload/upgrade commands for the runtime loop.
- Run a single runtime tick that applies local state, optionally reports to the panel, and returns a continue/reload/upgrade signal.
- Track machine self-upgrade status and launch the existing installer through a systemd-run or detached-shell boundary.
- Feed upgrade signals into the self-upgrade state machine so the next status report can include running/failed/succeeded state.
- Collect basic host resource snapshots for system metadata, Linux memory/swap, and uptime.
- Render panel users into Xray client entries for UUID/password based protocols.
- Use Go-compatible `node_tag|uuid` user emails in generated core clients.
- Load panel users per active node and pass them into runtime bootstrap planning by node tag to keep multi-site nodes distinct.
- Build a runtime plan from config with both node configs and panel user lists loaded.
- Pass Xray stream transport settings through for websocket, grpc, httpupgrade, xhttp, tcp, and related networks.
- Render PROXY protocol socket options from panel network settings.
- Render Go-compatible default inbound sniffing for HTTP and TLS targets.
- Render TLS `rejectUnknownSni` from panel certificate metadata.
- Render REALITY `dest`, `xver`, and `mldsa65Seed` from panel TLS settings.
- Render VLESS flow and Shadowsocks cipher/method options from panel node fields.
- Render supported VLESS encryption decryption strings instead of silently forcing `none`.
- Render Shadowsocks HTTP obfs transport headers and TCP-only network mode.
- Render Xray DNS, block, protocol, and custom outbound route rules from panel node routes.
- Render Go-compatible default outbound and DNS fallback settings.
- Render Xray stats and user traffic policy defaults needed for traffic reporting.
- Let runtime ticks rebuild the core plan from refreshed panel user sets before applying config.
- Render SOCKS/HTTP account settings and AnyTLS client/padding settings from panel users.
- Render HY2 bandwidth/obfs stream settings, Xray TUIC congestion/0-RTT settings, and native TUIC congestion settings.
- Render Shadowsocks 2022 server keys and Go-compatible per-user keys.
- Parse Naive and Mieru node protocols while refusing to fake them inside the Xray renderer.
- Split mixed node sets into Xray and per-node sidecar core plans for Naive/Mieru.
- Build explicit sidecar process specs only when a command and arguments are provided.
- Preserve sidecar core plans in runtime bootstrap without forcing them through Xray.
- Render Mieru sidecar `mita` server configs from panel ports and user credentials.
- Write sidecar config files during runtime apply without starting unconfigured sidecar processes.
- Start configured sidecar processes through explicit per-protocol command and argument settings.
- Pass configured sidecar process environment variables with `{config}` path replacement for tools such as `mita`.
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
- Wrap self-upgrade execution with install-dir backup, post-install version verification, and rollback.
- Probe external IPv4/IPv6 addresses for machine status when local interface candidates are missing.
- Collect Linux root disk usage and network byte counters for machine status payloads.
- Compute Linux CPU usage from `/proc/stat` samples, with `/proc/loadavg` as a fallback.
- Collect local and public IPv4/IPv6 candidates for machine status payloads without external network calls.
- Compute network byte rates across runtime loop samples for machine status payloads.
- Surface non-enforced per-user speed/device limits in machine status while external-core enforcement is pending.
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

- Complete per-protocol user options for bandwidth limits, device-limit enforcement, and advanced protocol-specific credentials inside the runtime data path.
- Naive sidecar runtime still needs a concrete Caddy forward_proxy integration before it can serve traffic.
- Mieru sidecar traffic requires operators to configure the `mita` command, arguments, and optional environment for their deployment style.
- Experimental `keli-core-rs` native rendering covers SOCKS/HTTP, Shadowsocks, VMess, VLESS, Trojan, AnyTLS, Hysteria2, TUIC, common TCP/WS/HTTPUpgrade/gRPC transports, VLESS REALITY config, direct outbound, per-user credentials, and basic domain block routes.
- Set `kernel.type: keli-core-rs` to select the experimental Rust-native core plan; `xray` remains the default.
- Real-client interop and production soak testing are still required before making `keli-core-rs` the default.
- Subscription reverse proxy.

The native renderer parity gate is tracked in `docs/NATIVE_CORE_PARITY.md`.

## Sidecar Process Example

Mieru sidecar nodes can run `mita` with the generated config path passed through an environment variable:

```yaml
kernel:
  sidecars:
    mieru:
      command: "/usr/local/bin/mita"
      args: ["run"]
      env:
        MITA_CONFIG_JSON_FILE: "{config}"
```

Use a small wrapper command instead when a sidecar needs a multi-step apply/start flow.

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
