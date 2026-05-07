# Roadmap

## Phase 1: Contract Parity

- Configuration model for direct node, multi-node, and machine binding runtime normalization.
- Config file loader and `check-config` bootstrap inspection command.
- Panel client with the existing Keli endpoint paths and query parameters.
- Node/user/alive/traffic payloads compatible with `kelinode`.
- Node manager initialization skeleton with machine-mode failure accounting.
- Panel-backed node manager bootstrap path.
- Machine reconcile decision logic for add/remove/restart/skip/full-reload.
- User delta and full-list diff helpers compatible with Go `kelinode`.
- User sync state path/load/save helpers for warm starts.
- V2 handshake and unified report client support.
- Core inbound planning for protocol/listen/security/ALPN parity.
- Node TLS certificate runtime defaults from config directory.
- Panel-backed machine profile fetch and aggregation entrypoint.
- Runtime resolver that merges machine profile nodes and agent config.
- HY2 port-forward rule planner with conflict checks.
- HY2 port-forward status/spec drift detection helpers.
- HY2 port-forward repair/cleanup command planner.
- HY2 port-forward executor abstraction for inspect/repair/cleanup.
- Runtime bootstrap plan combining resolved config, node bootstrap, core plan, and HY2 status.
- External core config file layout, Xray JSON rendering skeleton, and atomic writes.
- Core process spec and supervisor abstraction for start/reload/stop/status.
- Health and machine status payload aggregation matching keliboard status contract.
- Runtime control apply path that writes core config, reconciles HY2 state, starts core, and builds machine status.
- Runtime panel report boundary that maps machine status responses into reload/upgrade actions.
- Runtime tick skeleton with apply/report/signal phases for the long-running loop.
- Machine self-upgrade state and launcher abstraction compatible with Go agent behavior.
- Runtime signal handler that connects upgrade actions to the self-upgrade state machine.
- Host resource snapshot basics for system metadata, Linux memory/swap, and uptime.
- Core user client planning and Xray client rendering from panel user lists.
- Node user-set loading and runtime bootstrap planning with users keyed by node tag.
- Full bootstrap entrypoint that resolves nodes and user lists before building the runtime plan.
- Xray stream network settings passthrough for websocket/grpc/httpupgrade/xhttp/tcp-style transports.
- PROXY protocol socket option rendering from panel network settings.
- Go-compatible default inbound sniffing for HTTP and TLS targets.
- TLS `rejectUnknownSni` rendering from panel certificate metadata.
- REALITY `dest`, `xver`, and `mldsa65Seed` rendering from panel TLS settings.
- VLESS flow and Shadowsocks cipher/method rendering from panel node fields.
- VLESS supported encryption/decryption string rendering with unsupported values rejected.
- Shadowsocks HTTP obfs transport headers and TCP-only network mode.
- Xray route rendering for DNS servers, block rules, protocol rules, and custom outbound rules.
- Go-compatible default outbound and DNS fallback settings.
- Xray stats and user traffic policy defaults needed for traffic reporting.
- Runtime tick core-plan rebuild path for refreshed panel user sets.
- SOCKS/HTTP account rendering and AnyTLS client/padding rendering from panel users.
- HY2 bandwidth/obfs stream rendering and TUIC congestion/0-RTT rendering.
- Unified node traffic/online activity reporting with legacy endpoint fallback.
- Per-node activity batch reporting keyed by runtime tag for multi-node machines.
- User sync state advancement for delta and full-list responses with empty-list no-change semantics.
- Runtime user refresh backed by persisted user sync state with delta-first and full-list fallback.
- Realtime protocol models for websocket messages, receipts, URL derivation, and invalidate actions.
- Realtime runtime option resolution and message-to-task mapping for later websocket workers.
- Transport-neutral realtime session worker for initial ping, pong replies, and task dispatch.
- Shadowsocks 2022 server keys and Go-compatible per-user key rendering.
- Concrete `tokio-tungstenite` realtime connector with rustls webpki roots.
- Async runtime loop event channel for realtime reload and immediate user-refresh triggers.
- `run` command realtime worker startup with queued reload and user-refresh events.
- Realtime event replies for applied/failed receipts after runtime user-refresh handling.
- Self-upgrade wrapper with install-dir backup, post-install version verification, and rollback.
- External IPv4/IPv6 probes for machine status when local public candidates are missing.
- Go-compatible `node_tag|uuid` user emails in generated core clients.
- Linux root disk usage and network byte counter collection for machine status payloads.
- Linux `/proc/stat` CPU usage sampler with loadavg fallback for machine status payloads.
- Local/public IPv4/IPv6 candidate snapshot collection for machine status payloads.
- Runtime resource sampler that derives network byte rates between machine status samples.
- Runtime loop scheduler for periodic user refresh, panel reports, and reload/upgrade signal exits.
- Async runtime loop variant for panel-backed user refresh and report ticks.
- Panel-backed runtime loop adapter that refreshes users by node tag before applying ticks.
- Runtime `run` command that rebuilds bootstrap state after reload signals and reports upgrade state after upgrade commands.
- Multi-panel machine status reporting for machine-bound deployments with more than one site profile.
- Command shutdown signal handling that stops the active core process before exiting.
- Machine node resolution and subscription proxy config merging.
- Subscription proxy profile normalization and upstream subscription URL construction.
- Subscription proxy request routing for health checks and upstream subscription forwarding.
- Subscription proxy response forwarding plan with size limits and HEAD handling.
- Subscription proxy certificate domain normalization with IPv6-to-public-IPv4 fallback planning.
- Subscription proxy certificate status, owner site selection, and serve-mode fallback planning.
- Subscription proxy ZeroSSL config preservation across direct, machine, and runtime merge paths.
- Subscription proxy ZeroSSL validation-file and fullchain certificate write planning.
- Compatibility tests around protocol parsing and endpoint construction.

## Phase 2: Runtime Control

- External core adapter for Xray-compatible generated configs.
- Safe process lifecycle: start, reload, stop, status.
- Health endpoint compatible with existing operational checks.
- File layout matching binary deployment conventions.

## Phase 3: Machine Mode

- Fetch machine-bound nodes from `keliboard`.
- Reconcile added/removed nodes without full restart when possible.
- Report system status, node failures, and upgrade state.
- Keep continue-on-error behavior for partial node failures.

## Phase 4: Realtime and Reports

- Realtime websocket client.
- Config invalidation receipts.
- User delta sync receipts.
- Traffic and online device report loop.

## Phase 5: Protocol Coverage

- Match Go `kelinode` for vmess, vless, trojan, shadowsocks, hysteria2, tuic, anytls, socks, and http.
- Add sidecar path for protocols that should not be faked inside Xray, such as Naive and Mieru.
- Consider Rust-native fast paths only after contract and reporting are stable.
