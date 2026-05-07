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
- VLESS flow and Shadowsocks cipher/method rendering from panel node fields.
- VLESS supported encryption/decryption string rendering with unsupported values rejected.
- Xray route rendering for DNS servers, block rules, protocol rules, and custom outbound rules.
- Runtime tick core-plan rebuild path for refreshed panel user sets.
- SOCKS/HTTP account rendering and AnyTLS client/padding rendering from panel users.
- HY2 bandwidth/obfs stream rendering and TUIC congestion/0-RTT rendering.
- Unified node traffic/online activity reporting with legacy endpoint fallback.
- Per-node activity batch reporting keyed by runtime tag for multi-node machines.
- User sync state advancement for delta and full-list responses with empty-list no-change semantics.
- Linux root disk usage and network byte counter collection for machine status payloads.
- Machine node resolution and subscription proxy config merging.
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
