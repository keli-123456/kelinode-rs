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
