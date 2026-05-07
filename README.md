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
- Load panel users per active node and pass them into runtime bootstrap planning by node tag to keep multi-site nodes distinct.
- Build a runtime plan from config with both node configs and panel user lists loaded.
- Pass Xray stream transport settings through for websocket, grpc, httpupgrade, xhttp, tcp, and related networks.
- Render VLESS flow and Shadowsocks cipher/method options from panel node fields.
- Render supported VLESS encryption decryption strings instead of silently forcing `none`.
- Render Xray DNS, block, protocol, and custom outbound route rules from panel node routes.
- Let runtime ticks rebuild the core plan from refreshed panel user sets before applying config.
- Render SOCKS/HTTP account settings and AnyTLS client/padding settings from panel users.
- Render HY2 bandwidth/obfs stream settings and TUIC congestion/0-RTT settings.
- Report node traffic/online snapshots through the unified panel endpoint with legacy fallback.
- Batch report per-node activity snapshots by runtime tag for multi-node machines.
- Advance cached user sync state from delta or full-list responses with Go-compatible empty-list semantics.
- Collect Linux root disk usage and network byte counters for machine status payloads.

Not implemented yet:

- A long-running async loop for polling config changes, periodic reports, realtime invalidations, and shutdown.
- Full host metric collection for CPU, public/local IP fields, and network rates.
- Complete per-protocol user options for bandwidth limits, device-limit enforcement, and advanced protocol-specific credentials.
- Realtime websocket workers.
- Download verification and rollback around self-upgrade execution.
- Subscription reverse proxy.

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
```

This Windows workspace currently does not have Cargo installed, so build validation should run on a Rust-enabled Linux or CI machine.
