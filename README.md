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

Not implemented yet:

- A long-running async loop for polling config changes, periodic reports, realtime invalidations, and shutdown.
- Real host metric collection for CPU, memory, disk, network, IP, and system fields.
- User-authenticated external core config generation.
- Realtime websocket workers.
- Machine self-upgrade execution.
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
