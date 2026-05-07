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

Not implemented yet:

- Running Xray/sing-box/mihomo configs.
- Realtime websocket workers.
- HY2 port-forward reconciliation.
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
