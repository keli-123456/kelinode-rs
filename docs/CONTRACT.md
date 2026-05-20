# Keli Node API Contract

`kelinode-rs` must preserve the same contract used by Go `kelinode`.

## Node Query Parameters

Node-scoped panel requests include:

- `node_type=v2node`
- `node_id=<node id>`
- `token=<api token>`
- `machine_id=<machine id>` when machine binding is used

Machine-scoped requests use a JSON body instead:

```json
{
  "machine_id": 1,
  "token": "machine-token"
}
```

`POST /api/v2/server/machine/status` also includes a `status` object in that body.

## Endpoints

- `GET /api/v2/server/config`
- `GET /api/v1/server/UniProxy/user`
- `GET /api/v1/server/UniProxy/user_delta`
- `GET /api/v1/server/UniProxy/alivelist`
- `POST /api/v1/server/UniProxy/push`
- `POST /api/v1/server/UniProxy/alive`
- `POST /api/v2/server/machine/status`
- `POST /api/v2/server/machine/nodes`

## Protocols

Initial supported protocol names mirror Go `kelinode`:

- `vmess`
- `vless`
- `trojan`
- `shadowsocks`
- `hysteria2`
- `tuic`
- `anytls`
- `socks`
- `http`
- `mieru` natively
- `naive` natively for H2/TLS

Naive H3/QUIC remains intentionally rejected until the native core has a real QUIC/H3 path.

The `keli-core-rs` native core path renders SOCKS, HTTP, Shadowsocks, VMess, VLESS, Trojan, AnyTLS, Hysteria2, TUIC, Mieru TCP including expanded port ranges and stream multiplexing, Naive H2/TLS, common TCP/WS/HTTPUpgrade/H2/gRPC transports, XHTTP/splithttp stream-one route outbounds, old-QUIC route outbounds with `none`/`aes-128-gcm`/`chacha20-poly1305` packet security, VMess legacy alterId route outbounds, and VLESS REALITY config into the Rust core schema.

`kernel.type` defaults to `keli-core-rs`; operators may keep it explicit in config for readability. The embedded native release links `keli-core-rs` into the `kelinode` binary. Non-embedded development builds can still set `kernel.core_command` to an external `keli-core-rs` binary path.

The native renderer parity gate is documented in `docs/NATIVE_CORE_PARITY.md`. Unsupported panel options must be rejected for `keli-core-rs` instead of being silently dropped.
