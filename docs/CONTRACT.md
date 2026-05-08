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
- `mieru` natively with `kernel.type: keli-core-rs`, or through a matching sidecar process on the default Xray path

Naive still requires explicit Caddy forward_proxy integration before the panel should expose it as a Rust node supported protocol.

The experimental `keli-core-rs` native core path now renders SOCKS, HTTP, Shadowsocks, VMess, VLESS, Trojan, AnyTLS, Hysteria2, TUIC, Mieru TCP including expanded port ranges, common TCP/WS/HTTPUpgrade/gRPC transports, and VLESS REALITY config into the Rust core schema. Naive remains an explicit sidecar protocol.

Operators opt into that path with `kernel.type: keli-core-rs`; the default remains `xray` for production compatibility.

The native renderer parity gate is documented in `docs/NATIVE_CORE_PARITY.md`. Unsupported panel options must be rejected for `keli-core-rs` instead of being silently dropped.
