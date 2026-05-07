# Keli Node API Contract

`kelinode-rs` must preserve the same contract used by Go `kelinode`.

## Query Parameters

Every panel request includes:

- `node_type=v2node`
- `node_id=<node id>`
- `token=<api token>`
- `machine_id=<machine id>` when machine binding is used

## Endpoints

- `GET /api/v2/server/config`
- `GET /api/v1/server/UniProxy/user`
- `GET /api/v1/server/UniProxy/user_delta`
- `GET /api/v1/server/UniProxy/alivelist`
- `POST /api/v1/server/UniProxy/push`
- `POST /api/v1/server/UniProxy/alive`
- `POST /api/v2/server/machine/status`
- `GET /api/v2/server/machine/nodes`

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

Naive and Mieru require explicit sidecar integration before the panel should expose them as Rust node supported protocols.
