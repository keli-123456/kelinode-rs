# Trojan Native Maturity

This document tracks the Rust native Trojan path across `kelinode-rs` rendering and
`keli-core-rs` runtime behavior.

## Current Production Decision

| Combination | Status | Default native decision | Evidence |
| --- | --- | --- | --- |
| Trojan + TCP + none | UsableNeedsSoak | RenderNativeWithWarning | `keli-core-rs` Trojan unit/local runtime tests pass; GoLegacyBaseline still needs soak evidence. |
| Trojan + TCP + TLS | CanaryOnly | RenderNativeWithWarning | TLS runtime tests pass locally; SNI/ALPN/certificate real-client matrix still required. |
| Trojan + WS | Broken | Reject | Known maturity/evidence gap; `kelinode-rs` capability gate blocks native rendering. |
| Trojan + TLS + WS | Broken | Reject | Known maturity/evidence gap; `kelinode-rs` capability gate blocks native rendering. |
| Trojan + gRPC | Experimental | Reject | Route outbound coverage exists, but inbound production interop is not complete. |
| Trojan + HTTPUpgrade | Experimental | Reject | Route outbound coverage exists, but inbound production interop is not complete. |
| Trojan + UDP ASSOCIATE over stream | Experimental/CanaryOnly | Not stable | Local runtime coverage exists; real-client UDP matrix and soak are missing. |

## Local Evidence

Latest local focused command:

```powershell
cargo test trojan
```

Result on 2026-05-24: `41 passed; 0 failed`.

Covered local behavior includes:

- TCP auth success/failure and TCP relay.
- TLS relay and traffic accounting.
- WebSocket upgrade, fragmented frames, close handling, ping/pong-adjacent control handling, and large-frame request coverage.
- TLS WebSocket relay, close handling, and UDP-over-stream behavior.
- Traffic accounting with user id preservation.
- ApplyUserDelta add/update/delete behavior without listener rebinding.
- Route outbound coverage for Trojan TCP/TLS/WS/H2/gRPC/HTTPUpgrade outbounds.

## Known Gaps

Trojan WS and TLS WS have enough local regression coverage to keep improving safely, but they do
not yet have the external evidence required for default production native rendering:

- Official or ecosystem client interop for the exact panel combinations.
- Long-running soak with reconnects.
- CDN-shaped WebSocket behavior where Host/path/header handling matters.
- Tail-traffic and delete-user behavior under real client disconnect patterns.

Until those gaps are closed, the native renderer must reject Trojan WS and TLS WS instead of
emitting a config that looks production-ready.

## Next Validation

Run the remote/interoperability matrix on a Linux host with high ports only:

```bash
cargo test trojan
cargo build --release
cargo run --release --example interop_matrix -- --client mihomo --mihomo /path/to/mihomo --only trojan --probe-rounds 120 --probe-interval-ms 1000 --keep
```

Record the result in `docs/NATIVE_CORE_SELF_ACCEPTANCE.md` before widening Trojan beyond TCP/TLS
canary usage.
