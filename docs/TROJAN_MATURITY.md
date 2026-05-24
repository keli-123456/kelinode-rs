# Trojan Native Maturity

This document tracks the Rust native Trojan path across `kelinode-rs` rendering and
`keli-core-rs` runtime behavior.

## Current Production Decision

| Combination | Status | Default native decision | Evidence |
| --- | --- | --- | --- |
| Trojan + TCP + none | UsableNeedsSoak | RenderNativeWithWarning | `keli-core-rs` Trojan unit/local runtime tests pass; GoLegacyBaseline still needs soak evidence. |
| Trojan + TCP + TLS | CanaryOnly | RenderNativeWithWarning | TLS runtime tests pass locally; SNI/ALPN/certificate real-client matrix still required. |
| Trojan + WS | CanaryOnly | Reject | Local data-plane tests pass and sing-box real-client remote interop passed, but default native rendering remains rejected until an explicit canary switch and soak evidence exist. |
| Trojan + TLS + WS | CanaryOnly | Reject | Local TLS WS tests pass and sing-box real-client remote interop passed, but default native rendering remains rejected until an explicit canary switch and TLS/CDN-shaped soak evidence exist. |
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

## Remote Evidence

- Date: 2026-05-24.
- Host: `2.56.116.39`.
- Command: `scripts/interop/trojan_ws_remote.sh --rounds 3 --interval-ms 100 --base-port 19420`.
- Client: sing-box `v1.12.22` Linux amd64.
- Cases:
  - `trojan-ws-plain`: 3 probe rounds passed through sing-box SOCKS5.
  - `trojan-ws-tls`: 3 probe rounds passed through sing-box SOCKS5 with TLS enabled and `insecure` test trust.
- Evidence level: `ThirdPartyClientInterop`.

## Known Gaps

Trojan WS and TLS WS have enough local regression coverage and short third-party client evidence to
keep improving safely, but they do not yet have the evidence required for default production native
rendering:

- Long-running soak with reconnects.
- CDN-shaped WebSocket behavior where Host/path/header handling matters.
- Tail-traffic and delete-user behavior under real client disconnect patterns.
- An explicit canary switch in `kelinode-rs` runtime planning for sites that opt into these
  combinations.

Until those gaps are closed, the native renderer must keep rejecting Trojan WS and TLS WS by default
instead of emitting a config that looks production-ready.

## Next Validation

Run the remote/interoperability matrix on a Linux host with high ports only:

```bash
cargo test trojan
cargo build --release
scripts/interop/trojan_ws_remote.sh --rounds 120 --interval-ms 1000 --base-port 19420
```

Record the result in `docs/NATIVE_CORE_SELF_ACCEPTANCE.md` before widening Trojan beyond TCP/TLS
canary usage.
