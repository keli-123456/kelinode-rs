# Native Core Self Acceptance

Date: 2026-05-24
Branch: `codex/all-protocol-maturity-pass`

This document is evidence-based. `reviewed` is not treated as `passed`, a matrix entry is not a
maturity pass, and local loopback evidence is not treated as `Stable`.

## Evidence Rules

- Short remote interop passed does not mean `Stable`; it is evidence for `UsableNeedsSoak` or `CanaryOnly` until longer soak and gray rollout evidence exist.
- Trojan WS/TLS WS/gRPC/HTTPUpgrade remain default `Reject` even after sing-box interop; they need an explicit canary switch plus soak before default native rendering.
- Naive H3/QUIC official-client interop is still blocked at QUIC TLS certificate verification and cannot be marked stable.
- Mieru TCP official interop passed, but it still lacks soak evidence and cannot be marked stable.
- Mieru UDP underlay is explicitly `Unsupported / Reject`; it has a dedicated capability entry and must not fall through to a generic lookup miss.

## Capability Gates

| Item | Evidence | Status |
| --- | --- | --- |
| Capability model | `src/native_capability.rs` models protocol, direction, transport, security, UDP mode, status, decision, baseline, and evidence level. | Passed |
| Renderer/planning gate | `split_core_plans_for_nodes_with_kind` fails hard on rejected native capabilities instead of silently skipping active nodes. | Passed |
| Gray preflight gate | `native_gray_preflight_report` reports rejected capability blockers with protocol/direction/transport/security/status/baseline/evidence context. | Passed |
| Trojan WS/TLS WS default production gate | Status is `CanaryOnly`, but default decision remains `Reject` until an explicit canary switch and longer soak exist. | Passed |
| Go model parity audit | `docs/GO_MODEL_PARITY.md` plus `tests/fixtures/go_model_parity/go_legacy_fixtures.json` freeze Go panel, user, route, DNS, stream transport, TLS/REALITY, user-delta, and traffic-key semantics. | Passed |

## Protocol Evidence

| Protocol | ModelDefined | RendererGateConnected | LocalUnitPassed | LocalRuntimePassed | RemoteInteropPassed | OfficialClientInteropPassed | ThirdPartyClientInteropPassed | SoakTested | ProductionDecision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SOCKS | yes | yes | yes | yes | yes | n/a | yes: sing-box `socks-tcp` | no | UsableNeedsSoak / RenderNativeWithWarning |
| HTTP proxy | yes | yes | yes | yes | yes | n/a | yes: sing-box `http-proxy-tcp` | no | UsableNeedsSoak / RenderNativeWithWarning |
| Shadowsocks | yes | yes | yes | yes | yes | n/a | yes: sing-box `shadowsocks-tcp`, `shadowsocks-udp` | no | UsableNeedsSoak / RenderNativeWithWarning |
| VLESS | yes | yes | yes | yes | yes | n/a | yes: sing-box TCP/TLS/Vision/REALITY/WS/HTTPUpgrade/gRPC | no | UsableNeedsSoak or CanaryOnly / RenderNativeWithWarning |
| VMess | yes | yes | yes | yes | yes | n/a | yes: sing-box TCP/TLS/WS/HTTPUpgrade/gRPC | no | UsableNeedsSoak or CanaryOnly / RenderNativeWithWarning |
| Trojan TCP/TLS | yes | yes | yes | yes | yes | n/a | yes: sing-box TCP plain/TLS | no | UsableNeedsSoak or CanaryOnly / RenderNativeWithWarning |
| Trojan WS/TLS WS | yes | yes | yes | yes | yes | n/a | yes: sing-box WS plain/TLS | no | CanaryOnly / Reject by default until explicit canary gate |
| Trojan gRPC/HTTPUpgrade | yes | yes | yes | yes | yes | n/a | yes: sing-box gRPC and HTTPUpgrade plain/TLS | no | CanaryOnly / Reject by default until explicit canary gate |
| AnyTLS | yes | yes | yes | yes | yes | n/a | yes: sing-box `anytls-tls` | no | CanaryOnly / RenderNativeWithWarning |
| Hysteria2 | yes | yes | yes | yes | yes | n/a | yes: sing-box `hy2-tls`, `hy2-salamander` | no | UsableNeedsSoak / RenderNativeWithWarning |
| TUIC | yes | yes | yes | yes | yes | n/a | yes: sing-box `tuic-tls` | no | UsableNeedsSoak / RenderNativeWithWarning |
| Naive H2/TLS | yes | yes | yes | yes | yes | yes: official NaiveProxy H2/TLS | no | no | CanaryOnly / RenderNativeWithWarning |
| Naive H3/QUIC | yes | yes | yes | yes | no | no: official client blocked at QUIC TLS certificate verification | no | no | CanaryOnly / RenderNativeWithWarning, not Stable |
| Mieru TCP underlay | yes | yes | yes | yes | yes | yes: official Mieru TCP underlay | no | no | CanaryOnly / RenderNativeWithWarning |
| Mieru UDP underlay | yes | yes | yes reject path | n/a | no | no | no | no | Unsupported / Reject |
| Direct outbound | yes | yes | yes | yes | yes: exercised by remote relay cases | n/a | n/a | no | UsableNeedsSoak / RenderNative |
| Block route | yes | yes | yes | yes | local only | n/a | n/a | no | UsableNeedsSoak / RenderNativeWithWarning |
| DNS | yes | yes | yes | yes | local only | n/a | n/a | no | UsableNeedsSoak / RenderNativeWithWarning |
| Custom outbound routing | yes | yes | yes | yes | local only | n/a | n/a | no | UsableNeedsSoak / RenderNativeWithWarning |

## Local Verification Log

- `kelinode-rs`: `cargo fmt --check` passed.
- `kelinode-rs`: `cargo test native_capability --lib` passed.
- `kelinode-rs`: `cargo test split_core_plans_for_nodes_with_kind --lib` passed.
- `kelinode-rs`: `cargo test go_model_parity --lib` passed with 9 fixture-backed Go parity tests.
- `kelinode-rs`: `cargo test native_gray_preflight --bin kelinode` passed with 5 gray-preflight tests.
- `kelinode-rs`: `cargo test renders_keli_core_rs --lib` passed with 53 native renderer tests.
- `kelinode-rs`: `cargo test` passed: 392 library tests plus 14 binary tests.
- `keli-core-rs`: `cargo fmt --check` passed.
- `keli-core-rs`: `cargo test trojan` passed with 41 Trojan-focused tests.
- `keli-core-rs`: `cargo test naive` passed with 25 Naive-focused tests.
- `keli-core-rs`: `cargo test mieru` passed with 20 Mieru-focused tests.
- `keli-core-rs`: `cargo test hysteria` passed with 37 Hysteria2-focused tests.
- `keli-core-rs`: `cargo test tuic` passed with 24 TUIC-focused tests.
- `keli-core-rs`: `cargo test shadowsocks` passed with 16 Shadowsocks-focused tests.
- `keli-core-rs`: `cargo test vless` passed with 62 VLESS-focused tests.
- `keli-core-rs`: `cargo test vmess` passed with 23 VMess-focused tests.
- `keli-core-rs`: `cargo test websocket --lib` passed with 41 WebSocket/Trojan/VLESS/VMess focused tests.
- `keli-core-rs`: `cargo test` passed: 524 library tests plus `control_socket_smoke`.
- `keli-core-rs`: one earlier same-session `cargo test` run observed a transient failure in `service::tests::proxies_vless_grpc_tls_and_records_traffic`; the single-test rerun and the following full rerun both passed, so it is recorded as a possible pre-existing concurrency flake rather than hidden.

## Remote Verification Log

Remote host target: `2.56.116.39`.

- SSH readiness passed with `KELI_TEST_SSH_KEY`.
- `scripts/interop/naive_official_remote.sh --case naive-h2-tls --rounds 3 --interval-ms 100` passed official NaiveProxy `v148.0.7778.96-5` H2/TLS for 3 rounds.
- `scripts/interop/naive_official_remote.sh --case naive-h3-quic --rounds 3 --interval-ms 100` failed before HTTP/3 CONNECT. Failure layer: official NaiveProxy QUIC TLS/certificate verification; the helper had already supplied temporary CA, leaf SPKI allowlist, full chain, and `--no-post-quantum`.
- `scripts/interop/mieru_official_remote.sh --rounds 3 --interval-ms 100 --base-port 19380` passed official Mieru `v3.32.0`: auth success/failure, TCP relay, SOCKS UDP ASSOCIATE over TCP underlay, multiplexed TCP probes, per-user traffic accounting, and delete-user rejection.
- `scripts/interop/trojan_ws_remote.sh --rounds 3 --interval-ms 100 --base-port 19420` passed sing-box `v1.12.22` `trojan-ws-plain` and `trojan-ws-tls`.
- `scripts/interop/native_matrix_remote.sh --rounds 1 --interval-ms 0 --base-port 19500` passed 34 sing-box-compatible cases: SOCKS, HTTP proxy, Shadowsocks TCP/UDP, VLESS TCP/TLS/Vision/REALITY/WS/HTTPUpgrade/gRPC, VMess TCP/TLS/WS/HTTPUpgrade/gRPC, Trojan TCP/TLS/WS/HTTPUpgrade/gRPC, AnyTLS TLS, Hysteria2 TLS/salamander, and TUIC. Naive was skipped in this matrix by design and covered by the official NaiveProxy helper; Mieru is covered by the official Mieru helper.

## Blockers And Gaps

- Naive H3/QUIC: official NaiveProxy still fails QUIC TLS certificate verification before HTTP/3 CONNECT. Do not mark Stable.
- Trojan WS/TLS WS/gRPC/HTTPUpgrade: short third-party interop passed, but default production still rejects until explicit canary opt-in and soak are added.
- Mieru TCP: official interop passed, but SoakTested is missing. Do not mark Stable.
- Mieru UDP underlay: not implemented. Keep Unsupported / Reject.
- DNS, block route, and custom outbound routing: local runtime tests exist, but production-shaped remote route/DNS soak is still missing.
- `cargo clippy --all-targets -- -D warnings`: blocked locally because `cargo-clippy.exe` is not installed for `stable-x86_64-pc-windows-msvc`.

## Next Commands

```bash
bash scripts/interop/naive_official_remote.sh --case naive-h2-tls --rounds 120 --interval-ms 1000
bash scripts/interop/naive_official_remote.sh --case naive-h3-quic --rounds 3 --interval-ms 100
bash scripts/interop/mieru_official_remote.sh --rounds 120 --interval-ms 1000
bash scripts/interop/trojan_ws_remote.sh --rounds 120 --interval-ms 1000 --base-port 19420
bash scripts/interop/native_matrix_remote.sh --rounds 30 --interval-ms 1000 --base-port 19500
```
