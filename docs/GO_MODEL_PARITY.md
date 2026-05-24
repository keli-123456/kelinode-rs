# Go Model Parity Audit

Date: 2026-05-24
Branch: `codex/all-protocol-maturity-pass`

This audit checks whether the Rust native path uses the mature Go model as a real baseline, not
only as a label in the capability matrix. The Rust path must preserve Go panel interpretation
where `kelinode` plus `keli-core`/Xray had mature behavior, and it must fail loudly where the
native core cannot execute the Go-shaped option yet.

Golden fixtures live in `tests/fixtures/go_model_parity/go_legacy_fixtures.json`. They are
synthetic, secret-free panel inputs and expected Go/Xray-shaped semantics derived from the Go
renderer. The Rust tests load the same fixtures and assert either equivalent native rendering or
an explicit reject.

## Baseline Boundaries

GoLegacyBaseline applies to:

- SOCKS
- HTTP proxy
- Shadowsocks
- VLESS
- VMess
- Trojan
- route/block/custom outbound
- DNS route
- user model, user delta, and traffic key/accounting shape

OfficialUpstreamBaseline remains required for:

- Naive, because the Go legacy path does not provide a production Naive model.
- Mieru, because the Go legacy path does not provide a production Mieru model.

Mixed/Ecosystem baseline applies to:

- AnyTLS, because the local Go/Xray reference is incomplete for production maturity and the current
  evidence is ecosystem interop driven.
- Hysteria2 and TUIC, where Go/Xray model references are useful, but current Rust maturity still
  depends on QUIC ecosystem interop and soak.

## Golden Fixtures

| Fixture | Purpose |
| --- | --- |
| `trojan_tcp` | Trojan TCP panel model, password users, `tag|uuid` email key. |
| `trojan_tls` | Trojan TCP+TLS cert/SNI model. |
| `trojan_ws` | Go-supported Trojan WS path/Host model; Rust native rejects by default pending explicit canary. |
| `trojan_tls_ws` | Go-supported TLS-before-WS model; Rust native rejects by default pending explicit canary. |
| `vless_tcp_tls_vision` | VLESS TLS Vision flow and TLS model. |
| `vless_reality_vision` | VLESS REALITY Vision dest/private-key/short-id model. |
| `vmess_ws_tls` | VMess WS+TLS path/Host/user model. |
| `shadowsocks_aead_tcp_udp` | Shadowsocks AEAD TCP/UDP default network and password users. |
| `hysteria2_tcp_udp` | Hysteria2 TLS, salamander, bandwidth, password auth model. |
| `tuic_tcp_udp` | TUIC TLS, UUID/password, congestion model. |
| `socks` | SOCKS user-pass and UDP-associate capable model. |
| `http_proxy` | HTTP proxy account model. |
| `route_block` | Domain block route model. |
| `custom_outbound` | Xray-shaped custom outbound route model. |
| `dns_route` | Domain-scoped DNS route model. |
| `unsupported_tcp_header_field` | Go can pass TCP header settings to Xray, but Rust native rejects them explicitly today. |
| `user_delta` | Add/update/delete by UUID with Go-compatible result buckets. |
| `traffic_tail` | `tag|uuid` key plus deleted-user tail traffic mapped by retained user_id. |

## Model Dimensions

| Dimension | Go source reference | Rust target model | Already aligned | Gap | Test evidence | Next action |
| --- | --- | --- | --- | --- | --- | --- |
| Panel node model | `kelinode/api/v2board/node.go`, `kelinode/core/inbound.go` | `src/panel/types.rs::CommonNode`, `src/core.rs::build_inbound_plan_with_users` | Protocol, TLS value, network, network_settings, route, cert, flow, cipher, bandwidth, obfs, TUIC, AnyTLS, external transport fields are parsed instead of guessed. | Go wildcard listen defaults to `::`; Rust native stores `0.0.0.0` with IPv4 fallback because the native core has its own bind strategy. This is intentional and documented in tests. | `go_model_parity_all_renderable_go_legacy_fixtures`, existing `resolve_node_listen_ip_preserves_ipv4_wildcard`. | Keep panel deserialization tolerant, but reject unsupported native fields at render time. |
| User model | `kelinode/core/user.go`, `kelinode/common/format/user.go` | `InboundUserPlan`, `inbound_user_plan`, native config `users` | VLESS/VMess use UUID, Trojan/SS/SOCKS/HTTP/HY2/AnyTLS use password-shaped auth, TUIC uses UUID+password, user key remains `tag|uuid` before native email stripping. | Native config intentionally omits Xray email because `keli-core-rs` tracks user id/uuid directly. | `go_model_parity_trojan_ws_fixture`, `go_model_parity_vmess_ws_tls_fixture`, `go_model_parity_traffic_key_fixture`. | Preserve `tag|uuid` at control/report boundaries and keep native config email-free. |
| User delta model | `kelinode/node/user_delta.go` | `src/user.rs::apply_user_delta`, `apply_user_delta_body`, runner ApplyUserDelta control command | Deletes and upserts are keyed by UUID; deleted_applied/added/updated buckets match Go semantics, including ignoring missing deletes. | Rust sorts via `BTreeMap`; Go sorts next users by UUID. Semantics align for deterministic output. | `go_model_parity_user_delta_fixture`, existing user delta unit tests. | Keep delta tests fixture-backed when adding new user fields. |
| Traffic accounting model | `kelinode/core/user.go::GetUserTrafficSlice`, `kelinode/common/counter/traffic.go`, `kelinode/common/format/user.go` | `src/report.rs::keli_core_traffic_snapshots`, control `KeliCoreTrafficRecord` | Native reports preserve user_id on drained records, so deleted-user tail traffic can still be reported instead of dropped. Runtime user lookup covers records without user_id. | Go deletes counters when uid mapping is missing; Rust native keeps pending/requeue spool for failed panel reports. This is a safer native extension, not a protocol difference. | `go_model_parity_traffic_key_fixture`, existing `maps_keli_core_traffic_records_by_user_id_after_user_deletion`. | Add long soak around delete-user tail traffic with live connections. |
| Route model | `kelinode/core/custom.go` | `render_keli_core_rs_routes_for_inbound` | `block`, `block_ip`, `block_port`, `protocol`, domain route, IP route, and `default_out` are represented in native route syntax. Unsupported actions error instead of being silently skipped. | Go silently continues on malformed route/outbound JSON in several cases; Rust native rejects unsupported route options to avoid hidden production drift. | `go_model_parity_route_outbound_fixture`, existing route renderer tests. | Keep documenting intentional fail-loud deviations from Go silent-continue behavior. |
| Custom outbound model | `kelinode/core/custom.go`, `kelinode/core/outbound.go`, `keli-core/infra/conf/*` | `keli_core_rs_route_outbound`, native `outbounds` | Freedom/direct, blackhole-as-block, SOCKS/HTTP, Shadowsocks, Trojan, VLESS, VMess route outbounds are normalized into the native outbound schema. | KCP, packet-up XHTTP/H3, broad mux/sockopt behaviors remain unsupported and are rejected. | `go_model_parity_route_outbound_fixture`, `renders_keli_core_rs_*_route_outbounds`. | Add more fixtures for each custom outbound transport before widening production status. |
| DNS model | `kelinode/core/custom.go::GetCustomConfig`, `kelinode/core/outbound.go::buildDnsOutbound` | `render_keli_core_rs_dns` | Defaults to `1.1.1.1` and `8.8.8.8`; domain-scoped DNS routes append dedicated servers. | Native does not mirror Go's explicit `dns_out` outbound tag because native DNS is first-class in `keli-core-rs`; DoH/DoT production resolver soak is still missing. | `go_model_parity_route_outbound_fixture`, existing DNS/private-IP route tests. | Add remote DNS route soak with real resolver failures and private-IP blocking. |
| Stream transport model | `kelinode/core/inbound.go::{buildVLess,buildVMess,buildTrojan,buildAnyTLS}`, `keli-core/infra/conf/transport_internet.go` | `keli_core_rs_transport_network`, `render_keli_core_rs_transport`, capability matrix entries | TCP, WS, HTTPUpgrade, gRPC, H2/Naive, QUIC/HY2/TUIC, Mieru TCP, and route outbound stream settings are explicitly classified. | Trojan WS/TLS WS/gRPC/HTTPUpgrade are Go-supported but Rust default render still rejects pending explicit canary and soak. TCP header obfs and some Xray stream options are rejected. | `go_model_parity_trojan_ws_fixture`, `go_model_parity_trojan_tls_ws_fixture`, `go_model_parity_vmess_ws_tls_fixture`, `unsupported_go_panel_field_fails_loudly`. | Add explicit canary switch before allowing Trojan stream transports to render by default. |
| TLS/REALITY model | `kelinode/core/inbound.go::resolveTLSALPN`, TLS/REALITY branch in `buildInboundWithListenIP` | `render_keli_core_rs_tls`, `resolve_tls_alpn`, `resolve_reality_dest` | TLS cert/key/SNI/rejectUnknownSni/ALPN are preserved; REALITY server_name/dest/private_key/short_id/xver are represented. | `mldsa65Seed` is parsed but rejected in VLESS REALITY native until core support exists. | `go_model_parity_vless_reality_fixture`, existing TLS renderer tests. | Add fixture for `mldsa65Seed` reject once core support is scoped. |
| Unsupported option / fail-loudly model | Go often passes fields into Xray structs or silently continues on invalid custom config; see `kelinode/core/inbound.go` and `kelinode/core/custom.go` | `validate_keli_core_rs_*`, capability gate, gray preflight | Unsupported native fields produce explicit `CoreError` or capability `Reject` with protocol/transport/security/baseline/evidence context. | This intentionally differs from Go silent continue behavior for safety. Some Go-supported Xray options remain rejected until native data-plane support exists. | `unsupported_go_panel_field_fails_loudly`, capability gate tests, gray-preflight tests. | Keep adding fixtures for every new rejected Go field so lookup miss and silent drop cannot reappear. |

## Protocol Classification After Audit

| Protocol area | Parity result |
| --- | --- |
| SOCKS | Go model aligned for user-pass TCP and UDP-associate capability; still needs soak before Stable. |
| HTTP proxy | Go account model aligned for CONNECT/plain proxy path; still needs soak before Stable. |
| Shadowsocks | Go AEAD password and TCP/UDP default model aligned; unsupported ciphers reject. |
| VLESS | Go TCP/TLS/Vision/REALITY/WS/HTTPUpgrade/gRPC shape is modeled; non-TCP Vision and unsupported transports reject. |
| VMess | Go AEAD and WS/TLS/gRPC/HTTPUpgrade shape is modeled; legacy inbound alterId remains unsupported, route outbound alterId is rendered. |
| Trojan | Go TCP/TLS model renders; Go WS/TLS WS/gRPC/HTTPUpgrade semantics are recognized, but default native render rejects pending explicit canary plus soak. |
| Route/outbound/DNS | Go route actions and Xray-shaped custom outbounds are modeled where native core can execute them; unsupported options fail loudly. |
| User/traffic | `tag|uuid`, user delta, and deleted-user tail traffic are fixture-backed. |
| AnyTLS | Not fully proven by Go model; remains Mixed/EcosystemInteropBaseline. |
| Hysteria2/TUIC | Go/Xray references help shape config, but QUIC maturity remains Mixed with ecosystem interop and soak gaps. |
| Naive | OfficialUpstreamBaseline; do not use missing Go baseline as proof of stability. |
| Mieru | OfficialUpstreamBaseline; do not use missing Go baseline as proof of stability. |

## Test Evidence

New fixture-backed tests:

- `go_model_parity_trojan_ws_fixture`
- `go_model_parity_trojan_tls_ws_fixture`
- `go_model_parity_vless_reality_fixture`
- `go_model_parity_vmess_ws_tls_fixture`
- `go_model_parity_shadowsocks_tcp_udp_fixture`
- `go_model_parity_route_outbound_fixture`
- `go_model_parity_user_delta_fixture`
- `go_model_parity_traffic_key_fixture`
- `unsupported_go_panel_field_fails_loudly`
- `go_model_parity_all_renderable_go_legacy_fixtures`

Current run:

- `cargo test go_model_parity --lib`: passed, 9 tests.

## Remaining Parity Gaps

- Trojan WS/TLS WS/gRPC/HTTPUpgrade are recognized from Go/Xray, but remain default `Reject` until an explicit canary switch and soak exist.
- TCP header obfuscation and other Xray stream options remain unsupported in native and fail loudly.
- Go custom-route malformed JSON could be silently skipped; Rust native rejects unsupported options for safety. This is an intentional model divergence.
- Naive and Mieru cannot be made stable from Go evidence; they remain official-upstream driven.
- AnyTLS, Hysteria2, and TUIC still require broader real-client soak before Stable.
