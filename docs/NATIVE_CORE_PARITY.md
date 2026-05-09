# Native Core Renderer Parity

This document tracks what `kelinode-rs` is allowed to render into the experimental `keli-core-rs` schema.

Default production rendering remains `xray`. The native Rust core path is selected only with:

```yaml
kernel:
  type: keli-core-rs
```

The matching core-side gate is `keli-core-rs/docs/PARITY.md`.

When the native core is already running, `kelinode-rs` writes the rendered config file for persistence and sends the same config through the local `ApplyConfig` control socket. If the control socket is unavailable or too old, it falls back to the previous process reload behavior.

## Renderer Rules

- Render only options that `keli-core-rs` validates and has a runtime path for.
- Reject panel options that are only supported by Xray or sidecars.
- Keep Naive outside the native core renderer; render Mieru into `keli-core-rs` only for the supported TCP listener path.
- Preserve production `xray` rendering compatibility even when native rendering rejects a feature.

## Protocol Renderer Matrix

| Protocol | Native renderer status | Rendered into `keli-core-rs` | Intentionally rejected for native path |
| --- | --- | --- | --- |
| SOCKS | Code path | TCP listener, account users | None known |
| HTTP proxy | Code path | TCP listener, account users | None known |
| Shadowsocks | Partial | AEAD TCP+UDP ciphers supported by `keli-core-rs`; empty panel network renders as `tcp,udp` | Unsupported ciphers, WS/HTTP obfs transport settings, non-TCP/non-UDP transport |
| VLESS | Partial | TCP, UDP command, WS, HTTPUpgrade, H2, gRPC, TLS, Vision, REALITY | XUDP/Mux, KCP/QUIC/XHTTP, unsupported flow, REALITY on non-TCP |
| VMess | Partial | TCP, UDP command, WS, HTTPUpgrade, H2, gRPC, TLS, legacy alterId route outbound rendering | Legacy alterId inbound, KCP/QUIC/XHTTP |
| Trojan | Partial | TCP, UDP ASSOCIATE over stream, WS, HTTPUpgrade, H2, gRPC, TLS | KCP/QUIC/XHTTP |
| AnyTLS | Partial | TCP users, UDP-over-TCP, padding scheme | Real-client matrix |
| Hysteria2 | Partial | TLS, bandwidth options, salamander obfs | Transport settings, non-salamander obfs |
| TUIC | Partial | TLS, UUID users, cubic/bbr/new_reno congestion | zero-RTT, non-UUID users |
| Naive | Sidecar | Caddyfile sidecar plan | Native core rendering |
| Mieru | Partial | Native TCP inbound when `kernel.type: keli-core-rs`; Mieru port ranges expand to one native inbound per port; stream multiplexing is accepted because `keli-core-rs` demuxes sessions on the TCP underlay; UDP ASSOCIATE packets are relayed over the TCP tunnel; `mita` JSON sidecar plan for Xray/default path | UDP underlay transport, traffic-pattern tuning, broader real-client matrix |

## Route Renderer Matrix

| Route type | Native renderer status | Notes |
| --- | --- | --- |
| Domain block | Code path | Renders exact/wildcard/suffix plus `domain:`/`full:`/`keyword:`/`geosite:`/`regexp:` rules. |
| Direct/default direct | Code path | Native core uses the built-in `direct` outbound. |
| DNS route | Partial | Renders default UDP DNS servers and panel DNS routes into native core DNS config. Native core executes domain-scoped UDP and `tcp://` DNS resolution; DoH/DoT remain Xray-only. |
| Custom outbound route | Partial | Freedom, SOCKS5, HTTP, Shadowsocks, Trojan, VLESS, and VMess TCP outbound tags render into native core. Freedom supports direct address/port redirects; SOCKS5/HTTP support TCP proxy tunnels with username/password. SOCKS5 also supports UDP route outbounds through native UDP ASSOCIATE. Shadowsocks supports native AEAD TCP/UDP route outbounds. Trojan, VLESS, and VMess support TCP, TLS TCP, WS TCP, HTTPUpgrade TCP, H2 TCP, and gRPC TCP route outbounds. VLESS `xtls-rprx-vision` route outbounds render on TCP+TLS. VMess route outbounds can be selected by UDP route rules and execute UDP over VMess streams in `keli-core-rs`; VMess `users[0].alterId` renders to native `alter_id` for legacy auth. HTTP UDP, Trojan UDP, VLESS UDP/non-TCP flow, XHTTP, KCP, and QUIC outbounds remain Xray-only. |
| IP/port block | Partial | Numeric IP/CIDR, `geoip:`, and port/port-range block rules render into native core; domain targets are resolved lazily for IP matching, and arbitrary geo databases are read from `geoip/<rule>.txt` and `geosite/<rule>.txt` under the generated config directory. |
| Protocol block | Partial | Renders into native core and matches network labels, HTTP proxy plaintext, and UDP payload sniffing for common HTTP/TLS/QUIC/BitTorrent signatures. |

## Code-Complete Checklist Before Interop

For every protocol that is moved from partial to production candidate:

- `kelinode-rs` has renderer tests for the exact panel fields.
- `keli-core-rs` has validator tests for accepted and rejected options.
- `keli-core-rs` has listener/data-path tests for auth, forwarding, and traffic drain.
- `keli-core-rs` enforces device limits by user and client IP, so multiple sessions from the same IP count as one device.
- `kelinode-rs` rejects every panel option that the native core cannot execute.
- The same panel config still renders through the production `xray` path where supported.

The native renderer must fail loudly rather than silently dropping panel fields.
