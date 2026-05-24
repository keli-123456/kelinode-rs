# Native Core Self Acceptance

Date: 2026-05-24
Branch: `codex/all-protocol-maturity-pass`

## Checklist

- [x] capability model established
- [x] renderer/planning capability gate connected
- [x] gray-preflight capability gate connected
- [x] Trojan WS/TLS WS no longer enter default production native rendering
- [x] Trojan TCP baseline tests reviewed
- [x] Trojan TLS baseline tests reviewed
- [x] Trojan WS tests reviewed
- [x] Trojan TLS WS tests reviewed
- [x] Trojan traffic accounting tests reviewed
- [x] Trojan user delta tests reviewed
- [x] Trojan speed/device limit coverage reviewed through shared limiter/session tests
- [x] VLESS maturity matrix entry
- [x] VMess maturity matrix entry
- [x] Shadowsocks maturity matrix entry
- [x] Hysteria2 maturity matrix entry
- [x] TUIC maturity matrix entry
- [x] Naive maturity matrix entry
- [x] Mieru maturity matrix entry
- [x] AnyTLS maturity matrix entry
- [x] SOCKS/HTTP maturity matrix entry
- [x] Route/DNS/Outbound maturity matrix entry
- [x] docs and code matrix aligned for P0/P1/P2 baseline status
- [x] `cargo fmt --check` for `kelinode-rs`
- [ ] final `cargo test` for `kelinode-rs`
- [ ] final `cargo fmt --check` for `keli-core-rs`
- [ ] final `cargo test` for `keli-core-rs`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] local loopback interop tests
- [ ] 2.56.116.39 remote interop tests
- [x] external real-client/production soak missing items recorded

## Verification Log

### Local

- `kelinode-rs`: `cargo test native_capability --lib` passed.
- `kelinode-rs`: `cargo test native_gray_preflight --bin kelinode` passed.
- `kelinode-rs`: `cargo test trojan_websocket --lib` passed.
- `kelinode-rs`: `cargo test renders_keli_core_rs --lib` passed after gate integration.
- `keli-core-rs`: `cargo test trojan` passed with `41 passed; 0 failed`.

### Remote

Remote host target: `2.56.116.39`.

Current result: External Evidence Blocked.

Reason: the current environment does not provide `KELI_TEST_SSH_KEY`, and the default
`$HOME/.ssh/id_ed25519` path is missing. No alternate key was used because remote credentials must
come only from the required environment variables.

## Remaining External Evidence

- OfficialClientInterop + SoakTested for Naive H2/TLS and H3/QUIC on Linux.
- OfficialClientInterop + SoakTested for Mieru TCP underlay.
- ThirdPartyClientInterop/soak for Trojan WS and TLS WS before removing the reject gate.
- Remote QUIC soak for Hysteria2 and TUIC.
- Real route/DNS/custom outbound soak using production-shaped rule sets.

## Remote Commands

After providing the SSH key through `KELI_TEST_SSH_KEY`, run:

```bash
bash scripts/interop/naive_official_remote.sh --rounds 120 --interval-ms 1000 --case naive
bash scripts/interop/mieru_official_remote.sh --mieru /path/to/official/mieru
```

Use `--dry-run` first when checking host reachability and remote paths.

