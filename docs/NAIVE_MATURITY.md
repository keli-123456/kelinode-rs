# Naive Native Maturity

## Baseline

- Baseline source: OfficialUpstreamBaseline.
- Primary reference: official NaiveProxy H2/TLS and H3/QUIC CONNECT behavior.
- Ecosystem evidence can supplement the official client, but cannot replace it.

## Current Status

| Combination | Status | Decision | Evidence |
| --- | --- | --- | --- |
| Naive H2/TLS CONNECT | CanaryOnly | RenderNativeWithWarning | Local H2/TLS CONNECT runtime tests exist; 2026-05-24 official NaiveProxy remote 3-round probe passed on `2.56.116.39`; longer soak is still required. |
| Naive H3/QUIC CONNECT | CanaryOnly | RenderNativeWithWarning | Local H3/QUIC runtime tests exist; 2026-05-24 official NaiveProxy remote probe still fails at QUIC TLS certificate verification on `2.56.116.39` before HTTP/3 CONNECT reaches the core relay. |
| Basic authentication | CanaryOnly | RenderNativeWithWarning | Local validation/runtime tests exist. |
| Padding | CanaryOnly | RenderNativeWithWarning | Implemented locally; official-client behavior must be recorded. |

## Official Client Path

`keli-core-rs` already contains `scripts/naive_official_soak_linux.sh`. `kelinode-rs` adds
`scripts/interop/naive_official_remote.sh` to package the local `keli-core-rs` tree and run the
official helper on the Linux test host.

## Remote Evidence

- Date: 2026-05-24.
- Host: `2.56.116.39`.
- Official client: NaiveProxy `v148.0.7778.96-5`.
- H2 command: `scripts/interop/naive_official_remote.sh --case naive-h2-tls --rounds 3 --interval-ms 100`.
- H2 result: `naive-h2-tls` passed 3 official-client probe rounds after the helper switched to a temporary local CA, SPKI allowlist, and full certificate chain file.
- H3 command: `scripts/interop/naive_official_remote.sh --case naive-h3-quic --rounds 3 --interval-ms 100`.
- H3 result: `naive-h3-quic` failed. The helper now supplies the temporary CA through `SSL_CERT_FILE`, passes the leaf SPKI allowlist, sends a full chain to the server, and disables Chromium post-quantum negotiation with official `--no-post-quantum`; official NaiveProxy still sends a QUIC close with `TLS handshake failure ... certificate unknown` and then reports `ERR_QUIC_PROTOCOL_ERROR`.
- Failure layer: official client QUIC TLS/certificate verification. NetLog showed certificate path building against the temporary CA, then QUIC closed before HTTP/3 CONNECT and before native relay/auth handling. This is not a proven data-plane relay failure.
- Core log summary: `naive h3 connection error: aborted by peer: the cryptographic handshake failed ... CERTIFICATE_VERIFY_FAILED`, followed by Naive H3 handshake backoff.

### H3 Reproduction

```bash
export KELI_TEST_HOST=2.56.116.39
export KELI_TEST_USER=root
export KELI_TEST_SSH_PORT=22
export KELI_TEST_SSH_KEY=/path/to/test/key
bash scripts/interop/naive_official_remote.sh --case naive-h3-quic --rounds 3 --interval-ms 100
```

## Evidence Gaps

- SoakTested evidence with reconnects for H2/TLS.
- OfficialClientInterop on Linux for H3/QUIC after resolving the official NaiveProxy QUIC certificate verification failure.
- SoakTested evidence with reconnects for H3/QUIC.
- Weak-network H3/QUIC evidence.
- ProductionObserved traffic/accounting evidence.

## Production Advice

Keep Naive at `CanaryOnly` with `RenderNativeWithWarning`. H2/TLS has short official-client
interop evidence, but not soak. H3/QUIC must not be marked Stable and should not be promoted beyond
canary until the official NaiveProxy QUIC certificate verification blocker is fixed and official
client soak passes.
