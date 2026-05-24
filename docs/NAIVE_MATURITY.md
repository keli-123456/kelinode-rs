# Naive Native Maturity

## Baseline

- Baseline source: OfficialUpstreamBaseline.
- Primary reference: official NaiveProxy H2/TLS and H3/QUIC CONNECT behavior.
- Ecosystem evidence can supplement the official client, but cannot replace it.

## Current Status

| Combination | Status | Decision | Evidence |
| --- | --- | --- | --- |
| Naive H2/TLS CONNECT | CanaryOnly | RenderNativeWithWarning | Local H2/TLS CONNECT runtime tests exist; 2026-05-24 official NaiveProxy remote 3-round probe passed on `2.56.116.39`; longer soak is still required. |
| Naive H3/QUIC CONNECT | CanaryOnly | RenderNativeWithWarning | Local H3/QUIC runtime tests exist; 2026-05-24 official NaiveProxy remote probe failed certificate validation on `2.56.116.39`. |
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
- Command: `scripts/interop/naive_official_remote.sh --rounds 3 --interval-ms 100 --case naive`.
- Result: `naive-h2-tls` passed 3 probe rounds.
- Result: `naive-h3-quic` failed. Official NaiveProxy reported QUIC TLS handshake `certificate unknown` and `ERR_QUIC_PROTOCOL_ERROR`; `keli-core-rs` logged matching Naive H3 certificate validation failures and handshake backoff.

## Evidence Gaps

- SoakTested evidence with reconnects for H2/TLS.
- OfficialClientInterop on Linux for H3/QUIC after fixing the certificate trust path.
- SoakTested evidence with reconnects for H3/QUIC.
- Weak-network H3/QUIC evidence.
- ProductionObserved traffic/accounting evidence.

## Production Advice

Keep Naive at `CanaryOnly` with `RenderNativeWithWarning`. H2/TLS has short official-client
interop evidence, but not soak. H3/QUIC must not be widened until the certificate validation
failure is fixed and official-client soak passes.
