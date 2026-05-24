# Naive Native Maturity

## Baseline

- Baseline source: OfficialUpstreamBaseline.
- Primary reference: official NaiveProxy H2/TLS and H3/QUIC CONNECT behavior.
- Ecosystem evidence can supplement the official client, but cannot replace it.

## Current Status

| Combination | Status | Decision | Evidence |
| --- | --- | --- | --- |
| Naive H2/TLS CONNECT | CanaryOnly | RenderNativeWithWarning | Local H2/TLS CONNECT runtime tests exist; official Linux soak is still required. |
| Naive H3/QUIC CONNECT | CanaryOnly | RenderNativeWithWarning | Local H3/QUIC runtime tests exist; official Linux H3 soak is still required. |
| Basic authentication | CanaryOnly | RenderNativeWithWarning | Local validation/runtime tests exist. |
| Padding | CanaryOnly | RenderNativeWithWarning | Implemented locally; official-client behavior must be recorded. |

## Official Client Path

`keli-core-rs` already contains `scripts/naive_official_soak_linux.sh`. `kelinode-rs` adds
`scripts/interop/naive_official_remote.sh` to package the local `keli-core-rs` tree and run the
official helper on the Linux test host.

## Evidence Gaps

- OfficialClientInterop on Linux for H2/TLS.
- OfficialClientInterop on Linux for H3/QUIC.
- SoakTested evidence with reconnects.
- Weak-network H3/QUIC evidence.
- ProductionObserved traffic/accounting evidence.

## Production Advice

Keep Naive at `CanaryOnly` with `RenderNativeWithWarning`. Do not mark Stable until
OfficialClientInterop and SoakTested evidence are attached to this branch or release candidate.

