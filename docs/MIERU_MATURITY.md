# Mieru Native Maturity

## Baseline

- Baseline source: OfficialUpstreamBaseline.
- Primary reference: official Mieru client/server behavior.
- The old Go/Xray core is not a sufficient baseline for Mieru.

## Current Status

| Combination | Status | Decision | Evidence |
| --- | --- | --- | --- |
| TCP underlay | CanaryOnly | RenderNativeWithWarning | Native renderer/runtime support exists with local loopback evidence. |
| UDP underlay | Unsupported | Reject | Native UDP underlay is not implemented. |
| Stream demux/session multiplexing | CanaryOnly | RenderNativeWithWarning | Local implementation evidence exists; official-client evidence missing. |
| UDP ASSOCIATE over TCP underlay | CanaryOnly | RenderNativeWithWarning | Local implementation evidence exists; official-client evidence missing. |

## Official Client Path

`scripts/interop/mieru_official_remote.sh` prepares the remote `keli-core-rs` tree and fails loudly
until an official Mieru client binary is provided through `MIERU_CLIENT` or `--mieru`.

## Evidence Gaps

- OfficialClientInterop for TCP underlay.
- SoakTested evidence for TCP underlay.
- Official behavior comparison for random padding and replay protection.
- ProductionObserved traffic/accounting evidence.
- UDP underlay implementation, tests, and official interop.

## Production Advice

Keep Mieru at `CanaryOnly` for TCP underlay and `Unsupported` for UDP underlay. Do not mark Stable
until official-client interop and soak evidence exist.

