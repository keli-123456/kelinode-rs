# Mieru Native Maturity

## Baseline

- Baseline source: OfficialUpstreamBaseline.
- Primary reference: official Mieru client/server behavior.
- The old Go/Xray core is not a sufficient baseline for Mieru.

## Current Status

| Combination | Status | Decision | Evidence |
| --- | --- | --- | --- |
| TCP underlay | CanaryOnly | RenderNativeWithWarning | Native renderer/runtime support exists with local loopback evidence. On 2026-05-24, official Mieru `v3.32.0` passed a 3-round remote interop probe on `2.56.116.39`. |
| UDP underlay | Unsupported | Reject | Native UDP underlay is not implemented. |
| Stream demux/session multiplexing | CanaryOnly | RenderNativeWithWarning | The official-client remote run passed concurrent TCP requests with `MULTIPLEXING_HIGH`; longer soak is still missing. |
| UDP ASSOCIATE over TCP underlay | CanaryOnly | RenderNativeWithWarning | The official-client remote run passed SOCKS UDP ASSOCIATE over the TCP underlay. |

## Official Client Path

`scripts/interop/mieru_official_remote.sh` prepares the remote `keli-core-rs` tree and runs
`scripts/mieru_official_soak_linux.sh`. The helper downloads official Mieru `v3.32.0` into the
remote temporary tree when `MIERU_CLIENT` / `--mieru` is not supplied, verifies the release checksum
when available, starts native `keli-core-rs`, starts the official client with a temporary config, and
then probes through the official client's local SOCKS5 listener.

## Remote Evidence

- Date: 2026-05-24.
- Host: `2.56.116.39`.
- Command: `scripts/interop/mieru_official_remote.sh --rounds 3 --interval-ms 100 --base-port 19380`.
- Official client: Mieru `v3.32.0`, downloaded from the official release package
  `mieru_3.32.0_amd64.deb`.
- Passed:
  - official-client auth success.
  - official-client bad-password auth failure.
  - TCP CONNECT relay through the official client's SOCKS5 port.
  - SOCKS UDP ASSOCIATE over the TCP underlay.
  - concurrent TCP probes with `MULTIPLEXING_HIGH`.
  - per-user traffic accounting via native control `drain_traffic`.
  - `ApplyUserDelta` delete-user rejection for a new official-client relay.
- Evidence level: `OfficialClientInterop`.

## Evidence Gaps

- SoakTested evidence for TCP underlay.
- Official behavior comparison for random padding and replay protection.
- ProductionObserved traffic/accounting evidence.
- UDP underlay implementation, tests, and official interop.

## Production Advice

Keep Mieru at `CanaryOnly` for TCP underlay and `Unsupported` for UDP underlay. Do not mark Stable
until longer official-client soak evidence exists.
