# Go Parity Stabilization Design

## Goal

Make the Rust rewrite (`kelinode-rs` plus `keli-core-rs`) behave like the stable Go `kelinode` / `keli-core` path before doing any performance-oriented optimization.

## Scope

This stabilization track covers native protocol runtime behavior only:

- HY2 connection, auth, UDP relay, TCP relay, timeout, and cleanup behavior.
- VLESS Reality Vision handshake, target connect, relay, and high-latency behavior.
- Shared DNS, TCP connect, UDP relay, TLS handshake, stream relay, worker queue, and error classification paths.
- Node-side reporting, logs, metrics, user delta, and hot reload behavior needed to diagnose production problems.

This track does not redesign panel APIs, client UI, payment flows, or unrelated deployment behavior.

## Baselines

The primary compatibility baseline is the stable Go implementation:

- `kelinode` for node orchestration, machine binding, reporting, runtime updates, and deployment behavior.
- `keli-core` / Xray-compatible behavior for protocol runtime semantics where the Go node delegates to an external core.

The protocol-specific baselines are:

- Hysteria official behavior for HY2 auth, QUIC resources, UDP relay, stream handling, and timeout semantics.
- Xray and sing-box behavior for VLESS, Reality, XTLS Vision, transport handshakes, and route/connect behavior.

The Rust implementation may keep its own architecture, but visible behavior should match these baselines unless a divergence is documented and tested.

## Machine Roles

Every investigation and validation must keep these two machines separate:

- `test-node`: `45.32.122.113`
  - First deployment target for candidate fixes.
  - Used for controlled comparison, probes, pressure tests, and regression checks.
- `problem-node`: `2.56.116.39`
  - Production-like failure reproduction target.
  - Used only after test-node validation.

Logs, metrics, trace output, probes, and conclusions must label `node_role` and `node_ip`. A conclusion must state whether it comes from `test-node`, `problem-node`, or both.

## Stabilization Principles

Stability wins over speed until parity is reached.

Implementation changes should:

- Prefer Go/Xray-compatible behavior over new Rust-only policy.
- Avoid introducing stricter limits than Go/Xray unless required to prevent a known failure.
- Preserve existing Docker direct-node and binary machine-binding modes.
- Keep hot reload behavior explainable, especially when user deltas or node config changes occur.
- Treat timeout and connection errors as diagnosable categories, not generic failures.
- Avoid speculative performance refactors.

Performance changes are allowed only when they remove a stability failure such as resource exhaustion, queue buildup, stuck relay, or repeated timeout.

## Validation Contract

Each protocol or shared-path fix must record at least:

- Test machine IP and role.
- Protocol type.
- Transport type.
- Target address.
- TCP or QUIC connect time.
- First byte time when applicable.
- Relay duration.
- Error kind.
- Upload and download bytes.
- Whether transfer remains stable after the configured connect timeout window.

Validation order:

1. Add or update local regression tests in `keli-core-rs` or `kelinode-rs`.
2. Run local Rust tests for the touched crate.
3. Build the Linux binary.
4. Deploy to `test-node` and run protocol probes.
5. Inspect `test-node` logs and metrics.
6. Deploy to `problem-node` only after test-node is acceptable.
7. Run client-style probes against `problem-node`.
8. Inspect `problem-node` logs and metrics.
9. Commit, bump version for release changes, and push.

## Initial Work Order

1. HY2 parity stabilization.
   - Confirm QUIC resource limits, pre-auth limits, auth timeout, TCP relay timeout, UDP relay session cleanup, and connection cleanup against Go/Hysteria behavior.
   - Keep the recent QUIC limit widening as a stability fix, then continue with relay and timeout parity.

2. VLESS Reality Vision stabilization.
   - Compare Rust behavior with Xray-compatible behavior for handshake, target connect, first byte, half-close, and long-lived relay.
   - Focus on why `problem-node` still has high first-byte latency while `test-node` does not.

3. Shared DNS and connect path parity.
   - Compare DNS cache, IPv4/IPv6 ordering, private IP guard, target backoff, connect timeout, and error classification with stable behavior.

4. Native relay worker and lifecycle parity.
   - Inspect worker queue limits, stuck task cleanup, FD pressure behavior, and connection shutdown.

5. Metrics and log parity.
   - Ensure connection errors, DNS errors, timeout kinds, relay endings, and resource pressure are visible without high-cardinality labels.

## Non-Goals

- No broad rewrite of protocol architecture.
- No UI work.
- No panel API changes unless a Rust compatibility issue proves the API contract is being interpreted incorrectly.
- No benchmark-driven tuning until the protocol behavior is stable on both nodes.

## Success Criteria

This track is successful when:

- HY2 and VLESS no longer time out under normal client use on `problem-node`.
- `test-node` and `problem-node` logs no longer show unexplained resource-limit drops or stuck relay symptoms.
- Rust node behavior has regression tests for the fixed compatibility gaps.
- Each fix has test-node validation before problem-node validation.
- Remaining differences from Go/Xray are documented as intentional or still-open risks.
