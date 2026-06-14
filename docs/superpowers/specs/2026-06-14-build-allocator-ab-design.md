# Build And Allocator A/B Design

Date: 2026-06-14

## Goal

Evaluate whether release build settings or the Rust global allocator can improve production
resource use without reducing node speed or stability. The baseline is the current
`thin LTO + system allocator` release profile used by `kelinode-rs v0.1.310` with embedded
`keli-core-rs v0.1.203`.

## Scope

This track evaluates four candidates:

| Candidate | LTO | Allocator | Purpose |
| --- | --- | --- | --- |
| `thin-system` | `thin` | system allocator | Current baseline |
| `fat-system` | `fat` | system allocator | Measures compiler optimization effect |
| `thin-jemalloc` | `thin` | jemalloc | Measures allocator effect |
| `fat-jemalloc` | `fat` | jemalloc | Measures combined effect |

This track does not change QUIC congestion libraries, replace `quinn`, add `pingora`, add
`quiche`, or change protocol behavior. Those are protocol-stack changes and require separate
design, interop, and soak gates.

## Current Context

Both repositories already use:

- `lto = "thin"`
- `codegen-units = 1`
- `strip = "symbols"`
- `panic = "abort"`

The release workflow builds a static Linux package with:

```bash
cargo build --release --locked --features embedded-core --target x86_64-unknown-linux-musl
```

The core benchmark harness already supports same-host protocol comparison through
`bench suite` and `bench compare`, including opt-in hard gates for throughput, p99 latency,
candidate errors, and missing commands.

## Build Strategy

Do not change the default release profile first. Add an explicit experimental build path that can
build the four candidates with repeatable labels and output paths.

Recommended implementation shape:

- Keep checked-in default profile at `thin-system` until evidence proves a better candidate.
- Add a documented experiment script under `scripts/ops/` or `scripts/perf/`.
- For `fat` candidates, build with a temporary Cargo config or environment override instead of
permanently changing `[profile.release]`.
- For `jemalloc` candidates, add an opt-in feature that installs a global allocator only on
non-Windows targets and only when explicitly enabled.
- Build `kelinode-rs` with `--features embedded-core` for node artifact checks.
- Build and benchmark `keli-core-rs` directly for protocol speed checks.

The allocator feature must be off by default. A release can only switch defaults after the full
A/B evidence is recorded and reviewed.

## Measurement Strategy

Use the same host, commands, stream count, request count, payload size, and repeats for every
candidate. Treat single-run wins as weak evidence; compare at least three repeated suite runs or
a suite command that already aggregates repeated phases.

Protocol bench command shape:

```powershell
cargo run --release -- bench suite `
  --commands direct-tcp-stream,vless-tcp-stream,trojan-tcp-stream,hy2-tcp-stream,hy2-udp,tuic-tcp-stream,tuic-udp `
  --streams 8 `
  --requests 512 `
  --payload 1024 `
  --repeats 3 `
  --label <candidate-label> `
  --out ..\.codex-tmp\<candidate-label>.json
```

Comparison command shape:

```powershell
cargo run --release -- bench compare `
  --baseline ..\.codex-tmp\thin-system.json `
  --candidate ..\.codex-tmp\<candidate-label>.json `
  --out ..\.codex-tmp\<candidate-label>-compare.json `
  --max-throughput-drop-percent 10 `
  --max-p99-increase-percent 30 `
  --fail-on-errors `
  --require-all-baseline-commands
```

For production-like memory behavior, use the existing watcher/gate pair:

```bash
/tmp/native_resource_watch.sh --samples 60 --interval 60 --out /tmp/keli-ab-<candidate>
/tmp/native_resource_gate.sh \
  --samples /tmp/keli-ab-<candidate>/samples.tsv \
  --min-samples 60 \
  --max-native-pending 1 \
  --max-panic-lines 0 \
  --max-external-core-errors 0 \
  --max-rss-kb <candidate-limit>
```

Short production windows are only valid after local tests and benchmark gates pass. A short
production window cannot replace longer soak evidence if the candidate becomes the release
default.

## Acceptance Criteria

A candidate can be considered for merge only when all conditions are true:

- Full tests pass for `keli-core-rs`.
- Full tests pass for `kelinode-rs` with `embedded-core`.
- Release package build succeeds for Linux `x86_64-unknown-linux-musl`.
- Bench comparison does not fail any threshold.
- Candidate throughput does not regress more than 10% for any command.
- Candidate p99 latency does not increase more than 30% for any command.
- Candidate has zero bench errors and zero missing baseline commands.
- Candidate reduces RSS/systemd memory materially, or reduces CPU materially without increasing
  RSS/systemd memory.
- Production or production-like resource samples show no panic lines, no external core errors, and
  no sustained native relay backlog.
- Rollback path is proven before any production replacement test.

If no candidate meets these criteria, keep the current `thin-system` release default and record the
negative result. Not changing defaults is an acceptable outcome.

## Production Safety

Production replacement tests are optional and must be explicitly approved before execution.
When approved, the test must be short, reversible, and measured:

1. Record current service state, binary hash, RSS, systemd memory, CPU, sockets, and severe logs.
2. Backup the current binary under `/usr/local/kelinode/`.
3. Install the candidate binary.
4. Restart or reload only through the established service path.
5. Run a short resource watcher window.
6. Run the resource gate and severe log scan.
7. Roll back immediately if service state, errors, CPU, memory, or user traffic behavior regresses.

The production test should not be used to tune thresholds after the fact. Thresholds are decided
before deployment and can only be relaxed with raw evidence explaining a bounded transient.

## Deliverables

- A committed experiment design document.
- A committed implementation plan.
- Candidate build support with default release behavior unchanged.
- JSON bench reports for each candidate.
- Bench compare reports against `thin-system`.
- Resource sample summaries for any production or production-like run.
- A final recommendation: keep baseline, switch to `fat`, add opt-in `jemalloc`, or switch to a
  proven combined profile.

## Non-Goals

- No direct `quinn` fork or BBRv3 adoption in this track.
- No `pingora` or `quiche` replacement in this track.
- No protocol behavior changes.
- No production binary replacement without explicit approval.
- No release default change based only on local loopback throughput.
