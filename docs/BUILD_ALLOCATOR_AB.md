# Build Allocator A/B

This runbook compares release build and allocator candidates without changing the checked-in
release profile.

## Candidates

| Candidate | LTO | Features |
| --- | --- | --- |
| `thin-system` | `thin` | none |
| `fat-system` | `fat` | none |
| `thin-jemalloc` | `thin` | `jemalloc` |
| `fat-jemalloc` | `fat` | `jemalloc` |

The default release remains `thin-system` unless benchmark, memory, and stability evidence proves a
different candidate is better.

## Local Protocol Benchmark

Run from `kelinode-rs`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\perf\build-allocator-ab.ps1
```

The script writes candidate suite reports and compare reports under:

```text
.codex-tmp/allocator-ab
```

Use a quick parser and candidate-enumeration smoke without running benches:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\perf\build-allocator-ab.ps1 -SkipBench
```

Reuse existing JSON reports and rerun only the compare gates:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\perf\build-allocator-ab.ps1 -CompareOnly
```

Do not accept a candidate if `bench compare` fails, emits errors, or misses any baseline command.
The default comparison gates are:

| Gate | Limit |
| --- | --- |
| Per-command throughput drop | `<= 10%` |
| Per-command p99 latency increase | `<= 30%` |
| Candidate errors | `0` |
| Missing baseline commands | `0` |

On Windows/MSVC, the `jemalloc` feature compiles but the global allocator is not installed. Windows
local results are useful for feature plumbing and non-allocator protocol regressions, but allocator
memory decisions require Linux or musl evidence.

The harness writes report-only `*-compare.json` files before it runs gates. It continues checking
every candidate, then exits non-zero if any candidate fails its gate.

## Production Safety

Do not deploy an allocator candidate to production until local tests, local bench compare, and a
rollback command path have been recorded. Production replacement requires explicit approval.

For production-like memory validation, collect resource samples with the existing watcher and gate:

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

If no candidate clearly improves CPU or resident memory without speed and stability regression,
keep `thin-system`.

## Local Results

Run date: `2026-06-14T09:05:29.7297352+08:00`

Host: `WIN-JD01F8FBPP9`

Repository revisions:

| Repository | Revision |
| --- | --- |
| `kelinode-rs` | `04a26d0` |
| `keli-core-rs` | `619a2e9` |

Commands:

```powershell
cargo test --locked --workspace -j 1 -- --test-threads=1
cargo test --locked --workspace --features jemalloc -j 1 -- --test-threads=1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\perf\build-allocator-ab.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\perf\build-allocator-ab.ps1 -CompareOnly
```

Validation:

| Check | Result |
| --- | --- |
| `keli-core-rs` default tests | Pass: 664 unit tests, 1 control socket integration test |
| `keli-core-rs --features jemalloc` tests | Pass: 664 unit tests, 1 control socket integration test |
| Four-candidate local bench suite | Completed and wrote four suite reports under `.codex-tmp/allocator-ab` |
| `-CompareOnly` harness gate replay | Expected failure: all non-baseline candidates failed gates; exit code `1` |

Compare summary:

| Candidate | Commands | Worst throughput | Worst p99 | Errors | Retries | Gate |
| --- | ---: | --- | --- | ---: | ---: | --- |
| `fat-system` | 7 | `tuic-udp` `-28.48%` | `tuic-udp` `+52.65%` | 0 | 0 | Fail |
| `thin-jemalloc` | 7 | `tuic-udp` `-22.98%` | `hy2-tcp-stream` `+51.23%` | 0 | 0 | Fail |
| `fat-jemalloc` | 7 | `direct-tcp-stream` `-28.88%` | `tuic-udp` `+55.69%` | 0 | 0 | Fail |

Local recommendation:

Keep `thin-system` as the release default. The tested candidates produced no functional errors, but
each failed the protocol speed or tail-latency gates. On this Windows/MSVC host, the `jemalloc`
feature is a feature-plumbing check only because the global allocator is disabled for MSVC; no Linux
memory improvement should be inferred from this run. Do not replace the production binary from this
evidence. A Linux or musl allocator run can be scheduled later if a candidate first shows a speed-safe
case, or if the operator wants a separate non-production allocator memory experiment.
