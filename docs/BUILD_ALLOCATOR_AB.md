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
