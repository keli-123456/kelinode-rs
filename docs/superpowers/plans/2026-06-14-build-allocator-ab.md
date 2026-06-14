# Build Allocator A/B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a safe, repeatable A/B path for comparing `thin-system`, `fat-system`, `thin-jemalloc`, and `fat-jemalloc` without changing default release behavior until evidence proves a candidate wins.

**Architecture:** Keep the checked-in release default unchanged. Add an opt-in `jemalloc` feature to `keli-core-rs`, expose an embedded-node feature from `kelinode-rs`, and add scripts/docs that build and compare explicit candidates with Cargo profile environment overrides. Use existing `bench suite`, `bench compare`, resource watcher, and resource gate for evidence.

**Tech Stack:** Rust/Cargo features, `tikv-jemallocator`, Cargo profile environment overrides, PowerShell experiment harness, existing `keli-core-rs` bench tools, existing `kelinode-rs` resource watcher/gate.

---

### Task 1: Add Opt-In Jemalloc To `keli-core-rs`

**Files:**
- Modify: `C:\Users\Administrator\Documents\keli\keli-core-rs\Cargo.toml`
- Create: `C:\Users\Administrator\Documents\keli\keli-core-rs\src\allocator.rs`
- Modify: `C:\Users\Administrator\Documents\keli\keli-core-rs\src\lib.rs`

- [ ] **Step 1: Inspect current crate root**

Run:

```powershell
Get-Content -LiteralPath src\lib.rs
```

Expected: existing module declarations are visible so the new allocator module can be added near the top without changing protocol code.

- [ ] **Step 2: Add optional dependency and feature**

Patch `Cargo.toml` so it contains the feature and target-specific optional dependency:

```toml
[features]
default = []
jemalloc = ["dep:tikv-jemallocator"]

[target.'cfg(not(target_env = "msvc"))'.dependencies]
tikv-jemallocator = { version = "0.6", optional = true }
```

Keep the existing `[profile.release]` values unchanged:

```toml
[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
panic = "abort"
```

- [ ] **Step 3: Add allocator module**

Create `src/allocator.rs`:

```rust
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
```

- [ ] **Step 4: Include allocator module from the library**

Add this near the top of `src/lib.rs`:

```rust
mod allocator;
```

Do not add another global allocator in `keli-core-rs/src/main.rs`. The library-level allocator is used by the standalone core binary and by the embedded node build when the feature is enabled.

- [ ] **Step 5: Verify default build remains unchanged**

Run from `C:\Users\Administrator\Documents\keli\keli-core-rs`:

```powershell
cargo test --locked --workspace -j 1 -- --test-threads=1
```

Expected: all existing tests pass.

- [ ] **Step 6: Verify jemalloc feature compiles**

Run:

```powershell
cargo test --locked --workspace --features jemalloc -j 1 -- --test-threads=1
```

Expected: tests pass on non-Windows GNU targets. On Windows MSVC, if the optional dependency cannot build, replace this with a Linux CI/remote build check before claiming the feature is portable.

- [ ] **Step 7: Commit core feature**

Run:

```powershell
git add Cargo.toml Cargo.lock src/allocator.rs src/lib.rs
git commit -m "Add opt-in jemalloc allocator feature"
```

Expected: only the allocator feature, lockfile, and crate root changes are committed. Existing unrelated dirty files stay unstaged.

### Task 2: Expose Embedded Jemalloc Build In `kelinode-rs`

**Files:**
- Modify: `C:\Users\Administrator\Documents\keli\kelinode-rs\Cargo.toml`

- [ ] **Step 1: Add an opt-in embedded feature**

Patch the `[features]` section:

```toml
[features]
default = []
embedded-core = ["dep:keli-core-rs"]
embedded-core-jemalloc = ["embedded-core", "keli-core-rs/jemalloc"]
```

Do not change `[profile.release]`.

- [ ] **Step 2: Verify default embedded tests still pass**

Run from `C:\Users\Administrator\Documents\keli\kelinode-rs`:

```powershell
cargo test --locked --workspace --features embedded-core -j 1 -- --test-threads=1
```

Expected: all existing tests pass.

- [ ] **Step 3: Verify jemalloc embedded build compiles**

Run:

```powershell
cargo build --locked --release --features embedded-core-jemalloc
```

Expected: build succeeds on a target where `tikv-jemallocator` supports the environment. If Windows cannot build the allocator, run this check on Linux before acceptance.

- [ ] **Step 4: Commit node feature**

Run:

```powershell
git add Cargo.toml Cargo.lock
git commit -m "Expose embedded jemalloc build feature"
```

Expected: only feature and lockfile changes are committed. Existing unrelated dirty files stay unstaged.

### Task 3: Add Local A/B Experiment Harness

**Files:**
- Create: `C:\Users\Administrator\Documents\keli\kelinode-rs\scripts\perf\build-allocator-ab.ps1`
- Create: `C:\Users\Administrator\Documents\keli\kelinode-rs\docs\BUILD_ALLOCATOR_AB.md`

- [ ] **Step 1: Create experiment script**

Create `scripts/perf/build-allocator-ab.ps1`:

```powershell
param(
    [string]$CoreDir = (Resolve-Path "$PSScriptRoot\..\..\..\keli-core-rs").Path,
    [string]$OutDir = (Resolve-Path "$PSScriptRoot\..\..").Path + "\.codex-tmp\allocator-ab",
    [string]$Commands = "direct-tcp-stream,vless-tcp-stream,trojan-tcp-stream,hy2-tcp-stream,hy2-udp,tuic-tcp-stream,tuic-udp",
    [int]$Streams = 8,
    [int]$Requests = 512,
    [int]$Payload = 1024,
    [int]$Repeats = 3,
    [switch]$SkipBench
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$candidates = @(
    @{ Label = "thin-system"; Lto = "thin"; Features = "" },
    @{ Label = "fat-system"; Lto = "fat"; Features = "" },
    @{ Label = "thin-jemalloc"; Lto = "thin"; Features = "jemalloc" },
    @{ Label = "fat-jemalloc"; Lto = "fat"; Features = "jemalloc" }
)

Push-Location $CoreDir
try {
    foreach ($candidate in $candidates) {
        $env:CARGO_PROFILE_RELEASE_LTO = $candidate.Lto
        $label = $candidate.Label
        $out = Join-Path $OutDir "$label.json"

        $args = @("run", "--release", "--locked")
        if ($candidate.Features -ne "") {
            $args += @("--features", $candidate.Features)
        }
        $args += @("--", "bench", "suite", "--commands", $Commands, "--streams", "$Streams", "--requests", "$Requests", "--payload", "$Payload", "--repeats", "$Repeats", "--label", $label, "--out", $out)

        if ($SkipBench) {
            Write-Host "SKIP bench for $label"
        } else {
            Write-Host "Running $label"
            cargo @args
        }
    }

    foreach ($candidate in $candidates | Where-Object { $_.Label -ne "thin-system" }) {
        $label = $candidate.Label
        cargo run --release --locked -- bench compare `
            --baseline (Join-Path $OutDir "thin-system.json") `
            --candidate (Join-Path $OutDir "$label.json") `
            --out (Join-Path $OutDir "$label-compare.json") `
            --max-throughput-drop-percent 10 `
            --max-p99-increase-percent 30 `
            --fail-on-errors `
            --require-all-baseline-commands
    }
}
finally {
    Remove-Item Env:CARGO_PROFILE_RELEASE_LTO -ErrorAction SilentlyContinue
    Pop-Location
}
```

- [ ] **Step 2: Run script parser smoke**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\perf\build-allocator-ab.ps1 -SkipBench
```

Expected: prints `SKIP bench for thin-system`, `fat-system`, `thin-jemalloc`, and `fat-jemalloc`, then skips compare and exits successfully. This proves argument parsing and candidate enumeration work before the long bench is run.

- [ ] **Step 3: Create operator documentation**

Create `docs/BUILD_ALLOCATOR_AB.md`:

```markdown
# Build Allocator A/B

This runbook compares release build and allocator candidates without changing the default release
profile.

## Candidates

| Candidate | LTO | Features |
| --- | --- | --- |
| `thin-system` | `thin` | none |
| `fat-system` | `fat` | none |
| `thin-jemalloc` | `thin` | `jemalloc` |
| `fat-jemalloc` | `fat` | `jemalloc` |

## Local protocol benchmark

Run from `kelinode-rs`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\perf\build-allocator-ab.ps1
```

The script writes candidate suite reports and compare reports under:

```text
.codex-tmp/allocator-ab
```

The candidate must not be accepted if `bench compare` fails, emits errors, or misses any baseline
command.

## Production safety

Do not deploy an allocator candidate to production until local tests, local bench compare, and a
rollback command path have been recorded. Production replacement requires explicit approval.
```

- [ ] **Step 4: Commit harness docs**

Run:

```powershell
git add scripts/perf/build-allocator-ab.ps1 docs/BUILD_ALLOCATOR_AB.md
git commit -m "Add build allocator AB harness"
```

Expected: script and docs are committed.

### Task 4: Run Bench Matrix And Summarize Results

**Files:**
- Read: `C:\Users\Administrator\Documents\keli\kelinode-rs\.codex-tmp\allocator-ab\*.json`
- Modify: `C:\Users\Administrator\Documents\keli\kelinode-rs\docs\BUILD_ALLOCATOR_AB.md`

- [ ] **Step 1: Run core default tests**

Run from `C:\Users\Administrator\Documents\keli\keli-core-rs`:

```powershell
cargo test --locked --workspace -j 1 -- --test-threads=1
```

Expected: all tests pass.

- [ ] **Step 2: Run core jemalloc tests**

Run:

```powershell
cargo test --locked --workspace --features jemalloc -j 1 -- --test-threads=1
```

Expected: all tests pass on a supported target. If this host is unsupported, record that Linux CI/remote validation is required before production use.

- [ ] **Step 3: Run full A/B bench matrix**

Run from `C:\Users\Administrator\Documents\keli\kelinode-rs`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\perf\build-allocator-ab.ps1
```

Expected: four suite JSON reports and three compare JSON reports are created under `.codex-tmp\allocator-ab`.

- [ ] **Step 4: Summarize report numbers**

Open each compare JSON and record for every candidate:

- commands compared
- throughput drop percentage
- p99 increase percentage
- error count
- retry count
- whether the compare gate passed

Append a `## Local Results` section to `docs/BUILD_ALLOCATOR_AB.md` with the exact command, date,
host, and result table.

- [ ] **Step 5: Commit local evidence**

Run:

```powershell
git add docs/BUILD_ALLOCATOR_AB.md
git commit -m "Record local build allocator AB evidence"
```

Expected: only the runbook evidence is committed. Raw `.codex-tmp` reports stay untracked unless the operator explicitly wants them committed.

### Task 5: Optional Production Short Test

**Files:**
- Remote read/write only after explicit operator approval:
  - `/usr/local/kelinode/kelinode`
  - `/usr/local/kelinode/kelinode.backup-<timestamp>`
  - `/tmp/keli-ab-<candidate>/samples.tsv`

- [ ] **Step 1: Stop if no production approval exists**

If the operator has not explicitly approved production replacement in the current conversation,
do not run this task. Report that local evidence is ready and ask whether to schedule a short
production test.

- [ ] **Step 2: Capture pre-test state**

Run:

```powershell
ssh -i C:\Users\Administrator\.ssh\codex_keli_ed25519 -o BatchMode=yes root@2.56.116.39 "date -Is; sha256sum /usr/local/kelinode/kelinode; /usr/local/kelinode/kelinode version; systemctl show kelinode --property=ActiveState,SubState,MainPID,MemoryCurrent,NRestarts,ExecMainStartTimestamp --no-pager; ps -C kelinode -o pid,etimes,pcpu,pmem,rss,vsz,nlwp,cmd; free -m; ss -s"
```

Expected: service is `active/running`; binary hash and state are recorded.

- [ ] **Step 3: Upload the selected candidate binary**

Use `C:\Users\Administrator\Documents\keli\kelinode-rs\target\x86_64-unknown-linux-musl\release\kelinode` as the local candidate path for Linux production tests.

Run:

```powershell
scp -i C:\Users\Administrator\.ssh\codex_keli_ed25519 -o BatchMode=yes C:\Users\Administrator\Documents\keli\kelinode-rs\target\x86_64-unknown-linux-musl\release\kelinode root@2.56.116.39:/tmp/kelinode-ab-candidate
```

Expected: upload exits `0`.

- [ ] **Step 4: Install candidate with rollback backup**

Run:

```powershell
ssh -i C:\Users\Administrator\.ssh\codex_keli_ed25519 -o BatchMode=yes root@2.56.116.39 "cp /usr/local/kelinode/kelinode /usr/local/kelinode/kelinode.backup-before-ab && install -m 0755 /tmp/kelinode-ab-candidate /usr/local/kelinode/kelinode && systemctl restart kelinode"
```

Expected: restart succeeds and `systemctl is-active kelinode` returns `active`.

- [ ] **Step 5: Watch candidate window**

Run:

```powershell
ssh -i C:\Users\Administrator\.ssh\codex_keli_ed25519 -o BatchMode=yes root@2.56.116.39 "/tmp/native_resource_watch.sh --samples 60 --interval 60 --out /tmp/keli-ab-candidate --since \"$(date '+%Y-%m-%d %H:%M:%S')\""
```

Expected: 60 data rows are written.

- [ ] **Step 6: Gate candidate window**

Run:

```powershell
ssh -i C:\Users\Administrator\.ssh\codex_keli_ed25519 -o BatchMode=yes root@2.56.116.39 "/tmp/native_resource_gate.sh --samples /tmp/keli-ab-candidate/samples.tsv --min-samples 60 --max-native-pending 1 --max-panic-lines 0 --max-external-core-errors 0 --max-rss-kb 2500000"
```

Expected: gate passes. If it fails, roll back immediately.

- [ ] **Step 7: Roll back on any regression**

Run:

```powershell
ssh -i C:\Users\Administrator\.ssh\codex_keli_ed25519 -o BatchMode=yes root@2.56.116.39 "install -m 0755 /usr/local/kelinode/kelinode.backup-before-ab /usr/local/kelinode/kelinode && systemctl restart kelinode"
```

Expected: baseline binary is restored and service returns to `active/running`.

### Task 6: Decide And Publish

**Files:**
- Modify when the selected recommendation changes the default core build:
  - `C:\Users\Administrator\Documents\keli\keli-core-rs\Cargo.toml`
  - `C:\Users\Administrator\Documents\keli\keli-core-rs\Cargo.lock`
- Modify when the selected recommendation changes the embedded node build:
  - `C:\Users\Administrator\Documents\keli\kelinode-rs\Cargo.toml`
  - `C:\Users\Administrator\Documents\keli\kelinode-rs\Cargo.lock`
- Always modify:
  - `C:\Users\Administrator\Documents\keli\kelinode-rs\docs\BUILD_ALLOCATOR_AB.md`

- [ ] **Step 1: Apply decision rule**

Use this decision table:

| Evidence | Decision |
| --- | --- |
| No candidate passes compare gates | Keep `thin-system` default |
| `fat-system` wins without RSS regression | Consider switching release LTO to `fat` |
| `thin-jemalloc` materially improves RSS/systemd memory without speed regression | Keep feature opt-in or switch only after production soak |
| `fat-jemalloc` wins both speed and memory without stability regression | Consider default switch after extended soak |

- [ ] **Step 2: Record recommendation**

Append `## Recommendation` to `docs/BUILD_ALLOCATOR_AB.md` with:

- selected candidate
- evidence summary
- rejected candidates and reason
- whether default release behavior changes
- whether a production soak is still required

- [ ] **Step 3: Run final verification**

Run in `keli-core-rs`:

```powershell
cargo test --locked --workspace -j 1 -- --test-threads=1
```

Run in `kelinode-rs`:

```powershell
cargo test --locked --workspace --features embedded-core -j 1 -- --test-threads=1
```

Expected: both pass.

- [ ] **Step 4: Commit final recommendation**

Run:

```powershell
git add docs/BUILD_ALLOCATOR_AB.md Cargo.toml Cargo.lock
git commit -m "Record build allocator AB recommendation"
```

Expected: recommendation and any accepted default changes are committed. If the decision is to keep the baseline, commit only the documentation.

- [ ] **Step 5: Push and verify CI**

Run:

```powershell
git push origin main
```

Expected: push succeeds. Verify GitHub Actions CI completes successfully before claiming the goal is complete.
