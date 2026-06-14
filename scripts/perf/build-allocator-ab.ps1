param(
    [string]$CoreDir = (Resolve-Path "$PSScriptRoot\..\..\..\keli-core-rs").Path,
    [string]$OutDir = ((Resolve-Path "$PSScriptRoot\..\..").Path + "\.codex-tmp\allocator-ab"),
    [string]$Commands = "direct-tcp-stream,vless-tcp-stream,trojan-tcp-stream,hy2-tcp-stream,hy2-udp,tuic-tcp-stream,tuic-udp",
    [int]$Streams = 8,
    [int]$Requests = 512,
    [int]$Payload = 1024,
    [int]$Repeats = 3,
    [switch]$SkipBench
)

$ErrorActionPreference = "Stop"

$candidates = @(
    @{ Label = "thin-system"; Lto = "thin"; Features = "" },
    @{ Label = "fat-system"; Lto = "fat"; Features = "" },
    @{ Label = "thin-jemalloc"; Lto = "thin"; Features = "jemalloc" },
    @{ Label = "fat-jemalloc"; Lto = "fat"; Features = "jemalloc" }
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ($IsWindows -or $env:OS -eq "Windows_NT") {
    Write-Host "NOTE: Windows/MSVC builds compile the jemalloc feature path but do not install jemalloc."
    Write-Host "NOTE: Run Linux or musl builds before using allocator memory results for production decisions."
}

$previousLto = $env:CARGO_PROFILE_RELEASE_LTO

function Invoke-CargoChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    Write-Host ("cargo " + ($Args -join " "))
    cargo @Args
}

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
        $args += @(
            "--",
            "bench",
            "suite",
            "--commands",
            $Commands,
            "--streams",
            "$Streams",
            "--requests",
            "$Requests",
            "--payload",
            "$Payload",
            "--repeats",
            "$Repeats",
            "--label",
            $label,
            "--out",
            $out
        )

        if ($SkipBench) {
            Write-Host "SKIP bench for $label"
        } else {
            Write-Host "Running bench for $label"
            Invoke-CargoChecked -Args $args
        }
    }

    if ($SkipBench) {
        Write-Host "SKIP compare because -SkipBench was provided"
        return
    }

    $env:CARGO_PROFILE_RELEASE_LTO = "thin"
    $baseline = Join-Path $OutDir "thin-system.json"

    foreach ($candidate in $candidates | Where-Object { $_.Label -ne "thin-system" }) {
        $label = $candidate.Label
        $candidateReport = Join-Path $OutDir "$label.json"
        $compareReport = Join-Path $OutDir "$label-compare.json"
        $args = @(
            "run",
            "--release",
            "--locked",
            "--",
            "bench",
            "compare",
            "--baseline",
            $baseline,
            "--candidate",
            $candidateReport,
            "--out",
            $compareReport,
            "--max-throughput-drop-percent",
            "10",
            "--max-p99-increase-percent",
            "30",
            "--fail-on-errors",
            "--require-all-baseline-commands"
        )

        Write-Host "Comparing thin-system vs $label"
        Invoke-CargoChecked -Args $args
    }
}
finally {
    if ($null -eq $previousLto) {
        Remove-Item Env:CARGO_PROFILE_RELEASE_LTO -ErrorAction SilentlyContinue
    } else {
        $env:CARGO_PROFILE_RELEASE_LTO = $previousLto
    }
    Pop-Location
}
