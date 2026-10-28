# Build the shippable rgx binaries: portable x86-64 + Zen-4 (znver4) variant.
#
#   powershell -File scripts/build-release.ps1            # clippy gate + tests + both zips
#   powershell -File scripts/build-release.ps1 -SkipTests # iterate faster
#
# Unless -SkipTests, the release fails on any clippy warning
# (`cargo clippy --release --workspace --all-targets -- -D warnings`) —
# the workspace stays warning-free by policy.
#
# Outputs (.dist/):
#   rgx-v<version>-x86_64-windows.zip        baseline, runs on any x86-64 CPU
#   rgx-v<version>-znver4-windows.zip        tuned for Zen 4 (incl. 7950X3D)
# Each zip packs rgx.exe + README.md + COPYING (+ LICENSE-APACHE) at its root,
# matching the asset layout published on the forgejo release.
#
# The znver4 variant sets ONLY -C target-cpu: the linker still comes from
# .cargo/config.toml (lld-link). Measured effect (bench-linkers.ps1,
# 7950X3D): ~+1% corpus, ~+2.5% big-file literal, ~+5% big-file regex.
param(
    [switch]$SkipTests,
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# lld-link must be resolvable (build scripts link host binaries too)
$llvmBin = "C:\Program Files\LLVM\bin"
if ((Test-Path $llvmBin) -and ($env:Path -notlike "*$llvmBin*")) {
    $env:Path = "$llvmBin;$env:Path"
}
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $cargoBin) { $env:Path = "$cargoBin;$env:Path" }
if (-not (Get-Command lld-link.exe -ErrorAction SilentlyContinue)) {
    throw "lld-link.exe not found. Install LLVM first: winget install LLVM.LLVM"
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found; install Rust: https://rustup.rs"
}

if (-not $Version) {
    $Version = (Select-String -Path Cargo.toml -Pattern '^version = "([^"]+)"' |
        Select-Object -First 1).Matches.Groups[1].Value
}

if (-not $SkipTests) {
    # the workspace stays warning-free: any clippy warning fails the release
    cargo clippy --release --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "clippy warnings found; workspace must stay warning-free" }
    cargo test --release --locked --workspace
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}

New-Item -ItemType Directory -Force .dist | Out-Null

function Build-Variant([string]$name, [string]$targetDir, [string]$rustflags) {
    $env:RUSTFLAGS = $rustflags
    try {
        $env:CARGO_TARGET_DIR = $targetDir
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($name)" }
    } finally {
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
    }
    Join-Path $targetDir "release\rgx.exe"
}

# portable baseline (config.toml supplies lld-link; no target-cpu)
$exeGeneric = Build-Variant "generic" (Join-Path $root "target") ""

# Zen 4 tuned: AVX-512 + full Zen-4 scheduling. Baseline x86-64 CPUs must
# NOT run this binary (illegal instruction at startup).
$exeZnver4 = Build-Variant "znver4" (Join-Path $root "target\release-znver4") "-C target-cpu=znver4"

# smoke both: version + a real search over the repo's own sources
foreach ($exe in @($exeGeneric, $exeZnver4)) {
    & $exe --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "smoke --version failed: $exe" }
    $hits = & $exe -c "fn main" src | Out-String
    if ($hits -notmatch "main.rs:\d+") { throw "smoke search failed: $exe" }
    Write-Host "smoke ok: $exe"
}

function New-ReleaseZip([string]$exe, [string]$zipPath) {
    $stage = Join-Path $env:TEMP ("rgx-stage-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force $stage | Out-Null
    try {
        Copy-Item $exe (Join-Path $stage "rgx.exe")
        foreach ($doc in @("README.md", "COPYING", "LICENSE-APACHE", "NOTICE")) {
            if (Test-Path $doc) { Copy-Item $doc $stage }
        }
        Compress-Archive -Force (Join-Path $stage "*") $zipPath
    } finally {
        Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    }
}

# .dist, not dist: the directory this script creates above is the one
# .gitignore lists, and a plain `dist\` would be an unignored pile of
# 3 MB binaries sitting in git status as work to review.
$zipGeneric = ".dist\rgx-v$Version-x86_64-windows.zip"
$zipZnver4  = ".dist\rgx-v$Version-znver4-windows.zip"
New-ReleaseZip $exeGeneric (Join-Path $root $zipGeneric)
New-ReleaseZip $exeZnver4  (Join-Path $root $zipZnver4)
Write-Host "built: $zipGeneric"
Write-Host "built: $zipZnver4"
