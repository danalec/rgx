# Build the shippable rgx binaries: portable x86-64 and four instruction-set
# tuned variants (x86-64-v2, AVX2 / x86-64-v3, x86-64-v4, Zen-4 / znver4).
#
#   powershell -File scripts/build-release.ps1            # clippy gate + tests + five zips
#   powershell -File scripts/build-release.ps1 -SkipTests # iterate faster
#
# Unless -SkipTests, the release fails on any clippy warning
# (`cargo clippy --release --workspace --all-targets -- -D warnings`) —
# the workspace stays warning-free by policy.
#
# Outputs (.dist/):
#   rgx-v<version>-x86_64-windows.zip        baseline, runs on any x86-64 CPU
#   rgx-v<version>-v2-windows.zip            tuned for x86-64-v2 CPUs
#   rgx-v<version>-avx2-windows.zip          tuned for AVX2 CPUs (x86-64-v3)
#   rgx-v<version>-v4-windows.zip            tuned for AVX-512 CPUs (x86-64-v4)
#   rgx-v<version>-znver4-windows.zip        tuned for Zen 4 (incl. 7950X3D)
# Each zip holds a directory named after the archive, with rgx.exe, the
# README and the licences inside it. That is the layout the published asset
# has, the layout every package the winget repository accepts has, and the
# layout release-all.sh produces: an archive that packs the contents instead
# would install nothing and look right.
#
# Each tuned variant sets ONLY -C target-cpu, through the per-target
# CARGO_TARGET_<triple>_RUSTFLAGS variable: build scripts and proc-macros
# are host binaries and must not be built for a CPU the build machine may
# not have. The linker still comes from .cargo/config.toml (lld-link).
# Measured effect (bench-linkers.ps1, 7950X3D): ~+1% corpus, ~+2.5%
# big-file literal, ~+5% big-file regex for znver4.
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
    # The per-target variable, not RUSTFLAGS: RUSTFLAGS would also apply to
    # host build scripts and proc-macros, which must run on this machine.
    $hostTriple = (rustc -vV | Select-String '^host: ' | Select-Object -First 1).Line.Substring(6)
    $rustflagsVar = "CARGO_TARGET_" + ($hostTriple.ToUpperInvariant() -replace '-', '_') + "_RUSTFLAGS"
    Set-Item -Path "Env:$rustflagsVar" -Value $rustflags
    try {
        $env:CARGO_TARGET_DIR = $targetDir
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($name)" }
    } finally {
        Remove-Item "Env:$rustflagsVar" -ErrorAction SilentlyContinue
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
    }
    Join-Path $targetDir "release\rgx.exe"
}

# portable baseline (config.toml supplies lld-link; no target-cpu)
$exeGeneric = Build-Variant "generic" (Join-Path $root "target") ""

# The four instruction-set tiers, in ascending baseline order. A CPU older
# than the tier cannot run its binary (illegal instruction at startup).
$exeV2 = Build-Variant "v2" (Join-Path $root "target\release-v2") "-C target-cpu=x86-64-v2"
$exeAvx2 = Build-Variant "avx2" (Join-Path $root "target\release-avx2") "-C target-cpu=x86-64-v3"
$exeV4 = Build-Variant "v4" (Join-Path $root "target\release-v4") "-C target-cpu=x86-64-v4"
$exeZnver4 = Build-Variant "znver4" (Join-Path $root "target\release-znver4") "-C target-cpu=znver4"

# A variant built for an ISA this machine does not have cannot start here:
# its smoke is skipped with the reason rather than reported as a bad build.
function Test-CpuHas([string]$feature) {
    try {
        if ($feature -eq 'sse42') { return [System.Runtime.Intrinsics.X86.Sse42]::IsSupported }
        if ($feature -eq 'avx2') { return [System.Runtime.Intrinsics.X86.Avx2]::IsSupported }
        if ($feature -eq 'avx512') { return [System.Runtime.Intrinsics.X86.Avx512F]::IsSupported }
    } catch { return $false }
    return $false
}
function Invoke-Smoke([string]$exe) {
    & $exe --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "smoke --version failed: $exe" }
    $hits = & $exe -c "fn main" src | Out-String
    if ($hits -notmatch "main.rs:\d+") { throw "smoke search failed: $exe" }
    Write-Host "smoke ok: $exe"
}
Invoke-Smoke $exeGeneric
if (Test-CpuHas 'sse42') { Invoke-Smoke $exeV2 } else { Write-Host "smoke: skipped v2 (no SSE4.2 on this machine)" }
if (Test-CpuHas 'avx2') { Invoke-Smoke $exeAvx2 } else { Write-Host "smoke: skipped avx2 (no AVX2 on this machine)" }
if (Test-CpuHas 'avx512') { Invoke-Smoke $exeV4 } else { Write-Host "smoke: skipped v4 (no AVX-512 on this machine)" }
if (Test-CpuHas 'avx512') { Invoke-Smoke $exeZnver4 } else { Write-Host "smoke: skipped znver4 (no AVX-512 on this machine)" }

function New-ReleaseZip([string]$exe, [string]$zipPath) {
    # The directory inside the archive is named after the archive, so the
    # path the winget manifest names is the path that is really inside it.
    $base = [IO.Path]::GetFileNameWithoutExtension($zipPath)
    $stage = Join-Path $env:TEMP ("rgx-stage-" + [guid]::NewGuid().ToString("N"))
    $dir = Join-Path $stage $base
    New-Item -ItemType Directory -Force $dir | Out-Null
    try {
        Copy-Item $exe (Join-Path $dir "rgx.exe")
        foreach ($doc in @("README.md", "COPYING", "LICENSE-APACHE", "NOTICE")) {
            if (Test-Path $doc) { Copy-Item $doc $dir }
        }
        Compress-Archive -Force $dir $zipPath
    } finally {
        Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    }
    # The archive is checked, not trusted: a zip that does not hold the
    # executable where the manifest will name it installs nothing, and the
    # user sees nothing about why.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName })
    } finally {
        $zip.Dispose()
    }
    $wanted = "$base/rgx.exe"
    if ($entries -notcontains $wanted) {
        throw "the archive holds no ${wanted}: $($entries -join ', ')"
    }
}

# .dist, not dist: the directory this script creates above is the one
# .gitignore lists, and a plain `dist\` would be an unignored pile of
# 3 MB binaries sitting in git status as work to review.
$zipGeneric = ".dist\rgx-v$Version-x86_64-windows.zip"
$zipV2      = ".dist\rgx-v$Version-v2-windows.zip"
$zipAvx2    = ".dist\rgx-v$Version-avx2-windows.zip"
$zipV4      = ".dist\rgx-v$Version-v4-windows.zip"
$zipZnver4  = ".dist\rgx-v$Version-znver4-windows.zip"
New-ReleaseZip $exeGeneric (Join-Path $root $zipGeneric)
New-ReleaseZip $exeV2      (Join-Path $root $zipV2)
New-ReleaseZip $exeAvx2    (Join-Path $root $zipAvx2)
New-ReleaseZip $exeV4      (Join-Path $root $zipV4)
New-ReleaseZip $exeZnver4  (Join-Path $root $zipZnver4)
Write-Host "built: $zipGeneric"
Write-Host "built: $zipV2"
Write-Host "built: $zipAvx2"
Write-Host "built: $zipV4"
Write-Host "built: $zipZnver4"
