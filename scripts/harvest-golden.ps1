# Harvest real-world golden samples from this machine into tests/golden/.
#
#   powershell -File scripts/harvest-golden.ps1
#
# Synthetic fixtures prove the parsers handle well-formed input; golden
# samples prove they survive what real producers actually ship (Word, real
# PE linkers, camera EXIF, ...). Files are copied locally and gitignored —
# never committed (licensing); the CLI test skips silently when the
# directory is absent, so CI stays hermetic.
#
# Writes tests/golden/manifest.tsv: "<file>\t<pattern>" per line, where
# pattern is known to match in that file on this machine.
param(
    [string]$OutDir = "",
    [string]$PdfDir = (Join-Path $env:USERPROFILE "Documents")
)

$ErrorActionPreference = "Stop"
if (-not $OutDir) {
    $OutDir = Join-Path (Split-Path $PSScriptRoot -Parent) "tests\golden"
}
New-Item -ItemType Directory -Force $OutDir | Out-Null
$entries = @()

function Add-Golden([string]$name, [string]$source, [string]$pattern) {
    if (Test-Path $source) {
        $dest = Join-Path $OutDir $name
        Copy-Item $source $dest -Force
        $script:entries += "$name`t$pattern"
        Write-Host "golden: $name <- $source"
    } else {
        Write-Host "skip (not found): $source"
    }
}

# media: font name table + JPEG EXIF
Add-Golden "font-candara.ttf" "C:\Windows\Fonts\Candara.ttf" "Candara"
Add-Golden "wallpaper.jpg" "C:\Windows\Web\Wallpaper\Windows\img0.jpg" "EXIF|JFIF|http"

# inspect: a real PE from the OS
Add-Golden "kernel32.dll" "C:\Windows\System32\kernel32.dll" "KERNEL32|Microsoft"

# tabular: a real SQLite database from an installed app
$realDb = Get-ChildItem "$env:LOCALAPPDATA\AMD\CN\*.db" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($realDb) { Add-Golden "real.sqlite.db" $realDb.FullName "sqlite" }

# docs: a real PDF from the user corpus
$realPdf = Get-ChildItem $PdfDir -Filter *.pdf -ErrorAction SilentlyContinue | Select-Object -First 1
if ($realPdf) { Add-Golden "real.pdf" $realPdf.FullName "." } else { Write-Host "skip: no pdf in $PdfDir" }

$entries | Set-Content (Join-Path $OutDir "manifest.tsv")
Write-Host ""
Write-Host "harvested $($entries.Count) samples -> $OutDir"
Write-Host "run 'cargo test --release --test golden' to verify against them"
