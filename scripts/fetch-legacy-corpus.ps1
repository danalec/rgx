# fetch-legacy-corpus.ps1 — Windows wrapper for the bash fetch script.
#
#   powershell -File scripts\fetch-legacy-corpus.ps1
#
# The bash script in this directory is the source of truth; this wrapper
# exists so a developer on Windows who does not want to install Git Bash
# can still populate tests/fixtures/legacy-formats/ from PowerShell. It
# shells out to the same code path as the .sh: when bash is on PATH the
# wrapper invokes the bash script verbatim; when it is not, it runs the
# steps itself with PowerShell primitives.

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path "$ScriptDir\..").Path
$Fixtures  = Join-Path $RepoRoot 'tests\fixtures\legacy-formats'
New-Item -ItemType Directory -Force $Fixtures | Out-Null
New-Item -ItemType Directory -Force (Join-Path $Fixtures 'lotus') | Out-Null
New-Item -ItemType Directory -Force (Join-Path $Fixtures 'dif')   | Out-Null

$bashScript = Join-Path $ScriptDir 'fetch-legacy-corpus.sh'
$gitBash    = (Get-Command bash -ErrorAction SilentlyContinue)?.Source

# Delegate to bash only when that bash can actually READ the script.
#
# `bash` on PATH is not one thing: Git Bash understands `C:/...`, WSL's
# bash understands `/mnt/c/...`, and a stub does not understand either.
# Handing the first one a Windows path it cannot stat produced
# "No such file or directory" naming a path the developer never typed, and
# the fetch died before the native fallback -- which exists and works --
# ever ran. So the candidates are probed, and a bash that cannot see the
# file is not used at all.
if ($gitBash -and (Test-Path $bashScript)) {
    $posix = $bashScript -replace '\\', '/'
    $candidates = @($posix)
    if ($posix -match '^([A-Za-z]):(.*)$') {
        $candidates += ("/mnt/{0}{1}" -f $Matches[1].ToLower(), $Matches[2])
    }
    foreach ($cand in $candidates) {
        # The probe asks for the utilities the script itself needs, not
        # only for the file: a bash that can stat the script but has no
        # `mkdir`/`curl` on it dies at line 25 with "command not found",
        # which is the same dead end one level down.
        $probe = & $gitBash -c "test -f '$cand' && command -v mkdir >/dev/null && command -v curl >/dev/null && command -v git >/dev/null && echo rgx-fetch-ok" 2>$null
        if ($probe -match 'rgx-fetch-ok') {
            Write-Host "fetch-legacy-corpus: bash available, delegating to $cand"
            & $gitBash $cand @args
            return
        }
    }
    Write-Host "fetch-legacy-corpus: bash on PATH cannot read the script; running native PowerShell fallback."
} else {
    Write-Host "fetch-legacy-corpus: bash not on PATH, running native PowerShell fallback."
}

# ---- mdbtools/mdbtestdata (cloned via git) ----
$MdbTest = Join-Path $Fixtures 'mdbtestdata'
if (-not (Test-Path (Join-Path $MdbTest 'data\nwind.mdb'))) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Error "fetch-legacy-corpus: 'git' not on PATH and bash unavailable."
        return
    }
    if (Test-Path $MdbTest) { Remove-Item -Recurse -Force $MdbTest }
    git clone --depth=1 https://github.com/mdbtools/mdbtestdata $MdbTest
}

# ---- sembiance.com files (downloaded via Invoke-WebRequest) ----
$LotusUrl = 'https://sembiance.com/fileFormatSamples/document/lotus123'
$DifUrl   = 'https://sembiance.com/fileFormatSamples/text/dataInterchangeFormat'
$LotusFiles = @(
    '1530MTGE.WKB','AUTOLOAN.WKB','DEMO.WK4','example.123',
    'example.wk1','example.wk3','example.wk4','example.wks',
    'PEYNEVAL.WK1','PEYTREND.WK3','PF.WK1','TILE.WKS'
)
$DifFiles = @(
    'DIFTEST.DIF','EXAMPLE.DIF','EXAMPLE2.DIF','HDINFO.DIF',
    'MASK1.DIF','SAMPLE.DIF','beispiel.dif'
)

function Get-Sample {
    param([string]$Url, [string]$Out)
    if ((Test-Path $Out) -and ((Get-Item $Out).Length -gt 0)) { return }
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Out -UseBasicParsing -ErrorAction Stop
        Write-Host "  + $(Split-Path $Out -Leaf)"
    } catch {
        if (Test-Path $Out) { Remove-Item $Out }
        Write-Warning "  - $(Split-Path $Out -Leaf) ($($_.Exception.Message))"
    }
}

Write-Host "fetch-legacy-corpus: Lotus 1-2-3 samples ($LotusUrl) ..."
foreach ($f in $LotusFiles) {
    Get-Sample "$LotusUrl/$f" (Join-Path $Fixtures "lotus\$f")
}
# The `.wk2` extension is a rename, not a format. 1-2-3 v2.0 shipped the
# worksheet as `.wk1` and changed the extension to `.wk2` "quickly", so that
# the number in the extension would match the version number; the record
# layout did not change with it, and both files carry the BOF version code
# 0x0406. No `.wk2` sample is published where this script can reach one --
# the host above answers 404 for `example.wk2` -- so the corpus makes one:
# a copy of the `.wk1` under the `.wk2` name.
#
# It is a DISPATCH fixture. It shows that the extension reaches the v2
# reader and that the bytes under it are the v2 bytes; it says nothing new
# about the bytes, which the `.wk1` already exercises.
#
# The bash twin makes the same copy, and the two are held to the same
# corpus: without it the Windows corpus holds no `.wk2` at all, and
# `tests/legacy_formats.rs` FAILS on the fixture it is missing.
$wk1 = Join-Path $Fixtures 'lotus\example.wk1'
$wk2 = Join-Path $Fixtures 'lotus\example.wk2'
if ((Test-Path $wk1) -and -not (Test-Path $wk2)) {
    Copy-Item -LiteralPath $wk1 -Destination $wk2
    Write-Host "  + example.wk2 (a copy of example.wk1: the extension is a rename)"
}

Write-Host "fetch-legacy-corpus: DIF samples ($DifUrl) ..."
foreach ($f in $DifFiles) {
    Get-Sample "$DifUrl/$f" (Join-Path $Fixtures "dif\$f")
}

$difCount = (Get-ChildItem -Recurse -File (Join-Path $Fixtures 'dif') -ErrorAction SilentlyContinue | Measure-Object).Count
$lotusCount = (Get-ChildItem -Recurse -File (Join-Path $Fixtures 'lotus') -ErrorAction SilentlyContinue | Measure-Object).Count
$mdbCount = 0
$dataDir = Join-Path $MdbTest 'data'
if (Test-Path $dataDir) {
    $mdbCount = (Get-ChildItem -Recurse -File $dataDir -ErrorAction SilentlyContinue | Measure-Object).Count
}
Write-Host "fetch-legacy-corpus: done."
Write-Host "  dif:        $difCount file(s)"
Write-Host "  lotus:      $lotusCount file(s)"
Write-Host "  mdbtestdata:$mdbCount file(s) in data/"
Write-Host "fixtures root: $Fixtures"

# The probe above runs a native command, so `$LASTEXITCODE` carries its
# status into whoever called this script. A fetch that completed must not
# report the probe's failure.
exit 0