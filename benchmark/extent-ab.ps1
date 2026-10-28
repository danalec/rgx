# Extent-sparse A/B: one binary, two arms, `RGX_ABLATE_EXTENTS` as the control.
#
# Protocol, per AGENTS.md 9: the count gate is in front of every timing line
# (an arm whose -c disagrees with the other arm or with the direct path
# prints no timing), the verdict may refuse (inside the floor the row is a
# tie, and a winner is named only when every sample of one arm sits below
# every sample of the other), and the spawn floor is measured first and
# subtracted from both sides.
#
#   .\extent-ab.ps1 -Corpus ..\..\crates -Rounds 7
#
# The transcript is the run; findings.md quotes only what it prints.

param(
    [string]$Corpus = "",
    [string]$Store = "",
    [int]$Rounds = 7,
    # Comma-separated: -File invocation passes arrays as stray tokens.
    [string]$Patterns = "brotli,fn main",
    # Which ablation switch the control arm sets: RGX_ABLATE_EXTENTS (the
    # sparse read) or RGX_ABLATE_NGRAM (the whole filter, containers
    # included -- the arm that prices decompression avoided).
    [string]$AblateVar = "RGX_ABLATE_EXTENTS"
)

$ErrorActionPreference = "Stop"
$PatternList = @($Patterns.Split(",") | ForEach-Object { $_.Trim() })
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$rgxtv = Join-Path $root "target\release\rgx-tv.exe"
$rgx = Join-Path $root "target\release\rgx.exe"
# The corpus is the repository's own crates, resolved from the script's own
# location: a fixed absolute path would encode one person's home directory.
if (-not $Corpus) { $Corpus = Join-Path $root "crates" }
if ($Store -eq "") {
    $Store = Join-Path $env:TEMP ("rgx-extent-ab-" + [DateTime]::Now.Ticks)
}

# The three refusals the shell twin makes, in the same words and with the
# same exit status: no binary, no corpus, no run. The twins are held to the
# same behaviour, and this one had none of the three -- a missing binary
# died inside the caller's `ErrorActionPreference = "Stop"` with a message
# about the script, not about what to build.
if (-not (Test-Path -LiteralPath $rgxtv -PathType Leaf)) {
    [Console]::Error.WriteLine("no rgx-tv at $rgxtv; build it first: cargo build --release")
    exit 2
}
if (-not (Test-Path -LiteralPath $rgx -PathType Leaf)) {
    [Console]::Error.WriteLine("no rgx at $rgx; build it first: cargo build --release")
    exit 2
}
if (-not (Test-Path -LiteralPath $Corpus -PathType Container)) {
    [Console]::Error.WriteLine("no corpus at $Corpus")
    exit 2
}

function Measure-Once([scriptblock]$body) {
    $t = [System.Diagnostics.Stopwatch]::StartNew()
    & $body | Out-Null
    $t.Stop()
    return $t.Elapsed.TotalMilliseconds
}

function Median([double[]]$v) {
    $s = $v | Sort-Object
    $n = $s.Count
    if ($n % 2 -eq 1) { return [double]$s[[int](($n - 1) / 2)] }
    return ([double]$s[$n / 2 - 1] + [double]$s[$n / 2]) / 2
}

Write-Host "corpus:  $Corpus"
Write-Host "store:   $Store"
Write-Host "threads: default (identical both arms)"

# 0. The store, once.
& $rgxtv build $Corpus --store $Store | Out-Null
if ($LASTEXITCODE -ne 0) { throw "rgx-tv build failed" }

# 1. The spawn floor: the binary's own startup without a query, five times.
#    Direct invocation -- Start-Process measures window creation, not spawn --
#    and no stderr redirect: a redirect makes Windows PowerShell turn the
#    help text into a terminating NativeCommandError.
$floorSamples = @()
for ($i = 0; $i -lt 5; $i++) {
    $floorSamples += Measure-Once { & $rgxtv --help | Out-Null }
}
$floor = Median $floorSamples
Write-Host ("floor:   {0:N2} ms (median of 5 runs of --help)" -f $floor)

foreach ($pat in $PatternList) {
    # 2. The count gate, before any timing: arm A and arm B must agree on the
    #    total, and the total must equal the direct path's per-file sum.
    Set-Item "Env:$AblateVar" "1"
    $countA = (& $rgxtv search $pat --store $Store -c | Out-String).Trim()
    Remove-Item "Env:$AblateVar" -ErrorAction SilentlyContinue
    $countB = (& $rgxtv search $pat --store $Store -c | Out-String).Trim()
    $totalA = [int]($countA.Split(":")[-1])
    $totalB = [int]($countB.Split(":")[-1])
    $totalD = 0
    foreach ($line in ((& $rgx --engine rgx -F -c $pat $Corpus) | ForEach-Object { $_ })) {
        if ($line -match ':(\d+)$') { $totalD += [int]$Matches[1] }
    }
    if ($totalA -ne $totalB -or $totalA -eq 0) {
        Write-Host "pattern '$pat': COUNT GATE FAILED (arms disagree or zero) -- no timing printed"
        continue
    }
    if ($totalA -ne $totalD) {
        Write-Host "pattern '$pat': COUNT GATE FAILED (pack $totalA != direct $totalD) -- no timing printed"
        continue
    }
    Write-Host "pattern '$pat': count gate agrees (pack A == pack B == direct = $totalA)"

    # 3. Seven rounds, order rotated: A,B then B,A.
    $samplesA = @()
    $samplesB = @()
    for ($r = 0; $r -lt $Rounds; $r++) {
        $order = if ($r % 2 -eq 0) { @("A", "B") } else { @("B", "A") }
        foreach ($arm in $order) {
            if ($arm -eq "A") {
                Set-Item "Env:$AblateVar" "1"
                $samplesA += Measure-Once { & $rgxtv search $pat --store $Store -c | Out-Null }
                Remove-Item "Env:$AblateVar" -ErrorAction SilentlyContinue
            } else {
                $samplesB += Measure-Once { & $rgxtv search $pat --store $Store -c | Out-Null }
            }
        }
    }

    $minA = ($samplesA | Measure-Object -Minimum).Minimum
    $minB = ($samplesB | Measure-Object -Minimum).Minimum
    $medA = Median $samplesA
    $medB = Median $samplesB
    $adjA = $medA - $floor
    $adjB = $medB - $floor

    Write-Host ("pattern '{0}' after {1} rounds:" -f $pat, $Rounds)
    Write-Host ("  ablated : min {0,8:N2} ms  median {1,8:N2} ms  (median-floor {2,8:N2})" -f $minA, $medA, $adjA)
    Write-Host ("  sparse  : min {0,8:N2} ms  median {1,8:N2} ms  (median-floor {2,8:N2})" -f $minB, $medB, $adjB)
    if ($adjA -le 0 -or $adjB -le 0) {
        Write-Host "  verdict: under the floor -- not a result"
        continue
    }
    $ratio = $adjA / $adjB
    $overlap = -not (($maxA = ($samplesA | Measure-Object -Maximum).Maximum) -lt ($samplesB | Measure-Object -Minimum).Minimum -or ($samplesB | Measure-Object -Maximum).Maximum -lt ($samplesA | Measure-Object -Minimum).Minimum)
    $insideFloor = [math]::Abs($ratio - 1.0) -le 0.03
    if ($overlap) {
        Write-Host ("  verdict: overlap, not a result (floor-subtracted ratio {0:N2}x)" -f $ratio)
    } elseif ($insideFloor) {
        Write-Host "  verdict: tie inside the +-3% floor"
    } elseif ($ratio -gt 1) {
        Write-Host ("  verdict: sparse wins, {0:N2}x floor-subtracted" -f $ratio)
    } else {
        Write-Host ("  verdict: ablated wins, {0:N2}x floor-subtracted" -f (1 / $ratio))
    }
}

Write-Host "done. store kept at $Store"
