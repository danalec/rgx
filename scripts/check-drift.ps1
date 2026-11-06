<#
.SYNOPSIS
    Report vendored code that has fallen behind its upstream source.

.DESCRIPTION
    scripts/check-vendoring.ps1 enforces the *shape* of the vendoring rule:
    no [patch] redirect, a provenance header on each vendored tree. None
    of that can notice that a file was copied on Monday and that the
    upstream changed it on Tuesday.

    This asks the other half: for each file in scripts/vendored-sources.tsv,
    has the upstream changed the recorded source since the recorded pin?
    The comparison is upstream-against-upstream -- `git log <pin>..HEAD -- <source>` --
    so copy-time rewrites (alloc:: to std::, testdata paths, narrowed
    imports) never enter into it and there is nothing to normalise. What
    comes back is a list of commits the copy has not seen, by name.

    A row pinned with `-` is counted as a failure. A manifest that quietly
    leaves a file out, or pins it to a guess, is worse than one that says
    it has not looked: the first one reads as "nothing to do here".

.PARAMETER Upstream
    Path to a git checkout of the upstream source. Required. It is a
    local, read-only input -- passing it does not make rgx depend on the
    upstream, and nothing in any manifest changes.

.PARAMETER Pin
    Re-pin one row to the upstream commit its content best matches, chosen
    mechanically. Requires -Upstream. Use this instead of writing a hash by
    hand; a hand-picked pin is a check that passes over drift.

.PARAMETER For
    The rgx path of a single row to re-pin. Only meaningful with -Pin.

.EXAMPLE
    powershell -File scripts/check-drift.ps1 -Upstream ~/memchr
    Lists, per vendored file, the upstream commits it has not seen.

    Run from anywhere; the script re-roots itself from $PSScriptRoot.
    Exits 1 on any drift or any unpinned row, 0 otherwise.
#>

param(
    [string]$Upstream = "",
    [switch]$Pin,
    [string]$For = ""
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$manifestPath = Join-Path $PSScriptRoot 'vendored-sources.tsv'
if (-not (Test-Path $manifestPath)) {
    Write-Host "no manifest at $manifestPath" -ForegroundColor Red
    exit 1
}

if (-not $Upstream) {
    Write-Host "no -Upstream path given; this check needs a local upstream checkout to ask" -ForegroundColor Red
    Write-Host "  example: powershell -File scripts/check-drift.ps1 -Upstream ~/memchr" -ForegroundColor Red
    exit 1
}
$Upstream = (Resolve-Path -LiteralPath $Upstream).Path
if (-not (Test-Path (Join-Path $Upstream '.git'))) {
    Write-Host "$Upstream is not a git checkout" -ForegroundColor Red
    exit 1
}

# The rows are the manifest minus comments and blank lines. Field 3 is the
# pin; '-' means nobody has established one.
$rows = @()
foreach ($line in Get-Content -LiteralPath $manifestPath) {
    if ($line.Trim() -eq '' -or $line.StartsWith('#')) { continue }
    $f = $line -split "`t"
    if ($f.Count -lt 2) { continue }
    $note = ''
    if ($f.Count -ge 4) { $note = $f[3] }
    $rows += [pscustomobject]@{
        Rgx     = $f[0].Trim()
        Source  = $f[1].Trim()
        Commit  = $(if ($f.Count -ge 3) { $f[2].Trim() } else { '-' })
        Note    = $note
    }
}

# A pin that does not resolve reads as "zero commits behind" -- `git log`
# fails, the error is swallowed, and the row goes green having been checked
# against nothing. Resolve the commit first and say so when it is not real.
function Test-UpstreamCommit([string]$commit) {
    & git -C $Upstream rev-parse --verify -q "$commit^{commit}" *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-UpstreamLog([string]$commit, [string]$source) {
    $out = & git -C $Upstream log --oneline "$commit..HEAD" -- $source 2>$null
    if ($LASTEXITCODE -ne 0) { return @() }
    return @($out | Where-Object { $_.Trim() -ne '' })
}

# The upstream commit whose blob is closest to this rgx file.
#
# Closest, not identical: the copies are edited at copy time, so an exact
# match is not available and an exact-match requirement would pin nothing.
# Get-Content normalises line endings on both sides, so a CRLF checkout
# does not read as a thousand-line difference. Reads committed state only,
# so a dirty working tree -- which is the normal case here -- cannot
# move the answer.
function Find-BestCommit([string]$rgxPath, [string]$source) {
    $target = Join-Path $repoRoot $rgxPath
    if (-not (Test-Path $target)) { return $null }
    $mine = @(Get-Content -LiteralPath $target)

    $best = $null
    $bestScore = [int]::MaxValue
    $commits = & git -C $Upstream log --format=%H -- $source 2>$null
    foreach ($c in $commits) {
        $blob = @(& git -C $Upstream show "${c}:$source" 2>$null)
        if ($LASTEXITCODE -ne 0 -or $blob.Count -eq 0) { continue }
        $score = @(Compare-Object -ReferenceObject $mine -DifferenceObject $blob).Count
        if ($score -lt $bestScore) { $bestScore = $score; $best = $c.Substring(0, 7) }
    }
    if ($null -eq $best) { return $null }
    return [pscustomobject]@{ Commit = $best; Score = $bestScore }
}

# How far a copy may sit from an upstream commit and still be pinned by matching.
#
# Some vendored files are deliberately reduced ports -- a decoder with no
# encoder, a couple of functions out of a larger module. For those, "the
# commit whose blob is closest" is still a perfectly good match to the
# wrong question, and it will hand back the commit that created the file
# with a confident number attached. A tool that is confidently wrong about
# the one file you just fixed is worse than one that declines.
#
# Past this many differing lines, refuse and say so. Those rows get pinned
# by hand with a reason in the note column.
$script:MaxPinDistance = 150

Write-Host "checking vendored drift against upstream at $Upstream" -ForegroundColor Cyan

# --- re-pin one row -------------------------------------------------------
if ($Pin) {
    if (-not $For) { Write-Host "-Pin needs -For <rgx path>" -ForegroundColor Red; exit 1 }
    $row = $rows | Where-Object { $_.Rgx -eq $For }
    if ($null -eq $row) { Write-Host "no manifest row for $For" -ForegroundColor Red; exit 1 }
    $best = Find-BestCommit $row.Rgx $row.Source
    if ($null -eq $best) { Write-Host "could not match $For against any upstream commit" -ForegroundColor Red; exit 1 }
    if ($best.Score -gt $MaxPinDistance) {
        Write-Host "  $For is $($best.Score) lines from the closest upstream commit ($($best.Commit))" -ForegroundColor Yellow
        Write-Host "  that is a reduced port, not a copy: matching cannot say which commit it came from." -ForegroundColor Yellow
        Write-Host "  pin it by hand and put the reason in the note column." -ForegroundColor Yellow
        exit 1
    }
    $behind = Get-UpstreamLog $best.Commit $row.Source
    Write-Host "  $For matches upstream $($best.Commit) ($($best.Score) differing lines)"
    if ($behind.Count -gt 0) {
        Write-Host "  and is behind $($behind.Count) upstream commit(s):" -ForegroundColor Yellow
        foreach ($l in $behind) { Write-Host "    $l" -ForegroundColor Yellow }
    } else {
        Write-Host "  and is up to date with that source" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "pin it with:" -ForegroundColor Cyan
    Write-Host "  $For`t$($row.Source)`t$($best.Commit)" -ForegroundColor Cyan
    exit 0
}

# --- the check ------------------------------------------------------------
$drifted = New-Object System.Collections.Generic.List[string]
$unpinned = New-Object System.Collections.Generic.List[string]
$checked = 0

Write-Host "`n[1/1] vendored files against their upstream source" -ForegroundColor Cyan
foreach ($r in $rows) {
    if (-not (Test-Path (Join-Path $repoRoot $r.Rgx))) {
        Write-Host "  FAIL: $($r.Rgx): listed in the manifest but not in the tree" -ForegroundColor Red
        $drifted.Add("$($r.Rgx): missing from the tree")
        continue
    }
    if ($r.Commit -eq '-' -or $r.Commit -eq '') {
        $unpinned.Add($r.Rgx)
        continue
    }
    if (-not (Test-UpstreamCommit $r.Commit)) {
        $drifted.Add("$($r.Rgx): pin $($r.Commit) does not resolve in upstream")
        Write-Host "  FAIL: $($r.Rgx): pin $($r.Commit) is not an upstream commit" -ForegroundColor Red
        continue
    }
    $checked++
    $behind = Get-UpstreamLog $r.Commit $r.Source
    if ($behind.Count -gt 0) {
        $drifted.Add("$($r.Rgx) (pinned $($r.Commit), $($behind.Count) upstream commit(s) behind)")
        Write-Host "  FAIL: $($r.Rgx) is behind $($r.Source) since $($r.Commit):" -ForegroundColor Red
        foreach ($l in $behind) { Write-Host "    $l" -ForegroundColor Red }
    }
}

if ($unpinned.Count -gt 0) {
    Write-Host "  $($unpinned.Count) row(s) have no recorded sync point:" -ForegroundColor Yellow
    foreach ($u in $unpinned) { Write-Host "    - $u" -ForegroundColor Yellow }
    Write-Host "    pin one with: -Pin -For <path>" -ForegroundColor Yellow
}

Write-Host ""
if ($unpinned.Count -gt 0 -or $drifted.Count -gt 0) {
    $n = $drifted.Count + $unpinned.Count
    Write-Host "vendored drift: $n outstanding ($($drifted.Count) drifted, $($unpinned.Count) unpinned)" -ForegroundColor Red
    exit 1
}
Write-Host "ok: $checked vendored file(s) match the upstream source they were taken from" -ForegroundColor Green
exit 0
