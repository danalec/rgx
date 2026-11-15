# commit-block.ps1 -- commit one block, with the test count of the tree that
# commit carries.
#
# The order matters:
#   1. the block's own files are staged, and the hunks of the shared
#      documents that belong to this block;
#   2. everything else is stashed, so the tree is the one the commit will
#      carry -- the count in the commit message has to be the count of that
#      tree, not of the tree with the other blocks in it;
#   3. the gate runs on that tree;
#   4. the count goes into AGENTS.md and the workflow, and they are staged;
#   5. the stash comes back, and the commit is made.
#
# The hunks go into the index BEFORE the gate, and not after it: the tree
# the gate measures is the tree the commit carries, and a README that
# claims an extension the registry does not is a test that fails.
#
# The Windows counterpart of scripts/commit-block.sh.
#
# Usage:
#   powershell -File scripts/commit-block.ps1 -Message target/fmt/msg-b1.txt `
#       -Files crates/rgx-adapters-inspect/src/scientific.rs `
#       -Patches target/patches/ph-b1-README_md.patch `
#       -CountNote "the GRIB spectral packing landed"
#
# The paths are relative to the repository root, and the files and the
# patches are lists separated by commas.
param(
    [Parameter(Mandatory = $true)][string]$Message,
    [string]$Files = '',
    [string]$Patches = '',
    [string]$CountNote = '',
    [switch]$NoCount
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function RunGit([string[]]$a) { & git -C $repo @a }

Write-Output '=== staging the block ==='
# Each block starts from a clean index: a patch that failed to apply in an
# earlier attempt can still be sitting there.
RunGit @('reset', '-q') | Out-Null
if ($Files) { RunGit (@('add', '--') + ($Files -split ',')) | Out-Null }

Write-Output '=== the hunks of the shared documents ==='
# The hunks go into the index before the gate: the tree the gate measures is
# the tree the commit carries, and a README that claims an extension the
# registry does not is a test that fails.
if ($Patches) {
    foreach ($p in ($Patches -split ',')) {
        & git -C $repo apply --cached --unidiff-zero --whitespace=nowarn (Join-Path $repo $p)
        if ($LASTEXITCODE -ne 0) { throw "the patch $p did not apply" }
        Write-Output "  staged $p"
    }
}

Write-Output '=== stashing the other blocks ==='
RunGit @('stash', 'push', '--keep-index', '-m', 'the other blocks') | Out-Null

Write-Output '=== the gate, on the tree this commit carries ==='
$gate = & (Join-Path $PSScriptRoot 'gate-and-count.ps1') 2>&1
$gate | ForEach-Object { Write-Output $_ }
$count = ($gate | Select-String -Pattern '^COUNT: passed=(\d+) failed=(\d+) ignored=(\d+) suites=(\d+)').Line
if (-not $count) { RunGit @('stash', 'pop') | Out-Null; throw 'the gate did not print a count' }
if ($count -notmatch 'failed=0 ') { RunGit @('stash', 'pop') | Out-Null; throw "the gate is red: $count" }
$m = [regex]::Match($count, 'passed=(\d+) failed=(\d+) ignored=(\d+) suites=(\d+)')
if (-not $m.Success) { RunGit @('stash', 'pop') | Out-Null; throw "the count does not say what it should: $count" }
# the groups of the match, and not `$Matches`: that one is filled by the
# `-match` above, which has no groups of its own.
$passed = $m.Groups[1].Value
$ignored = $m.Groups[3].Value
$suites = $m.Groups[4].Value
if (-not $passed) { RunGit @('stash', 'pop') | Out-Null; throw "the count has no number of tests: $count" }

Write-Output '=== the stash comes back ==='
RunGit @('stash', 'pop') | Out-Null

if (-not $NoCount) {
    Write-Output '=== the count in the working notes and the workflow ==='
    $today = (Get-Date).ToString('yyyy-MM-dd')
    # The count and the note that says what it was taken after: the script
    # writes the note into the newest clause of the count's history and
    # leaves the older clauses alone.
    & (Join-Path $PSScriptRoot 'stamp-count.ps1') -Agents (Join-Path $repo 'AGENTS.md') `
        -Workflow (Join-Path $repo '.github/workflows/ci.yml') `
        -Passed $passed -Ignored $ignored -Date $today -Note $CountNote
    if ($LASTEXITCODE -ne 0) { throw "the count was not stamped: the notes say $LASTEXITCODE" }
    RunGit @('add', 'AGENTS.md') | Out-Null
    RunGit @('add', '.github/workflows/ci.yml') | Out-Null
}

Write-Output '=== the commit ==='
RunGit @('commit', '-F', (Join-Path $repo $Message)) | Out-Null
Write-Output "committed: $(& git -C $repo log --oneline -1)"
Write-Output "the tree of that commit: $passed passed, $ignored ignored, $suites suites"
