# gate-and-count.ps1 -- the workspace gate, and the test count of THIS tree.
#
# The count belongs in the commit that is about to be made, so it has to be
# measured on the tree the commit carries, and not on the tree the other
# blocks will add later. The caller stashes the later blocks' files before
# calling this, and pops the stash after.
#
# The three steps are the ones the project gates on: `cargo fmt --check`,
# `cargo clippy` with the warnings as errors, and `cargo test` over the
# whole workspace with `--no-fail-fast`, so a failure in one suite does not
# hide the others.
#
# The line that starts with `COUNT:` is what the caller reads: the number of
# tests that passed, the number that failed, the number ignored, and the
# number of test binaries. The logs are in target/gate/.
#
# The Windows counterpart of scripts/gate-and-count.sh.
#
# Usage:
#   powershell -File scripts/gate-and-count.ps1
#   powershell -File scripts/gate-and-count.ps1 -SkipTests
param(
    [switch]$SkipTests
)

$ErrorActionPreference = 'Continue'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$out = Join-Path $repo 'target/gate'
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Output '=== fmt ==='
cargo fmt --manifest-path "$repo/Cargo.toml" --all -- --check > "$out/fmt.log" 2>&1
$fmtExit = $LASTEXITCODE
Get-Content "$out/fmt.log" -Tail 4
Write-Output "fmt exit=$fmtExit"

Write-Output '=== clippy ==='
cargo clippy --manifest-path "$repo/Cargo.toml" --release --locked --workspace --all-targets -- -D warnings > "$out/clippy.log" 2>&1
$clippyExit = $LASTEXITCODE
Write-Output "clippy exit=$clippyExit"
if ($clippyExit -ne 0) { Get-Content "$out/clippy.log" -Tail 20 }

if ($SkipTests) {
    if ($fmtExit -gt $clippyExit) { exit $fmtExit }
    exit $clippyExit
}

Write-Output '=== test ==='
cargo test --manifest-path "$repo/Cargo.toml" --release --locked --workspace --no-fail-fast > "$out/test.log" 2>&1
$testExit = $LASTEXITCODE
$log = Get-Content "$out/test.log"
$sum = $log | Select-String -Pattern '^test result:'
$passed = 0; $failed = 0; $ignored = 0
foreach ($l in $sum) {
    if ($l.Line -match '(\d+) passed; (\d+) failed; (\d+) ignored') {
        $passed += [int]$Matches[1]; $failed += [int]$Matches[2]; $ignored += [int]$Matches[3]
    }
}
Write-Output "test exit=$testExit"
Write-Output "COUNT: passed=$passed failed=$failed ignored=$ignored suites=$($sum.Count)"
if ($failed -gt 0) { $log | Select-String -Pattern '^(failures:|test .* FAILED)' | Select-Object -First 10 }

if ($fmtExit -gt $clippyExit) { exit $fmtExit }
if ($clippyExit -gt $testExit) { exit $clippyExit }
exit $testExit
