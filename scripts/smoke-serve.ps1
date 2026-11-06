# smoke-serve.ps1 -- ask the --serve mode the same question two ways.
#
# The Windows counterpart of scripts/smoke-serve.sh.
#
# `--serve` reads one JSON argv-array per line on stdin and answers each
# one, framed by begin/end sentinels. The two queries here are the same
# search asked two ways: once plainly, once with `-c`. Both are pointed at
# the same directory, so the two answers have to agree -- a serve-mode
# query that answers a different count than the same search on the command
# line is the bug this catches.
#
# The binary is resolved from the repository, so this works from any cwd
# and does not encode one person's home directory.
#
# Usage:
#   powershell -File scripts/smoke-serve.ps1 <dir>
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here '..')).Path
$rgx = Join-Path $repo 'target/release/rgx.exe'

$dir = $args[0]
if (-not $dir) { Write-Error 'usage: powershell -File scripts/smoke-serve.ps1 <dir>'; exit 2 }
if (-not (Test-Path $rgx)) {
    Write-Error "no rgx binary at $rgx; build it first: cargo build --release"
    exit 2
}

$queries = @(
    (@('needle', $dir) | ConvertTo-Json -Compress),
    (@('-c', 'needle', $dir) | ConvertTo-Json -Compress)
) -join "`n"

$queries | & $rgx --serve
exit $LASTEXITCODE
