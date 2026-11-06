# compare-rg.ps1 -- parity of rgx against ripgrep on a real corpus.
#
# Two things must be normalized before the two outputs can be compared, and
# both are properties of the platform rather than of either searcher:
#
#   1. the path separator. rg prints what the OS gave it (backslash on
#      Windows); rgx normalizes to '/', which MANUAL.md documents as
#      the normalization under which the file sets are identical.
#   2. the ORDER. Both tools search in parallel and neither promises an
#      order, so a corpus-wide comparison sorts before it compares.
#
# Outputs go to files and are normalized with sort.exe rather than being
# collected into PowerShell arrays: the line-output cases on a 56k-file
# corpus emit hundreds of thousands of lines, and piping them through
# PowerShell's pipeline is slower by an order of magnitude than the search
# they are checking.
#
# Usage:
#   powershell -NoProfile -File scripts/compare-rg.ps1 -Rgx target\release\rgx.exe
#   powershell -NoProfile -File scripts/compare-rg.ps1 -Corpus crates -Rgx ...
param(
    [string]$Rgx = "target\release\rgx.exe",
    [string]$Rg = "rg.exe",
    # 'registry' = the 56,232 real .rs files of the cargo registry, which is
    # the corpus benchmark/status.md calls "56k small files". 'crates' = this
    # repository's own sources, for the modes whose output is too large to
    # hold in memory on the big corpus.
    [ValidateSet("registry", "crates")]
    [string]$Corpus = "registry",
    [string]$Pattern = "pub fn",
    [string]$Ext = "*.rs",
    # Explicit corpus root. Required to compare two DIFFERENT binaries fairly:
    # a checkout's own tree differs between commits, so "run both against
    # each one's crates/" compares different file sets and proves nothing.
    [string]$Root = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot
$RgxPath = (Resolve-Path -LiteralPath $Rgx).Path
try { $RgPath = (Get-Command $Rg -CommandType Application -ErrorAction Stop).Source }
catch { if (Test-Path -LiteralPath $Rg) { $RgPath = (Resolve-Path -LiteralPath $Rg).Path } else { throw } }

if ($Root) {
    $root = (Resolve-Path -LiteralPath $Root).Path
} elseif ($Corpus -eq "registry") {
    $root = "$env:USERPROFILE\.cargo\registry\src"
    if (-not (Test-Path -LiteralPath $root)) { throw "corpus missing: $root (run 'cargo fetch')" }
} else {
    $root = "crates"
}

# Every case is a mode where the per-file line buffer is either consulted or
# provably dead, so a change to that buffer cannot pass here by accident.
# -o and -r and the default printer READ hit.lines; -c and -l do not, except
# -o -c which re-counts matches inside the buffered lines.
$cases = @(
    @{ Name = "-c (count)";          Extra = @("-c") },
    @{ Name = "-l (list)";           Extra = @("-l") },
    @{ Name = "-o -c (reads lines)"; Extra = @("-o", "-c") },
    @{ Name = "-c -m 3";             Extra = @("-c", "-m", "3") },
    @{ Name = "-l -m 2";             Extra = @("-l", "-m", "2") },
    @{ Name = "-c (no match)";       Extra = @("-c"); Pattern = "ZZZ-no-such-needle-ZZZ" },
    @{ Name = "-l (no match)";       Extra = @("-l"); Pattern = "ZZZ-no-such-needle-ZZZ" },
    @{ Name = "-q (quiet)";          Extra = @("-q") },
    @{ Name = "-c -A1 (context)";    Extra = @("-c", "-A", "1") },
    @{ Name = "default line output"; Extra = @() },
    @{ Name = "-o (reads lines)";    Extra = @("-o") },
    @{ Name = "-r X (reads lines)";  Extra = @("-r", "X") },
    # -r with capture groups, and the shape where ripgrep's `$` rule and the
    # `regex` crate's differ: `X$1X` is the group named "1X" (absent) and
    # `${1}X` is group 1.
    @{ Name = "-o -r groups";       Extra = @("-o", "-r", '[$2=$1]');  Pattern = "(\w+)\s*=\s*(\w+)" },
    @{ Name = "-o -r bare dollar";  Extra = @("-o", "-r", 'X$1X');     Pattern = "(\w+)\s*=\s*(\w+)" },
    @{ Name = "-o -r braced";       Extra = @("-o", "-r", 'X${1}Y');   Pattern = "(\w+)\s*=\s*(\w+)" },
    @{ Name = "-o -r named";        Extra = @("-o", "-r", '$2=$1');    Pattern = "(?<key>\w+)\s*=\s*(?<val>\w+)" },
    @{ Name = "--json";              Extra = @("--json") },
    @{ Name = "default -A1 -B1";     Extra = @("-A", "1", "-B", "1") },
    @{ Name = "-v (invert)";         Extra = @("-v") }
)

$tmpRg = Join-Path $env:TEMP "cmp-rg.txt"
$tmpRx = Join-Path $env:TEMP "cmp-rgx.txt"

# Read one tool's output, normalize the path separator, put it in a
# deterministic order, and digest it. Done in .NET rather than through the
# PowerShell pipeline because the line-output cases on a 56k-file corpus
# emit hundreds of thousands of lines, and Sort-Object over that is slower
# by an order of magnitude than the search it is checking.
#
# Ordinal comparison, not culture-aware: the two sides must be ordered by
# the same rule or the digests differ for reasons that have nothing to do
# with the searcher.
function Digest([string]$path) {
    $lines = [System.IO.File]::ReadAllLines($path)
    $norm = [string[]]::new($lines.Length)
    for ($i = 0; $i -lt $lines.Length; $i++) { $norm[$i] = $lines[$i].Replace('\', '/') }
    [Array]::Sort($norm, [System.StringComparer]::Ordinal)
    $joined = [string]::Join("`n", $norm)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        return [pscustomobject]@{
            Hash = [BitConverter]::ToString($sha.ComputeHash($bytes))
            Count = $lines.Length
            Lines = $norm
        }
    } finally { $sha.Dispose() }
}

$fail = 0
$rows = @()
foreach ($c in $cases) {
    $pat = if ($c.ContainsKey("Pattern")) { $c.Pattern } else { $Pattern }
    $argv = @($c.Extra) + @($pat) + @("-g", $Ext) + @($root)
    # Start-Process joins an array into a bare space-separated string, so an
    # argument carrying a wildcard or a space ('*.rs', 'ZZZ-no-such-needle')
    # would be re-parsed by the child. Quote each one, same as bench.ps1.
    $argline = (($argv | ForEach-Object { '"{0}"' -f ($_ -replace '"', '\"') }) -join ' ')

    $p1 = Start-Process -FilePath $RgPath -ArgumentList $argline -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $tmpRg -RedirectStandardError "$tmpRg.err"
    $p2 = Start-Process -FilePath $RgxPath -ArgumentList $argline -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $tmpRx -RedirectStandardError "$tmpRx.err"

    $a = Digest $tmpRg
    $b = Digest $tmpRx
    $na = $a.Count
    $nb = $b.Count
    # exit codes are the other half of rg's contract: 0 = matched, 1 = none.
    $ecOk = ($p1.ExitCode -eq $p2.ExitCode)

    if ($a.Hash -eq $b.Hash -and $ecOk) {
        Write-Host ("  OK    {0,-24} {1,9} lines  exit {2}" -f $c.Name, $na, $p1.ExitCode)
        $rows += [pscustomobject]@{ case = $c.Name; lines = $na; exit_rg = $p1.ExitCode; exit_rgx = $p2.ExitCode; verdict = "OK" }
    } else {
        $fail++
        Write-Host ("  FAIL  {0,-24} rg={1} rgx={2} exit rg={3} rgx={4}" -f $c.Name, $na, $nb, $p1.ExitCode, $p2.ExitCode) -ForegroundColor Red
        $rows += [pscustomobject]@{ case = $c.Name; lines = "$na vs $nb"; exit_rg = $p1.ExitCode; exit_rgx = $p2.ExitCode; verdict = "FAIL" }
        $d = Compare-Object $a.Lines $b.Lines | Select-Object -First 3
        foreach ($x in $d) { Write-Host ("        {0} {1}" -f $x.SideIndicator, $x.InputObject) }
    }
}

Write-Host ""
Write-Host "corpus : $Corpus ($root)"
Write-Host "rg     : $RgPath"
Write-Host "rgx    : $RgxPath"
if ($fail -eq 0) {
    Write-Host "parity : all $($cases.Count) cases byte-identical (separator-normalized, sorted), exit codes equal" -ForegroundColor Green
    exit 0
} else {
    Write-Host "parity : $fail of $($cases.Count) cases diverged" -ForegroundColor Red
    exit 1
}
