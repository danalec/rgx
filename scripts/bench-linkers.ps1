# A/B/C: rgx link.exe-generic vs lld-generic vs lld-znver4
# Interleaved rounds, per-process timing, median.
#
# The arms are named by the target directory they live in, resolved from the
# repository: a fixed absolute path would encode one person's home
# directory, and it would measure whatever was left there from last time.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here '..')).Path
$variants = @(
    @{ name = "link-generic"; exe = Join-Path $repo 'target/release/rgx.exe' },
    @{ name = "lld-generic";  exe = Join-Path $repo 'target/bench-lld/release/rgx.exe' },
    @{ name = "lld-znver4";   exe = Join-Path $repo 'target/bench-lld-znver4/release/rgx.exe' }
)
$scenarios = @(
    @{ name = "corpus";     args = @("-c", "ZIRCALOY", "$env:USERPROFILE\.rgx-bench") },
    @{ name = "big-literal"; args = @("-c", "ZIRCALOY", "$env:USERPROFILE\.rgx-big\big.txt") },
    @{ name = "big-regex";  args = @("-c", "line [0-9]+ filler", "$env:USERPROFILE\.rgx-big\big.txt") }
)
$rounds = 9
foreach ($sc in $scenarios) {
    $times = @{}
    foreach ($v in $variants) { $times[$v.name] = @() }
    # warmup each once
    foreach ($v in $variants) { & $v.exe @($sc.args) | Out-Null }
    for ($r = 0; $r -lt $rounds; $r++) {
        foreach ($v in $variants) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & $v.exe @($sc.args) | Out-Null
            $sw.Stop()
            $times[$v.name] += $sw.Elapsed.TotalMilliseconds
        }
    }
    Write-Host ("{0}:" -f $sc.name)
    $base = $null
    foreach ($v in $variants) {
        $sorted = $times[$v.name] | Sort-Object
        $med = $sorted[[int]($sorted.Count / 2)]
        if ($null -eq $base) { $base = $med }
        Write-Host ("  {0,-13} median {1,8:N1} ms   (min {2,8:N1})   x{3:N3}" -f $v.name, $med, ($sorted | Select-Object -First 1), ($base / $med))
    }
}
