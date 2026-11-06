# check-egm-contracts.ps1 -- validate the EGM contracts of THIS tree.
#
# The Windows counterpart of scripts/check-egm-contracts.sh. Both twins are
# deliberately thin: the checks live in check-egm-contracts.py, so the pair
# cannot disagree about what a valid contract is.
#
# Usage:
#   powershell -File scripts/check-egm-contracts.ps1 [-Root DIR] [-SelfTest] [-Reindex] [-Fix]
#   powershell -File scripts/check-egm-contracts.ps1 --self-test
param(
    [string]$Root,
    [switch]$SelfTest,
    [switch]$Reindex,
    [switch]$Fix,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'check-egm-contracts.py'

$python = $null
foreach ($candidate in @('python3', 'python')) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $python = $candidate
        break
    }
}
if (-not $python) {
    [Console]::Error.WriteLine('EGM CONTRACTS: no python3 or python on PATH')
    exit 2
}

$argsList = @($script)
if ($Root) { $argsList += @('--root', $Root) }
if ($SelfTest) { $argsList += '--self-test' }
if ($Reindex) { $argsList += '--reindex' }
if ($Fix) { $argsList += '--fix' }
if ($Rest) { $argsList += $Rest }
& $python @argsList
exit $LASTEXITCODE
