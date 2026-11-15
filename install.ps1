#Requires -Version 5.1
<#
.SYNOPSIS
    Install rgx on Windows.

.DESCRIPTION
    Downloads the rgx release zip (x86_64 generic, v2, avx2, v4 or znver4),
    verifies its SHA256, unpacks rgx.exe into the install directory and
    prepends it to the user PATH.

.EXAMPLE
    irm https://raw.githubusercontent.com/danalec/rgx/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Channel znver4
    .\install.ps1 -Channel avx2
    .\install.ps1 -Channel v2
    .\install.ps1 -Channel v4
#>
[CmdletBinding()]
param(
    # generic x86-64 build, or one of the four instruction-set tuned ones:
    # v2 (x86-64-v2), avx2 (x86-64-v3), v4 (x86-64-v4), znver4 (AMD Zen 4)
    [ValidateSet('x64', 'v2', 'avx2', 'v4', 'znver4')]
    [string]$Channel = 'x64',

    # install destination; default %LOCALAPPDATA%\Programs\rgx
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\rgx",

    # override the download base (mirror/self-hosted Forgejo)
    [string]$BaseUrl = 'https://github.com/danalec/rgx/releases/download',

    # pin the version instead of asking the server for the latest rgx-*
    [string]$Version = 'rgx-v0.1.11',

    # skip SHA256 verification (not recommended)
    [switch]$SkipChecksum
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$asset = switch ($Channel) {
    'x64'    { "$Version-x86_64-windows.zip" }
    'v2'     { "$Version-v2-windows.zip" }
    'avx2'   { "$Version-avx2-windows.zip" }
    'v4'     { "$Version-v4-windows.zip" }
    'znver4' { "$Version-znver4-windows.zip" }
}
$expected = switch ($Channel) {
    'x64'    { '819BE9704DDA79B6060B80A5020EDC8C73A29E9BA5A60FF716BBFB5B8FF55F92' }
    'v2'     { 'A5625921EBF7E6E9B48C44D85EE4407D50E65DFD90CD8F3A28E97C75E4E36702' }
    'avx2'   { 'C595B08E7A6FEAA3A309562BA7BE4A056CB4F89C85F76DA898C3347EFBF19A63' }
    'v4'     { 'F052262FAF4AC411ECD91B88B3FC59928CEA4925F244778D1092C750885BB07F' }
    'znver4' { '2FBCF71EFCD1B86C37A8D6235F2F6F118C557A227F87FD8B2040EDBFADEAD969' }
}

$url = "$BaseUrl/$Version/$asset"
$tmp = Join-Path $env:TEMP "rgx-install-$asset"

Write-Host "Downloading $url ..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing

if (-not $SkipChecksum) {
    $actual = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash
    if ($actual -ne $expected) {
        Remove-Item $tmp -Force
        throw "SHA256 mismatch for $asset`n expected $expected`n got      $actual"
    }
    Write-Host "SHA256 verified." -ForegroundColor Green
}

$staging = Join-Path $env:TEMP "rgx-staging-$(Get-Random)"
Expand-Archive -Path $tmp -DestinationPath $staging -Force

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $staging 'rgx.exe') -Destination $InstallDir -Force
Copy-Item -Path (Join-Path $staging 'README.md') -Destination $InstallDir -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $staging 'COPYING') -Destination $InstallDir -Force -ErrorAction SilentlyContinue

Remove-Item $tmp -Force
Remove-Item $staging -Recurse -Force

# user PATH (idempotent prepend)
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', "$InstallDir;$userPath", 'User')
    Write-Host "Added $InstallDir to user PATH (open a new terminal to pick it up)." -ForegroundColor Yellow
}

$installed = & (Join-Path $InstallDir 'rgx.exe') --version
Write-Host "Installed: $installed -> $InstallDir" -ForegroundColor Green
