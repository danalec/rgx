#Requires -Version 5.1
<#
.SYNOPSIS
    Install rgx on Windows.

.DESCRIPTION
    Downloads the rgx release zip (x86_64 generic or znver4), verifies its
    SHA256, unpacks rgx.exe into the install directory and prepends it to
    the user PATH.

.EXAMPLE
    irm https://raw.githubusercontent.com/danalec/rgx/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Channel znver4
#>
[CmdletBinding()]
param(
    # generic x86-64 build, or znver4 (AMD Zen 4 tuned)
    [ValidateSet('x64', 'znver4')]
    [string]$Channel = 'x64',

    # install destination; default %LOCALAPPDATA%\Programs\rgx
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\rgx",

    # override the download base (mirror/self-hosted Forgejo)
    [string]$BaseUrl = 'https://github.com/danalec/rgx/releases/download',

    # pin the version instead of asking the server for the latest rgx-*
    [string]$Version = 'rgx-v0.1.10',

    # skip SHA256 verification (not recommended)
    [switch]$SkipChecksum
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$asset = switch ($Channel) {
    'x64'    { "$Version-x86_64-windows.zip" }
    'znver4' { "$Version-znver4-windows.zip" }
}
$expected = switch ($Channel) {
    'x64'    { 'DC6DB9D47766811179F749191C9BBDF31C95254CBAB981A09F4FF504D2B5EAFC' }
    'znver4' { 'D2178792BAB721E1867C26E2B8C5984EFD2FC0EE1B4D44A96D594C8CF5FF1FD5' }
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
