# publish-cratesio.ps1 -- publish every package of the workspace to crates.io,
# in the order the dependency graph asks for.
#
#   powershell -File scripts/publish-cratesio.ps1              # dry-run
#   powershell -File scripts/publish-cratesio.ps1 -Publish     # do it
#
# The order is the graph: a crate can only be uploaded once the crates it
# depends on are on the registry, because the registry resolves the
# dependency by name and version. `rgx-core` and `rar-codec` stand alone;
# the adapters stand on `rgx-core`; `rgx-adapters-docs` stands on two
# adapters; the root package stands on all of them.
#
# The registry name of the root package is `rgx-search` -- `rgx` is taken on
# crates.io by an unrelated project -- and the binary it installs is `rgx`.
#
# crates.io publishes an index entry within a minute or two of the upload,
# so each package is retried for a while: the first attempt of the next
# package can arrive before the registry can see the previous one. It also
# limits how many NEW crates an account may publish in a short period, and
# answers a 429 with the time the window opens again -- which is why the
# wait between attempts is longer than that window on purpose.
param(
    [switch]$Publish,
    [switch]$AllowExisting,
    [int]$Attempts = 20,
    [int]$WaitSeconds = 300
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$Version = (Select-String -Path Cargo.toml -Pattern '^version = "([^"]+)"' |
    Select-Object -First 1).Matches.Groups[1].Value

# The order the graph asks for.
$Order = @(
    "rgx-core",
    "rar-codec",
    "rgx-adapters-archive",
    "rgx-adapters-inspect",
    "rgx-adapters-llm",
    "rgx-adapters-mail",
    "rgx-adapters-media",
    "rgx-adapters-office",
    "rgx-adapters-pdf",
    "rgx-adapters-tabular",
    "rgx-adapters-threed",
    "rgx-adapters-docs",
    "rgx-search"
)

function Test-Published([string]$pkg, [string]$version) {
    # The registry answers with the versions a crate has; the one this
    # workspace wants is there when the package is already up. A run that
    # was interrupted by the rate limit picks up where it stopped.
    try {
        $r = Invoke-RestMethod -Uri "https://crates.io/api/v1/crates/$pkg/versions" `
            -TimeoutSec 20 -Headers @{ "User-Agent" = "rgx-publish" }
        return @($r.versions | Where-Object { $_.num -eq $version }).Count -gt 0
    } catch {
        return $false
    }
}

Write-Host ">> rgx $Version -> crates.io, $($Order.Count) packages"

foreach ($pkg in $Order) {
    if (Test-Published $pkg $Version) {
        if ($AllowExisting) {
            Write-Host ">> $pkg $Version is already on crates.io, skipping"
            continue
        }
        Write-Host ">> $pkg $Version is already on crates.io."
        Write-Host ">> A published version cannot be edited: to publish this one with"
        Write-Host ">> the current licence and author, delete it on crates.io first."
        Write-Host ">> crates.io allows a version to be deleted within 72 hours of the"
        Write-Host ">> upload, and then holds the NAME for 24 hours before it can be"
        Write-Host ">> used again."
        exit 1
    }
    if (-not $Publish) {
        Write-Host "[dry-run] cargo publish -p $pkg --locked"
        continue
    }
    Write-Host ">> publishing $pkg"
    $done = $false
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        & cargo publish -p $pkg --locked
        if ($LASTEXITCODE -eq 0) { $done = $true; break }
        Write-Host ">> $pkg not accepted yet (attempt $attempt/$Attempts); the registry may not see the package it depends on yet"
        Start-Sleep -Seconds $WaitSeconds
    }
    if (-not $done) {
        throw "$pkg could not be published after $Attempts attempts"
    }
}

if ($Publish) {
    Write-Host ">> every package is on crates.io"
} else {
    Write-Host ">> dry run: nothing was published"
}
