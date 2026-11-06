# Publish an rgx release end to end:
#
#   powershell -File scripts/publish-release.ps1              # full pipeline
#   powershell -File scripts/publish-release.ps1 -SkipTests   # trust the build
#   powershell -File scripts/publish-release.ps1 -DryRun      # show, don't touch
#
# Pipeline: build both zips -> tag rgx-v<version> + push -> create/update the
# forgejo release and (re)upload assets -> refresh the winget manifests
# (version, sha256, date, URLs) -> winget validate -> optional -Commit of the
# manifest changes. The forgejo API uses the same stored git credentials
# (`git credential fill`); no tokens live in this script.
#
# Version comes from Cargo.toml unless -Version is given. Winget ships the
# generic build only; the znver4 zip rides the release page.
param(
    [string]$Version = "",
    [switch]$SkipTests,
    [switch]$Commit,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if (-not $Version) {
    $Version = (Select-String -Path Cargo.toml -Pattern '^version = "([^"]+)"' |
        Select-Object -First 1).Matches.Groups[1].Value
}
$tag = "rgx-v$Version"
# The forgejo is the development upstream, and where it lives is the
# operator's business: the address of a private box is not a fact about the
# project. It comes from the environment, and the values below are only the
# defaults the owner runs with.
$forgejoUrl = if ($env:RGX_FORGEJO_URL) { $env:RGX_FORGEJO_URL } else { 'http://192.168.0.10:3000' }
$forgejoRepo = if ($env:RGX_FORGEJO_REPO) { $env:RGX_FORGEJO_REPO } else { 'danalec/rgx' }
$repoApi = "$forgejoUrl/api/v1/repos/$forgejoRepo"
$forgejo = "$forgejoUrl/$forgejoRepo"
# The host and the port the credentials are stored under, taken from the URL.
$forgejoHost = ($forgejoUrl -replace '^[a-zA-Z]*://', '' -replace '/.*$', '')

# --- 1. build --------------------------------------------------------------
& (Join-Path $PSScriptRoot "build-release.ps1") -Version $Version -SkipTests:$SkipTests
if ($LASTEXITCODE -ne 0) { throw "build failed" }

# The artifacts are in .dist/, the directory build-release.ps1 writes to
# and the one .gitignore lists -- not in dist/, which nothing creates and
# which nothing ignores.
$zipGeneric = Get-Item ".dist\$tag-x86_64-windows.zip"
$zipZnver4  = Get-Item ".dist\$tag-znver4-windows.zip"

# --- 2. tag + push ---------------------------------------------------------
$existingTag = git tag -l $tag
if (-not $existingTag) {
    if ($DryRun) { Write-Host "[dry-run] git tag $tag; git push forgejo $tag" }
    else {
        git tag $tag
        git push forgejo $tag
    }
} else {
    Write-Host "tag $tag already exists"
}

# --- 3. forgejo release + assets -------------------------------------------
$credLines = "protocol=http`nhost=$forgejoHost`n`n" | git credential fill
$user = ($credLines | Where-Object { $_ -like "username=*" }) -replace "username=", ""
$pass = ($credLines | Where-Object { $_ -like "password=*" }) -replace "password=", ""
if (-not $user -or -not $pass) { throw "no git credentials for the forgejo" }
$auth = @{ Authorization = "Basic " + [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes("${user}:${pass}")) }

$release = $null
try {
    $release = Invoke-RestMethod -Headers $auth "$repoApi/releases/tags/$tag"
    Write-Host "release exists: $($release.html_url)"
} catch {
    Write-Host "release $tag does not exist yet"
}

$body = @"
Search inside everything — PDFs, Office documents, archives, 3D models, LLM checkpoints, databases, e-mail. Ripgrep-compatible, adapters in-process.

**Windows builds** (portable zip: rgx.exe + README + licenses):
- ``$tag-x86_64-windows.zip`` — generic x86-64
- ``$tag-znver4-windows.zip`` — tuned for AMD Zen 4 (znver4)

Feature-parity with the rga adapter set: archives (zip/7z/tar/cpio/decompress),
3D models, LLM model files, media metadata, SQLite/DBF/SHP/Parquet, e-mail,
external tools (ffmpeg/ffprobe, tesseract, soffice).

Apache-2.0.
"@

if ($DryRun) {
    Write-Host "[dry-run] create/patch release $tag and upload $($zipGeneric.Name), $($zipZnver4.Name)"
} else {
    if (-not $release) {
        $release = Invoke-RestMethod -Headers $auth -Method Post "$repoApi/releases" `
            -ContentType "application/json" -Body ([Text.Encoding]::UTF8.GetBytes(
                (@{ tag_name = $tag; name = "rgx v$Version"; body = $body } |
                    ConvertTo-Json -Compress)))
    } elseif ($release.body -ne $body) {
        $release = Invoke-RestMethod -Headers $auth -Method Patch "$repoApi/releases/$($release.id)" `
            -ContentType "application/json" -Body ([Text.Encoding]::UTF8.GetBytes(
                (@{ name = "rgx v$Version"; body = $body } | ConvertTo-Json -Compress)))
    }

    foreach ($zip in @($zipGeneric, $zipZnver4)) {
        $stale = $release.assets | Where-Object { $_.name -eq $zip.Name }
        if ($stale) {
            Invoke-RestMethod -Headers $auth -Method Delete "$repoApi/releases/$($release.id)/assets/$($stale.id)" | Out-Null
            Write-Host "replaced asset: $($zip.Name)"
        }
        Invoke-RestMethod -Headers $auth -Method Post "$($release.upload_url)?name=$($zip.Name)" `
            -ContentType "application/octet-stream" -Body ([IO.File]::ReadAllBytes($zip.FullName)) | Out-Null
        Write-Host "uploaded: $($zip.Name) ($([math]::Round($zip.Length / 1MB, 2)) MB)"
    }
}

# --- 4. winget manifests ----------------------------------------------------
$sha = (Get-FileHash $zipGeneric -Algorithm SHA256).Hash
$today = Get-Date -Format "yyyy-MM-dd"
$wingetDir = Join-Path $root ".winget"

function Set-Yaml([string]$file, [hashtable]$repl) {
    $text = Get-Content $file -Raw
    foreach ($k in $repl.Keys) {
        $text = $text -replace $k, $repl[$k]
    }
    Set-Content $file $text -NoNewline
}

if ($DryRun) {
    Write-Host "[dry-run] winget manifests -> version $Version, sha256 $sha, date $today"
} else {
    Set-Yaml (Join-Path $wingetDir "danalec.rgx.installer.yaml") @{
        "PackageVersion: .*"    = "PackageVersion: $Version"
        "ReleaseDate: .*"       = "ReleaseDate: $today"
        "InstallerUrl: .*"      = "InstallerUrl: $forgejo/releases/download/$tag/$($zipGeneric.Name)"
        "InstallerSha256: .*"   = "InstallerSha256: $sha"
    }
    Set-Yaml (Join-Path $wingetDir "danalec.rgx.yaml") @{
        "PackageVersion: .*"    = "PackageVersion: $Version"
    }
    Set-Yaml (Join-Path $wingetDir "danalec.rgx.locale.en-US.yaml") @{
        "PackageVersion: .*"    = "PackageVersion: $Version"
        "ReleaseNotesUrl: .*"   = "ReleaseNotesUrl: $forgejo/releases/tag/$tag"
    }
    Write-Host "manifests updated: version $Version, sha256 $sha, date $today"
}

# --- 5. winget validate -----------------------------------------------------
$winget = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\winget.exe"
if (Test-Path $winget) {
    if ($DryRun) { Write-Host "[dry-run] winget validate --manifest $wingetDir" }
    else {
        & $winget validate --manifest $wingetDir
        if ($LASTEXITCODE -ne 0) { throw "winget validate failed" }
        Write-Host "winget validate: ok"
    }
} else {
    Write-Host "winget.exe not found, skipping validation"
}

# --- 6. commit --------------------------------------------------------------
if ($Commit -and -not $DryRun) {
    git add .winget
    git commit -m "release: $tag winget manifests"
    $branch = git rev-parse --abbrev-ref HEAD
    git push forgejo $branch
    Write-Host "manifests committed and pushed"
}

Write-Host ""
Write-Host "published $tag : $forgejo/releases/tag/$tag"
