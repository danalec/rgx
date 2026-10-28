# publish-homebrew.ps1 -- open the homebrew-core pull request for a release.
#
#   pwsh -File scripts/publish-homebrew.ps1 [-Version 0.1.0] [-DryRun]
#
# Homebrew-core is a git repository like any other: a pull request is a
# branch, a commit and a merge. This script does the first two and opens
# the third.
#
#   1. check that the release artifact the formula names is there
#   2. clone homebrew-core (shallow: it is a big repository)
#   3. put the formula -- the one this repository carries, with the url,
#      the sha256 and the version the release flow just rewrote -- into a
#      branch
#   4. commit it and push the branch to the fork
#   5. open the pull request
#
# What the CI on that pull request runs is `brew audit --new --formula` and
# `brew readall`, and both need a Mac. The script says so here rather than
# pretending the pull request is the last step.
#
# The formula is called rgx, the way the crate is called rgx-search: the
# two registries took different names for the same binary, and the binary
# itself is rgx on both.
#
# Requires git, curl and gh (authenticated). The fork is created if it is
# not there yet.
param(
    [string]$Version = "",
    [string]$Formula = "rgx",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$coreRepo = "Homebrew/homebrew-core"
$coreFork = "danalec/homebrew-core"

$formulaFile = "Formula/$Formula.rb"
if (-not (Test-Path $formulaFile)) {
    Write-Error "no formula at $formulaFile"
    exit 1
}

# Homebrew-core keeps its formulae under the directory of the formula's
# first letter: Formula/r/rgx.rb, beside Formula/r/ripgrep.rb. The Formula
# directory there holds those directories and nothing else, so a formula
# written to Formula/rgx.rb lands in a path no formula of the tap occupies
# and the pull request carries a file the tap does not read.
$coreLetter = $Formula.Substring(0, 1).ToLowerInvariant()
$coreFormulaDir = "Formula/$coreLetter"
$coreFormulaFile = "$coreFormulaDir/$Formula.rb"

# The version comes from the formula, and the formula's url and sha256
# come from the release flow: they are the release's own data, rewritten
# when the release was published.
if (-not $Version) {
    $m = Select-String -Path $formulaFile -Pattern '^\s*version "([^"]+)"' | Select-Object -First 1
    if ($m) { $Version = $m.Matches.Groups[1].Value }
}
if (-not $Version) { Write-Error "no version in $formulaFile"; exit 1 }

$url = ""
$m = Select-String -Path $formulaFile -Pattern '^\s*url "([^"]+)"' | Select-Object -First 1
if ($m) { $url = $m.Matches.Groups[1].Value }
$sha = ""
$m = Select-String -Path $formulaFile -Pattern '^\s*sha256 "([^"]+)"' | Select-Object -First 1
if ($m) { $sha = $m.Matches.Groups[1].Value }
if (-not $url) { Write-Error "no url in $formulaFile"; exit 1 }
if (-not $sha) { Write-Error "no sha256 in $formulaFile"; exit 1 }
# The formula carries placeholders until the release flow rewrites them,
# and a digest of zeros is not a digest: a pull request that carries one
# is a pull request the tap's audit rejects on sight.
if ($sha -notmatch '^[0-9a-fA-F]{64}$') { Write-Error "the sha256 in $formulaFile is not a digest: $sha"; exit 1 }
if ($sha -notmatch '[1-9a-fA-F]') { Write-Error "the sha256 in $formulaFile is a placeholder: $sha"; exit 1 }

Write-Host ">> $Formula $Version"
Write-Host ">> url    $url"
Write-Host ">> sha256 $sha"

# --- 1. the release has to exist --------------------------------------------
# A pull request whose formula names a URL that answers with something
# other than the file is a pull request the CI will fail on, and the
# failure is slower and less clear than this one.
Write-Host ">> checking the release"
try {
    $head = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing
    if ($head.StatusCode -ne 200) { throw "status $($head.StatusCode)" }
} catch {
    Write-Error "the release artifact is not there yet: $url"
    Write-Error "publish the release first (scripts/publish-release.ps1), then run this"
    exit 1
}

# --- 2. the fork ------------------------------------------------------------
gh repo view $coreFork *> $null
if ($LASTEXITCODE -ne 0) {
    if ($DryRun) {
        Write-Host "[dry-run] would create the fork $coreFork"
    } else {
        Write-Host ">> forking $coreRepo"
        gh repo fork $coreRepo --clone=false
        if ($LASTEXITCODE -ne 0) { throw "the fork could not be created" }
    }
}

# --- 3. the branch ----------------------------------------------------------
$work = Join-Path ([IO.Path]::GetTempPath()) "rgx-brew-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $work | Out-Null
Write-Host ">> cloning $coreRepo"
git clone --quiet --depth 1 "https://github.com/$coreRepo.git" "$work/core"
if ($LASTEXITCODE -ne 0) { throw "the clone failed" }
$branch = "$Formula-$Version"
git -C "$work/core" checkout --quiet -b $branch
New-Item -ItemType Directory -Force -Path "$work/core/$coreFormulaDir" | Out-Null
Copy-Item $formulaFile "$work/core/$coreFormulaFile" -Force

# --- 4. the commit ----------------------------------------------------------
git -C "$work/core" add $coreFormulaFile
git -C "$work/core" -c user.name="danalec" -c user.email="danalec@gmail.com" commit --quiet -m "$Formula $Version"
if ($LASTEXITCODE -ne 0) { throw "the commit failed" }

if ($DryRun) {
    Write-Host "[dry-run] would push $branch to $coreFork and open the pull request"
    git -C "$work/core" show --stat --oneline HEAD
    exit 0
}

Write-Host ">> pushing $branch to $coreFork"
git -C "$work/core" push --quiet "https://github.com/$coreFork.git" $branch
if ($LASTEXITCODE -ne 0) { throw "the push failed" }

# --- 5. the pull request ----------------------------------------------------
# The body answers the questions homebrew-core's template asks, because a
# pull request that answers them is one review round shorter.
$body = @"
$Formula $Version

**What is this tool doing?**

rgx is ``rg`` that reads inside files. It keeps ripgrep's interface -- the
same flags, the same exit codes -- and adds the half ripgrep cannot do: a
hit inside a PDF, an Office document, an archive, a 3D model, an LLM
checkpoint, a database or an e-mail.

    rgx "invoice" ~/Documents          # the search ripgrep would do
    rgx --type pdf "tesla" ~/Documents  # and the same search inside a PDF

**Does this pull request change the software that Homebrew installs?**

This is the first release: it adds the formula, so it adds the software.
There is no previous version in Homebrew to replace.

**Why should this be in Homebrew core?**

It is a command-line tool that installs from a prebuilt, signed-by-digest
archive, needs no system library beyond what macOS ships, and has a stable
tagged release. The repository carries the formula, the release script and
the installers: https://github.com/danalec/rgx

**What does the test do?**

It writes a file and asks the CLI how many lines match, so the test is the
product doing its own job.

"@
$bodyFile = Join-Path $work "pr.md"
Set-Content $bodyFile $body -NoNewline

Write-Host ">> opening the pull request"
gh pr create --repo $coreRepo --head "$coreFork`:$branch" --title "$Formula $Version" --body-file $bodyFile
if ($LASTEXITCODE -ne 0) { throw "the pull request could not be opened" }

Write-Host ""
Write-Host ">> what happens next: the CI runs 'brew audit --new --formula' and"
Write-Host ">> 'brew readall'. Both need a Mac; the audit checks the url, the"
Write-Host ">> digest, the licence, the description and the test."
