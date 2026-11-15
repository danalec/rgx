# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Point DeepSeek Harness's `grep` and `glob` at rgx — or put ripgrep back.

.DESCRIPTION
    DeepSeek Harness does not look for `rg` on PATH. Its `grep` and `glob`
    tools spawn the ripgrep binary the harness ships — under
    `resources/app.asar.unpacked/dsh/node_modules/@vscode/ripgrep-*/bin/` —
    and always prefix `--no-config` to the argv. There is no environment
    variable and no settings field for that path, so the way to make those
    tools run rgx is to replace that one file, keeping a backup so `-Restore`
    can put the shipped binary back.

    Both halves are discovered wherever they are installed:

      * the harness by its unpacked `app.asar.unpacked` directory — the
        installer's `%LOCALAPPDATA%\Programs`, a machine-wide
        `%ProgramFiles%`, a winget package directory, a scoop app, or
        whatever `-HarnessRoot` names;
      * rgx by `-RgxPath`, else `$env:RGX_BIN`, else every `rgx*` command on
        PATH (`rgx`, and the `rgx-znver4`/`rgx-avx2` spelling a package
        manager may install) — so a scoop shim, a winget link, a cargo
        install and a hand-unpacked zip all work. The first candidate that
        can answer the harness's argv is the one used.

    Before copying anything the script asks each rgx build the same questions
    the harness will ask it: `--no-config` with `--files`, `--regexp=VALUE`,
    and `--sort=modified`. A build that cannot answer one is reported with
    the flag it failed, and nothing is touched.

    Run it again after a harness update: the installer puts ripgrep back, and
    a second `-Apply` is what re-points it. `-Status` is the default.

.PARAMETER Apply
    Back up the packaged ripgrep and copy rgx over it.

.PARAMETER Restore
    Put the backed-up ripgrep back.

.PARAMETER Status
    Report what is installed and whether the harness is running rgx.
    The default when no mode is named.

.PARAMETER RgxPath
    The rgx executable to install. Defaults to `$env:RGX_BIN`, then every
    `rgx*` command on PATH.

.PARAMETER HarnessRoot
    A DeepSeek Harness installation root to search instead of the discovery
    list. Point it at the directory holding `resources\app.asar.unpacked`.

.EXAMPLE
    .\use-with-dsh.ps1
    Report what is installed and whether the harness is currently running rgx.

.EXAMPLE
    .\use-with-dsh.ps1 -Apply
    Point every harness install found at the first compatible rgx on PATH.

.NOTES
    Exit codes: 0 ok, 2 usage, 3 rgx not found, 4 harness not found,
    5 no rgx build can answer the harness's argv.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Restore,
    [switch]$Status,
    [string]$RgxPath,
    [string]$HarnessRoot
)

$ErrorActionPreference = 'Stop'

function Fail([int]$code, [string]$message) {
    [Console]::Error.WriteLine("rgx: $message")
    exit $code
}

$modes = @($Apply, $Restore, $Status) | Where-Object { $_ }
if ($modes.Count -gt 1) {
    Fail 2 'choose one of -Apply, -Restore and -Status, not more'
}

# The first line of `--version` is the identity: ripgrep says `ripgrep x.y.z`
# and rgx says `rgx x.y.z` (its second line is the format list).
function Get-VersionLine([string]$exe) {
    try {
        $line = & $exe --version 2>$null | Select-Object -First 1
        if ($null -eq $line) { return '' }
        return $line.Trim()
    } catch {
        return ''
    }
}

function Test-IsRgx([string]$versionLine) {
    return $versionLine -like 'rgx *'
}

# Every rgx build the machine offers, in the order to try them: the one named
# explicitly, then the environment's, then PATH. The package managers of this
# project install `rgx`, `rgx-znver4` and `rgx-avx2` as separate commands, and
# a machine may hold more than one, so the caller picks by capability rather
# than by name.
function Get-RgxCandidates {
    param([string]$Explicit)

    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) {
            Fail 3 "no rgx at the path given: $Explicit"
        }
        return @((Resolve-Path -LiteralPath $Explicit).Path)
    }
    if ($env:RGX_BIN) {
        if (-not (Test-Path -LiteralPath $env:RGX_BIN)) {
            Fail 3 "RGX_BIN names a path that does not exist: $($env:RGX_BIN)"
        }
        return @((Resolve-Path -LiteralPath $env:RGX_BIN).Path)
    }

    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($command in @(Get-Command -Name 'rgx*' -CommandType Application -ErrorAction SilentlyContinue)) {
        $source = $command.Source
        if ($source -and -not $paths.Contains($source)) { $paths.Add($source) }
    }
    return $paths
}

# The unpacked directory is the harness's own name for "these files are real
# files on disk", and the packaged ripgrep is the only executable in there
# that the search tools spawn. Searching for it by name finds the harness
# whatever installed it.
function Find-HarnessBinaries {
    param([string]$Root)

    $patterns = @()
    if ($Root) {
        $patterns += (Join-Path $Root 'resources\app.asar.unpacked')
        $patterns += (Join-Path $Root 'app.asar.unpacked')
    } else {
        $local = $env:LOCALAPPDATA
        $programs = $env:ProgramFiles
        $programsX86 = ${env:ProgramFiles(x86)}
        $winget = if ($local) { Join-Path $local 'Microsoft\WinGet\Packages' } else { $null }
        $scoop = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'scoop\apps' } else { $null }

        $patterns += @(
            (Join-Path $local 'Programs\*\resources\app.asar.unpacked'),
            (Join-Path $programs '*\resources\app.asar.unpacked'),
            (Join-Path $programsX86 '*\resources\app.asar.unpacked'),
            (Join-Path $winget '*\resources\app.asar.unpacked'),
            (Join-Path $winget '*\*\resources\app.asar.unpacked'),
            (Join-Path $scoop '*\current\resources\app.asar.unpacked')
        )
    }

    $found = New-Object System.Collections.Generic.List[string]
    foreach ($pattern in $patterns) {
        if ([string]::IsNullOrEmpty($pattern)) { continue }
        $dirs = Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $dirs) {
            $binaries = Get-ChildItem -LiteralPath $dir.FullName -Recurse -File -Filter 'rg*' -ErrorAction SilentlyContinue |
                Where-Object {
                    # The harness's own layout: the packed app's `dsh` tree is
                    # what holds the search package. Matching `@vscode/ripgrep`
                    # alone finds every Electron app on the machine, and
                    # pointing another one's search at rgx is not this
                    # script's business.
                    $_.FullName -like '*\dsh\node_modules\@vscode\ripgrep-*\bin\rg.exe' -or
                    $_.FullName -like '*/dsh/node_modules/@vscode/ripgrep-*/bin/rg'
                }
            foreach ($binary in $binaries) {
                if (-not $found.Contains($binary.FullName)) { $found.Add($binary.FullName) }
            }
        }
    }
    return $found
}

# The three questions the harness asks, one at a time, so a failure names the
# flag that could not be answered instead of "incompatible".
function Test-RgxCompatibility {
    param([string]$Rgx, [string]$ProbeDir)

    $probeFile = Join-Path $ProbeDir 'rgx-probe.txt'
    if (-not (Test-Path -LiteralPath $probeFile)) {
        Set-Content -LiteralPath $probeFile -Value 'rgx-probe' -Encoding ascii
    }
    $failures = New-Object System.Collections.Generic.List[string]

    $probes = @(
        @{ Name = '--no-config'; Argv = @('--no-config', '--files', $ProbeDir) },
        @{ Name = '--regexp';    Argv = @('--json', '--regexp=rgx-probe', $ProbeDir) },
        @{ Name = '--sort=modified'; Argv = @('--files', '--sort=modified', $ProbeDir) }
    )

    foreach ($probe in $probes) {
        $output = & $Rgx @($probe.Argv) 2>&1
        $code = $LASTEXITCODE
        if ($code -gt 1) {
            $detail = ($output | Select-Object -First 1)
            $failures.Add("$($probe.Name): $detail")
        }
    }
    return $failures
}

# ---------------------------------------------------------------- discovery

$binaries = Find-HarnessBinaries -Root $HarnessRoot
if ($binaries.Count -eq 0) {
    Fail 4 'no DeepSeek Harness installation found: pass -HarnessRoot pointing at the directory that holds resources\app.asar.unpacked'
}

$probeDir = Join-Path ([System.IO.Path]::GetTempPath()) ('rgx-dsh-probe-' + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $probeDir | Out-Null

# What gets asked depends on what is being answered. `-Apply` has to know
# whether a candidate may be installed, so it probes the candidates; `-Status`
# reports on the binary the harness is *already* running, so it probes that
# one — a machine whose PATH rgx is old can still be running a good one.
$rgx = $null
$rgxVersion = ''
try {
    if ($Apply) {
        $candidates = Get-RgxCandidates -Explicit $RgxPath
        if ($candidates.Count -eq 0) {
            Fail 3 'rgx not found: put it on PATH, pass -RgxPath, or set RGX_BIN'
        }
        $firstFailures = $null
        foreach ($candidate in $candidates) {
            $candidateFailures = Test-RgxCompatibility -Rgx $candidate -ProbeDir $probeDir
            if ($candidateFailures.Count -eq 0) {
                $rgx = $candidate
                $rgxVersion = Get-VersionLine $candidate
                break
            }
            if ($null -eq $firstFailures) {
                # The first candidate is the one the report speaks for: naming
                # every build on a machine with three would bury the reason.
                $firstFailures = $candidateFailures
                $rgxVersion = Get-VersionLine $candidate
            }
        }
        if ($null -eq $rgx) {
            Write-Output "rgx:     $($candidates[0]) ($rgxVersion)"
            Write-Output 'probe:   failed'
            foreach ($failure in $firstFailures) { Write-Output "         $failure" }
            if ($candidates.Count -gt 1) {
                Write-Output "note:    none of the $($candidates.Count) rgx builds on PATH answers the harness argv"
            }
            exit 5
        }
        Write-Output "rgx:     $rgx ($rgxVersion)"
        Write-Output 'probe:   ok (--no-config, --regexp, --sort=modified)'
    }
} finally {
    Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
}

$failed = 0
$applied = 0
$skipped = 0
foreach ($binary in $binaries) {
    $backup = "$binary.rgx-backup"
    $version = Get-VersionLine $binary
    $isRgx = Test-IsRgx $version

    Write-Output "harness: $binary ($version)"

    if ($Restore) {
        if (Test-Path -LiteralPath $backup) {
            Copy-Item -LiteralPath $backup -Destination $binary -Force
            Remove-Item -LiteralPath $backup -Force
            Write-Output 'action:  restored the packaged ripgrep'
            $applied++
        } else {
            Write-Output 'state:   not applied (no backup to restore)'
            $skipped++
        }
        continue
    }

    if (-not $Apply) {
        if ($isRgx) {
            Write-Output 'state:   applied'
            if (-not (Test-Path -LiteralPath $backup)) {
                Write-Output 'note:    no ripgrep backup beside the binary (-Restore cannot undo this one)'
            }
            $probeDir = Join-Path ([System.IO.Path]::GetTempPath()) ('rgx-dsh-probe-' + [System.Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Force -Path $probeDir | Out-Null
            try {
                $failures = Test-RgxCompatibility -Rgx $binary -ProbeDir $probeDir
            } finally {
                Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            if ($failures.Count -eq 0) {
                Write-Output 'probe:   ok (--no-config, --regexp, --sort=modified)'
            } else {
                Write-Output 'probe:   failed (this build cannot answer the harness argv)'
                foreach ($failure in $failures) { Write-Output "         $failure" }
                $failed++
            }
        } else {
            Write-Output 'state:   not applied'
        }
        continue
    }

    if ($isRgx) {
        # Already rgx: only a *different* rgx build is worth a copy, so that
        # upgrading rgx and re-running this lands the new one while a later
        # -Restore still restores the ripgrep this harness shipped.
        $same = (Get-FileHash -LiteralPath $binary).Hash -eq (Get-FileHash -LiteralPath $rgx).Hash
        if ($same) {
            Write-Output 'action:  already rgx (nothing to do)'
            $skipped++
            continue
        }
        Copy-Item -LiteralPath $rgx -Destination $binary -Force
        if (Test-Path -LiteralPath $backup) {
            Write-Output 'action:  replaced the installed rgx with this build'
        } else {
            Write-Output 'action:  replaced the installed rgx with this build (no ripgrep backup beside it: -Restore cannot undo this one)'
        }
        $applied++
        continue
    }

    # The harness ships ripgrep: the backup must be *this* build, not one a
    # previous harness version shipped, or -Restore would put back a binary
    # the tools were never tested against.
    Copy-Item -LiteralPath $binary -Destination $backup -Force
    Copy-Item -LiteralPath $rgx -Destination $binary -Force
    Write-Output 'action:  installed rgx (backup kept beside the binary)'
    $applied++
}

if ($failed -gt 0) {
    exit 5
}
exit 0
