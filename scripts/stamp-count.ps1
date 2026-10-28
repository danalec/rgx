# stamp-count.ps1 -- write the count of the tests into the working notes and
# into the workflow, and write the note that says what the count was taken
# after.
#
# The Windows counterpart of scripts/stamp-count.sh.
#
# The count of the tests is a fact about the tree a commit carries, and the
# notes of the project carry it in two places: the line that says how many
# tests pass, and the comment in the workflow that says the same number.
#
# The history of the counts is a list of clauses, and each clause says what
# a re-snapshot was after:
#
#     (re-snapped 2026-10-25, after the type filter learned to be
#     ripgrep's: the eight new tests are ...)
#
# The newest clause is the one this script rewrites, and only that one: the
# history is cumulative, and a script that rewrote every clause would
# replace the history with the last note. The header of the clause runs
# from its "(" to the first ":" after the date, and everything from that
# colon on is the body of the clause, which stays.
#
# Usage:
#   powershell -File scripts/stamp-count.ps1 -Agents AGENTS.md `
#       -Workflow .github/workflows/ci.yml -Passed 2569 -Ignored 8 `
#       -Date 2026-10-25 -Note "the filters learned to be ripgrep's"
#
# The paths are the two files to stamp, the counts are the ones the gate
# printed, and the date is the one to write (today by default). The note is
# what the count was taken after, and it is refused when it holds a colon:
# the note is written into a header that ends at the first colon, and a
# colon in it would end that header in the wrong place. An empty note
# stamps the counts and leaves the history alone.
#
# The exit code: 0 when the stamp is written, 2 when it is refused.
param(
    [Parameter(Mandatory = $true)][string]$Agents,
    [Parameter(Mandatory = $true)][string]$Workflow,
    [Parameter(Mandatory = $true)][int]$Passed,
    [Parameter(Mandatory = $true)][int]$Ignored,
    [string]$Date = '',
    [string]$Note = ''
)

$ErrorActionPreference = 'Stop'

function Die([string]$message) {
    [Console]::Error.WriteLine($message)
    exit 2
}

if (-not $Date) { $Date = (Get-Date).ToString('yyyy-MM-dd') }

if ($Note.Contains(':')) { Die 'the note cannot hold a colon: it ends the header of the clause' }
if ($Note.Contains([char]10) -or $Note.Contains([char]13)) { Die 'the note cannot hold a newline: it is one clause' }

if (-not (Test-Path -LiteralPath $Agents)) { Die "the notes file is not there: $Agents" }
if (-not (Test-Path -LiteralPath $Workflow)) { Die "the workflow file is not there: $Workflow" }

# The number with the thousands the notes of the project write: 2455 is
# 2,455 there. The locale of the machine does not decide it: on a
# Portuguese machine "N0" writes "2 569", and the Linux twin writes
# "2,569", and the two would put two different numbers in the same notes.
$formatted = $Passed.ToString('N0', [System.Globalization.CultureInfo]::InvariantCulture)

# The bytes of the file, decoded as Latin-1: every byte is one character,
# so the offsets of a match are the offsets of the bytes, and the splice
# below is byte for byte. A round trip through UTF-8 would turn every byte
# that is not valid UTF-8 into U+FFFD, and the Linux twin, which counts
# bytes, would write the file the byte it was.
$latin = [System.Text.Encoding]::GetEncoding(28591)
$utf8 = [System.Text.UTF8Encoding]::new($false)

# Replace the first match of a pattern with a literal, byte for byte.
function Replace-First([string]$path, [string]$pattern, [string]$literal) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = $latin.GetString($bytes)
    $found = [regex]::Match($text, $pattern)
    if (-not $found.Success) { return $false }
    $spliced = $latin.GetBytes($text.Substring(0, $found.Index)) +
        $utf8.GetBytes($literal) +
        $latin.GetBytes($text.Substring($found.Index + $found.Length))
    [System.IO.File]::WriteAllBytes($path, $spliced)
    return $true
}

# The count of the tests, in the notes and in the workflow.
if (-not (Replace-First $Agents '\*\*[0-9,]+ tests pass, [0-9]+ fail, [0-9]+ ignored\*\*' "**$formatted tests pass, 0 fail, $Ignored ignored**")) {
    Die 'the notes have no count of tests to stamp'
}
if (-not (Replace-First $Workflow 'the [0-9,]+ tests in the workspace' "the $formatted tests in the workspace")) {
    Die 'the workflow has no count of tests to stamp'
}

if ($Note) {
    # The header of the newest clause: from its "(" to the first ":" after
    # the date. The header can hold more than one line, so the colon that
    # ends it is looked for in the text that follows it and not in a line
    # of its own. The body of the clause is everything from that colon on,
    # and it stays.
    # The header is put together with a concatenation and not with an
    # interpolation: a note that holds a quote would end the string.
    $header = '(re-snapped ' + $Date + ', after ' + $Note + ' landed:'
    if (-not (Replace-First $Agents '\(re-snapped [0-9]{4}-[0-9]{2}-[0-9]{2}[^:]*:' $header)) {
        Die 'the notes have no clause to stamp: no (re-snapped YYYY-MM-DD'
    }
}

# The line is written with a line feed and not with the carriage return
# the shell of Windows would write: the two twins are the same job, and
# the bytes they say are the same bytes.
[Console]::Out.Write("stamped: $formatted tests pass, $Ignored ignored, on $Date`n")
