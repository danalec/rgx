#!/usr/bin/env bash
# stamp-count.sh -- write the count of the tests into the working notes and
# into the workflow, and write the note that says what the count was taken
# after.
#
# The Linux counterpart of scripts/stamp-count.ps1.
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
#   bash scripts/stamp-count.sh --agents AGENTS.md \
#       --workflow .github/workflows/ci.yml \
#       --passed 2569 --ignored 8 \
#       --date 2026-10-25 --note "the filters learned to be ripgrep's"
#
# The paths are the two files to stamp, the counts are the ones the gate
# printed, and the date is the one to write (today by default). The note is
# what the count was taken after, and it is refused when it holds a colon:
# the note is written into a header that ends at the first colon, and a
# colon in it would end that header in the wrong place. An empty note
# stamps the counts and leaves the history alone.
#
# The exit code: 0 when the stamp is written, 2 when it is refused.
set -u

tmp=""

die() { echo "$1" >&2; exit 2; }

# The file that is being written, and the file that is not there while it
# is written: a script that dies in the middle leaves nothing behind.
cleanup() { [ -n "$tmp" ] && rm -f "$tmp"; }
trap cleanup EXIT

# The number with the thousands the notes of the project write: 2455 is
# 2,455 there. The locale of the machine does not decide it: the Windows
# twin writes the comma with the invariant culture, and a culture that
# writes "2 569" would put two different numbers in the same notes.
#
# The count is written by awk and not by sed, because the sed that does it
# is a GNU one: the "|" of the alternation is spelled "\|" in a basic
# expression, and the sed of macOS does not know that spelling and leaves
# the number alone -- so the two twins wrote 2,575 and 2575 into the same
# notes. And the awk counts from the right, so a number of seven digits
# comes out 1,234,567 and not 1234,567.
thousands() {
    printf '%s' "$1" | awk '{
        n = $0
        out = ""
        while (length(n) > 3) {
            out = "," substr(n, length(n) - 2) out
            n = substr(n, 1, length(n) - 3)
        }
        printf "%s%s", n, out
    }'
}

# Replace the first match of a pattern with a literal, byte for byte: grep
# counts the bytes it finds, and the bytes that are not the match are the
# bytes that were there. A sed would do the same on Linux and not on
# Windows, where it reads the file in text mode and takes the carriage
# returns of a Windows checkout with it -- and the notes of the project are
# a Windows checkout.
replace_first() {
    file=$1
    pattern=$2
    literal=$3
    hit=$(grep -bo -m1 -E "$pattern" "$file" | head -1)
    [ -n "$hit" ] || return 1
    at=${hit%%:*}
    found=${hit#*:}
    len=$(printf '%s' "$found" | wc -c | tr -d ' ')
    tmp="$file.stamp.$$"
    {
        head -c "$at" "$file"
        printf '%s' "$literal"
        tail -c +$((at + len + 1)) "$file"
    } > "$tmp" || return 1
    mv -f "$tmp" "$file" || return 1
    tmp=""
}

# The header of the newest clause, byte by byte. The header can hold more
# than one line, so the colon that ends it is looked for in the bytes that
# follow it and not in a line of its own.
stamp_clause() {
    file=$1
    on=$2
    what=$3
    open=$(grep -bo -m1 -E '\(re-snapped [0-9]{4}-[0-9]{2}-[0-9]{2}' "$file" | head -1 | cut -d: -f1)
    [ -n "$open" ] || die "the notes have no clause to stamp: no (re-snapped YYYY-MM-DD"
    colon=$(tail -c +$((open + 1)) "$file" | grep -bo -m1 ':' | head -1 | cut -d: -f1)
    [ -n "$colon" ] || die "the clause of the notes has no colon to end its header"
    at=$((open + 1 + colon))
    tmp="$file.stamp.$$"
    {
        head -c "$open" "$file"
        printf '(re-snapped %s, after %s landed:' "$on" "$what"
        tail -c +$((at + 1)) "$file"
    } > "$tmp" || die "the notes could not be written"
    mv -f "$tmp" "$file" || die "the notes could not be replaced"
    tmp=""
}

agents=""
workflow=""
passed=""
ignored=""
day=$(date +%Y-%m-%d)
note=""

while [ $# -gt 0 ]; do
    case "$1" in
        --agents) agents=${2:-}; shift 2 ;;
        --workflow) workflow=${2:-}; shift 2 ;;
        --passed) passed=${2:-}; shift 2 ;;
        --ignored) ignored=${2:-}; shift 2 ;;
        --date) day=${2:-}; shift 2 ;;
        --note) note=${2:-}; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ -n "$agents" ] || die "the notes file is missing"
[ -n "$workflow" ] || die "the workflow file is missing"
[ -n "$passed" ] || die "the count of the tests is missing"
[ -n "$ignored" ] || die "the count of the ignored tests is missing"
[ -f "$agents" ] || die "the notes file is not there: $agents"
[ -f "$workflow" ] || die "the workflow file is not there: $workflow"

# the newline, kept: a command substitution would strip it, and a pattern
# that holds nothing matches every note.
nl=$'\n'
case "$note" in
    *:*) die "the note cannot hold a colon: it ends the header of the clause" ;;
    *"$nl"*) die "the note cannot hold a newline: it is one clause" ;;
esac

formatted=$(thousands "$passed")

# The count of the tests, in the notes and in the workflow.
replace_first "$agents" '\*\*[0-9,]+ tests pass, [0-9]+ fail, [0-9]+ ignored\*\*' "**$formatted tests pass, 0 fail, $ignored ignored**" \
    || die "the notes have no count of tests to stamp"
replace_first "$workflow" 'the [0-9,]+ tests in the workspace' "the $formatted tests in the workspace" \
    || die "the workflow has no count of tests to stamp"

if [ -n "$note" ]; then
    stamp_clause "$agents" "$day" "$note"
fi

echo "stamped: $formatted tests pass, $ignored ignored, on $day"
