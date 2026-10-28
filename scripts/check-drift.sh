#!/usr/bin/env bash
# check-drift.sh -- report vendored code that has fallen behind its upstream
# source.
#
# The Linux counterpart of scripts/check-drift.ps1.
#
# scripts/check-vendoring.sh enforces the *shape* of the vendoring rule: no
# [patch] redirect, a provenance header on each vendored tree. None of that
# can notice that a file was copied on Monday and that the upstream changed
# it on Tuesday.
#
# This asks the other half: for each file in scripts/vendored-sources.tsv,
# has the upstream changed the recorded source since the recorded pin? The
# comparison is upstream-against-upstream -- `git log <pin>..HEAD -- <source>`
# -- so copy-time rewrites (alloc:: to std::, testdata paths, narrowed
# imports) never enter into it and there is nothing to normalise. What
# comes back is a list of commits the copy has not seen, by name.
#
# A row pinned with `-` is counted as a failure. A manifest that quietly
# leaves a file out, or pins it to a guess, is worse than one that says it
# has not looked: the first one reads as "nothing to do here".
#
# The Linux counterpart differs from the Windows one in one place: the
# "closest upstream commit" is measured with `comm` over sorted lines,
# which counts a multiset difference the way Compare-Object does, and both
# sides have their carriage returns stripped first so a CRLF checkout does
# not read as a thousand-line difference.
#
# Usage:
#   bash scripts/check-drift.sh --upstream ~/memchr
#   bash scripts/check-drift.sh --upstream ~/memchr --pin --for crates/rgx-core/src/memchr.rs
#
# Run from anywhere; the script re-roots itself from its own path.
# Exits 1 on any drift or any unpinned row, 0 otherwise.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cd "$repo"

upstream=""
pin=0
for_row=""

while [ $# -gt 0 ]; do
    case "$1" in
        --upstream) upstream=${2:-}; shift 2 ;;
        --pin) pin=1; shift ;;
        --for) for_row=${2:-}; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

manifest="$here/vendored-sources.tsv"
if [ ! -f "$manifest" ]; then
    echo "no manifest at $manifest" >&2
    exit 1
fi

if [ -z "$upstream" ]; then
    echo "no --upstream path given; this check needs a local upstream checkout to ask" >&2
    echo "  example: bash scripts/check-drift.sh --upstream ~/memchr" >&2
    exit 1
fi
if [ ! -d "$upstream/.git" ]; then
    echo "$upstream is not a git checkout" >&2
    exit 1
fi
upstream=$(cd "$upstream" && pwd)

# How far a copy may sit from an upstream commit and still be pinned by
# matching.
#
# Some vendored files are deliberately reduced ports -- a decoder with no
# encoder, a couple of functions out of a larger module. For those, "the
# commit whose blob is closest" is still a perfectly good match to the
# wrong question, and it will hand back the commit that created the file
# with a confident number attached. A tool that is confidently wrong about
# the one file you just fixed is worse than one that declines.
#
# Past this many differing lines, refuse and say so. Those rows get pinned
# by hand with a reason in the note column.
max_pin_distance=150

upstream_commit_exists() {
    git -C "$upstream" rev-parse --verify -q "$1^{commit}" > /dev/null 2>&1
}

upstream_log() {
    git -C "$upstream" log --oneline "$1..HEAD" -- "$2" 2>/dev/null | sed '/^[[:space:]]*$/d'
}

# The upstream commit whose blob is closest to this rgx file.
#
# Closest, not identical: the copies are edited at copy time, so an exact
# match is not available and an exact-match requirement would pin nothing.
# Reads committed state only, so a dirty working tree -- which is the
# normal case here -- cannot move the answer.
#
# Prints "<commit> <score>" on stdout, nothing if no commit could be read.
best_commit() {
    local rgx_path="$1" source="$2"
    local target="$repo/$rgx_path"
    [ -f "$target" ] || return 0

    local mine blob
    mine=$(mktemp)
    blob=$(mktemp)
    tr -d '\r' < "$target" | LC_ALL=C sort > "$mine"

    local best="" best_score=0 first=1
    local commits c score
    commits=$(git -C "$upstream" log --format=%H -- "$source" 2>/dev/null)
    for c in $commits; do
        git -C "$upstream" show "${c}:$source" > /dev/null 2>&1 || continue
        tr -d '\r' < <(git -C "$upstream" show "${c}:$source") | LC_ALL=C sort > "$blob"
        score=$(comm -3 "$mine" "$blob" | wc -l | tr -d ' ')
        if [ "$first" = 1 ] || [ "$score" -lt "$best_score" ]; then
            best_score=$score
            best=$(printf '%s' "$c" | cut -c1-7)
            first=0
        fi
    done
    rm -f "$mine" "$blob"

    [ -n "$best" ] || return 0
    printf '%s %s\n' "$best" "$best_score"
}

echo "checking vendored drift against upstream at $upstream"

# The rows are the manifest minus comments and blank lines. Field 3 is the
# pin; '-' means nobody has established one.
rows=$(awk -F'\t' '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    NF < 2 { next }
    {
        rgx = $1; src = $2;
        gsub(/^[ \t]+|[ \t]+$/, "", rgx);
        gsub(/^[ \t]+|[ \t]+$/, "", src);
        pin = (NF >= 3 ? $3 : "-");
        gsub(/^[ \t]+|[ \t]+$/, "", pin);
        if (pin == "") pin = "-";
        print rgx "\t" src "\t" pin;
    }
' "$manifest")

# --- re-pin one row -------------------------------------------------------
if [ "$pin" = 1 ]; then
    if [ -z "$for_row" ]; then
        echo "--pin needs --for <rgx path>" >&2
        exit 1
    fi
    row=$(printf '%s\n' "$rows" | awk -F'\t' -v want="$for_row" '$1 == want { print; exit }')
    if [ -z "$row" ]; then
        echo "no manifest row for $for_row" >&2
        exit 1
    fi
    rgx_path=$(printf '%s' "$row" | cut -f1)
    source=$(printf '%s' "$row" | cut -f2)

    match=$(best_commit "$rgx_path" "$source")
    if [ -z "$match" ]; then
        echo "could not match $for_row against any upstream commit" >&2
        exit 1
    fi
    best=$(printf '%s' "$match" | awk '{print $1}')
    score=$(printf '%s' "$match" | awk '{print $2}')

    if [ "$score" -gt "$max_pin_distance" ]; then
        echo "  $for_row is $score lines from the closest upstream commit ($best)"
        echo "  that is a reduced port, not a copy: matching cannot say which commit it came from."
        echo "  pin it by hand and put the reason in the note column."
        exit 1
    fi

    behind=$(upstream_log "$best" "$source")
    echo "  $for_row matches upstream $best ($score differing lines)"
    if [ -n "$behind" ]; then
        n=$(printf '%s\n' "$behind" | wc -l | tr -d ' ')
        echo "  and is behind $n upstream commit(s):"
        printf '%s\n' "$behind" | sed 's/^/    /'
    else
        echo "  and is up to date with that source"
    fi
    echo ""
    echo "pin it with:"
    printf '  %s\t%s\t%s\n' "$rgx_path" "$source" "$best"
    exit 0
fi

# --- the check ------------------------------------------------------------
#
# The loop runs in a subshell (it is the right side of a pipe), so it
# cannot count; it writes a marker per row and the counters are read out
# of the file afterwards.
report=$(mktemp)
trap 'rm -f "$report"' EXIT

printf '%s\n' "$rows" | while IFS="$(printf '\t')" read -r rgx_path source pin; do
    [ -n "$rgx_path" ] || continue

    if [ ! -f "$repo/$rgx_path" ]; then
        echo "  FAIL: $rgx_path: listed in the manifest but not in the tree"
        echo "DRIFT|$rgx_path"
        continue
    fi
    if [ "$pin" = "-" ]; then
        echo "UNPINNED|$rgx_path"
        continue
    fi
    if ! upstream_commit_exists "$pin"; then
        echo "  FAIL: $rgx_path: pin $pin is not an upstream commit"
        echo "DRIFT|$rgx_path"
        continue
    fi
    behind=$(upstream_log "$pin" "$source")
    if [ -n "$behind" ]; then
        n=$(printf '%s\n' "$behind" | wc -l | tr -d ' ')
        echo "  FAIL: $rgx_path is behind $source since $pin:"
        printf '%s\n' "$behind" | sed 's/^/    /'
        echo "DRIFT|$rgx_path"
        continue
    fi
    echo "OK|$rgx_path"
done > "$report"

drifted=$(grep -c '^DRIFT|' "$report" || true)
unpinned=$(grep -c '^UNPINNED|' "$report" || true)
checked=$(grep -c '^OK|' "$report" || true)

if [ "$unpinned" -gt 0 ]; then
    echo "  $unpinned row(s) have no recorded sync point:"
    grep '^UNPINNED|' "$report" | sed 's/^UNPINNED|//' | sed 's/^/    - /'
    echo "    pin one with: --pin --for <path>"
fi

echo ""
if [ "$unpinned" -gt 0 ] || [ "$drifted" -gt 0 ]; then
    n=$((drifted + unpinned))
    echo "vendored drift: $n outstanding ($drifted drifted, $unpinned unpinned)" >&2
    exit 1
fi
echo "ok: $checked vendored file(s) match the upstream source they were taken from"
exit 0
