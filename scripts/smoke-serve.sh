#!/usr/bin/env bash
# smoke-serve.sh -- ask the --serve mode the same question two ways.
#
# The Linux counterpart of scripts/smoke-serve.ps1.
#
# `--serve` reads one JSON argv-array per line on stdin and answers each
# one, framed by begin/end sentinels. The two queries here are the same
# search asked two ways: once plainly, once with `-c`. Both are pointed at
# the same directory, so the two answers have to agree -- a serve-mode
# query that answers a different count than the same search on the command
# line is the bug this catches.
#
# The Windows script names the binary by its absolute path; this one
# resolves it from the repository, so it works from any cwd and does not
# encode one person's home directory.
#
# Usage:
#   bash scripts/smoke-serve.sh <dir>
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
rgx="$repo/target/release/rgx.exe"
[ -x "$rgx" ] || rgx="$repo/target/release/rgx"

dir=${1:-}
[ -n "$dir" ] || { echo "usage: bash scripts/smoke-serve.sh <dir>" >&2; exit 2; }
[ -x "$rgx" ] || { echo "no rgx binary at $rgx; build it first: cargo build --release" >&2; exit 2; }

# A JSON string needs its backslashes and its quotes escaped; a path has
# nothing else that JSON cares about.
json_str() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

{
    printf '["needle","%s"]\n' "$(json_str "$dir")"
    printf '["-c","needle","%s"]\n' "$(json_str "$dir")"
} | "$rgx" --serve
