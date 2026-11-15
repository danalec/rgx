#!/usr/bin/env bash
# commit-block.sh -- commit one block, with the test count of the tree that
# commit carries.
#
# The order matters:
#   1. the block's own files are staged, and the hunks of the shared
#      documents that belong to this block;
#   2. everything else is stashed, so the tree is the one the commit will
#      carry -- the count in the commit message has to be the count of that
#      tree, not of the tree with the other blocks in it;
#   3. the gate runs on that tree;
#   4. the count goes into AGENTS.md and the workflow, and they are staged;
#   5. the stash comes back, and the commit is made.
#
# The hunks go into the index BEFORE the gate, and not after it: the tree
# the gate measures is the tree the commit carries, and a README that
# claims an extension the registry does not is a test that fails.
#
# The Linux counterpart of scripts/commit-block.ps1.
#
# Usage:
#   bash scripts/commit-block.sh --message target/fmt/msg-b1.txt \
#       --files crates/rgx-adapters-inspect/src/scientific.rs \
#       --patches target/patches/ph-b1-README_md.patch \
#       --note "the GRIB spectral packing landed"
#
# The paths are relative to the repository root, and the files and the
# patches are lists separated by commas.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)

message=""
files=""
patches=""
note=""
no_count=0

while [ $# -gt 0 ]; do
    case "$1" in
        --message) message=${2:-}; shift 2 ;;
        --files) files=${2:-}; shift 2 ;;
        --patches) patches=${2:-}; shift 2 ;;
        --note) note=${2:-}; shift 2 ;;
        --no-count) no_count=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ -n "$message" ] || { echo "the message is missing" >&2; exit 2; }
[ -f "$repo/$message" ] || { echo "the message is not there: $message" >&2; exit 2; }

git_run() { git -C "$repo" "$@"; }

echo '=== staging the block ==='
# Each block starts from a clean index: a patch that failed to apply in an
# earlier attempt can still be sitting there.
git_run reset -q > /dev/null
if [ -n "$files" ]; then
    # shellcheck disable=SC2086
    git_run add -- $(echo "$files" | tr ',' ' ') > /dev/null
fi

echo '=== the hunks of the shared documents ==='
# The hunks go into the index before the gate: the tree the gate measures is
# the tree the commit carries, and a README that claims an extension the
# registry does not is a test that fails.
if [ -n "$patches" ]; then
    for p in $(echo "$patches" | tr ',' ' '); do
        if ! git_run apply --cached --unidiff-zero --whitespace=nowarn "$repo/$p"; then
            echo "the patch $p did not apply" >&2
            exit 1
        fi
        echo "  staged $p"
    done
fi

echo '=== stashing the other blocks ==='
git_run stash push --keep-index -m 'the other blocks' > /dev/null

echo '=== the gate, on the tree this commit carries ==='
gate=$("$here/gate-and-count.sh" 2>&1)
echo "$gate"
count=$(printf '%s\n' "$gate" | grep -E '^COUNT: passed=[0-9]+ failed=[0-9]+ ignored=[0-9]+ suites=[0-9]+$' || true)
[ -n "$count" ] || { echo 'the gate did not print a count' >&2; git_run stash pop > /dev/null; exit 1; }
case "$count" in
    *"failed=0 "*) ;;
    *) echo "the gate is red: $count" >&2; git_run stash pop > /dev/null; exit 1 ;;
esac
passed=$(printf '%s' "$count" | sed -E 's/^COUNT: passed=([0-9]+) .*/\1/')
ignored=$(printf '%s' "$count" | sed -E 's/.* ignored=([0-9]+) .*/\1/')
suites=$(printf '%s' "$count" | sed -E 's/.* suites=([0-9]+)$/\1/')

echo '=== the stash comes back ==='
git_run stash pop > /dev/null

if [ "$no_count" -eq 0 ]; then
    echo '=== the count in the working notes and the workflow ==='
    today=$(date +%Y-%m-%d)
    # The count and the note that says what it was taken after: the script
    # writes the note into the newest clause of the count's history and
    # leaves the older clauses alone.
    if ! bash "$here/stamp-count.sh" \
        --agents "$repo/AGENTS.md" \
        --workflow "$repo/.github/workflows/ci.yml" \
        --passed "$passed" --ignored "$ignored" \
        --date "$today" --note "$note"; then
        echo 'the count was not stamped' >&2
        exit 1
    fi
    git_run add -- AGENTS.md > /dev/null
    git_run add -- .github/workflows/ci.yml > /dev/null
fi

echo '=== the commit ==='
git_run commit -F "$repo/$message" > /dev/null || { echo "the commit failed" >&2; exit 1; }
echo "committed: $(git_run log --oneline -1)"
echo "the tree of that commit: $passed passed, $ignored ignored, $suites suites"
