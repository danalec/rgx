#!/usr/bin/env bash
# compare-rg.sh -- parity of rgx against ripgrep on a real corpus.
#
# The Linux counterpart of scripts/compare-rg.ps1, case for case. Porting
# rather than rewriting is the point: a parity harness that exists on one
# platform only is a parity harness nobody runs on the other one, and the
# two platforms disagree about exactly the things that break it.
#
# Two things must be normalized before the two outputs can be compared, and
# both are properties of the platform rather than of either searcher:
#
#   1. the path separator. rg prints what the OS gave it (backslash on
#      Windows); rgx normalizes to '/', which MANUAL.md documents as the
#      normalization under which the file sets are identical. On Linux the
#      substitution is a no-op -- it stays in the script so the two ports
#      cannot drift apart on the one thing that is hardest to debug later.
#   2. the ORDER. Both tools search in parallel and neither promises an
#      order, so a corpus-wide comparison sorts before it compares.
#
# The sort is `LC_ALL=C sort`, not a locale sort: byte order is the only
# ordering both sides can agree on without agreeing on a locale, and under a
# UTF-8 collation the digests diverge for reasons that have nothing to do
# with the searcher.
#
# Outputs go through files, never through the shell: the line-output cases
# on a 56k-file corpus emit hundreds of thousands of lines, and a shell
# pipeline over that is slower by an order of magnitude than the search it
# is checking.
#
# Usage:
#   scripts/compare-rg.sh
#   scripts/compare-rg.sh --corpus crates
#   scripts/compare-rg.sh --root /path/to/tree --pattern 'pub fn' --ext '*.rs'
#   scripts/compare-rg.sh --rgx target/release/rgx --rg /usr/bin/rg
set -u

RGX="target/release/rgx.exe"
[ -x "$RGX" ] || RGX="target/release/rgx"
RG="rg"
CORPUS="registry"
PATTERN="pub fn"
EXT="*.rs"
ROOT=""

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --rgx)   RGX="${2:-}"; shift 2 ;;
    --rg)    RG="${2:-}"; shift 2 ;;
    --corpus) CORPUS="${2:-}"; shift 2 ;;
    --pattern) PATTERN="${2:-}"; shift 2 ;;
    --ext)   EXT="${2:-}"; shift 2 ;;
    --root)  ROOT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
ROOTDIR=$(cd "$HERE/.." && pwd)
cd "$ROOTDIR" || exit 2

[ -x "$RGX" ] || { echo "rgx not found or not executable: $RGX" >&2; exit 2; }
command -v "$RG" >/dev/null 2>&1 || { echo "ripgrep not on PATH (--rg to point at it)" >&2; exit 2; }

if [ -n "$ROOT" ]; then
  corpus_root="$ROOT"
  CORPUS="custom"
elif [ "$CORPUS" = "registry" ]; then
  corpus_root="${CARGO_HOME:-$HOME/.cargo}/registry/src"
  [ -d "$corpus_root" ] || { echo "corpus missing: $corpus_root (run 'cargo fetch')" >&2; exit 2; }
else
  corpus_root="crates"
fi
[ -d "$corpus_root" ] || { echo "corpus root is not a directory: $corpus_root" >&2; exit 2; }

# name|extra argv|pattern override. The names are the PowerShell port's, so
# a failure reported on either platform names the same case.
CASES='-c (count)|-- -c||0
-l (list)|-- -l||0
-o -c (reads lines)|-- -o -c||0
-c -m 3|-- -c -m 3||0
-l -m 2|-- -l -m 2||0
-c (no match)|-- -c||ZZZ-no-such-needle-ZZZ
-l (no match)|-- -l||ZZZ-no-such-needle-ZZZ
-q (quiet)|-- -q||0
-c -A1 (context)|-- -c -A 1||0
default line output|--||0
-o (reads lines)|-- -o||0
-r X (reads lines)|-- -r X||0
-o -r groups|-- -o -r [$2=$1]|(\w+)\s*=\s*(\w+)
-o -r bare dollar|-- -o -r X$1X|(\w+)\s*=\s*(\w+)
-o -r braced|-- -o -r X${1}Y|(\w+)\s*=\s*(\w+)
-o -r named|-- -o -r $2=$1|(?<key>\w+)\s*=\s*(?<val>\w+)
--json|-- --json||0
default -A1 -B1|-- -A 1 -B 1||0
-v (invert)|-- -v||0'

TMP=$(mktemp -d "${TMPDIR:-/tmp}/cmp-rg.XXXXXX") || exit 2
# The trap matters: on the FAIL path this script exits non-zero with the last
# corpus-wide outputs still on disk, and those are the evidence for the
# divergence it just reported.
trap 'rm -rf "$TMP"' EXIT

# Normalize, sort, digest. `sed` for the separator, LC_ALL=C for the order,
# and sha256sum for the comparison -- all three external on purpose; the
# in-shell alternative is what makes this slow enough to skip running.
digest() {
  sed 's|\\|/|g' "$1" | LC_ALL=C sort > "$2"
  wc -l < "$2" | tr -d ' '
}

total=0
fail=0

echo "corpus: $CORPUS ($corpus_root)"
echo "rg    : $(command -v "$RG")"
echo "rgx   : $RGX"
echo

while IFS='|' read -r name extra pat; do
  [ -n "$name" ] || continue
  total=$((total + 1))
  use_pat="$PATTERN"
  [ "$pat" != "0" ] && use_pat="$pat"

  # shellcheck disable=SC2086 -- $extra is a deliberate argv split.
  set -- $extra "$use_pat" -g "$EXT" "$corpus_root"

  "$RG"  "$@" >"$TMP/rg.txt"  2>"$TMP/rg.err";  ec_rg=$?
  "$RGX" "$@" >"$TMP/rgx.txt" 2>"$TMP/rgx.err"; ec_rgx=$?

  n_rg=$(digest "$TMP/rg.txt"  "$TMP/rg.norm")
  n_rgx=$(digest "$TMP/rgx.txt" "$TMP/rgx.norm")
  h_rg=$(sha256sum <"$TMP/rg.norm"  | cut -d' ' -f1)
  h_rgx=$(sha256sum <"$TMP/rgx.norm" | cut -d' ' -f1)

  # exit codes are the other half of rg's contract: 0 = matched, 1 = none.
  if [ "$h_rg" = "$h_rgx" ] && [ "$ec_rg" = "$ec_rgx" ]; then
    printf '  OK    %-24s %9s lines  exit %s\n' "$name" "$n_rg" "$ec_rg"
  else
    fail=$((fail + 1))
    printf '  FAIL  %-24s rg=%s rgx=%s  exit rg=%s rgx=%s\n' "$name" "$n_rg" "$n_rgx" "$ec_rg" "$ec_rgx"
    # First divergent lines. Sorted inputs make this a plain diff, and the
    # head is the answer to "what broke" in nearly every real failure.
    diff "$TMP/rg.norm" "$TMP/rgx.norm" | head -6 | sed 's/^/        /'
    [ -s "$TMP/rgx.err" ] && sed 's/^/        rgx stderr: /' "$TMP/rgx.err" | head -3
  fi
done <<EOF
$CASES
EOF

echo
if [ "$fail" -eq 0 ]; then
  echo "parity: all $total cases byte-identical (separator-normalized, sorted), exit codes equal"
  exit 0
fi
echo "parity: $fail of $total cases diverged"
exit 1