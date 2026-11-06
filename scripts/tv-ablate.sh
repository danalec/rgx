#!/usr/bin/env bash
# End-to-end tier ablation for the pack store, under the house protocol.
#
# What this fills in: the two rows of the paper's ablation ledger that say
# "not run (no switch)" -- the same query over the same store with one tier
# disabled at a time. The switches are `RGX_ABLATE_NGRAM` (the per-file
# signature stands down) and `RGX_ABLATE_MASK` (the compiled mask is not
# built); both may change cost and must never change answers, and the count
# gate below is what enforces the second half.
#
# Protocol, identical to `tv-vs-rg.sh`: one untimed count pass per arm
# first (the gate), then ROUNDS timed rounds with the arm order rotated per
# round, wall clock around the whole process, output discarded, and the
# MINIMUM reported -- the uncontended floor of a warm run. No cache drop:
# these are warm-cache numbers, as the paper's Setup says.
#
# Usage:
#   bash scripts/tv-ablate.sh --store STORE --root CORPUS [--threads N] [--rounds N]
#
# The store must already exist (`rgx --tv-build CORPUS --tv-store STORE`).

set -euo pipefail

STORE=""
ROOT=""
THREADS=10
ROUNDS=7
while [ $# -gt 0 ]; do
  case "$1" in
    --store)   STORE="$2"; shift 2 ;;
    --root)    ROOT="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --rounds)  ROUNDS="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 1 ;;
  esac
done
[ -n "$STORE" ] && [ -n "$ROOT" ] || { echo "--store and --root are required" >&2; exit 1; }

# One binary in two spellings: the Windows name first, then the bare
# one, because the Unix host has no `.exe` and the Windows host has no
# bare `rgx`. The TV engine is a flag of the main binary, not a second
# program, so both arms run the one that exists.
RGX="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx.exe"
[ -x "$RGX" ] || RGX="${RGX%.exe}"
TV="$RGX"
[ -x "$RGX" ] || { echo "build --release first" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TIMEFORMAT='%3R'

# `-c` lines are `path:count`, and a Windows path carries its own colon at
# position 2. The trailing run of digits is the count in every case.
sum_counts() { sed -E 's/^.*:([0-9]+)$/\1/' "$1" | awk '{n += $1} END {print n + 0}'; }

# Set the ablation env for one arm. Runs inside the caller's subshell, so
# the exports never leak into the next arm.
select_arm() {
  case "$1" in
    base)     unset RGX_ABLATE_NGRAM RGX_ABLATE_MASK ;;
    no-ngram) export RGX_ABLATE_NGRAM=1; unset RGX_ABLATE_MASK ;;
    no-mask)  export RGX_ABLATE_MASK=1; unset RGX_ABLATE_NGRAM ;;
    both-off) export RGX_ABLATE_NGRAM=1 RGX_ABLATE_MASK=1 ;;
    *) echo "unknown arm $1" >&2; return 1 ;;
  esac
}

counts_for() {
  local name="$1" pat="$2" out="$3"
  ( select_arm "$name"; "$TV" -c -j "$THREADS" "$pat" --engine tv --tv-store "$STORE" > "$out" 2>"$out.err" )
  sum_counts "$out"
}

# One timed sample of one arm, in milliseconds, output discarded.
arm() {
  local name="$1" pat="$2" ms
  ms=$( { time ( select_arm "$name"; "$TV" -c -j "$THREADS" "$pat" --engine tv --tv-store "$STORE" > /dev/null 2>/dev/null ) ; } 2>&1 )
  awk -v s="$ms" 'BEGIN{printf "%.1f", s*1000}'
}

PATTERNS=('e' 'e.' 'foo.*bar' 'e[0-9]' 'a|b' 'pub fn' '(pub|fn) [a-z]+' 'let mut' 'fn main')
ARMS=(base no-ngram no-mask both-off)

echo "=== tv-ablate: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "store=$STORE root=$ROOT threads=$THREADS rounds=$ROUNDS"
echo "arms: base | no-ngram (RGX_ABLATE_NGRAM=1) | no-mask (RGX_ABLATE_MASK=1) | both-off"
echo "[ms] = best of $ROUNDS paired rounds, arm order rotated, warm cache, wall clock,"
echo "output discarded. An arm whose summed -c differs from base's is a false negative"
echo "or a superset: its row prints the counts and no timings."

for pat in "${PATTERNS[@]}"; do
  declare -A best count
  for name in "${ARMS[@]}"; do best[$name]=99999; done

  # The gate: the count is the cheapest thing that can disagree, and a
  # whole table of zeros "passes" a count gate, so the row is refused when
  # the base arm counted nothing or any arm complained on stderr. A stale
  # binary that rejects the store reads as an empty answer otherwise, and
  # the harness printed a full table of that once.
  ref_count=$(counts_for base "$pat" "$TMP/c-base.txt")
  gate=0
  why=""
  for name in "${ARMS[@]}"; do
    count[$name]=$(counts_for "$name" "$pat" "$TMP/c-$name.txt")
    if [ "${count[$name]}" != "$ref_count" ]; then gate=1; why="$why $name-count=${count[$name]}"; fi
    if grep -qi error "$TMP/c-$name.txt.err"; then gate=1; why="$why $name-stderr"; fi
  done
  if [ "$ref_count" = 0 ]; then gate=1; why="$why base-count=0"; fi

  if [ "$gate" = 0 ]; then
    for ((r = 0; r < ROUNDS; r++)); do
      for ((k = 0; k < 4; k++)); do
        name="${ARMS[$(( (r + k) % 4 ))]}"
        ms=$(arm "$name" "$pat")
        best[$name]=$(awk -v a="${best[$name]}" -v b="$ms" 'BEGIN{print (b<a)?b:a}')
      done
    done
    printf '%-16s | base %8.1f | no-ngram %8.1f | no-mask %8.1f | both-off %8.1f | (ms)\n' \
      "$pat" "${best[base]}" "${best[no-ngram]}" "${best[no-mask]}" "${best[both-off]}"
  else
    printf '%-16s | GATE FAILED: summed counts' "$pat"
    for name in "${ARMS[@]}"; do printf ' %s=%s' "$name" "${count[$name]}"; done
    echo
  fi
  unset best count
done
