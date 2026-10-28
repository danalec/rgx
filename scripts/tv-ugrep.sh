#!/usr/bin/env bash
# The fourth baseline, under the house protocol: ugrep beside ripgrep,
# direct rgx and the pack store.
#
# What this fills in: the paper's Setup says "not run here: ugrep" and then
# declines to place the store against it. This runs ugrep under the same
# gate -- thread-matched (`ugrep -J` is its jobs flag; `-j` is its
# smart-case and must not be used as one), same patterns, same corpus,
# summed -c equality first, minimum of rotated rounds second.
#
# Usage:
#   bash scripts/tv-ugrep.sh --store STORE --root CORPUS [--threads N] [--rounds N]

set -euo pipefail

STORE=""
ROOT=""
THREADS=10
ROUNDS=7
PATTERNS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --store)   STORE="$2"; shift 2 ;;
    --root)    ROOT="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --rounds)  ROUNDS="$2"; shift 2 ;;
    --patterns) IFS='|' read -r -a PATTERNS <<< "$2"; shift 2 ;;
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
command -v ugrep >/dev/null || { echo "ugrep not on PATH (winget install Genivia.ugrep)" >&2; exit 2; }
command -v rg >/dev/null || { echo "ripgrep not on PATH" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TIMEFORMAT='%3R'

sum_counts() { sed -E 's/^.*:([0-9]+)$/\1/' "$1" | awk '{n += $1} END {print n + 0}'; }

# ugrep on Windows does not recurse over a backslash path -- it silently
# answers nothing and exits 1, which a count gate reads as a corpus with no
# matches. A mixed C:/ path recurses; so does `-r`. Normalised here rather
# than in the caller's arguments so rg and rgx keep the shape they shipped.
ROOT_UG="$(printf '%s' "$ROOT" | sed 's|\\|/|g')"

run_arm() {
  case "$1" in
    tv)  "$TV" -c -j "$THREADS" "$2" --engine tv --tv-store "$STORE" ;;
    rgx) RGX_ENGINE=rgx "$RGX" -c -j "$THREADS" "$2" "$ROOT" ;;
    rg)  rg -c --no-filename -j"$THREADS" "$2" "$ROOT" ;;
    ug)  ugrep -r -c -E -J "$THREADS" -- "$2" "$ROOT_UG" ;;
    *) return 1 ;;
  esac
}

counts_for() {
  ( run_arm "$1" "$2" > "$3" 2>"$3.err" ) || true
  sum_counts "$3"
}

arm() {
  local ms
  ms=$( { time ( run_arm "$1" "$2" > /dev/null 2>/dev/null ) ; } 2>&1 )
  awk -v s="$ms" 'BEGIN{printf "%.1f", s*1000}'
}

# The nine shapes the paper's tables carry, unless --patterns said otherwise.
if [ "${#PATTERNS[@]}" -eq 0 ]; then
  PATTERNS=('e' 'e.' 'foo.*bar' 'e[0-9]' 'a|b' 'pub fn' '(pub|fn) [a-z]+' 'let mut' 'fn main')
fi
ARMS=(rg rgx tv ug)

echo "=== tv-ugrep: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "store=$STORE root=$ROOT threads=$THREADS rounds=$ROUNDS"
echo "arms: rg (ripgrep) | rgx (direct) | tv (pack store) | ug (ugrep -E -J)"
echo "[ms] = best of $ROUNDS paired rounds, arm order rotated, warm cache, wall clock,"
echo "output discarded. Rows with unequal summed -c print counts, not timings."

for pat in "${PATTERNS[@]}"; do
  declare -A best count
  for name in "${ARMS[@]}"; do best[$name]=99999; done

  ref_count=$(counts_for rg "$pat" "$TMP/c-rg.txt")
  gate=0
  for name in "${ARMS[@]}"; do
    count[$name]=$(counts_for "$name" "$pat" "$TMP/c-$name.txt")
    if [ "${count[$name]}" != "$ref_count" ]; then gate=1; fi
    if grep -qi error "$TMP/c-$name.txt.err"; then gate=1; fi
  done

  if [ "$gate" = 0 ] && [ "$ref_count" != 0 ]; then
    for ((r = 0; r < ROUNDS; r++)); do
      for ((k = 0; k < 4; k++)); do
        name="${ARMS[$(( (r + k) % 4 ))]}"
        ms=$(arm "$name" "$pat")
        best[$name]=$(awk -v a="${best[$name]}" -v b="$ms" 'BEGIN{print (b<a)?b:a}')
      done
    done
    printf '%-16s | rg %8.1f | rgx %8.1f | tv %8.1f | ug %8.1f | (ms)\n' \
      "$pat" "${best[rg]}" "${best[rgx]}" "${best[tv]}" "${best[ug]}"
  else
    printf '%-16s | GATE: counts' "$pat"
    for name in "${ARMS[@]}"; do printf ' %s=%s' "$name" "${count[$name]}"; done
    echo
  fi
  unset best count
done
