#!/usr/bin/env bash
# Paired A/B/C of the three search paths over one corpus, one store.
#
# The pairing rules this project uses, applied to the pack:
#   - every arm is sampled once per round and the reference arm is sampled in
#     the same round; the reported number is the minimum of the per-arm
#     samples, never two medians taken minutes apart (this machine drifts ~25%
#     over a long session, which is what RGX-TV-AXES.md §2 is about);
#   - the order rotates per round, so no arm is permanently first;
#   - a count gate in front of every number: the summed match count of an arm
#     must equal the reference's, or the arm does not enter the table;
#   - output goes to a file, never to a pipe -- a pipe reader competing with
#     parallel writers is what made an earlier harness read a 60% regression
#     that was not there.
#
# Usage: tv-vs-rg.sh --store <dir> --root <corpus> [--rounds N] [--threads N]
#                   [--patterns 'a b c'] [--pattern 'pub fn']...
#
# `--pattern` is repeatable and takes one whole pattern as its argument, so
# multi-word patterns survive; `--patterns` still splits on whitespace and is
# kept for the default-shaped invocations.
set -u

STORE=""; ROOT=""; ROUNDS=7; THREADS=32; PATTERNS=("a|b|c" "e" "pub fn" "fn main")
CLI_PATTERNS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --store) STORE="$2"; shift 2;;
    --root) ROOT="$2"; shift 2;;
    --rounds) ROUNDS="$2"; shift 2;;
    --threads) THREADS="$2"; shift 2;;
    --patterns) read -r -a PATTERNS <<< "$2"; shift 2;;
    --pattern) CLI_PATTERNS+=("$2"); shift 2;;
    *) echo "unknown option $1" >&2; exit 1;;
  esac
done
[ ${#CLI_PATTERNS[@]} -gt 0 ] && PATTERNS=("${CLI_PATTERNS[@]}")
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

# `-c` lines are `path:count` on both rgx paths and a bare `count` under
# `rg --no-filename`, and a Windows path carries its own colon at position 2.
# The trailing run of digits is the count in every case, so take that.
sum_counts() { sed -E 's/^.*:([0-9]+)$/\1/' "$1" | awk '{n += $1} END {print n + 0}'; }

# The count and the time come from different runs, on purpose.
#
# `-c` prints one line per matching file -- 83,224 of them on the registry,
# 58,917 bytes -- and writing that to a file on this NTFS volume costs about
# 400 ms, which is 40% of the whole `rg pub fn` query. Charging the search for
# the harness's own bookkeeping produced a table in which ripgrep looked 2x
# slower than it is, and a 6x speedup that was two thirds bookkeeping. So:
# one untimed run per arm writes the counts, and every timed run writes to
# /dev/null.
counts_for() {
  local name="$1" pat="$2" out="$3"
  case "$name" in
    rg)  rg -c --no-filename -j"$THREADS" "$pat" "$ROOT" > "$out" 2>/dev/null ;;
    rgx) RGX_ENGINE=rgx "$RGX" -c -j"$THREADS" "$pat" "$ROOT" > "$out" 2>/dev/null ;;
    tv)  "$TV" -c -j "$THREADS" "$pat" --engine tv --tv-store "$STORE" > "$out" 2>/dev/null ;;
    *) : > "$out"; return 1 ;;
  esac
  sum_counts "$out"
}

# one timed sample of one arm, in milliseconds, output discarded.
arm() {
  local name="$1" pat="$2" ms
  case "$name" in
    rg)  ms=$( { time rg -c --no-filename -j"$THREADS" "$pat" "$ROOT" > /dev/null 2>/dev/null; } 2>&1 ) ;;
    rgx) ms=$( { time RGX_ENGINE=rgx "$RGX" -c -j"$THREADS" "$pat" "$ROOT" > /dev/null 2>/dev/null; } 2>&1 ) ;;
    tv)  ms=$( { time "$TV" -c -j "$THREADS" "$pat" --engine tv --tv-store "$STORE" > /dev/null 2>/dev/null; } 2>&1 ) ;;
    *) echo "0"; return ;;
  esac
  # TIMEFORMAT is seconds; the table is milliseconds.
  awk -v s="$ms" 'BEGIN{printf "%.1f", s*1000}'
}

for pat in "${PATTERNS[@]}"; do
  # one untimed pass per arm: the counts the gate compares
  ref_count=$(counts_for rg  "$pat" "$TMP/c-rg.txt")
  count_rgx=$(counts_for rgx "$pat" "$TMP/c-rgx.txt")
  count_tv=$(counts_for tv  "$pat" "$TMP/c-tv.txt")
  declare -A count=( [rg]="$ref_count" [rgx]="$count_rgx" [tv]="$count_tv" )

  declare -A best
  declare -A seen
  best[rg]=99999; best[rgx]=99999; best[tv]=99999
  seen[rg]=0; seen[rgx]=0; seen[tv]=0
  order=(rg rgx tv)
  for ((r = 0; r < ROUNDS; r++)); do
    # rotate: round 0 runs rg,rgx,tv; round 1 runs rgx,tv,rg; and so on
    for ((k = 0; k < 3; k++)); do
      name="${order[$(( (r + k) % 3 ))]}"
      read -r ms count <<< "$(arm "$name" "$pat") ${count[$name]}"
      if [ "$count" -lt "$ref_count" ]; then
        # Fewer lines than the reference is a false negative, whatever the
        # clock says. It does not enter the table at all.
        best[$name]=-2
        continue
      fi
      if [ "$count" -gt "$ref_count" ]; then
        # More lines is a superset: the adapters render text ripgrep never
        # saw. The time is still real, but it is not the same search, so it
        # is reported with the excess rather than as a ratio.
        best[$name]=$(awk -v a="${best[$name]}" -v b="$ms" 'BEGIN{print (b<a)?b:a}')
        seen[$name]=$(( count - ref_count ))
        continue
      fi
      seen[$name]=0
      best[$name]=$(awk -v a="${best[$name]}" -v b="$ms" 'BEGIN{print (b<a)?b:a}')
    done
  done

  # A ratio only where the two arms counted the same lines. `+N` where the
  # second arm is a superset of the first: the millisecond figure is printed,
  # the multiplier is not, because the two are not the same search.
  ratio() {
    if [ "${seen[$2]}" != "0" ]; then echo "  +${seen[$2]}"; return; fi
    awk -v a="$1" -v b="$3" 'BEGIN{printf "%5.2fx", a/b}'
  }
  cell() {
    if [ "${best[$1]}" = "-2" ]; then echo " FEWER"; return; fi
    printf "%6.0f ms" "${best[$1]}"
  }

  printf '%-10s | %s | %s | %s | vs rg %s | vs direct %s\n' \
    "$pat" "$(cell rg)" "$(cell rgx)" "$(cell tv)" \
    "$(ratio "${best[rg]}" tv "${best[tv]}")" \
    "$(ratio "${best[rgx]}" rgx "${best[tv]}")"
  echo "            ref count ${ref_count}; excess lines vs rg — rgx: ${seen[rgx]}, rgx-tv: ${seen[tv]}  ([ms] = best of ${ROUNDS} paired rounds, -j${THREADS}, order rotated; a +N marks a superset of rg, where no ratio is printed)"
  unset best seen order
done
