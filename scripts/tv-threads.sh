#!/usr/bin/env bash
# The thread-count sweep for `rgx-tv search`, on the clock a user is timed by.
#
# The work stage of a pack query is memory-bandwidth-bound, not CPU-bound: the
# whole store has to come through the page cache whatever the thread count is,
# and past the point where the copies saturate the extra threads only add
# contention on the same L2s and the same memory controller. The default has to
# be found by measurement, not by `available_parallelism`, and it is the one
# knob a one-shot query has that costs nothing to change.
#
# The pairing rules are the ones RGX-TV-AXES.md §2 states, applied to a sweep
# rather than an A/B:
#   - every arm is sampled once per round and the reference arm is sampled in
#     the same round, so the delta is a mean of per-round differences and never
#     two medians taken minutes apart (this machine drifts ~25% over a session);
#   - the order rotates per round, so no arm is permanently first or last;
#   - a count gate in front of every number: the summed `-c` count of an arm
#     must equal the reference's or the arm does not enter the table;
#   - the count comes from one untimed run, every timed run goes to /dev/null --
#     writing 84k count lines to this NTFS volume costs ~400 ms, which is more
#     than the whole query, and charging the search for the harness's own
#     bookkeeping is what once made ripgrep look 6x slower than it is.
#
# Usage:
#   scripts/tv-threads.sh --store <dir> [--pattern 'pub fn'] [--rounds N]
#                         [--arms 8,12,16,32] [--ref 32]
#                         [--mode buf|mmap] [--pool] [--count-gate]
set -u

STORE=""; PATTERN="pub fn"; ROUNDS=9
ARMS=(4 8 12 16 20 24 32); REF=""; MODE="buf"; POOL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --store) STORE="$2"; shift 2;;
    --pattern) PATTERN="$2"; shift 2;;
    --rounds) ROUNDS="$2"; shift 2;;
    --arms) IFS=',' read -r -a ARMS <<< "$2"; shift 2;;
    --ref) REF="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    --pool) POOL=1; shift;;
    -h|--help) sed -n '2,22p' "$0"; exit 0;;
    *) echo "unknown option $1" >&2; exit 1;;
  esac
done
[ -n "$STORE" ] || { echo "--store is required" >&2; exit 1; }
[ -n "$REF" ] || REF="${ARMS[${#ARMS[@]}-1]}"

TV="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx.exe"
[ -x "$TV" ] || TV="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx"
[ -x "$TV" ] || { echo "build --release first" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TIMEFORMAT='%3R'

# The read mode is a flag on the same line as everything else, so the two axes
# can be swept together and the pool is only reachable on the mmap arm.
extra=""
case "$MODE" in
  buf)  extra="--no-mmap";;
  mmap) extra="--mmap";;
  *) echo "--mode is buf or mmap" >&2; exit 1;;
esac
[ "$POOL" = 1 ] && extra="$extra --pool"

# An arm named `auto` is the query with no `-j` at all, which is the arm a user
# actually runs; the numbered arms are the two widths it chooses between.
jflag() {
  case "$1" in
    auto) printf '' ;;
    *) printf -- '-j %s' "$1" ;;
  esac
}

run() { # arm -> writes "seconds countfile"
  local j="$1" out="$2" t
  t=$({ time "$TV" -c $(jflag "$j") --engine tv --tv-store "$STORE" $extra "$PATTERN" \
        > /dev/null 2> /dev/null; } 2>&1)
  printf '%s %s\n' "$t" "$out"
}

count_for() {
  "$TV" -c $(jflag "$REF") --engine tv --tv-store "$STORE" $extra "$PATTERN" > "$1" 2>/dev/null
}

sum_counts() { sed -E 's/^.*:([0-9]+)$/\1/' "$1" | awk '{n += $1} END {print n + 0}'; }

REF_COUNT_FILE="$TMP/count.$REF"
count_for "$REF_COUNT_FILE"
REF_COUNT="$(sum_counts "$REF_COUNT_FILE")"
echo "# store=$STORE pattern='$PATTERN' mode=$MODE pool=$POOL rounds=$ROUNDS"
echo "# reference arm: $REF   (match count $REF_COUNT)"

for a in "${ARMS[@]}"; do
  count_for "$TMP/count.$a"
  n="$(sum_counts "$TMP/count.$a")"
  if [ "$n" != "$REF_COUNT" ]; then
    echo "-j$a GATE FAILED: $n != $REF_COUNT, not in the table"
  fi
done

# Per-round samples, one line per round per arm: arm round seconds
: > "$TMP/samples"
for ((r = 0; r < ROUNDS; r++)); do
  n=${#ARMS[@]}
  for ((k = 0; k < n; k++)); do
    a="${ARMS[$(( (k + r) % n ))]}"
    t=$({ time "$TV" -c $(jflag "$a") --engine tv --tv-store "$STORE" $extra "$PATTERN" \
          > /dev/null 2> /dev/null; } 2>&1)
    printf '%s %d %s\n' "$a" "$r" "$t" >> "$TMP/samples"
  done
done

echo
echo "| threads | min ms | median ms | paired vs arm \`$REF\` |"
echo "|---:|---:|---:|---:|"
for a in "${ARMS[@]}"; do
  [ "$(sum_counts "$TMP/count.$a")" = "$REF_COUNT" ] || continue
  awk -v arm="$a" -v ref="$REF" -v rounds="$ROUNDS" '
    { v[$1, $2] = $3 * 1000 }
    END {
      for (i = 0; i < rounds; i++) {
        r = v[ref, i]
        if (r != "") { n++; d = (v[arm, i] - r) / r * 100; s += d }
      }
      m = 0
      for (i = 0; i < rounds; i++) if (v[arm, i] != "") { t[m++] = v[arm, i] }
      asort_lo = 0
      # insertion sort, n <= ROUNDS
      for (i = 1; i < m; i++) { x = t[i]; j = i - 1
        while (j >= 0 && t[j] > x) { t[j+1] = t[j]; j-- }
        t[j+1] = x }
      med = m % 2 ? t[int(m/2)] : (t[m/2-1] + t[m/2]) / 2
      printf "| %s | %.1f | %.1f | %s |\n", arm, t[0], med,
             n ? sprintf("%+.1f%%", s / n) : "n/a"
    }' "$TMP/samples"
done
echo
echo "# floor +/-2%: inside it the verdict is a tie, not a ratio."
