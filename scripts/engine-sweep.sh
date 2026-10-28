#!/usr/bin/env bash
# Which engine is faster for which pattern, on one store.
#
# The pack can run `grep`'s matcher or the project's own byte engine
# (`--engine rgx`). Neither wins everywhere — `e` is 26% faster in-house and
# `pub fn` is 4% slower — so this asks the question a detector would have to
# answer: what predicts the sign?
#
# The two passes are the count pass (untimed, to a file, because writing
# `-c` output to a file on this volume costs 400 ms) and the timing pass
# (`/dev/null`). Best of N, count gate first: an arm whose count differs from
# the reference does not enter the table.
set -u

STORE=""; ROUNDS=7
while [ $# -gt 0 ]; do
  case "$1" in
    --store) STORE="$2"; shift 2;;
    --rounds) ROUNDS="$2"; shift 2;;
    *) echo "unknown option $1" >&2; exit 1;;
  esac
done
[ -n "$STORE" ] || { echo "--store is required" >&2; exit 1; }

TV="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx.exe"
[ -x "$TV" ] || TV="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx"
[ -x "$TV" ] || { echo "build --release first" >&2; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
TIMEFORMAT='%3R'

PATTERNS=(
  'e' 'q' 'zzz' 'nonexistent_token_xyz'
  'fn' 'ab' 'pub' 'let'
  'pub fn' 'let mut' 'fn main'
  'a|b|c' 'pub|fn' 'foo|bar|baz'
  'e[0-9]' '[a-z]+' '\d'
  '^pub' 'pub$' '\bfoo\b'
  'e.' 'foo.*bar' 'x{2,4}' 'a+'
  '(?i)PUB' 'pub (fn|struct)'
)

sum() { sed -E 's/^.*:([0-9]+)$/\1/' "$1" | awk '{n += $1} END {print n + 0}'; }

best_ms() {
  local engine="$1" pat="$2" b=99999 t i
  for i in $(seq 1 "$ROUNDS"); do
    t=$( { time "$TV" -c -j 32 --engine "$engine" "$pat" --tv-store "$STORE" >/dev/null 2>&1; } 2>&1 )
    t=$(awk -v x="$t" 'BEGIN{printf "%.0f", x*1000}')
    [ "$t" -lt "$b" ] && b=$t
  done
  echo "$b"
}

printf '%-22s %12s %8s %8s %9s\n' pattern lines auto inhouse delta
printf '%s\n' "--------------------------------------------------------------------------------"
for pat in "${PATTERNS[@]}"; do
  "$TV" -c -j 32 "$pat" --tv-store "$STORE" > "$TMP/g.txt" 2>/dev/null
  ref=$(sum "$TMP/g.txt")
  "$TV" -c -j 32 --engine rgx "$pat" --tv-store "$STORE" > "$TMP/r.txt" 2>/dev/null
  got=$(sum "$TMP/r.txt")
  if [ "$got" != "$ref" ]; then
    printf '%-22s %12s %8s %8s %9s\n' "$pat" "$ref" - - "COUNT"
    continue
  fi
  g=$(best_ms auto "$pat")
  r=$(best_ms rgx "$pat")
  printf '%-22s %12s %7sms %7sms %8s\n' "$pat" "$ref" "$g" "$r" \
    "$(awk -v g="$g" -v r="$r" 'BEGIN{printf "%+.1f%%", (r-g)/g*100}')"
done
