#!/usr/bin/env bash
# bench-linkers.sh -- A/B/C of rgx linked with the system linker vs lld.
# The Linux counterpart of scripts/bench-linkers.ps1.
#
# Linker choice moves startup and layout, so it is a benchmark input like any
# other: three arms, interleaved rounds, median and minimum per arm.
#
# Two differences from the PowerShell port, both deliberate:
#
#   * the arms are BUILT here, not assumed to exist at fixed paths. The
#     PowerShell script hardcoded three absolute target/ directories, which
#     silently measures whatever was left there from last time; a stale arm
#     is a wrong number, not a missing number.
#   * there is a match-count gate in front of every timing line. The
#     PowerShell port timed three binaries with -c and threw the counts
#     away, so a build whose searcher stopped matching would have printed a
#     beautiful, meaningless median. Per benchmark/status.md: a row whose
#     counts disagree is withheld, not printed with a ratio.
#
# Usage:
#   scripts/bench-linkers.sh
#   scripts/bench-linkers.sh --cpu znver4              # add a target-cpu arm
#   scripts/bench-linkers.sh --big ~/.rgx-big/big.txt
#   scripts/bench-linkers.sh --rounds 9 --no-build
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOTDIR=$(cd "$HERE/.." && pwd)
cd "$ROOTDIR" || exit 2

ROUNDS=9
CPU=""
BIG="${RGX_BIG:-$HOME/.rgx-big/big.txt}"
CORPUS="${RGX_CORPUS:-$HOME/.rgx-bench}"
BUILD=1
KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --rounds)   ROUNDS="${2:-}"; shift 2 ;;
    --cpu)      CPU="${2:-}"; shift 2 ;;
    --big)      BIG="${2:-}"; shift 2 ;;
    --corpus)   CORPUS="${2:-}"; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    --keep)     KEEP=1; shift ;;
    -h|--help)  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$ROUNDS" in
  ''|*[!0-9]*) echo "--rounds must be a number" >&2; exit 2 ;;
esac
[ "$ROUNDS" -ge 3 ] || { echo "fewer than 3 rounds is not a measurement" >&2; exit 2; }

command -v cargo >/dev/null 2>&1 || { echo "cargo not on PATH" >&2; exit 2; }

# arm name -> target subdirectory
NAMES="generic"
DIRS="bench-generic"
# lld is an opt-in arm because it may not be installed; `-fuse-ld=lld` on a
# toolchain without it fails the build, not the benchmark.
if command -v ld.lld >/dev/null 2>&1 || command -v lld >/dev/null 2>&1; then
  NAMES="$NAMES lld"
  DIRS="$DIRS bench-lld"
fi
if [ -n "$CPU" ]; then
  NAMES="$NAMES lld-$CPU"
  DIRS="$DIRS bench-lld-$CPU"
fi

# Each arm gets its own target directory so cargo cannot reuse the previous
# arm's objects: sharing one target dir is how "lld" silently measures the
# generic build.
build_arm() {
  local dir="$1" flags="$2"
  if [ "$BUILD" = "0" ]; then return 0; fi
  echo "== building $dir =="
  RUSTFLAGS="$flags" CARGO_TARGET_DIR="$ROOTDIR/target/$dir" \
    cargo build --release --bin rgx >/dev/null || { echo "build failed: $dir" >&2; return 1; }
}

i=0
for n in $NAMES; do
  dir=$(echo "$DIRS" | cut -d' ' -f$((i + 1)))
  case "$n" in
    generic)    build_arm "$dir" "" ;;
    lld)        build_arm "$dir" "-C link-arg=-fuse-ld=lld" ;;
    lld-*)      build_arm "$dir" "-C link-arg=-fuse-ld=lld -C target-cpu=$CPU" ;;
  esac || exit 2
  i=$((i + 1))
done

EXES=""
i=0
for n in $NAMES; do
  dir=$(echo "$DIRS" | cut -d' ' -f$((i + 1)))
  exe="$ROOTDIR/target/$dir/release/rgx"
  [ -x "$exe" ] || exe="$ROOTDIR/target/$dir/release/rgx.exe"
  [ -x "$exe" ] || { echo "missing arm binary: $dir (run without --no-build)" >&2; exit 2; }
  EXES="$EXES $n=$exe"
  i=$((i + 1))
done

median() { LC_ALL=C sort -n | awk -v n="$1" 'NR==int((n+1)/2){print $1}'; }

run_scenario() {  # run_scenario <name> <pattern> <path>
  local name="$1" pat="$2" path="$3"
  if [ ! -e "$path" ]; then
    echo "$name: SKIP (corpus missing: $path)"
    return 0
  fi

  # Count gate, before anything is timed.
  local ref="" spec v n out
  for spec in $EXES; do
    n="${spec%%=*}"; out=$("${spec#*=}" -c "$pat" "$path" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
    if [ -z "$ref" ]; then ref="$out"; fi
    if [ "$out" != "$ref" ]; then
      echo "$name: WITHHELD (match counts disagree: $n=$out vs $ref) -- no timing printed"
      return 0
    fi
  done

  # Warmup every arm once, so the first timed round is not paying for the
  # page cache being cold on one arm and not the others.
  for spec in $EXES; do "${spec#*=}" -c "$pat" "$path" >/dev/null 2>&1; done

  local times start end samples
  for spec in $EXES; do
    n="${spec%%=*}"
    samples=""
    r=0
    while [ "$r" -lt "$ROUNDS" ]; do
      start=$(date +%s%N)
      "${spec#*=}" -c "$pat" "$path" >/dev/null 2>&1
      end=$(date +%s%N)
      samples="$samples $(( (end - start) / 1000000 ))"
      r=$((r + 1))
    done
    times="$times $n=$samples"
  done

  echo "$name: (count $ref, $ROUNDS rounds)"
  local base=""
  for spec in $EXES; do
    n="${spec%%=*}"
    s=$(echo "$times" | tr ' ' '\n' | grep "^$n=" | cut -d= -f2)
    med=$(echo "$s" | median "$(echo "$s" | wc -w | tr -d ' ')")
    mn=$(echo "$s" | LC_ALL=C sort -n | head -1)
    [ -z "$base" ] && base="$med"
    printf '  %-14s median %8s ms   min %8s ms   x%s\n' "$n" "$med" "$mn" \
      "$(awk -v b="$base" -v m="$med" 'BEGIN{printf "%.3f", (m>0? b/m : 0)}')"
  done
}

times=""
run_scenario corpus     "ZIRCALOY"          "$CORPUS"
run_scenario big-literal "ZIRCALOY"          "$BIG"
run_scenario big-regex  "line [0-9]+ filler" "$BIG"

if [ "$KEEP" = "1" ]; then
  echo
  echo "arms left in: $(for d in $DIRS; do printf 'target/%s ' "$d"; done)"
fi