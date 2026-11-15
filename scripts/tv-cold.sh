#!/usr/bin/env bash
# Cold-cache protocol: the first query over a store whose pages are gone.
#
# What this fills in: the paper's Setup says every published latency is a
# warm-cache number and that a cold-cache regime is not measured -- on
# Windows there is no drop_caches. This runs on a host that has one: each
# cold sample is preceded by a page-cache drop, so the sample is the first
# query over packs that must come off the device; the warm samples are the
# same query immediately after, which is what the published tables are.
#
# The claim it prices: "a first query over a cold store pays the pack read
# in full and is bounded below by the transport floor". The numbers say
# what "in full" is, and whether the direct arm suffers the same penalty.
#
# Usage:
#   bash scripts/tv-cold.sh --store STORE --root CORPUS [--pattern P]
#       [--samples 5] [--threads N] [--sudo-password PW]
#
# `--sudo-password` is fed to `sudo -S` to write drop_caches; it is held
# in the shell's memory for the run and never written to disk. Omit it to
# run without drops (useless) or when the caller is already root.

set -euo pipefail

STORE=""
ROOT=""
PATTERN="fn main"
SAMPLES=5
THREADS=10
SUDO_PW=""
while [ $# -gt 0 ]; do
  case "$1" in
    --store)   STORE="$2"; shift 2 ;;
    --root)    ROOT="$2"; shift 2 ;;
    --pattern) PATTERN="$2"; shift 2 ;;
    --samples) SAMPLES="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --sudo-password) SUDO_PW="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 1 ;;
  esac
done
[ -n "$STORE" ] && [ -n "$ROOT" ] || { echo "--store and --root are required" >&2; exit 1; }

RGX="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx.exe"
[ -x "$RGX" ] || RGX="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx"
# One binary, two arms: the pack store is a flag set on `rgx`, not a second
# tool. The TV arm is `--engine tv` and the store is named with `--tv-store`.
TV="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx.exe"
[ -x "$TV" ] || TV="$(cd "$(dirname "$0")/.." && pwd)/target/release/rgx"
[ -x "$RGX" ] && [ -x "$TV" ] || { echo "build --release first" >&2; exit 1; }

TIMEFORMAT='%3R'

drop_caches() {
  sync
  if [ -n "$SUDO_PW" ]; then
    printf '%s\n' "$SUDO_PW" | sudo -S sh -c 'echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null
  else
    sudo -n sh -c 'echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null || return 1
  fi
}

# One timed sample of one arm, milliseconds, output discarded.
arm() {
  local ms
  ms=$( { time ( case "$1" in
    tv)  "$TV" -c -j "$THREADS" "$PATTERN" --engine tv --tv-store "$STORE" ;;
    rgx) "$RGX" -c -j "$THREADS" "$PATTERN" "$ROOT" ;;
    rg)  rg -c --no-filename -j"$THREADS" "$PATTERN" "$ROOT" ;;
  esac > /dev/null 2>/dev/null ) ; } 2>&1 )
  awk -v s="$ms" 'BEGIN{printf "%.1f", s*1000}'
}

echo "=== tv-cold: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "store=$STORE root=$ROOT pattern=$PATTERN threads=$THREADS samples=$SAMPLES"
echo "cold = first query after sync + drop_caches; warm = same query right after."
echo "ms, one sample per line; the summary prints min and median per arm."

declare -A PENALTY

for name in tv rgx rg; do
  cold=()
  warm=()
  for ((s = 0; s < SAMPLES; s++)); do
    if ! drop_caches; then
      echo "drop_caches failed; is the sudo password right? (cold samples would be warm)" >&2
      exit 2
    fi
    cold+=("$(arm "$name")")
    warm+=("$(arm "$name")")
  done
  echo "$name cold: ${cold[*]}"
  echo "$name warm: ${warm[*]}"
  printf '%s' "$name" > /tmp/.tv-cold-name
  printf '%s\n' "${cold[@]}" | sort -n > /tmp/.tv-cold-c
  printf '%s\n' "${warm[@]}" | sort -n > /tmp/.tv-cold-w
  cmin=$(head -1 /tmp/.tv-cold-c); cmed=$(sed -n "$(( (SAMPLES + 1) / 2 ))p" /tmp/.tv-cold-c)
  wmin=$(head -1 /tmp/.tv-cold-w); wmed=$(sed -n "$(( (SAMPLES + 1) / 2 ))p" /tmp/.tv-cold-w)
  echo "$name summary: cold min $cmin / med $cmed | warm min $wmin / med $wmed"

  # Cold penalty, with a MAD pass on the cold samples first. The first cold
  # sample after a drop_caches also faults in the binary's own text and the
  # store manifest, so it prices more than the corpus; a mean would publish
  # that artefact as a cache penalty. On the 2026-10-14 run it moved rgx's
  # mean cold to 124.6 ms against a median of 104.0. Dropping is a choice,
  # so what was dropped is printed. See benchmark/findings.md 20.
  read -r pen note <<< "$(awk -v c="${cold[*]}" -v w="${warm[*]}" '
    function med(a, n,   i, j, v, t, m) {
      for (i = 1; i <= n; i++) t[i] = a[i]
      for (i = 2; i <= n; i++) {
        v = t[i]; j = i - 1
        while (j >= 1 && t[j] > v) { t[j+1] = t[j]; j-- }
        t[j+1] = v
      }
      m = int((n + 1) / 2)
      return (n % 2) ? t[m] : (t[m] + t[m+1]) / 2
    }
    BEGIN {
      nc = split(c, C, " "); nw = split(w, W, " ")
      cb = med(C, nc); wb = med(W, nw)
      for (i = 1; i <= nc; i++) { d = C[i] - cb; if (d < 0) d = -d; AD[i] = d }
      mad = med(AD, nc); thr = 3 * 1.4826 * mad
      nk = 0; drop = ""
      for (i = 1; i <= nc; i++) {
        if (mad > 0 && AD[i] > thr) {
          drop = drop sprintf("%ssample %d = %.1f", (drop ? ", " : ""), i, C[i])
        } else { nk++; K[nk] = C[i] }
      }
      pen = (nk ? med(K, nk) : cb) - wb
      printf "%.2f\t%s", pen, drop
    }')"
  if [ -n "$note" ]; then
    echo "$name penalty: $pen ms (cold median minus warm median; MAD-dropped $note)"
  else
    echo "$name penalty: $pen ms (cold median minus warm median)"
  fi
  PENALTY[$name]=$pen
done

# The cache-immunity ratio: what the prepared path saves in cold penalty
# against what the per-file paths pay. A ratio near 1 is the falsifier of
# findings.md 20 -- it says the asymmetry has collapsed and the store's
# query path is as cache-sensitive as a walk.
if [ -n "${PENALTY[tv]:-}" ]; then
  for other in rgx rg; do
    [ -n "${PENALTY[$other]:-}" ] || continue
    ratio=$(awk -v a="${PENALTY[$other]}" -v b="${PENALTY[tv]}" \
      'BEGIN{ printf "%.2f", (b > 0) ? a / b : 0 }')
    echo "$other pays ${ratio}x the prepared arm's cold penalty (${PENALTY[$other]} ms against ${PENALTY[tv]} ms)."
  done
fi
