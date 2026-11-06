#!/usr/bin/env bash
# mmap vs read path on Linux, large-file-only workload.
# Paired within the round, order rotated, 11 rounds, count gate first.
set -u
# The Windows name first, then the bare one: the Unix host has no
# `.exe` and the Windows host has no bare `rgx`. The one that exists
# is the one the harness runs.
RGX="$HOME/dev/rgx-mmap-measure/target/release/rgx.exe"
[ -x "$RGX" ] || RGX="$HOME/dev/rgx-mmap-measure/target/release/rgx"
CORPUS="$HOME/.rgx-bench/big235.rs"
ROUNDS=11
PATTERNS=("pub fn" "e." "nonexistent_token_xyz")

echo "host  : $(uname -srm)"
echo "cpu   : $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
# The build's own mtime, not a commit id: a hardcoded sha goes stale the next
# commit, and a live `git rev-parse` names an object that a rebase can move.
echo "binary: $RGX  (rgx main, --release, built $(date -u -r "$RGX" +%Y-%m-%dT%H:%M:%SZ))"
echo "corpus: $CORPUS  ($(stat -c%s "$CORPUS") bytes)"
echo "protocol: arms paired inside each round, order rotated, min/median/max"
echo "          of $ROUNDS rounds, '-c -j1', count gate before any timing"
echo

ms() { local s e; s=$(date +%s%N); "$@" >/dev/null 2>&1; e=$(date +%s%N); echo $(( (e - s) / 1000000 )); }
med() { printf '%s\n' "$@" | sort -n | awk '{x[NR]=$1} END{ if (NR%2) print x[(NR+1)/2]; else printf "%.1f\n", (x[NR/2]+x[NR/2+1])/2 }'; }
stats() { printf '%s\n' "$@" | sort -n > /tmp/.mab.$$; local mn=$(head -1 /tmp/.mab.$$) mx=$(tail -1 /tmp/.mab.$$) md=$(med "$@"); rm -f /tmp/.mab.$$; echo "$md $mn $mx"; }

for p in "${PATTERNS[@]}"; do
  ca=$(RGX_MMAP=1 "$RGX" --no-filename -c -- "$p" "$CORPUS" 2>/dev/null | tail -1)
  cb=$(RGX_MMAP=0 "$RGX" --no-filename -c -- "$p" "$CORPUS" 2>/dev/null | tail -1)
  gate="ok"; [ "$ca" = "$cb" ] || gate="COUNTS $ca/$cb"
  a=(); b=()
  for ((r = 0; r < ROUNDS; r++)); do
    if (( r % 2 == 0 )); then
      a+=("$(ms env RGX_MMAP=1 "$RGX" -c -- "$p" "$CORPUS")")
      b+=("$(ms env RGX_MMAP=0 "$RGX" -c -- "$p" "$CORPUS")")
    else
      b+=("$(ms env RGX_MMAP=0 "$RGX" -c -- "$p" "$CORPUS")")
      a+=("$(ms env RGX_MMAP=1 "$RGX" -c -- "$p" "$CORPUS")")
    fi
  done
  read -r amed amin amax <<<"$(stats "${a[@]}")"
  read -r bmed bmin bmax <<<"$(stats "${b[@]}")"
  d=$(awk -v a="$amed" -v b="$bmed" 'BEGIN{printf "%+.1f%%", 100*(a-b)/b}')
  printf '%-22s mmap med %7s (min %s max %s) | read med %7s (min %s max %s) | mmap-read %8s  gate=%s count=%s\n' \
    "$p" "$amed" "$amin" "$amax" "$bmed" "$bmin" "$bmax" "$d" "$gate" "$ca"
done
