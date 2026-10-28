#!/usr/bin/env bash
# detect-ccd.sh -- CPU topology, from /sys. The Linux counterpart of
# scripts/detect-ccd.ps1.
#
# The Windows script reaches into kernel32 with GetLogicalProcessorInformation
# because Win32 has no filesystem answer to "how is this machine laid out".
# Linux does have one, and it is the same answer: everything below is read
# from /sys/devices/system/cpu, which is what the kernel exports and what
# every topology tool on Linux reads.
#
# Why a benchmark cares. An AMD Zen CCD owns its own slice of L3, so a run
# with threads spread over two CCDs does not measure the same machine as a
# run with threads inside one. The reported figures are the inputs to that
# choice -- how many threads fit inside one CCD, and how many share an L2.
# On Intel, where die_id is absent, it prints the package/core shape and
# says the CCD split does not apply rather than inventing one.
#
# Usage:
#   scripts/detect-ccd.sh
#   scripts/detect-ccd.sh --cores-only    # just the suggested thread count
set -u

SYS=/sys/devices/system/cpu
CORES_ONLY=0
[ "${1:-}" = "--cores-only" ] && CORES_ONLY=1

[ -d "$SYS" ] || { echo "no $SYS on this machine" >&2; exit 2; }

cpus=$(echo "$SYS"/cpu[0-9]* | tr ' ' '\n' | sed 's|.*/||' | sort -V)
[ -n "$cpus" ] || { echo "no cpus under $SYS" >&2; exit 2; }
ncpu=$(echo "$cpus" | wc -l | tr -d ' ')

field() {  # field <cpu> <topology-entry>
  cat "$SYS/$1/topology/$2" 2>/dev/null || echo "?"
}

packages=$(for c in $cpus; do field "$c" physical_package_id; done | sort -u | tr '\n' ' ')
dies=$(for c in $cpus; do field "$c" die_id; done | sort -u | tr '\n' ' ')
cores=$(for c in $cpus; do printf '%s:%s\n' "$(field "$c" physical_package_id)" "$(field "$c" core_id)"; done | sort -u | wc -l | tr -d ' ')

# Threads per core, counted from the sibling lists rather than assumed: SMT
# is not always on, and a benchmark that thinks it has 16 physical cores on a
# 8-core machine draws its thread sweep wrong.
smt=$(echo "$(field "$(echo "$cpus" | head -1)" thread_siblings_list)" | tr ',' '\n' | wc -l | tr -d ' ')

# L2/L3 sharing. `shared_cpu_list` is the kernel's own answer to which cores
# fight over the same cache, which is the whole question.
cache_share() {  # cache_share <level>
  local lvl="$1" dir idx
  for idx in "$SYS"/cpu*/cache/index*; do
    [ -d "$idx" ] || continue
    [ "$(cat "$idx/level" 2>/dev/null)" = "$lvl" ] || continue
    [ "$(cat "$idx/type" 2>/dev/null)" = "Unified" ] || continue
    dir="$idx"; break
  done
  [ -n "${dir:-}" ] || return 1
  cat "$dir/shared_cpu_list" 2>/dev/null
}

# shared_cpu_list uses "0-3,8,10-11": a comma-separated mix of single CPUs and
# inclusive ranges. Counting elements with `wc -l` reads "0-15" as one CPU,
# which is how a 16-thread L3 gets reported as shared by one.
count_cpus() {
  local spec="$1" part lo hi total=0
  local IFS=','
  for part in $spec; do
    case "$part" in
      *-*) lo=${part%%-*}; hi=${part##*-}; total=$((total + hi - lo + 1)) ;;
      *)   total=$((total + 1)) ;;
    esac
  done
  echo "$total"
}

[ "$CORES_ONLY" = "1" ] && { echo "$cores"; exit 0; }

echo "machine"
echo "  logical cpus        : $ncpu"
echo "  physical cores      : $cores"
echo "  threads per core    : $smt"
echo "  packages (socket)   : $packages"
echo "  dies (CCD)          : $dies"

ndies=$(echo "$dies" | wc -w | tr -d ' ')
case "$ndies" in
  0|1)
    echo "  CCD split           : not applicable (no die_id exported; Intel or a single die)"
    ;;
  *)
    # Threads that fit inside one CCD: the smallest die, counted in logical
    # cpus. This is the figure a thread sweep should stay under.
    smallest=$(for c in $cpus; do field "$c" die_id; done | sort | uniq -c | sort -n | head -1 | awk '{print $1}')
    echo "  CCD split           : yes, $ndies dies"
    echo "  logical cpus / CCD  : $smallest (smallest)"
    echo "  cores / CCD         : $((smallest / (smt > 0 ? smt : 1)))"
    ;;
esac

echo
echo "cache sharing"
for lvl in 2 3; do
  share=$(cache_share "$lvl")
  if [ -n "${share:-}" ]; then
    size=$(cat "$SYS/cpu0/cache/index0/size" 2>/dev/null)
    printf '  L%s %-8s shared by %s logical cpus: %s\n' "$lvl" "$size" "$(count_cpus "$share")" "$share"
  else
    printf '  L%s not exported by this kernel\n' "$lvl"
  fi
done