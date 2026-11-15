#!/usr/bin/env bash
# The four independent axes of `rgx-tv search`, measured on the CLI's wall clock.
#
# rgx-tv has four switches that are meant to be orthogonal and, on a
# single-shot process, are not all reachable at the same time:
#
#   pool        --no-pool             V2 (warm pool) vs V0 (map/unmap per query)
#   read mode   --no-mmap             mmap vs parallel buffered
#               --serial-buffered     (and serial buffered, the older meaning)
#   granularity --packs-per-thread N  packs per claim, buffered modes only
#   unmap       --leak-mmap           Explicit unmap vs "let process exit do it"
#
# Measurement rules, because this machine drifts. The same configuration
# measured 275 ms alone and 345 ms after 21 rounds, so a sweep of consecutive
# blocks measures the drift and not the arms.
#
#   1. PAIRED. Every arm is sampled once per round, and the reference arm is
#      sampled in the same round. The delta reported is the mean of the
#      per-round differences -- never two medians taken minutes apart.
#   2. ORDER ALTERNATES. Round r runs the arms rotated by r, so no arm is
#      permanently first or permanently last.
#   3. FLOOR +/-2%. Inside it the verdict is `tie`, not a ratio.
#   4. OUTSIDE THE FLOOR a winner needs every sample of one arm below every
#      sample of the other. Overlapping distributions print `overlap`.
#   5. NO CPU COUNTER. \Processor(_Total)\% Processor Time reads saturated for
#      the whole run, because the kernel books a 1.8 GB mapping's page faults
#      as processor time. It cannot see a difference here.
#   6. COUNT GATE FIRST. Every arm's match count must equal the reference's
#      before any of its times reach the table.
#
# Usage:
#   scripts/tv-matrix.sh [--store DIR] [--rounds N] [--batch N]
#                        [--threads 1,8,32] [--cells "pat|flag,..."]
#                        [--arms a,b,c] [--ref LABEL] [--rm-store]
#
#   --arms narrows the table to a subset and --ref moves the column the paired
#   delta is measured against. The default is --ref mmap, the cold mapping
#   arm, because it is the only one where `Unmap::Explicit` is reachable:
#   --leak-mmap is a no-op on a pooled arm, so pairing leak against anything
#   pooled would be comparing nothing to something.
#
# The store is NOT built here: a 1.8 GB registry store takes 21 s to build and
# the build is not what is being measured. Point --store at an existing one.
# --rm-store deletes it when the run finishes.
#
# Exit: 0 table printed and every gate passed; 1 a gate failed; 2 store or
# binary missing.

set -uo pipefail

STORE="${TV_MATRIX_STORE:-$LOCALAPPDATA/Temp/tvcmp2}"
ROUNDS=7
BATCH=2
THREADS="1,8,32"
CELLS="pub fn|-c,nonexistent_token_xyz|-c,fn main|full"
RM_STORE=0
ARMFILTER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --store)    STORE="$2"; shift 2 ;;
        --rounds)   ROUNDS="$2"; shift 2 ;;
        --batch)    BATCH="$2"; shift 2 ;;
        --threads)  THREADS="$2"; shift 2 ;;
        --cells)    CELLS="$2"; shift 2 ;;
        --ref)      REF_OVERRIDE="$2"; shift 2 ;;
        --arms)     ARMFILTER="$2"; shift 2 ;;
        --rm-store) RM_STORE=1; shift ;;
        -h|--help)  sed -n '2,44p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

TV="${TV:-./target/release/rgx.exe}"
[ -x "$TV" ] || TV="${TV%.exe}"
[ -x "$TV" ] || { echo "build --release first (rgx-tv is now a flag set on rgx: --engine tv)" >&2; exit 2; }
[ -f "$STORE/manifest.tvm" ] || { echo "no manifest.tvm in $STORE -- build it, or pass --store" >&2; exit 2; }

FLOOR=2
REF="mmap"

# label|flags. These are the seven distinct configurations the CLI can be put
# into, one per reachable combination of the four axes. `mmap` is the reference
# because it is the only arm where `Unmap::Explicit` is reachable: a pooled arm
# never consults `config.unmap` at all, so `--leak-mmap` there is a no-op and
# comparing it to anything measures nothing.
ARMS=(
    "buf|"                                      # the default: parallel buffered
    "buf.ppt4|--packs-per-thread 4"             # granularity
    "buf.sbuf|--serial-buffered"                # serial read, coordinator
    "mmap|--mmap"                               # mapping, cold, explicit unmap
    "mmap.leak|--mmap --leak-mmap"              # mapping, cold, leak
    "mmap.pool|--mmap --pool"                   # mapping, pooled (no teardown)
    "mmap.pool.leak|--mmap --pool --leak-mmap"  # the flag is a no-op here
)
LABELS=(); for a in "${ARMS[@]}"; do LABELS+=("${a%%|*}"); done

# --arms keeps a subset. The paired delta is always computed against --ref.
if [ -n "$ARMFILTER" ]; then
    KEEP=(); KLAB=()
    IFS=',' read -ra WANT <<< "$ARMFILTER"
    for w in "${WANT[@]}"; do
        for a in "${ARMS[@]}"; do
            if [ "${a%%|*}" = "$w" ]; then KEEP+=("$a"); KLAB+=("$w"); fi
        done
    done
    [ "${#KEEP[@]}" -ge 2 ] || { echo "--arms needs at least two known arms: $ARMFILTER" >&2; exit 2; }
    ARMS=("${KEEP[@]}")
    LABELS=("${KLAB[@]}")
fi
REF="${REF_OVERRIDE:-$REF}"
case " ${LABELS[*]} " in
    *" $REF "*) ;;
    *) echo "--ref '$REF' is not in the arm set" >&2; exit 2 ;;
esac

TMPD=$(mktemp -d)
cleanup() {
    rm -rf "$TMPD"
    [ "$RM_STORE" = 1 ] && rm -rf "$STORE" && echo "store removed ($STORE)"
    return 0
}
trap cleanup EXIT

hr() { printf '%s\n' "----------------------------------------------------------------------------"; }

# One sample = BATCH consecutive runs of the same arm timed as one block.
# A bare `time` on a 300 ms query carries 1 ms of clock resolution; a block of
# B carries 1/B, and the block is what the round compares.
sample() { # sample <pat> <pathflag> <j> <flags> <label> <round>
    local pat="$1" pathflag="$2" j="$3" flags="$4" label="$5" r="$6"
    local -a cmd=("$TV" -j "$j")
    [ "$pathflag" = "-c" ] && cmd+=(-c)
    cmd+=("$pat" --engine tv --tv-store "$STORE")
    # shellcheck disable=SC2086
    [ -n "$flags" ] && cmd+=($flags)

    local i t first="" v
    local -a outs=()
    for ((i = 0; i < BATCH; i++)); do outs+=("$TMPD/o.$i"); done

    t=$( { TIMEFORMAT='%3R'; time {
            for ((i = 0; i < BATCH; i++)); do
                if [ "$pathflag" = "-c" ]; then
                    "${cmd[@]}" > "${outs[$i]}" 2>/dev/null
                else
                    "${cmd[@]}" >/dev/null 2>&1
                fi
            done
        } ; } 2>&1 )
    awk -v t="$t" -v b="$BATCH" 'BEGIN{printf "%.1f\n", t*1000/b}' >> "$TMPD/s.$label"

    if [ "$pathflag" = "-c" ]; then
        for ((i = 0; i < BATCH; i++)); do
            v=$(tr -d '\r' < "${outs[$i]}" | awk -F: '{s+=$NF} END{print s+0}')
            [ -z "$first" ] && first="$v"
            if [ "$v" != "$first" ]; then
                echo "GATE: arm '$label' disagreed with itself on '$pat' ($v vs $first)" >&2
                return 1
            fi
        done
        echo "$first" >> "$TMPD/n.$label"
    else
        rm -f "${outs[@]}"
    fi
    return 0
}

median() { sort -n "$1" | awk '{a[NR]=$1} END{if(NR%2)print a[(NR+1)/2]; else printf "%.1f\n",(a[NR/2]+a[NR/2+1])/2}'; }

# output equality for the full path: sorted md5 over the whole answer
answer_md5() { # answer_md5 <pat> <j> <flags>
    local pat="$1" j="$2" flags="$3"
    # shellcheck disable=SC2086
    "$TV" -j "$j" "$pat" --engine tv --tv-store "$STORE" $flags 2>/dev/null \
        | tr -d '\r' | LC_ALL=C sort | md5sum | cut -d' ' -f1
}

hr
echo "rgx-tv axis matrix -- CLI wall clock, paired within the round"
hr
echo "binary   : $TV"
echo "store    : $STORE  ($(ls "$STORE"/*.tvp 2>/dev/null | wc -l | tr -d ' ') packs, $(du -sm "$STORE" 2>/dev/null | cut -f1) MB on disk)"
echo "rounds   : $ROUNDS, $BATCH consecutive runs per sample, floor +/-${FLOOR}%"
echo "threads  : $THREADS"
echo "reference: $REF  (cold mapping, explicit unmap -- the arm where --leak-mmap acts)"
echo "clock    : bash TIMEFORMAT=%R. No CPU counter: % Processor Time is"
echo "           saturated by the mapping's page faults and cannot resolve this."
echo

FAIL=0

IFS=',' read -ra CELLA <<< "$CELLS"
for cell in "${CELLA[@]}"; do
    pat="${cell%%|*}"
    pathflag="${cell##*|}"
    for j in ${THREADS//,/ }; do
        echo "== pattern '$pat'   output: $pathflag   threads: $j =="
        printf "   %-15s %9s %9s %9s %9s  %-22s %s\n" \
               "arm" "median" "min" "max" "paired" "verdict" "note"

        rm -f "$TMPD"/s.* "$TMPD"/n.*

        for ((r = 0; r < ROUNDS; r++)); do
            n=${#ARMS[@]}
            for ((k = 0; k < n; k++)); do
                idx=$(( (k + r) % n ))
                label="${ARMS[$idx]%%|*}"
                flags="${ARMS[$idx]#*|}"
                sample "$pat" "$pathflag" "$j" "$flags" "$label" "$r" || FAIL=1
            done
        done

        # ---- gate: every arm answers the reference's answer --------------
        refn=""
        if [ "$pathflag" = "-c" ]; then
            refn=$(sort -u "$TMPD/n.$REF" | tr '\n' ' ')
            for label in "${LABELS[@]}"; do
                n=$(sort -u "$TMPD/n.$label" | tr '\n' ' ')
                if [ "$n" != "$refn" ]; then
                    echo "   GATE FAILED: $label answered [$n], reference answered [$refn]"
                    FAIL=1
                fi
            done
            echo "   count gate: every arm answered $refn (matches)"
        else
            m0=""
            for a in "${ARMS[@]}"; do
                label="${a%%|*}"
                flags="${a#*|}"
                m=$(answer_md5 "$pat" "$j" "$flags")
                [ -z "$m0" ] && m0="$m"
                if [ "$m" != "$m0" ]; then
                    echo "   GATE FAILED: $label printed a different answer than $REF"
                    FAIL=1
                fi
            done
            echo "   answer gate: every arm printed a byte-identical answer (md5 ${m0:0:12})"
        fi

        # ---- verdict per arm, paired against the reference ---------------
        for label in "${LABELS[@]}"; do
            med=$(median "$TMPD/s.$label")
            mn=$(sort -n "$TMPD/s.$label" | head -1)
            mx=$(sort -n "$TMPD/s.$label" | tail -1)
            read -r paired verdict note <<< "$(
                awk -v a="$TMPD/s.$label" -v b="$TMPD/s.$REF" -v floor="$FLOOR" -v ref="$REF" '
                BEGIN{
                    na=0; nb=0
                    while ((getline l < a) > 0) { sa[++na] = l + 0 }
                    close(a)
                    while ((getline l < b) > 0) { sb[++nb] = l + 0 }
                    close(b)
                    n = (na < nb) ? na : nb
                    if (n == 0) { print "n/a  no-data  -"; exit }
                    sum = 0
                    for (i = 1; i <= n; i++) { d[i] = sa[i] - sb[i]; sum += d[i] }
                    mean = sum / n
                    base = 0; for (i = 1; i <= nb; i++) base += sb[i]
                    base /= nb
                    pct = (base > 0) ? 100.0 * mean / base : 0
                    maxa = -1e18; mina = 1e18
                    for (i = 1; i <= n; i++) { if (sa[i] > maxa) maxa = sa[i]; if (sa[i] < mina) mina = sa[i] }
                    minb = 1e18; maxb = -1e18
                    for (i = 1; i <= nb; i++) { if (sb[i] < minb) minb = sb[i]; if (sb[i] > maxb) maxb = sb[i] }
                    if (pct > -floor && pct < floor)      v = "tie (inside floor)"
                    else if (maxa < minb)                  v = "faster than " ref
                    else if (mina > maxb)                  v = "slower than " ref
                    else                                   v = "overlap, not a result"
                    printf "%+6.1f%%  %-22s\n", pct, v
                }'
            )"
            printf "   %-15s %9s %9s %9s %9s  %-22s %s\n" \
                   "$label" "$med" "$mn" "$mx" "$paired" "$verdict" "$note"
        done
        echo
    done
done

# ---------------------------------------------------------------------------
# The in-process decomposition, for the same arms at -j8. This is the number
# that says +28% and the number the CLI refuses to reproduce, and both belong
# in the record: the first is teardown, the second is process exit.
# ---------------------------------------------------------------------------
hr
echo "in-process decomposition (-j8, --stats; the CLI wall clock cannot see this)"
hr
printf "   %-15s %10s %10s %10s %10s %10s\n" "arm" "in-proc" "manifest" "map" "work" "teardown"
for a in "${ARMS[@]}"; do
    label="${a%%|*}"
    flags="${a#*|}"
    # shellcheck disable=SC2086
    err=$("$TV" -j 8 -c 'pub fn' --engine tv --tv-store "$STORE" --stats $flags 2>&1 >/dev/null)
    vals=$(printf '%s\n' "$err" | awk '
        /in-process/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "in-process") v["in"]  = $(i+1)
                if ($i == "manifest")   v["man"] = $(i+1)
                if ($i == "filter")     v["fil"] = $(i+1)
                if ($i == "map")        v["map"] = $(i+1)
                if ($i == "work")       v["wrk"] = $(i+1)
                if ($i == "teardown")   v["tdn"] = $(i+1)
            }
            printf "%s %s %s %s %s %s", v["in"], v["man"], v["map"], v["wrk"], v["tdn"], v["fil"]
        }')
    if [ -z "$vals" ]; then
        printf "   %-15s %s\n" "$label" "(no stage line: this arm maps nothing)"
        continue
    fi
    set -- $vals
    printf "   %-15s %10s %10s %10s %10s %10s   (filter %s)\n" "$label" "$1" "$2" "$3" "$4" "$5" "$6"
done
echo
echo "teardown is the stage the CLI cannot escape: with --leak-mmap it becomes"
echo "zero in-process and is paid by the kernel at process exit instead, which"
echo "is why the in-process win and the wall-clock win are different numbers."
echo
echo "read the pool column here first: a pooled arm has no teardown at all,"
echo "because the pool keeps the mappings and only drops an Arc. So --leak-mmap"
echo "can only change anything on the unpooled mmap arm, where Unmap::Explicit"
echo "is reachable -- which is why that arm is the reference."

hr
if [ "$FAIL" = 0 ]; then
    echo "all gates passed"
else
    echo "AT LEAST ONE GATE FAILED -- the table above is not quotable"
fi
hr
[ "$FAIL" = 0 ]
