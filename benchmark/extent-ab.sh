#!/usr/bin/env bash
# extent-ab.sh -- extent-sparse A/B: one binary, two arms,
# `RGX_ABLATE_EXTENTS` as the control.
#
# The Linux counterpart of benchmark/extent-ab.ps1.
#
# Protocol, per AGENTS.md 9: the count gate is in front of every timing line
# (an arm whose -c disagrees with the other arm or with the direct path
# prints no timing), the verdict may refuse (inside the floor the row is a
# tie, and a winner is named only when every sample of one arm sits below
# every sample of the other), and the spawn floor is measured first and
# subtracted from both sides.
#
#   bash benchmark/extent-ab.sh --corpus crates --rounds 7
#
# The transcript is the run; findings.md quotes only what it prints.
#
# The timing is `date +%s%N` where the kernel gives nanoseconds, and the
# fallback is bash's own EPOCHREALTIME on a date(1) that does not. A
# millisecond clock would round the floor to zero and the floor is the
# whole point.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)

corpus="$repo/crates"
store=""
rounds=7
patterns="brotli,fn main"
ablate_var="RGX_ABLATE_EXTENTS"

while [ $# -gt 0 ]; do
    case "$1" in
        --corpus) corpus=${2:-}; shift 2 ;;
        --store) store=${2:-}; shift 2 ;;
        --rounds) rounds=${2:-}; shift 2 ;;
        --patterns) patterns=${2:-}; shift 2 ;;
        --ablate-var) ablate_var=${2:-}; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

rgxtv="$repo/target/release/rgx-tv"
rgx="$repo/target/release/rgx"
[ -x "$rgxtv" ] || { echo "no rgx-tv at $rgxtv; build it first: cargo build --release" >&2; exit 2; }
[ -x "$rgx" ] || { echo "no rgx at $rgx; build it first: cargo build --release" >&2; exit 2; }
[ -d "$corpus" ] || { echo "no corpus at $corpus" >&2; exit 2; }

[ -n "$store" ] || store=$(mktemp -d "/tmp/rgx-extent-ab-XXXXXX")

# The clock, in milliseconds. `date +%s%N` is nanoseconds on GNU
# coreutils; where the %N is not there, bash's EPOCHREALTIME is the
# fallback.
clock_ms() {
    local ns
    ns=$(date +%s%N 2>/dev/null || echo "")
    case "$ns" in
        *N*|'') echo "0"; return ;;
    esac
    if [ "${#ns}" -lt 19 ]; then
        # No nanoseconds: bash's own clock, in microseconds since the
        # epoch. The unit has to be fixed here, or every measurement
        # below is a thousand times too large and the floor swallows the
        # signal.
        printf '%s' "$EPOCHREALTIME" | awk '{printf "%.3f\n", $1 * 1000}'
        return
    fi
    printf '%s' "$ns" | awk '{printf "%.3f\n", $1/1000000}'
}

# measure <command...> -- the elapsed milliseconds, the command's own
# output discarded.
#
# The two timestamps are read by ONE awk, not by two: awk runs its program
# once per line, so a two-line input read as "$1 - $2" subtracts the
# second field of each line from the first -- and each line has only one
# field, so the result is the timestamp itself. The floor then comes out
# as the epoch, and every measurement below it is noise.
measure() {
    local start end
    start=$(clock_ms)
    "$@" > /dev/null 2>&1
    end=$(clock_ms)
    printf '%s\n%s\n' "$end" "$start" | awk 'NR == 1 { e = $1 } NR == 2 { printf "%.3f\n", e - $1 }'
}

# total_of <output> -- the sum of the per-file counts in a `-c` listing.
#
# The listing is one "file:count" per line, and the count is the answer
# the whole run adds up to: the pack store answers in one number, and the
# direct path answers in one per file. The two have to be comparable, so
# both are summed the same way.
total_of() {
    printf '%s\n' "$1" | awk -F: '
        {
            n = $NF
            if (n ~ /^[0-9]+$/) sum += n
        }
        END { print sum + 0 }'
}

# median <sample...> -- the middle sample, or the mean of the two middle
# ones when the count is even.
median() {
    printf '%s\n' "$@" | sort -n | awk '
        { a[NR] = $1 }
        END {
            if (NR == 0) { print 0; exit }
            if (NR % 2) { print a[(NR+1)/2] }
            else { print (a[NR/2] + a[NR/2+1]) / 2 }
        }'
}

echo "corpus:  $corpus"
echo "store:   $store"
echo "threads: default (identical both arms)"

# 0. The store, once.
"$rgxtv" build "$corpus" --store "$store" > /dev/null || { echo "rgx-tv build failed" >&2; exit 1; }

# 1. The spawn floor: the binary's own startup without a query, five
#    times.
floor_samples=""
for _ in 1 2 3 4 5; do
    floor_samples="$floor_samples $(measure "$rgxtv" --help)"
done
floor=$(median $floor_samples)
printf 'floor:   %.2f ms (median of 5 runs of --help)\n' "$floor"

for pat in $(printf '%s' "$patterns" | tr ',' ' '); do
    pat=$(printf '%s' "$pat" | sed 's/^ *//; s/ *$//')
    [ -n "$pat" ] || continue

    # 2. The count gate, before any timing: arm A and arm B must agree on
    #    the total, and the total must equal the direct path's per-file
    #    sum.
    count_a=$(env "$ablate_var=1" "$rgxtv" search "$pat" --store "$store" -c | tr -d '\r')
    count_b=$("$rgxtv" search "$pat" --store "$store" -c | tr -d '\r')
    total_a=$(total_of "$count_a")
    total_b=$(total_of "$count_b")
    total_d=$(total_of "$("$rgx" --engine rgx -F -c "$pat" "$corpus")")

    if [ "$total_a" != "$total_b" ] || [ "$total_a" -eq 0 ]; then
        echo "pattern '$pat': COUNT GATE FAILED (arms disagree or zero) -- no timing printed"
        continue
    fi
    if [ "$total_a" != "$total_d" ]; then
        echo "pattern '$pat': COUNT GATE FAILED (pack $total_a != direct $total_d) -- no timing printed"
        continue
    fi
    echo "pattern '$pat': count gate agrees (pack A == pack B == direct = $total_a)"

    # 3. The rounds, order rotated: A,B then B,A.
    samples_a=""
    samples_b=""
    r=0
    while [ "$r" -lt "$rounds" ]; do
        if [ $((r % 2)) -eq 0 ]; then
            order="A B"
        else
            order="B A"
        fi
        for arm in $order; do
            if [ "$arm" = "A" ]; then
                samples_a="$samples_a $(measure env "$ablate_var=1" "$rgxtv" search "$pat" --store "$store" -c)"
            else
                samples_b="$samples_b $(measure "$rgxtv" search "$pat" --store "$store" -c)"
            fi
        done
        r=$((r + 1))
    done

    min_a=$(printf '%s\n' $samples_a | sort -n | head -1)
    min_b=$(printf '%s\n' $samples_b | sort -n | head -1)
    max_a=$(printf '%s\n' $samples_a | sort -n | tail -1)
    max_b=$(printf '%s\n' $samples_b | sort -n | tail -1)
    med_a=$(median $samples_a)
    med_b=$(median $samples_b)
    # The floor comes off both medians. One awk reads both numbers: awk
    # runs its program once per line, so a two-line input read as
    # "$1 - $2" subtracts nothing and prints the medians back.
    adj_a=$(printf '%s\n%s\n' "$med_a" "$floor" | awk 'NR == 1 { m = $1 } NR == 2 { printf "%.3f\n", m - $1 }')
    adj_b=$(printf '%s\n%s\n' "$med_b" "$floor" | awk 'NR == 1 { m = $1 } NR == 2 { printf "%.3f\n", m - $1 }')

    echo "pattern '$pat' after $rounds rounds:"
    printf '  ablated : min %8.2f ms  median %8.2f ms  (median-floor %8.2f)\n' "$min_a" "$med_a" "$adj_a"
    printf '  sparse  : min %8.2f ms  median %8.2f ms  (median-floor %8.2f)\n' "$min_b" "$med_b" "$adj_b"

    if [ "$(awk -v a="$adj_a" -v b="$adj_b" 'BEGIN { print (a <= 0) || (b <= 0) }')" = "1" ]; then
        echo "  verdict: under the floor -- not a result"
        continue
    fi
    ratio=$(awk -v a="$adj_a" -v b="$adj_b" 'BEGIN { printf "%.4f", a / b }')
    # A winner is named only when every sample of one arm sits below
    # every sample of the other.
    overlap=$(awk -v a="$max_a" -v b="$min_b" -v c="$max_b" -v d="$min_a" 'BEGIN { print !((a < b) || (c < d)) }')
    inside_floor=$(awk -v r="$ratio" 'BEGIN { d = r - 1.0; if (d < 0) d = -d; print (d <= 0.03) }')

    if [ "$overlap" = "1" ]; then
        printf '  verdict: overlap, not a result (floor-subtracted ratio %.2fx)\n' "$ratio"
    elif [ "$inside_floor" = "1" ]; then
        echo "  verdict: tie inside the +-3% floor"
    elif [ "$(awk -v r="$ratio" 'BEGIN { print (r > 1) }')" = "1" ]; then
        printf '  verdict: sparse wins, %.2fx floor-subtracted\n' "$ratio"
    else
        printf '  verdict: ablated wins, %.2fx floor-subtracted\n' "$(awk -v r="$ratio" 'BEGIN { printf "%.4f", 1 / r }')"
    fi
done

echo "done. store kept at $store"
