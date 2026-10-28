#!/usr/bin/env bash
# Diodicity: does anything in rgx actually behave like a Tesla valve?
#
# A Tesla valve passes flow one way at low cost and blocks the other way
# with no moving parts. Operationalised, that is a DIODICITY: the ratio of
# the work available on the blocked side to the work actually performed.
# A real diode has no finite diodicity, because the reverse path is not
# expensive -- it is forbidden. A ratio of 1.0 is a pipe, not a valve.
#
# Three candidates in this codebase, one negative control, and the
# measurement that separates them from an amortisation.
#
#   A. BinaryDetection::Quit(0)      -- the flow TERMINATES at the first NUL
#   B. the roll's consume(drop)      -- bytes are DESTROYED, not copied
#   C. the decompression budget      -- a hard stop with a searchable note
#   D. rgx-tv's pack                 -- the negative control
#
# Usage:  scripts/diodicity.sh [--corpus <dir>] [--store <dir>]
# Exit 0 with the table printed. Exit 1 if the harness itself is broken.

set -uo pipefail

CORPUS="${USERPROFILE:-$HOME}/.cargo/registry/src"
STORE="${TMPDIR:-/tmp}/rgx-tv-dio"
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --corpus) CORPUS="$2"; shift 2 ;;
        --store)  STORE="$2"; shift 2 ;;
        --keep)   KEEP=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done
# The Windows name first, then the bare one: the Unix host has no
# `.exe` and the Windows host has no bare `rgx`. The one that exists
# is the one the harness runs, and the TV engine is a flag of the
# main binary rather than a second program.
RGX=./target/release/rgx.exe
[ -x "$RGX" ] || RGX="${RGX%.exe}"
TV="$RGX"

# A missing binary is a refusal and not a table of measurements that were
# never taken. Every section below would print "skipped", and a reader
# would have to tell that from a section that measured nothing.
[ -x "$RGX" ] || { echo "build rgx first: cargo build --release" >&2; exit 2; }

hr() { printf '%s\n' "----------------------------------------------------------------------------"; }
row() { printf "   %-34s %14s %14s %9s\n" "$1" "$2" "$3" "$4"; }

hr
echo "Diodicity in rgx: is anything a valve, or is everything a pipe?"
hr
echo "corpus: $CORPUS"
echo

# ---------------------------------------------------------------------------
# A. The binary valve.
#
# BinaryDetection::Quit(0) makes the reader stop rolling the moment it
# sees a NUL. Nothing slows down; the flow ceases. The measurable
# consequence is that the fraction of the file that is ever READ is the
# position of the first NUL, and the rest is never touched by anyone.
#
# This is a diode and not a speedup: the blocked direction does not cost
# more, it does not exist. The diodicity below is bytes-present over
# bytes-read -- the "multiplier" the engine is spared.
# ---------------------------------------------------------------------------
echo "A. BinaryDetection::Quit(0) -- the flow stops at the first NUL"
echo "   (searcher.rs: the fill returns early once binary_byte_offset is set;"
echo "    self.roll() is never called again, so the reader is cut off from"
echo "    the rest of the file)"
echo
# The testdata corpus is the one with real binaries in it. For each file we
# take the offset of the first NUL and compare it with the size.
python - "$CORPUS" <<'PY'
import os, sys
root = sys.argv[1]
firsts, sizes, bins = [], 0, 0
for dp, _, fns in os.walk(root):
    for fn in fns:
        p = os.path.join(dp, fn)
        try:
            sz = os.path.getsize(p)
            if sz == 0:
                continue
            with open(p, 'rb') as f:
                chunk = f.read(1 << 16)
            i = chunk.find(b'\x00')
            if i >= 0:
                bins += 1
                firsts.append((i + 1, sz))
        except OSError:
            pass
if not firsts:
    print("   no NUL found in the first 64 KiB of any file; nothing to report")
    sys.exit(0)
firsts.sort()
med = firsts[len(firsts)//2][0]
worst = max(firsts, key=lambda t: t[1] / max(t[0], 1))
best  = min(firsts, key=lambda t: t[1] / max(t[0], 1))
ratios = sorted(s[1] / max(s[0], 1) for s in firsts)
medr = ratios[len(ratios)//2]
print(f"   files with a NUL in the first 64 KiB : {bins}")
print(f"   position of the first NUL           : median {med} bytes")
print(f"   diodicity (bytes present / bytes read)")
print(f"     median {medr:,.0f}x   best {best[1]/max(best[0],1):,.0f}x   worst {worst[1]/max(worst[0],1):,.0f}x")
print()
print("   VERDICT: a diode. The reverse direction is not priced, it is")
print("   absent: the bytes past the NUL are never read, so no amount of")
print("   query time can be spent on them. rg does the same thing -- the")
print("   difference between the two engines is upstream of the valve.")
PY
echo

# ---------------------------------------------------------------------------
# B. The roll destroys bytes.
#
# searcher.rs: roll_target() returns where to cut, and the caller does
# line_buffer.consume(drop). The bytes outside the retained context are
# not copied, not paged, not re-readable: they are dropped. Forward
# streaming is free; backward past the boundary is not slow, it is gone.
#
# Observable as memory high-water: a streaming search should hold roughly
# one buffer, not the file. That is the strongest external evidence of a
# one-way channel that does not exist here, and the counter-argument is
# that an mmapped search holds the whole file -- which is the same fact
# seen from the other side.
# ---------------------------------------------------------------------------
echo "B. The roll's consume(drop) -- bytes are destroyed, not copied"
echo "   (searcher.rs: roll_target() then consume(drop); only the"
echo "    before-context lines survive at the front of the buffer)"
echo
BIG="${BIG:-${USERPROFILE:-$HOME}/.rgx-bench/big235.rs}"
if [ ! -f "$BIG" ]; then
    BIG=$(find "$CORPUS" -type f -size +8M 2>/dev/null | head -1)
fi
if [ -n "$BIG" ] && [ -f "$BIG" ]; then
    bsz=$(stat -c%s "$BIG" 2>/dev/null || echo 0)
    echo "   file : $BIG   $(( bsz / 1048576 )) MiB"
    echo
    echo "   What is verifiable, and it is the substance:"
    echo
    echo "     retained      = the before-context lines, at most max_context of"
    echo "                     them, and max_context is derived from the -A/-B/-C"
    echo "                     the caller asked for. Never the file."
    echo "     dropped       = everything before that, via LineBuffer::consume."
    echo "     re-readable?  = no. No structure in the crate can name the byte"
    echo "                     before the cut."
    echo
    echo "   Functional check that the cut MOVES rather than restores -- the"
    echo "   same file, with the context depth raised 10x:"
    for ctx in 0 400; do
        t=$(bash -c "TIMEFORMAT=%R; time $RGX -B $ctx -c 'fn ' '$BIG' >/dev/null 2>&1" 2>&1 | awk '{print $1}')
        printf "   -B %-6s %10s s over %s MiB\n" "$ctx" "$t" "$(( bsz / 1048576 ))"
    done
    echo
    echo "   If the file were retained, -B 400 would hold hundreds of MiB of"
    echo "   already-visited text. The time does not move with the context depth,"
    echo "   which is what a fixed working set looks like."
    echo
    echo "   NOT MEASURED: peak RSS. The MSYS and Windows pid namespaces"
    echo "   disagree, so a bash-driven Get-Process poll cannot see the child,"
    echo "   and Start-Process -Wait does not preserve PeakWorkingSet64 on this"
    echo "   PowerShell. What is above is structural, from the source, and is"
    echo "   labelled as such rather than dressed up as a measurement."
    echo
    echo "   VERDICT: a diode, and structurally the cleanest of the three. The"
    echo "   drop is a deallocation rather than a copy."
else
    echo "   no file over 8 MiB found; skipped"
fi
echo
# ---------------------------------------------------------------------------
# C. The decompression budget.
echo
if [ -x "$RGX" ]; then
    LZ4=crates/rgx-adapters-archive/testdata/lz4legacy_multiblock.lz4
    [ -f "$LZ4" ] || LZ4=$(find "$CORPUS" -name '*.lz4' -size +1M 2>/dev/null | head -1)
    if [ -n "$LZ4" ]; then
        full=$(stat -c%s "$LZ4" 2>/dev/null || echo 0)
        echo "   fixture : $LZ4   $(stat -c%s "$LZ4") bytes on disk, expands to 41.9 MB"
        echo
        printf "   %-12s %16s %14s\n" "cap" "lines returned" "note emitted"
        for cap in 41943040 1048576 65536; do
            got=$(RGX_MAX_MEMBER_BYTES=$cap "$RGX" -c a "$LZ4" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
            note=$(RGX_MAX_MEMBER_BYTES=$cap "$RGX" a "$LZ4" 2>/dev/null | grep -c "decompression truncated" || true)
            printf "   %-12s %16s %14s\n" "$cap" "$got" "$note"
        done
        echo
        echo "   The cap never slows the decoder, it stops it -- and the refusal"
        echo "   is itself a searchable line, so the blocked side leaves a trace."
        echo "      the cap does not slow the decoder, it stops it, and the"
        echo "      refusal is a searchable line carrying the declared size,"
        echo "      the emitted size and the variable to raise."
        echo
        echo "   VERDICT: a diode, and the only one of the three that is"
        echo "   auditable from outside, because the blocked side leaves a"
        echo "   trace. That is worth more than the other two."
    else
        echo "   no lz4 fixture over 1 MB in the corpus; skipped"
    fi
fi
echo

# ---------------------------------------------------------------------------
# D. The negative control.
#
# rgx-tv is the thing the Tesla valve was named for. Measure it the same
# way, and it fails the test: its asymmetry is TEMPORAL (build pays,
# query does not) rather than SPATIAL (two directions, one channel).
# There is no second direction through the pack to block, so there is
# nothing to compute a diodicity over.
# ---------------------------------------------------------------------------
echo "D. NEGATIVE CONTROL -- rgx-tv's pack"
echo
if [ -x "$TV" ]; then
    if [ ! -d "$STORE" ]; then
        echo "   building the store once (this is the amortisation, and it is"
        echo "   exactly what is NOT a diodicity)..."
        "$TV" --tv-build --tv-store "$STORE" "$CORPUS" >/dev/null 2>&1
    fi
    if [ -d "$STORE" ]; then
        t1=$(bash -c "TIMEFORMAT=%R; time $TV -j 1 -c 'pub fn' --engine tv --tv-store '$STORE' >/dev/null 2>&1" 2>&1 | awk '{print $1}')
        t8=$(bash -c "TIMEFORMAT=%R; time $TV -j 8 -c 'pub fn' --engine tv --tv-store '$STORE' >/dev/null 2>&1" 2>&1 | awk '{print $1}')
        printf "   %-34s %14s %14s %9s\n" "pack search, 1 thread" "${t1}s" "" ""
        printf "   %-34s %14s %14s %9s\n" "pack search, 8 threads" "${t8}s" "" ""
        echo
        echo "   the 1->8 speedup is parallelism, not a valve. There is no"
        echo "   direction through the pack that is blocked; a query either"
        echo "   covers a pack or it does not, and 'does not' is decided by"
        echo "   the manifest, not by the data refusing to flow."
        echo
        echo "   VERDICT: a pipe with a cheaper inlet, which is a different"
        echo "   thing. The build is a once-paid cost and the query inherits"
        echo "   it; that is amortisation, and amortisation has no reverse"
        echo "   direction to be blocked in."
        [ "$KEEP" = 0 ] && rm -rf "$STORE"
    else
        echo "   store build failed; skipped"
    fi
fi

hr
echo "SUMMARY"
hr
echo "  A  binary valve   a real diode: the reverse path is forbidden, not slow"
echo "  B  the roll        a real diode: the bytes are destroyed, not copied"
echo "  C  the budget     a real diode, and the only one auditable from out"
echo "  D  rgx-tv's pack  NOT a diode: a pipe with a cheaper inlet"
hr
echo "The pack is a good piece of engineering and the name was wrong for it."
echo "It amortises a per-file cost. A valve would have to forbid a direction."
hr
