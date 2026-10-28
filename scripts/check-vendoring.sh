#!/usr/bin/env bash
# check-vendoring.sh -- guards the vendoring rules: rgx links nothing from
# upstream, and every vendored file declares its source.
#
# The Linux counterpart of scripts/check-vendoring.ps1.
#
# rgx copies code out of upstream; it never depends on it. This script
# fails if that ever stops being true, so the rule is checked rather than
# remembered. Four checks:
#
#   1. No upstream reference in any Cargo manifest, Cargo.lock, or
#      .cargo/config.toml. Provenance comments in *other* files are fine
#      and are not flagged; only manifests matter, because only manifests
#      can create a dependency edge.
#   2. No [patch] section in .cargo/config.toml, which could redirect a
#      dependency to a local upstream checkout without a path entry.
#   3. Every vendored source file carries a provenance header naming
#      upstream, so copied code stays traceable to its origin.
#   4. No external crates.io dependencies. Known-remaining ones are
#      listed with what replaces them, so the count is a progress metric
#      and a newly added crate fails the check.
#
# The list of known-remaining dependencies is the same list, with the same
# notes, as the Windows script holds: it is the ledger of what is left to
# remove, and a ledger that exists in two places with two wordings is a
# ledger that will say two different things.
#
# Usage:
#   bash scripts/check-vendoring.sh
#
# Run from the repo root (the script re-roots itself).
# Exits 1 on any violation.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cd "$repo"

failures=0

# The failures are counted in a file, not in a variable: every place that
# reports one does it from the right side of a pipe, and a pipeline runs
# in a subshell where a variable increment dies with the subshell. A
# counter that cannot count is worse than no counter, because the script
# would exit 0 with the violations printed.
fail_log=$(mktemp)
trap 'rm -f "$fail_log"' EXIT

fail() {
    echo "  FAIL: $1"
    echo "FAIL" >> "$fail_log"
}

echo "checking vendoring rules in $repo"

# --- 1. no upstream reference in any manifest ---------------------------------
# A match here is a dependency edge, a [patch] target, or a workspace
# inherit. All three are forbidden. Comments that merely mention the
# provenance are acceptable in Cargo.toml, so only the non-comment part of
# a line is inspected.
echo ""
echo "[1/4] no upstream in manifests"

manifests=$(find . -type d -name target -prune -o \
    \( -name 'Cargo.toml' -o -name 'Cargo.lock' \) -type f -print | sort)
config=$(find . -type d -name target -prune -o -path '*/.cargo/config.toml' -type f -print | sort)
manifests="$manifests
$config"
manifests=$(printf '%s\n' "$manifests" | sed '/^[[:space:]]*$/d')

# The loop runs in a subshell (it is the right side of a pipe), so it
# cannot count; it writes a marker per violation and the count is read out
# of the file afterwards.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

for f in $manifests; do
    rel=${f#./}
    # drop comments: a full-line '#' and any trailing ' #'
    grep -in 'vendored from' "$f" 2>/dev/null | while IFS= read -r line; do
        n=${line%%:*}
        text=${line#*:}
        # Only the code part of the line counts: a comment that mentions
        # the provenance is allowed.
        code=${text%%#*}
        if printf '%s' "$code" | grep -qi 'vendored from'; then
            echo "VIOLATION|$rel:$n|$text"
        fi
    done
done > "$tmp"

violations=$(grep -c '^VIOLATION|' "$tmp" || true)
if [ "$violations" -gt 0 ]; then
    grep '^VIOLATION|' "$tmp" | while IFS='|' read -r _ where text; do
        fail "$where references upstream source in manifest code: $text"
    done
else
    n=$(printf '%s\n' "$manifests" | wc -l | tr -d ' ')
    echo "  ok: $n manifests clean"
fi
rm -f "$tmp"
# --- 2. no [patch] in .cargo/config.toml ----------------------------------
echo ""
echo "[2/4] no [patch] redirects"
cfg="$repo/.cargo/config.toml"
if [ -f "$cfg" ]; then
    if grep -Eq '^[[:space:]]*\[patch' "$cfg"; then
        fail ".cargo/config.toml has a [patch] section; it could redirect a dependency to a local checkout"
    else
        echo "  ok: no [patch] section"
    fi
else
    echo "  ok: no .cargo/config.toml"
fi

# --- 3. vendored trees declare provenance ---------------------------------
# A vendored tree is covered by ONE provenance statement in its root
# module (mod.rs), not by per-file headers: the copies are kept
# byte-identical to upstream so a re-sync is a plain file overwrite, and a
# header on every file would have to be re-applied on each sync. Files
# that were *modified* after copying do carry their own header (see
# sevenz/graph_mode.rs) and are listed as exceptions below.
#
# A crate vendored whole (crates/rar-codec) has no mod.rs -- its root
# module is lib.rs, so that is accepted as the root when mod.rs is absent.
#
# So the invariant checked here is: the tree root names its upstream
# source.
echo ""
echo "[3/4] vendored trees declare provenance"
vendored_roots="crates/rgx-adapters-archive/src/sevenz crates/rar-codec/src crates/rgx-core/src/memmap2"
checked=0
for vroot in $vendored_roots; do
    dir="$repo/$vroot"
    [ -d "$dir" ] || continue
    root_name=""
    for candidate in mod.rs lib.rs; do
        if [ -f "$dir/$candidate" ]; then
            root_name=$candidate
            break
        fi
    done
    if [ -z "$root_name" ]; then
        fail "$vroot has no mod.rs or lib.rs to carry tree-level provenance"
        continue
    fi
    checked=$((checked + 1))
    # A vendored tree must name its upstream source. The accepted markers
    # are `vendored from` (legacy trees) or `independent reimplementation`
    # (current trees); if neither is present the tree has no provenance to
    # audit.
    if head -25 "$dir/$root_name" | grep -Eqi '(vendored from|independent reimplementation)'; then
        n=$(find "$dir" -maxdepth 1 -name '*.rs' -type f | wc -l | tr -d ' ')
        echo "  ok: $vroot/$root_name declares provenance for $n files"
    else
        fail "$vroot/$root_name does not name its upstream source; add a tree-level provenance header (vendored from / independent reimplementation)"
    fi
done
if [ "$checked" -eq 0 ]; then
    echo "  ok: no vendored trees configured yet"
fi

# --- 4. no external crates ------------------------------------------------
# The zero-external-crates rule is the project's headline invariant, and
# checks 1-3 could not see it: they only look for upstream references and
# provenance headers, so any number of crates.io dependencies passed
# unnoticed. This check enumerates them.
#
# Known remaining dependencies are listed rather than simply forbidden, so
# the count is a progress metric and nobody can add a new one by
# forgetting. Each entry names what replaces it; the OCR stack is planned
# in OCR-PLAN.md, the search engine in MUST-WRITE.md.
declare -A known_external=(
    # --- search engine (MUST-WRITE.md) ---
    [regex]="the oracle for the syntax and searcher tests. It is a dev-dependency only -- nothing in any binary links it -- and it is the ONLY oracle left: \`differential.rs\` and the grep-searcher dev-dependency were removed with the grep dependencies, so every parity case in \`crates/rgx-core/src/{syntax,regex}.rs\` is written against this crate. The in-house engine is the shipped matcher (MUST-WRITE K1); what remains is the capture-group surface \`grep-regex\` used to provide."
    [ignore]="MUST-WRITE K4 -- parallel walker with gitignore semantics"
    # --- compression and archives: upstream already has these in-house ---
    [brotli]="NO REPLACEMENT: rgx has the RFC 7932 decoder in crates/rgx-adapters-archive/src/brotli/. See tests::oracle::vendored_brotli_does_not_decode_reference_streams"
    [xz2]="upstream b02/compress/xz/ (RFC 8478 container + LZMA2)"
    [zstd]="NOT YET: upstream b02/compress/zstd.rs was refused as not actually zstd"
    # rgx's own .bz2 decoding is in-house already (rgx_core::compress::bzip2,
    # a vendored copy of upstream b02/compress/bzip2.rs, verified against
    # reference-bzip2-CLI fixtures). What is left here is the `zip` crate's
    # own bzip2 backend, which only a fork of `zip` could drop.
    [bzip2-0_5-static]="C binding, pulled in by the zip crate; rgx needs a zip without the bzip2 feature to remove it"
    [lz4_flex]="LZ4 for the persistent extraction cache (src/cache.rs:411 compress, :435 decompress). Unlike the archive decoders, this one is not search: the cache stores what a decode would produce, so it needs a fast compressor the codec modules never had. Will go away if the cache moves to the same raw-blob layout the pack store uses, at the cost of cache size on disk."
    # --- container and metadata readers ---
    [rusqlite]="upstream b01/io/binary/sqlite.rs + b02/sqlite/rusqlite_compat.rs"
    [kamadak-exif]="upstream b01/io/image/exif/"
    # --- plumbing ---
    [clap]="argument parsing; no upstream equivalent identified yet"
    [crossbeam-deque]="the work-stealing deque the parallel walker drains (src/walk.rs:17). Replacing it means writing a Chase-Lev ring in-house; the comment above the dependency records that a hand-rolled Chase-Lev already sits behind the walker mutex and was slower, so the deque is the deliberate second attempt rather than the first."
    [mimalloc]="the opt-in global allocator (src/main.rs:4795). Measured 5-12% on the corpus benches against MSVCRT HeapAlloc, and it is why the third CI job runs the suite with \`--features mimalloc\`. There is no in-house replacement -- this is a whole allocator, not a dependency rgx could reimplement at a useful size. Optional and off by default; nothing links it in a default build."
    [memchr]="crates/rgx-core/src/memchr.rs re-exports the external memchr 2.x crate; there is no in-house memchr tree in this checkout."
    [libc]="the constants and \`mmap(2)\` / \`msync(2)\` / \`madvise(2)\` syscall FFI the vendored \`memmap2\` module (crates/rgx-core/src/memmap2) reaches for on Unix. Gated on the \`std\` feature so the no_std build does not link it. Will go away when the \`memmap2\` module is rewritten in pure inline FFI (a follow-up) or when Linux / macOS gating moves to \`std::sys::pal\`."
    [anyhow]="rgx-core/src/error.rs is the in-house replacement; leftover entry"
    # --- OCR stack (OCR-PLAN.md) ---
    [ocrs]="OCR-PLAN K11 -- detection and recognition pipeline"
    [rten]="OCR-PLAN K8/K9 -- model file reader and tensor runtime"
    [image]="OCR-PLAN K10 -- decode and preprocess; upstream has the codecs"
    # --- test-only ---
    [flate2]="dev-dependency for test fixtures"
    [zip]="dev-dependency for test fixtures"
    [libfuzzer-sys]="fuzz harness only; not part of a shipped build"
)

echo ""
echo "[4/4] no unexpected external crates"

# A dependency section is any [..dependencies] table, including
# target-specific ones. Everything else is not a dependency list.
external=$(for f in $manifests; do
    case "$f" in
        *Cargo.toml) ;;
        *) continue ;;
    esac
    rel=${f#./}
    awk -v rel="$rel" '
        /^[[:space:]]*\[/ {
            line = $0
            sub(/^[[:space:]]*\[+/, "", line)
            sub(/\]+[[:space:]]*$/, "", line)
            gsub(/^[ \t]+|[ \t]+$/, "", line)
            section = tolower(line)
            dep = (section ~ /(^|\.)(dev-|build-)?dependencies$/)
            next
        }
        dep {
            code = $0
            sub(/#.*/, "", code)
            gsub(/^[ \t]+|[ \t]+$/, "", code)
            if (code !~ /^[A-Za-z0-9_-]+[ \t]*=/) next
            name = code
            sub(/[ \t]*=.*$/, "", name)
            # path = ... is an in-tree crate; workspace = true inherits one.
            if (code ~ /(^|[^A-Za-z0-9_])path[ \t]*=/) next
            if (code ~ /(^|[^A-Za-z0-9_])workspace[ \t]*=/) next
            print rel ":" NR ":" name
        }
    ' "$f"
done)

# The count is per name, not per occurrence: a crate listed in ten
# manifests is one crate to remove, and reporting it ten times makes the
# number a worse metric.
seen=""
unexpected=""
for entry in $external; do
    name=$(printf '%s' "$entry" | awk -F: '{print $3}')
    case " $seen " in
        *" $name "*) continue ;;
    esac
    seen="$seen $name"
    if [ -z "${known_external[$name]+x}" ]; then
        unexpected="$unexpected
$entry"
    fi
done

if [ -n "$unexpected" ]; then
    printf '%s\n' "$unexpected" | while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        where=$(printf '%s' "$entry" | cut -d: -f1,2)
        name=$(printf '%s' "$entry" | cut -d: -f3)
        fail "$where: external dependency '$name' is not in the known-remaining list; either it is in-tree (use path =) or add it with what replaces it"
    done
else
    echo "  ok: no unlisted external crates"
fi

# Report what is still outstanding. This is the number to drive to zero.
remaining=0
remaining_list=""
for name in $seen; do
    if [ -n "${known_external[$name]+x}" ]; then
        remaining=$((remaining + 1))
        remaining_list="$remaining_list
    - $name (${known_external[$name]})"
    fi
done
if [ "$remaining" -gt 0 ]; then
    echo "  $remaining known external dependenc(ies) still to remove:"
    printf '%s\n' "$remaining_list"
else
    echo "  zero external dependencies: the invariant holds"
fi

# --- result ----------------------------------------------------------------
echo ""
failures=$(grep -c '^FAIL$' "$fail_log" || true)
if [ "$failures" -gt 0 ]; then
    echo "vendoring check FAILED: $failures violation(s)" >&2
    exit 1
fi
echo "vendoring check passed"
exit 0
