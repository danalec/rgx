#!/usr/bin/env bash
# An adapter that transforms makes rgx a SUBSET of ripgrep.
# An adapter that decompresses makes it a SUPERSET. Measure which is which.
#
# The claim, stated so it can fail:
#
#   * A DECOMPRESSING adapter (zip, gz, pdf, png, ...) claims a binary
#     extension that ripgrep refuses to read at all. Everything rgx reports
#     from such a file is text ripgrep could never have produced. Superset.
#
#   * A TRANSFORMING adapter (html, md, rtf, tex, ...) claims an extension
#     that ripgrep already reads perfectly as plain text. rgx replaces those
#     bytes with a flattened rendering, and the flattening deletes whatever
#     the renderer had no place for -- <script> bodies, JSON, link targets,
#     control words. Anything deleted is a match ripgrep reported and rgx does
#     not. Strict subset, and no flag recovered it, because the bytes were
#     gone before the matcher ran.
#
# `rgx_core::Reach` and `rgx_core::Policy` exist because of this property, and
# they make it switchable at run time via RGX_ADAPTER_VIEW:
#
#     unset / source  the file's own bytes. A transforming adapter does not get
#                     the file. This is the default and the only view under
#                     which rgx is a superset of ripgrep on a Render format.
#     render          the adapter's rendering, whatever it is. This is what
#                     every rgx before Reach did, and it is what makes rgx a
#                     strict subset. Kept, and measured below, because a
#                     rendering is a better DOCUMENT and someone will want it.
#     both            the union. Heavier and duplicate-heavy, and not even a
#                     strict superset -- see Policy's own doc comment.
#
# So this harness runs the whole registry three times, once per view, and
# prints all three numbers. The delta between the first two rows IS the size
# of the subset property, in files.
#
# The single-file demonstration is `oorandom-11.1.5/tarpaulin-report.html`:
# two `var data = {...}` blobs embedded in <script> tags.
#
# Usage:  scripts/adapter-subset.sh [--corpus <dir>] [--probe <str>] [--jobs N]
# Exit 0 with the tables printed; 1 if the harness itself is broken.

set -uo pipefail

# The cargo registry's unpacked crates. The last component of the
# directory name carries a hash that changes with the cargo version, so it
# is FOUND and not written down: a path with one machine's hash in it is
# a corpus that exists on that machine and on no other.
cargo_registry_src() {
    local src d
    if [ -n "${CARGO_HOME:-}" ]; then
        src="$CARGO_HOME/registry/src"
    elif [ -n "${USERPROFILE:-}" ]; then
        src="$USERPROFILE/.cargo/registry/src"
    else
        src="${HOME:-}/.cargo/registry/src"
    fi
    for d in "$src"/index.crates.io-*; do
        if [ -d "$d" ]; then
            printf '%s\n' "$d"
            return 0
        fi
    done
    return 1
}
CORPUS="${CORPUS:-$(cargo_registry_src || true)}"
PROBE="e"
JOBS=16

while [ $# -gt 0 ]; do
    case "$1" in
        --corpus) CORPUS="$2"; shift 2 ;;
        --probe)  PROBE="$2"; shift 2 ;;
        --jobs)   JOBS="$2"; shift 2 ;;
        -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

# The Windows name first, then the bare one: the Unix host has no
# `.exe` and the Windows host has no bare `rgx`. The one that exists
# is the one the harness runs.
RGX="${RGX:-./target/release/rgx.exe}"
[ -x "$RGX" ] || RGX="${RGX%.exe}"
RG="${RG:-rg}"

[ -x "$RGX" ] || { echo "build rgx first: cargo build --release" >&2; exit 1; }
command -v "$RG" >/dev/null 2>&1 || { echo "ripgrep not on PATH" >&2; exit 1; }
[ -n "$CORPUS" ] && [ -d "$CORPUS" ] || {
    echo "corpus not found: the cargo registry holds no unpacked crates here;" >&2
    echo "run 'cargo fetch' first, or pass --corpus DIR" >&2
    exit 1
}

hr() { printf '%s\n' "----------------------------------------------------------------------------"; }

hr
echo "Adapter registry: subset or superset?"
hr
echo "corpus  : $CORPUS"
echo "rg      : $($RG --version | head -1)"
echo "rgx     : $RGX  ($(stat -c%y "$RGX" 2>/dev/null | cut -c1-19))"
echo "probe   : -o -F '$PROBE'   (occurrences per engine, each under its own default rules)"
echo "views   : RGX_ADAPTER_VIEW unset/source, =render, =both"
echo

# ---------------------------------------------------------------------------
# Part 1. One file, all three views, so the property is visible before it is
# counted. The extension on the left is the one the adapter CLAIMS.
# ---------------------------------------------------------------------------
echo "1. THE MECHANISM, on one file"
echo
W="$CORPUS/oorandom-11.1.5/tarpaulin-report.html"
if [ -f "$W" ]; then
    T=$(mktemp -d)
    cp "$W" "$T/as.txt"
    for e in html htm xhtml md markdown gfm rst tex rtf; do cp "$W" "$T/as.$e"; done
    printf "   %-11s %6s %14s %10s %8s\n" "claimed as" "rg" "rgx (default)" "render" "both"
    for e in txt html htm xhtml md markdown gfm rst tex rtf; do
        f="$T/as.$e"
        printf "   %-11s %6s %14s %10s %8s\n" ".$e" \
            "$($RG -c -F --no-filename 'files":[' "$f" 2>/dev/null | awk '{s+=$1} END{print s+0}')" \
            "$("$RGX" -c -F --no-filename 'files":[' "$f" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')" \
            "$(RGX_ADAPTER_VIEW=render "$RGX" -c -F --no-filename 'files":[' "$f" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')" \
            "$(RGX_ADAPTER_VIEW=both   "$RGX" -c -F --no-filename 'files":[' "$f" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')"
    done
    rm -rf "$T"
    echo
    echo "   .txt is ripgrep's own view and is the truth: 2 blobs, both inside a"
    echo "   <script> element. Under =render the HTML arm deletes the <script>"
    echo "   subtree and reports 0; the Markdown and RST arms keep one blob each"
    echo "   and lose the other to their own escaping rules. Under the default"
    echo "   the file's own bytes are searched and the answer is 2, like rg's."
    echo "   This is why Reach::Render exists and why the default is not Render."
else
    echo "   $W not present; skipped"
fi
echo

# ---------------------------------------------------------------------------
# Part 2. The count, over every file in the corpus whose extension some
# adapter claims, once per view. Both engines run with their own defaults,
# which is the point: a decompressing adapter wins on a file ripgrep refuses
# and a transforming adapter loses on a file ripgrep reads.
# ---------------------------------------------------------------------------
echo "2. THE SIZE OF IT, over every claimed extension in this corpus"
echo

RGX_ABS="$(cd "$(dirname "$RGX")" && pwd)/$(basename "$RGX")"

python - "$CORPUS" "$RG" "$RGX_ABS" "$PROBE" "$JOBS" <<'PY'
import os, re, subprocess, sys, collections
from concurrent.futures import ThreadPoolExecutor

corpus, rg, rgx, probe, jobs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
EXT_RE = re.compile(r'^[A-Za-z0-9_+][A-Za-z0-9_+.]{0,11}$')
VIEWS = [('', 'default (Source)'), ('render', 'RGX_ADAPTER_VIEW=render'), ('both', 'RGX_ADAPTER_VIEW=both')]
root = os.getcwd()


def claimed_extensions():
    """Every `fn extensions() -> &'static [&'static str] { .. }` literal in the
    adapter crates. Source-derived on purpose: it is the registry as written,
    with no way for a build to disagree with the table."""
    out = collections.OrderedDict()
    for dp, _, fns in os.walk(os.path.join(root, 'crates')):
        if 'adapters' not in dp:
            continue
        for fn in sorted(fns):
            if not fn.endswith('.rs'):
                continue
            f = os.path.join(dp, fn)
            src = open(f, encoding='utf-8', errors='replace').read()
            for m in re.finditer(r"fn\s+extensions\(&self\)\s*->\s*&'static\s*\[&'static\s*str\]\s*\{", src):
                i, depth = m.end(), 1
                while i < len(src) and depth > 0:
                    if src[i] == '{':
                        depth += 1
                    elif src[i] == '}':
                        depth -= 1
                    i += 1
                body = src[m.end():i - 1]
                if 'self.exts' in body:      # ProcAdapter: its own table
                    continue
                exts = [t for t in re.findall(r'"([^"]*)"', body) if EXT_RE.match(t) and '\\' not in t]
                if exts:
                    out.setdefault(os.path.relpath(f, root), []).extend(exts)
    return out


def occurrences(cmd, env_view=None):
    env = dict(os.environ)
    if env_view:
        env['RGX_ADAPTER_VIEW'] = env_view
    try:
        r = subprocess.run(cmd, capture_output=True, env=env)
    except Exception:
        return -1
    if r.returncode not in (0, 1):
        return -1
    return r.stdout.count(b'\n')


registry = claimed_extensions()
extset = set(e.lower() for v in registry.values() for e in v)
slots = sum(len(v) for v in registry.values())
print("   adapter extension blocks : %d" % len(registry))
print("   extension slots          : %d   distinct: %d" % (slots, len(extset)))
print()

files = []
for dp, _, fns in os.walk(corpus):
    for fn in fns:
        e = fn.rsplit('.', 1)[-1].lower() if '.' in fn else ''
        if e in extset:
            files.append((os.path.join(dp, fn), e))
print("   files carrying a claimed extension : %d" % len(files), flush=True)


def one(job):
    path, ext = job
    raw = occurrences([rg, '-o', '-F', '--no-filename', probe, path])
    return None if raw < 0 else (ext, path, raw)


with ThreadPoolExecutor(max_workers=jobs) as ex:
    base = [r for r in ex.map(one, files) if r]
if not base:
    print("   ripgrep measured nothing -- the harness is broken", file=sys.stderr)
    sys.exit(1)


def sweep(view):
    def one2(t):
        ext, path, raw = t
        gx = occurrences([rgx, '-o', '-F', '--no-filename', probe, path], view)
        return None if gx < 0 else (ext, raw, gx)
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        return [r for r in ex.map(one2, base) if r and not (r[1] == 0 and r[2] == 0)]


print("   files with a non-zero answer from at least one engine : %d" % len(base))
print()
results = {}
for env, label in VIEWS:
    res = sweep(env)
    results[env] = res
    sub = sum(1 for _, r, g in res if g < r)
    sup = sum(1 for _, r, g in res if g > r)
    eq = len(res) - sub - sup
    print("   %-26s subset %5d (%5.1f%%)   equal %5d   superset %5d (%5.1f%%)"
          % (label, sub, 100.0 * sub / len(res), eq, sup, 100.0 * sup / len(res)))
print()

print("   SUBSET files by extension, per view")
print("   (subset = rgx reports fewer occurrences of a byte the file already had)")
print()
keys = sorted(set(e for env, _ in VIEWS for e, _, _ in results[env]),
              key=lambda k: -(sum(1 for e, r, g in results[''] if e == k and g < r)
                              + sum(1 for e, r, g in results['render'] if e == k and g < r) // 4))
print("   %-9s %7s %9s %9s %9s" % ("ext", "files", "default", "render", "both"))
for k in keys[:30]:
    n = sum(1 for e, _, _ in results[''] if e == k)
    row = [sum(1 for e, r, g in results[env] if e == k and g < r) for env, _ in VIEWS]
    if n < 2 or sum(row) == 0:
        continue
    print("   %-9s %7d %9d %9d %9d" % (k, n, row[0], row[1], row[2]))
print()
print("   A subset that survives into the `default` column is a bug: those are")
print("   files rgx still reads less of than ripgrep, with the file's own bytes")
print("   searched. A subset that only appears in the `render` column is the")
print("   subset property, correctly quarantined.")
PY
rc=$?
[ "$rc" = 0 ] || { echo "harness failed (exit $rc)" >&2; exit 1; }

echo
hr
echo "The README positions rgx as strictly more than ripgrep. That is true for"
echo "the decompressing adapters and false for the transforming ones, which"
echo "claim the extensions a Rust codebase is mostly made of. The tables above"
echo "are the size of that exception under each view."
hr
