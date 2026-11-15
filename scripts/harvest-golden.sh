#!/usr/bin/env bash
# harvest-golden.sh -- harvest real-world golden samples from this machine
# into tests/golden/.
#
# The Linux counterpart of scripts/harvest-golden.ps1.
#
# Synthetic fixtures prove the parsers handle well-formed input; golden
# samples prove they survive what real producers actually ship (a real
# font, a real ELF shared object, a camera JPEG, a real database, a real
# PDF). Files are copied locally and gitignored -- never committed
# (licensing); the CLI test skips silently when the directory is absent,
# so CI stays hermetic.
#
# The Windows script takes its samples from C:\Windows\Fonts, from
# C:\Windows\System32 and from an installed application. The paths here
# are the Linux equivalents of the same four kinds of thing: a system
# font, a system shared object, a JPEG, a database, and a PDF from the
# user's own tree. A sample that is not on this machine is skipped, never
# faked.
#
# One difference from the Windows script, and it is the better of the two:
# every sample is *verified* against the pattern before it is recorded.
# The Windows script writes the pattern it expects and moves on; here the
# built binary has to agree that the pattern is in the file, and a sample
# that does not match is reported and left out of the manifest. A
# manifest that names a sample the tool cannot find is a test that fails
# on the next machine, which is the opposite of what a golden sample is
# for.
#
# Writes tests/golden/manifest.tsv: "<file>\t<pattern>" per line, where
# the pattern is known to match in that file on this machine.
#
# Usage:
#   bash scripts/harvest-golden.sh
#   bash scripts/harvest-golden.sh --out-dir /tmp/golden --pdf-dir ~/Documents
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)

out_dir=""
pdf_dir="$HOME/Documents"

while [ $# -gt 0 ]; do
    case "$1" in
        --out-dir) out_dir=${2:-}; shift 2 ;;
        --pdf-dir) pdf_dir=${2:-}; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ -n "$out_dir" ] || out_dir="$repo/tests/golden"
mkdir -p "$out_dir"

rgx="$repo/target/release/rgx.exe"
[ -x "$rgx" ] || rgx="$repo/target/release/rgx"
have_rgx=0
[ -x "$rgx" ] && have_rgx=1

manifest="$out_dir/manifest.tsv"
: > "$manifest"
count=0

# add_golden <name> <source> <pattern>
#
# Copies the sample in, and records it only if the pattern really is in
# it. The pattern is a fixed-string match: the samples are binary, and a
# regex over a JPEG's bytes is a way to lose the sample to a surprise.
add_golden() {
    local name="$1" source="$2" pattern="$3"

    if [ ! -f "$source" ]; then
        echo "skip (not found): $source"
        return
    fi

    cp -f "$source" "$out_dir/$name"

    if [ "$have_rgx" = 1 ]; then
        if ! "$rgx" -l -F "$pattern" "$out_dir/$name" > /dev/null 2>&1; then
            echo "skip (pattern not in the sample): $name <- $source"
            rm -f "$out_dir/$name"
            return
        fi
    else
        echo "note: no rgx binary, the pattern of $name is unverified"
    fi

    printf '%s\t%s\n' "$name" "$pattern" >> "$manifest"
    echo "golden: $name <- $source"
    count=$((count + 1))
}

# media: a font's name table (the table tag is ASCII in the table
# directory, which is what a byte-oriented search can see).
font=$(find /usr/share/fonts /usr/local/share/fonts -name '*.ttf' -type f 2>/dev/null | sort | head -1)
if [ -n "$font" ]; then
    add_golden "font.ttf" "$font" "cmap"
else
    echo "skip: no ttf under /usr/share/fonts"
fi

# media: a JPEG with its own header.
jpeg=$(find /usr/share /usr/local/share -name '*.jpg' -type f 2>/dev/null | sort | head -1)
if [ -n "$jpeg" ]; then
    add_golden "wallpaper.jpg" "$jpeg" "JFIF|Exif"
else
    echo "skip: no jpg under /usr/share"
fi

# inspect: a real ELF shared object from the system.
so=$(find /usr/lib /lib -name 'libc.so.6' -type f 2>/dev/null | sort | head -1)
if [ -n "$so" ]; then
    add_golden "libc.so" "$so" "GLIBC"
else
    echo "skip: no libc.so.6 under /usr/lib"
fi

# tabular: a real SQLite database from the user's own tree.
db=$(find "$HOME/.local/share" "$HOME/.config" -name '*.db' -type f 2>/dev/null | sort | head -1)
if [ -n "$db" ]; then
    add_golden "real.sqlite.db" "$db" "SQLite format 3"
else
    echo "skip: no .db under ~/.local/share or ~/.config"
fi

# docs: a real PDF from the user's corpus.
pdf=$(find "$pdf_dir" -maxdepth 2 -name '*.pdf' -type f 2>/dev/null | sort | head -1)
if [ -n "$pdf" ]; then
    add_golden "real.pdf" "$pdf" "."
else
    echo "skip: no pdf in $pdf_dir"
fi

echo ""
echo "harvested $count samples -> $out_dir"
echo "run 'cargo test --release --test golden' to verify against them"
