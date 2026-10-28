#!/usr/bin/env python3
"""Per-file count comparison between two rgx search axes, and against ripgrep.

`comm` and `join` were both wrong on this data more than once -- one produced
a "common" set larger than either population, because the two sides spell
paths with different separators and sort orders. This does the comparison in
one place: strip the root, normalise separators, key on the relative path,
and count what is only on each side and what disagrees.

Both arms are given the SAME root, and that is what makes the two spellings
of a file agree. The direct arm prints `<root>/<rel>` and the pack arm
prints `<root>/<rel>` too, because the pack prints the prefix the caller
typed and the path it holds for the file. The first version left the root
off the pack arm, so the pack printed a bare relative path where the direct
arm printed an absolute one, and the key had to GUESS which file was which:
by a cargo registry marker, and then by a list of directory names that look
like a root component. A guess like that collapses two files into one key
(`accesskit-0.24.1/Cargo.toml` and `Inflector-0.11.4/Cargo.toml` are one
key under it), and on any corpus that is not a cargo registry it lines
nothing up at all: every file came out "only in ref" and "only in packs",
and the verdict said SUBSET about a pack that had never been asked.

The key is therefore the path under the root, and the root is a fact the
caller gave the script rather than something to be inferred from a path.

The cargo registry marker is still found rather than written down, because
its last component carries a hash that changes with the cargo version (the
sparse index and the git index hash differently), and a marker written into
this file is the marker of one machine. It is a shortening of the key, not
what makes the two sides agree: it is in the path of both sides or in
neither, because both sides walked the same tree.

Usage:
    scripts/axis-diff.py --root DIR --store DIR [--pattern P] [--vs rg|direct]

Exit 0 when the pack is a superset of the direct answer, 1 when the two
disagree, and 2 when the harness itself is broken -- the store is over
another tree, or the two sides do not name the same files.
"""

import argparse
import os
import subprocess
import sys
from collections import Counter


def registry_marker():
    """The directory cargo unpacks crates into, as a path component.

    The last component carries a hash that changes with the cargo version
    (the sparse index and the git index hash differently), so it is found
    rather than written down: a marker written into this file is the
    marker of one machine, and a machine whose cargo hashes differently
    would strip nothing.
    """
    home = os.environ.get("CARGO_HOME") or os.path.join(os.path.expanduser("~"), ".cargo")
    src = os.path.join(home, "registry", "src")
    if os.path.isdir(src):
        for name in sorted(os.listdir(src)):
            if name.startswith("index.crates.io-"):
                return name + "/"
    return ""


def relative(path, root, marker):
    """The key of a file: its path under the root the two arms share.

    Both arms print the prefix the caller typed, so the two spellings of a
    file are the same string and the key is the tail under the root.

    The registry marker comes first because it makes the key the crate's
    own path (`accesskit-0.24.1/Cargo.toml`) rather than the registry's,
    and it is in the path of both sides or in neither -- so it shortens
    the key and cannot make the two sides disagree.

    A path that is absolute and not under the root is a path from another
    tree, and it is kept whole: the comparison below then finds no file
    in common and says so, which is the truth, rather than pretending the
    two sides are comparable.
    """
    p = path.replace("\\", "/")
    if marker:
        i = p.find(marker)
        if i >= 0:
            return p[i + len(marker):]
    r = root.replace("\\", "/").rstrip("/")
    if r and p.startswith(r + "/"):
        return p[len(r) + 1:]
    return p


def counts(cmd, root, marker):
    """The per-file counts, keyed under the root."""
    out = subprocess.run(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL).stdout.decode("utf-8", "replace")
    got = {}
    for line in out.splitlines():
        head, sep, tail = line.rpartition(":")
        if sep and tail.isdigit():
            got[relative(head, root, marker)] = int(tail)
    return got


def listed(cmd):
    """The files a command names, one per line.

    The listing is over the whole store and not over the files that match
    the pattern, so it is an answer even when the pattern matched nothing.
    """
    out = subprocess.run(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL).stdout.decode("utf-8", "replace")
    return [ln for ln in out.splitlines() if ln.strip()]


def find_rgx():
    """The binary, wherever cargo put it and whatever the host calls it.

    The Windows name first, then the bare one: the Unix host has no
    `.exe`. The same fallback `benchmark/diffrig/fuzz.py` makes.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for profile in ("debug", "release"):
        for name in ("rgx.exe", "rgx"):
            candidate = os.path.join(root, "target", profile, name)
            if os.path.isfile(candidate):
                return candidate
    return os.path.join(root, "target", "release", "rgx")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--store", required=True)
    ap.add_argument("--rgx", default=None)
    ap.add_argument("--pattern", default="a|b|c")
    ap.add_argument("--vs", choices=["direct", "rg"], default="direct")
    ap.add_argument("--jobs", type=int, default=32)
    ap.add_argument("--show", type=int, default=5)
    a = ap.parse_args()

    a.rgx = a.rgx or find_rgx()
    if not os.path.isfile(a.rgx):
        print(f"no rgx at {a.rgx}; build it first: cargo build --release", file=sys.stderr)
        return 2

    # The root is made absolute once, and both arms are given THAT, so the
    # two spell the same file the same way. A relative root would have the
    # pack print a bare path and the direct arm print one with a "./" on
    # it, and the two would have to be told apart again.
    root = os.path.abspath(a.root)
    marker = registry_marker()

    # The store is an INPUT the caller names, and it has to be a store:
    # `rgx --tv-store` builds one over the root when the path holds none,
    # so a store that is missing -- or a directory that is not a store --
    # would be built by the harness itself, and the verdict would be about
    # a store the caller never asked for. A store is a directory with the
    # manifest in it.
    if not os.path.isfile(os.path.join(a.store, "manifest.tvm")):
        print("there is no pack store at %s" % a.store, file=sys.stderr)
        print("Build one over the root you compare:", file=sys.stderr)
        print("  rgx --tv-build %s --tv-store %s" % (root, a.store), file=sys.stderr)
        return 2

    if a.vs == "direct":
        ref_cmd = [a.rgx, "--engine", "rgx", "-j%d" % a.jobs, "-c", a.pattern, root]
    else:
        ref_cmd = ["rg", "-j%d" % a.jobs, "-c", a.pattern, root]
    # The same root on the pack arm. The pack prints the prefix the caller
    # typed and the path it holds for the file, so with the root on both
    # sides the two print the same string for the same file.
    pack_cmd = [a.rgx, "--engine", "tv", "-c", a.pattern, "--tv-store", a.store, root]

    ref = counts(ref_cmd, root, marker)
    pack = counts(pack_cmd, root, marker)

    # The store has to be over this tree. The pack names the files it
    # holds by their path under the root it was built over, and if that
    # was another tree the names are of files that are not here. The
    # counts below would then be about the mismatch and not about the
    # pack, and the verdict would read as a finding about the engine.
    #
    # The listing is asked of the store and not of the pattern, because a
    # pattern that matched nothing leaves the pack with no name to check.
    sample = listed([a.rgx, "--engine", "tv", "--files", "--tv-store", a.store, root])[:8]
    if sample and not any(os.path.isfile(p) for p in sample):
        print("the store names files that are not under the root:\n  " + "\n  ".join(sample),
              file=sys.stderr)
        print("The store was built over another tree. Build it over the root you\n"
              f"compare: rgx --tv-build {root} --tv-store {a.store}", file=sys.stderr)
        return 2

    common = set(ref) & set(pack)
    if ref and pack and not common:
        print("the two axes have no file in common: the paths of the two sides do\n"
              "not line up, and the counts below would be about that and not about\n"
              "the pack.", file=sys.stderr)
        return 2

    lower = sorted(f for f in common if pack[f] < ref[f])
    higher = sorted(f for f in common if pack[f] > ref[f])
    only_ref = sorted(set(ref) - set(pack))
    only_pack = sorted(set(pack) - set(ref))

    print("pattern %r   packs vs %s" % (a.pattern, a.vs))
    print("  %-22s %d" % ("files in ref", len(ref)))
    print("  %-22s %d" % ("files in packs", len(pack)))
    print("  %-22s %d" % ("in common", len(common)))
    print("  %-22s %d" % ("equal counts", len(common) - len(lower) - len(higher)))
    print("  %-22s %d" % ("packs with MORE", len(higher)))
    print("  %-22s %d" % ("packs with LESS", len(lower)))
    print("  %-22s %d" % ("only in ref", len(only_ref)))
    print("  %-22s %d" % ("only in packs", len(only_pack)))
    verdict = "SUPERSET" if not lower and not only_ref else "SUBSET"
    print("  VERDICT: %s" % verdict)

    for label, names in (("LESS", lower), ("only in ref", only_ref),
                         ("MORE", higher), ("only in packs", only_pack)):
        for f in names[:a.show]:
            print("    %-14s %-60s ref=%s packs=%s"
                  % (label, f, ref.get(f, "-"), pack.get(f, "-")))
    return 0 if verdict == "SUPERSET" else 1


if __name__ == "__main__":
    sys.exit(main())
