#!/usr/bin/env python3
"""sync-licence.py -- put the tree's licence and notice into every crate.

The tree has ONE `LICENSE-APACHE` and ONE `NOTICE`, and every crate under
`crates/` carries a copy of each. That is not carelessness: a crate is
downloaded on its own from crates.io, so the copy inside the crate's
tarball is the one a reader opens -- and Apache-2.0 section 4(d) asks for
the attribution notices to travel with the work they describe. The copies
are the law, and `tests/crate_licence.rs` is what holds them to it: it
fails on the first crate whose `NOTICE` drifted from the tree's, because
two copies that disagree are worse than one copy that is right.

What was missing was the other half: a way to REFRESH them. Until this
script, changing the tree's `NOTICE` meant copying it into twelve crates
by hand, and the test only told you afterwards that you had forgotten
one.

    scripts/sync-licence.py --check     report what is out of sync
    scripts/sync-licence.py             make them match

The copy is byte for byte, so the line endings of each file are whatever
the tree's file already has: the licence is CRLF in this checkout and the
notice is LF, and both stay that way.
"""

import argparse
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CRATES = os.path.join(REPO, "crates")

# The two files a crate ships, and where the tree's copy of each lives.
DOCS = ("LICENSE-APACHE", "NOTICE")


def crate_dirs():
    """Every crate of the workspace: a directory under `crates/` with a
    manifest in it. The fixture directories under a crate's `testdata/`
    are not crates and are not reached."""
    out = []
    for name in sorted(os.listdir(CRATES)):
        path = os.path.join(CRATES, name)
        if os.path.isdir(path) and os.path.exists(os.path.join(path, "Cargo.toml")):
            out.append(path)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="report what is out of sync and exit 1; write nothing")
    args = parser.parse_args()

    trees = {}
    for doc in DOCS:
        path = os.path.join(REPO, doc)
        if not os.path.exists(path):
            print("FAIL: the tree has no %s" % doc)
            return 2
        with open(path, "rb") as fh:
            trees[doc] = fh.read()

    problems = []
    for crate in crate_dirs():
        name = os.path.basename(crate)
        for doc in DOCS:
            path = os.path.join(crate, doc)
            if not os.path.exists(path):
                problems.append((name, doc, "missing"))
                continue
            with open(path, "rb") as fh:
                have = fh.read()
            if have != trees[doc]:
                problems.append((name, doc, "drifted"))

    if args.check:
        if not problems:
            print("ok: %d crate(s) carry the tree's %s"
                  % (len(crate_dirs()), " and ".join(DOCS)))
            return 0
        for name, doc, what in problems:
            print("%s: %s is %s" % (name, doc, what))
        print("%d problem(s)" % len(problems))
        return 1

    if not problems:
        print("ok: %d crate(s) already carry the tree's %s"
              % (len(crate_dirs()), " and ".join(DOCS)))
        return 0

    for name, doc, what in problems:
        crate = os.path.join(CRATES, name)
        with open(os.path.join(crate, doc), "wb") as fh:
            fh.write(trees[doc])
        print("%s: %s %s" % (name, doc, "written" if what == "missing" else "refreshed"))
    print("%d file(s) written" % len(problems))
    return 0


if __name__ == "__main__":
    sys.exit(main())
