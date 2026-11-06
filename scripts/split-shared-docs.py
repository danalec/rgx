#!/usr/bin/env python3
"""split-shared-docs.py -- cut the diff of a shared document into per-block patches.

Several documents of this repository are touched by more than one block: the
root `README.md`, the tabular crate's `README.md` and its `testdata/README.md`,
the inspect crate's `testdata/README.md`, the Zarr fixtures' `README.md` and
the Zarr fixture script. Each block has to carry its own text, or the commit
that lands a format says the format is still refused.

The cut is by hunk, and by line inside a hunk when the lines belong to
different blocks: a hunk that adds three table rows, one per block, is cut
into three patches, each with the same before-image and its own rows.

A line belongs to the block whose keywords appear in it; a hunk with no
keyword in any of its added lines is reported as unassigned, because
guessing where a sentence belongs is how a commit ends up claiming
something it did not do.

The cut inside a hunk is by POSITION and never by text: the same line of
code can appear twice in one hunk, and a cut that goes by text drags the
wrong copy along with it.

A hunk that carries the prose of two blocks in one piece -- the two fixture
writers at the end of `main()` -- is cut at a marker: the lines from the
marker on belong to the block the marker names, and the lines before it
stay with the hunk's owner. The marker is given with `--marker`.

The patch of a block is a diff with no context, and the numbers of its
header are recomputed so that it can be applied on its own:

    git apply --cached --unidiff-zero target/patches/ph-b2-README_md.patch

Usage:
    scripts/split-shared-docs.py <file> <block>=<kw1>|<kw2> ...
        [--marker <block>:<text>] [--out <directory>]

The keywords are matched against the added lines, in lower case, and the
first block whose keyword appears in a line owns that line.
"""

import argparse
import io
import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def git(*args):
    # The output is captured as BYTES on purpose: `text=True` would apply
    # the universal-newline translation and drop the CR of a CRLF line,
    # and the patch would then not match the blob it claims to patch.
    raw = subprocess.run(
        ["git", "-C", REPO] + list(args), capture_output=True, check=True
    ).stdout
    return raw.decode("utf-8")


def hunks(path):
    """The diff of one file, as (header, [hunk lines]) pairs."""
    out = git("diff", "-U0", "--", path)
    if not out.strip():
        return "", []
    lines = out.split("\n")
    first = next(i for i, l in enumerate(lines) if l.startswith("@@"))
    header = "\n".join(lines[:first]) + "\n"
    hs = []
    cur = None
    for line in lines[first:]:
        if line.startswith("@@"):
            if cur:
                hs.append(cur)
            cur = [line]
        elif cur is not None:
            cur.append(line)
    if cur:
        hs.append(cur)
    return header, hs


def parse(hunk):
    """The parts of a hunk: where it starts, and the lines of its body."""
    m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)", hunk[0])
    before_at = int(m.group(1))
    before_n = int(m.group(2)) if m.group(2) is not None else 1
    after_at = int(m.group(3))
    after_n = int(m.group(4)) if m.group(4) is not None else 1
    tail = m.group(5)
    body = hunk[1:]
    trailing = ""
    if body and body[-1] == "":
        body = body[:-1]
        trailing = "\n"
    return before_at, before_n, after_at, after_n, tail, body, trailing


def piece(before_at, tail, body):
    """A hunk that carries only some of the lines of another one."""
    return (before_at, tail, list(body))


def added_indexes(body):
    return [i for i, l in enumerate(body) if l.startswith("+")]


def split_by_markers(hunk, markers):
    """Cut a hunk at a marker line.

    A hunk that carries the calls of two blocks in one piece -- the three
    fixture writers at the end of `main()` -- is cut at the marker: the
    lines from the marker on belong to the block the marker names, and the
    lines before it stay with the hunk's owner.

    The cut is by position. The same line of code can appear twice in one
    hunk, and a cut that goes by the text of the line takes the wrong copy
    of it along.

    Returns a list of (block, piece); the block is None for the part that
    keeps the hunk's owner.
    """
    if not markers:
        before_at, _bn, _an, _an2, tail, body, _tr = parse(hunk)
        return [(None, piece(before_at, tail, body))]

    before_at, _bn, _an, _an2, tail, body, _tr = parse(hunk)
    cut = None
    for text, block in markers:
        for i in added_indexes(body):
            if text.lower() in body[i].lower():
                cut = (i, block)
                break
        if cut:
            break
    if cut is None:
        return [(None, piece(before_at, tail, body))]
    if any(l.startswith("-") for l in body):
        # a hunk that removes lines cannot be cut in the middle: the
        # removal would be split in two and neither half would apply.
        print("NOTE in the hunk at %d: it removes lines and is not cut" % before_at)
        return [(None, piece(before_at, tail, body))]
    i, block = cut
    head = piece(before_at, tail, body[:i])
    tailp = piece(before_at, tail, body[i:])
    return [(None, head), (block, tailp)]


def classify(body, blocks):
    """The block of every added line, and the lines of each block.

    A hunk that only removes lines has no added line to name the block it
    belongs to, so the removed lines are the ones that say: the change is
    about what the text stops saying.
    """
    idxs = added_indexes(body)
    if not idxs:
        idxs = [i for i, l in enumerate(body) if l.startswith("-")]
    owners = []
    for i in idxs:
        low = body[i][1:].lower()
        owner = None
        for name, kws in blocks.items():
            if any(k in low for k in kws):
                owner = name
                break
        owners.append((i, owner))
    matched = {}
    for i, owner in owners:
        matched.setdefault(owner, []).append(i)
    return owners, matched


def slug(path):
    return path.replace("/", "_").replace("\\", "_").replace(".", "_")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    parser.add_argument("rules", nargs="+", help="<block>=<kw1>|<kw2>")
    parser.add_argument("--marker", action="append", default=[],
                        help="<block>:<text> -- a hunk is cut at the line that "
                             "holds the text, and the part from there belongs "
                             "to the block")
    parser.add_argument("--out", default=os.path.join("target", "patches"),
                        help="where the patches are written")
    args = parser.parse_args()

    blocks = {}
    for rule in args.rules:
        name, _, kws = rule.partition("=")
        if not kws:
            print("a rule is not <block>=<keywords>: %s" % rule)
            return 2
        blocks[name] = [k.lower() for k in kws.split("|")]

    markers = []
    for m in args.marker:
        block, _, text = m.partition(":")
        if not text:
            print("a marker is not <block>:<text>: %s" % m)
            return 2
        markers.append((text, block))

    header, hs = hunks(args.file)
    if not hs:
        print("no diff for %s" % args.file)
        return 1

    per_block = {}
    for h in hs:
        for marker_block, p in split_by_markers(h, markers):
            before_at, tail, body = p
            if not body:
                # a cut that leaves nothing behind: the part is already in
                # the tree the diff was taken from.
                continue
            owners, matched = classify(body, blocks)

            if marker_block is not None:
                # the marker says who owns this part of the hunk.
                per_block.setdefault(marker_block, []).append(p)
                continue

            named = [n for n in matched if n is not None]
            if len(named) == 0:
                print("UNASSIGNED in %s:\n%s"
                      % (args.file, "\n".join(body[i] for i in matched.get(None, []))))
                continue
            if len(named) == 1:
                # One block, the whole hunk: the lines that name no block
                # are part of the same paragraph and go with it.
                per_block.setdefault(named[0], []).append(p)
                continue

            if added_indexes(body) and all(
                body[i][1:].startswith("|") for i in added_indexes(body)
            ):
                # A hunk that adds whole table rows is cut between the rows:
                # each row belongs to the block it names. The line of a row
                # carries the '+' of the diff, and the text of the row is
                # what follows it.
                for name, idxs in matched.items():
                    if name is None:
                        continue
                    per_block.setdefault(name, []).append(
                        piece(before_at, tail, [body[i] for i in idxs]))
                continue

            # Otherwise the hunk is one piece of prose or one function, and it
            # goes whole to the block that owns most of its lines: a
            # paragraph that two blocks touch is one paragraph.
            counts = {n: len(v) for n, v in matched.items() if n is not None}
            owner = max(counts, key=counts.get)
            per_block.setdefault(owner, []).append(p)
            others = [n for n in counts if n != owner]
            if others:
                print("NOTE in %s: the hunk also mentions %s"
                      % (args.file, ", ".join(others)))

    out_dir = args.out if os.path.isabs(args.out) else os.path.join(REPO, args.out)
    os.makedirs(out_dir, exist_ok=True)

    for name, pieces in per_block.items():
        # The "+" line numbers of a hunk are relative to the file AFTER
        # every hunk of the diff -- including the ones this patch does not
        # carry. They are recomputed here, so the patch is self-consistent
        # and can be applied on its own.
        delta = 0
        fixed = []
        for before_at, tail, body in pieces:
            before = sum(1 for l in body if not l.startswith("+"))
            after = sum(1 for l in body if not l.startswith("-"))
            if before == 0 and after == 0:
                continue
            # The "+" side of a hunk says where its lines land in the file
            # the patch produces. A hunk that adds lines without taking any
            # away is an insertion, and the diff says it happens AFTER the
            # line it names: the new side starts one line further on. The
            # hunks that came before in this patch moved the lines, and
            # that is what the delta carries.
            new_start = before_at + delta + (1 if before == 0 else 0)
            fixed.append(
                ["@@ -%d,%d +%d,%d @@%s" % (before_at, before, new_start, after, tail)]
                + body
            )
            delta += after - before
        patch = header + "\n".join("\n".join(h) for h in fixed) + "\n"
        target = os.path.join(out_dir, "ph-%s-%s.patch" % (name, slug(args.file)))
        with io.open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(patch)
        print("%s: %d hunk(s) -> %s" % (name, len(pieces), target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
