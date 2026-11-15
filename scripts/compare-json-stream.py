#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare two `rg --json` streams record by record.

The harness that runs rgx in place of ripgrep reads the JSON stream and
acts on the records, so the two streams have to agree on the records
themselves. Three things about them cannot agree, and all three are
properties of the platform or of the clock rather than of either
searcher:

  1. the path separator. rg prints the path the OS gave it -- a
     backslash on Windows -- and rgx normalizes it to '/'. The path is
     compared after the separator is normalized.
  2. the order of the files. Both tools search in parallel and neither
     promises an order, so the records are grouped by file and the
     files are compared as a set. The order WITHIN a file is compared,
     because that is the order the reader sees.
  3. the clock. rg reports an `elapsed` beside every set of counters,
     and two runs never agree on it. The value is replaced by a
     placeholder; the PRESENCE of the field is still compared, so a
     stream that drops it fails.

`bytes_printed` is replaced by a placeholder too, and for a reason
that is worth stating: rg counts the bytes it printed, and the path it
printed carries the platform's separator -- which the JSON escapes as
two characters where rgx's costs one. The two numbers therefore differ
by the number of path mentions in the file, and the difference says
nothing about the search. The rule behind the number is pinned by a
test in `tests/cli.rs` instead.

The summary's `bytes_searched` is replaced by a placeholder, and for
a different reason: rg counts the bytes it LOOKED AT, and it stops at
the first NUL, so a binary file costs it nothing. rgx counts every
file it searched, and it reads the formats rg cannot -- an archive, a
model, a database -- so its total is larger on any corpus that holds
one. That is the superset property doing its work, not a divergence
in the search. The per-file `bytes_searched` is still compared, and it
agrees: a file both tools read is counted the same way.

Usage:
    python3 scripts/compare-json-stream.py <rg.json> <rgx.json>

Exits 0 when the two streams agree and 1 when they do not, printing
the first divergent records either way.
"""

import json
import sys

# The placeholder that replaces a value that cannot agree.
TIMING = "<timing>"


def normalize(obj):
    """The record with the unavoidable differences removed."""
    data = obj.get("data")
    if isinstance(data, dict):
        path = data.get("path")
        if isinstance(path, dict) and isinstance(path.get("text"), str):
            path["text"] = path["text"].replace("\\", "/")
        stats = data.get("stats")
        if isinstance(stats, dict):
            if "elapsed" in stats:
                stats["elapsed"] = TIMING
            if "bytes_printed" in stats:
                stats["bytes_printed"] = TIMING
            if obj.get("type") == "summary" and "bytes_searched" in stats:
                # The aggregate: rg counts the bytes it looked at and
                # rgx counts every file it searched, and rgx reads the
                # formats rg cannot. The per-file number is compared.
                stats["bytes_searched"] = TIMING
        if "elapsed_total" in data:
            data["elapsed_total"] = TIMING
    return obj


def load(path):
    """The records of one stream, grouped by the file they belong to.

    The group key is the normalized path, so the file order does not
    matter and the order inside a file does.
    """
    groups = {}
    order = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = normalize(json.loads(line))
            except ValueError as exc:
                raise SystemExit(f"{path}:{number}: not JSON: {exc}")
            kind = record.get("type")
            data = record.get("data") or {}
            path_text = (data.get("path") or {}).get("text")
            if kind == "summary" or path_text is None:
                key = "<summary>"
            else:
                key = path_text
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(record)
    return groups, order


def main(argv):
    if len(argv) != 3:
        print("usage: compare-json-stream.py <rg.json> <rgx.json>", file=sys.stderr)
        return 2
    left, _ = load(argv[1])
    right, _ = load(argv[2])

    problems = []
    for key in sorted(set(left) | set(right)):
        a = left.get(key)
        b = right.get(key)
        if a is None:
            problems.append(f"{key}: only rgx has it ({len(b)} records)")
            continue
        if b is None:
            problems.append(f"{key}: only rg has it ({len(a)} records)")
            continue
        if len(a) != len(b):
            problems.append(f"{key}: rg has {len(a)} records, rgx has {len(b)}")
            continue
        for index, (x, y) in enumerate(zip(a, b)):
            if x != y:
                problems.append(
                    f"{key}: record {index} differs\n"
                    f"    rg : {json.dumps(x, sort_keys=True)}\n"
                    f"    rgx: {json.dumps(y, sort_keys=True)}"
                )
                break

    if problems:
        for problem in problems[:5]:
            print(problem)
        if len(problems) > 5:
            print(f"... and {len(problems) - 5} more")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
