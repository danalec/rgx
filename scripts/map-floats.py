#!/usr/bin/env python3
"""Map float placement from a LaTeX .aux file.

Reads every \\newlabel{tab:...}/{fig:...}/{code:...} entry and prints the
page each float landed on, sorted by page. The point is the ordering: a
tall table that cannot share a page with text queues every float behind it,
and a clean compile log says nothing about that. Run after every .tex edit
that touches floats, before believing the PDF:

    python scripts/map-floats.py path/to/tesla-valve.aux [more.aux ...]

Exit code is 0 with a map, 1 when no float label is found (an empty map is
almost always the wrong file, not a paper without figures).
"""

import re
import sys

LABEL = re.compile(r"\\newlabel\{((?:tab|fig|code):[^}@]*)\}\{\{([^}]*)\}\{(\d+)\}")


def map_aux(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        aux = fh.read()
    rows = []
    for m in LABEL.finditer(aux):
        rows.append((int(m.group(3)), m.group(1), m.group(2)))
    return sorted(rows)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    total = 0
    for path in argv[1:]:
        rows = map_aux(path)
        total += len(rows)
        print(f"--- {path}: {len(rows)} floats ---")
        for page, label, number in rows:
            print(f"p{page:>3}  {label:<14} ({number})")
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
