#!/usr/bin/env python3
"""suite-counts.py -- the counts per suite of a gate's log.

The notes of the project list the counts per suite next to the total, and
the list has to be of the tree that is published. This reads the log of a
gate run and says what each test binary holds, so the list can be compared
with the numbers the log holds.

Usage:
    scripts/suite-counts.py                      # target/gate/test.log
    scripts/suite-counts.py path/to/test.log
    scripts/suite-counts.py --total              # the four numbers only
"""

import argparse
import io
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# The "Running" line names the binary, and cargo prints its path: the
# relative one on Windows and the absolute one on Linux, so the name of the
# binary is what the regex takes. The doctests come on a line of their own.
RUN = re.compile(r"^\s*Running\s+(?:unittests\s+)?(\S+)\s+\((?:[^)]*[/\\])?deps[/\\]([A-Za-z0-9_]+)-")
DOC = re.compile(r"^\s*Doc-tests\s+(\S+)")
RESULT = re.compile(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", default=os.path.join("target", "gate", "test.log"))
    parser.add_argument("--total", action="store_true",
                        help="print the four numbers and nothing else")
    args = parser.parse_args()

    path = args.log if os.path.isabs(args.log) else os.path.join(REPO, args.log)
    if not os.path.exists(path):
        print("the log is not there: %s" % path)
        return 1

    with io.open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().split("\n")

    suites = []
    current = None
    for line in lines:
        m = RUN.match(line)
        if m:
            current = (m.group(1).replace("\\", "/"), m.group(2))
            continue
        m = DOC.match(line)
        if m:
            current = ("doc", m.group(1))
            continue
        m = RESULT.match(line)
        if m and current:
            suite, exe = current
            name = exe if suite.startswith("src/") else suite
            if suite == "doc":
                name = "doc:" + exe
            suites.append((name, int(m.group(1)), int(m.group(3))))
            current = None

    passed = sum(s[1] for s in suites)
    ignored = sum(s[2] for s in suites)
    if args.total:
        print("%d %d %d %d" % (passed, 0, ignored, len(suites)))
        return 0

    print("%d suites, %d tests, %d ignored" % (len(suites), passed, ignored))
    for name, p, i in suites:
        print("  %-46s %4d%s" % (name, p, " (+%d ignored)" % i if i else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
