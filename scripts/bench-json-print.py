#!/usr/bin/env python3
"""`--json` against the text path, under the repo's four benchmark rules.

The dense shape is the one that prices the machine-readable path: few files,
many matches each, so a per-line cost is visible. The wide shape (many files,
one match each) hides it completely and reads as `overlap, not a result` for
the same two binaries -- which is why this harness takes the shape as a
parameter and defaults to dense.

Rules, per AGENTS.md section 9:
  1. thread-matched   -- the same -j N to every mode;
  2. a count gate     -- no timing is printed unless all modes agree;
  3. a verdict that can refuse -- a winner only if every sample of one mode
                        is below every sample of the other, else "overlap";
  4. the floor        -- `--version` is measured and subtracted first.

Usage:
    python scripts/bench-json-print.py [dense|wide] [rounds]

The corpus is generated under the system temp directory and is byte-stable
for a fixed shape; it is not the dashboard corpus and this harness does not
regenerate `status.md`.
"""
import os
import pathlib
import shutil
import statistics
import subprocess
import sys

RGX = os.environ.get("RGX") or os.path.join("target", "release", "rgx")
if not os.path.exists(RGX) and os.path.exists(RGX + ".exe"):
    RGX += ".exe"
PATTERN = "needle"
THREADS = "8"


def gen_corpus(shape: str) -> pathlib.Path:
    root = pathlib.Path(os.environ["TEMP"]) / ("rgx-json-print-" + shape)
    stamp = root / ".stamp"
    if root.exists() and stamp.exists():
        return root
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    hit = b"lorem ipsum dolor sit amet " + PATTERN.encode() + b" padding bytes\n"
    miss = b"sed do eiusmod tempor incididunt ut labore\n"
    if shape == "wide":
        # One matching line per file: the per-FILE shape. A per-line cost is
        # invisible here, and that is the point of running both.
        files, lines, matched = 20000, 20, 1
    else:
        # Every line matches: the per-LINE shape, few files, many matches.
        files, lines, matched = 20, 20000, 20000
    body = b"".join(hit if i < matched else miss for i in range(lines))
    for i in range(files):
        (root / ("f%05d.txt" % i)).write_bytes(body)
    stamp.write_bytes(b"ok")
    return root


def run(argv, capture=False):
    t0 = __import__("time").perf_counter()
    p = subprocess.run(
        [RGX] + argv,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ms = (__import__("time").perf_counter() - t0) * 1000.0
    if p.returncode not in (0, 1):
        raise SystemExit("rgx exited %d on %s" % (p.returncode, argv))
    return ms, (p.stdout if capture else b"")


def main() -> int:
    shape = sys.argv[1] if len(sys.argv) > 1 else "dense"
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    if shape not in ("dense", "wide"):
        raise SystemExit("shape must be dense or wide")
    corpus = gen_corpus(shape)
    modes = {
        "text": [PATTERN, str(corpus)],
        "json": ["--json", PATTERN, str(corpus)],
        "count": ["-c", PATTERN, str(corpus)],
    }

    # 2. count gate first: a disagreement suppresses every timing below.
    counts = {}
    for name, argv in modes.items():
        _, out = run(["-j", THREADS] + argv, capture=True)
        if name == "text":
            counts[name] = out.count(b"\n")
        elif name == "json":
            counts[name] = out.count(b'"type":"match"')
        else:
            counts[name] = sum(
                int(tail)
                for tail in (
                    l.decode("utf-8", "replace").rsplit(":", 1)[-1].strip()
                    for l in out.splitlines()
                )
                if tail.isdigit()
            )
    print("shape=%s  corpus=%s" % (shape, corpus))
    print("count gate: %s" % counts)
    if len(set(counts.values())) != 1:
        print("count gate disagrees -- timings suppressed")
        return 1

    # 4. the floor.
    floor = statistics.median([run(["--version"])[0] for _ in range(9)])

    # 1 + 3. paired, rotated rounds and a verdict that can refuse.
    samples = {n: [] for n in modes}
    for r in range(rounds):
        names = list(modes)
        order = names[r % len(names):] + names[: r % len(names)]
        for name in order:
            dt, _ = run(["-j", THREADS] + modes[name])
            samples[name].append(dt)

    print("floor (--version): %.2f ms" % floor)
    print("%-6s %9s %9s %9s %11s" % ("mode", "median", "min", "max", "-floor"))
    for name, s in samples.items():
        print(
            "%-6s %9.2f %9.2f %9.2f %11.2f"
            % (name, statistics.median(s), min(s), max(s), statistics.median(s) - floor)
        )
    print()
    for a, b in (("json", "text"), ("json", "count"), ("text", "count")):
        sa, sb = samples[a], samples[b]
        ra = statistics.median(sa) - floor
        rb = statistics.median(sb) - floor
        if max(sa) < min(sb) or max(sb) < min(sa):
            winner = a if max(sa) < min(sb) else b
            print(
                "%s vs %s: %s faster on every sample (%.2f vs %.2f minus floor, %.1f%%)"
                % (a, b, winner, ra, rb, 100.0 * (rb - ra) / ra)
            )
        else:
            print(
                "%s vs %s: overlap, not a result (%.2f vs %.2f minus floor)"
                % (a, b, ra, rb)
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
